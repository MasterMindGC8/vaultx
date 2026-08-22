// ignore_for_file: avoid_print
// Manual smoke check for the file-transfer envelope protocol (see
// lib/services/file_transfer.dart), run directly via
// `dart run tool/manual_file_transfer_smoke.dart` against a locally
// reachable transport_relay. Exercises a multi-chunk transfer (a payload
// well over one chunk's worth of bytes) through the real relay + real
// PQXDH/ratchet session, proving there's no practical size ceiling.
import 'dart:async';
import 'dart:typed_data';

import 'package:client_app/bridge/native_crypto.dart';
import 'package:client_app/services/file_transfer.dart';
import 'package:client_app/services/relay_client.dart';

Future<void> main() async {
  const relayUrl = 'http://51.81.84.85:8443';
  var failures = 0;
  void check(String label, bool condition) {
    print(condition ? '[OK] $label' : '[FAIL] $label');
    if (!condition) failures++;
  }

  await NativeCrypto.ensureInitialized();
  final alice = NativeCrypto.instance.generateIdentity();
  final bob = NativeCrypto.instance.generateIdentity();
  final aliceId = alice.deviceIdHex();
  final bobId = bob.deviceIdHex();

  final http = RelayHttp(baseUrl: relayUrl);
  await http.publishPreKeyBundle(aliceId, alice.publicBundleBytes());
  await http.publishPreKeyBundle(bobId, bob.publicBundleBytes());

  final aliceStream = RelayStream(baseUrl: relayUrl, deviceId: aliceId);
  final bobStream = RelayStream(baseUrl: relayUrl, deviceId: bobId);
  await aliceStream.connect();
  await bobStream.connect();

  final bobBundle = await http.fetchPreKeyBundle(bobId);
  final initiateOutcome = NativeCrypto.instance.initiateSession(alice, bobBundle!);
  final aliceSession = initiateOutcome!.session;

  NativeSession? bobSession;
  IncomingFileTransfer? incoming;
  Uint8List? receivedBytes;
  final done = Completer<void>();

  bobStream.deliveries.listen((delivery) {
    if (delivery.payload.isEmpty) return;
    final tag = delivery.payload[0];
    final body = delivery.payload.sublist(1);
    if (tag == relayTagHandshake) {
      bobSession = NativeCrypto.instance.respondSession(bob, body);
      bobStream.ack(delivery.packetId);
      return;
    }
    if (tag != relayTagMessage || bobSession == null) return;
    final plaintext = bobSession!.decrypt(Uint8List.fromList(body));
    if (plaintext == null) return;
    final envelope = MessageEnvelope.decode(plaintext);
    switch (envelope) {
      case FileOfferEnvelope(:final name, :final size, :final chunkCount):
        incoming = IncomingFileTransfer(name: name, size: size, chunkCount: chunkCount);
      case FileChunkEnvelope(:final index, :final data):
        incoming?.addChunk(index, data);
      case FileDoneEnvelope():
        if (incoming != null && incoming!.isComplete) {
          receivedBytes = incoming!.assemble();
          if (!done.isCompleted) done.complete();
        }
      case TextEnvelope():
        break;
    }
    bobStream.ack(delivery.packetId);
  });

  aliceStream.send(
    bobId,
    'handshake-1',
    Uint8List.fromList([relayTagHandshake, ...initiateOutcome.initialMessageBytes]),
  );
  await Future.delayed(const Duration(milliseconds: 500));

  // A payload deliberately larger than one chunk, so this actually proves
  // multi-chunk reassembly, not just the single-chunk case.
  final fileBytes = Uint8List.fromList(
    List.generate(fileChunkSize * 3 + 12345, (i) => i % 256),
  );
  final chunks = splitIntoChunks(fileBytes);
  check('file splits into multiple chunks', chunks.length > 1);

  const transferId = 'smoke-transfer-1';
  void sendEnvelope(MessageEnvelope envelope) {
    final ciphertext = aliceSession.encrypt(envelope.encode());
    aliceStream.send(
      bobId,
      'pkt-${DateTime.now().microsecondsSinceEpoch}',
      Uint8List.fromList([relayTagMessage, ...ciphertext]),
    );
  }

  sendEnvelope(
    FileOfferEnvelope(
      id: transferId,
      name: 'smoke-test.bin',
      size: fileBytes.length,
      chunkCount: chunks.length,
    ),
  );
  for (var i = 0; i < chunks.length; i++) {
    sendEnvelope(FileChunkEnvelope(id: transferId, index: i, data: chunks[i]));
  }
  sendEnvelope(FileDoneEnvelope(transferId));

  await done.future.timeout(const Duration(seconds: 15));
  check('received bytes match sent bytes exactly', _bytesEqual(receivedBytes, fileBytes));

  await aliceStream.close();
  await bobStream.close();
  aliceSession.dispose();
  bobSession?.dispose();
  alice.dispose();
  bob.dispose();

  print(failures == 0 ? '\nALL CHECKS PASSED' : '\n$failures CHECK(S) FAILED');
}

bool _bytesEqual(Uint8List? a, Uint8List b) {
  if (a == null || a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
