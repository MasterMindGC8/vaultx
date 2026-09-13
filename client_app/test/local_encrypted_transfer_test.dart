import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:client_app/bridge/native_crypto.dart';
import 'package:client_app/services/file_transfer.dart';
import 'package:client_app/services/file_sender.dart';
import 'package:client_app/services/transfer_progress.dart';
import 'package:client_app/services/relay_client.dart';

// Explicitly opt in against a loopback-only test relay. Never contacts the
// public relay and never opens a user's identity, vault, or attachment.
void main() {
  final relayUrl = Platform.environment['VAULTX_TEST_RELAY'];
  for (final size in [0, fileChunkSize * 6 + 17]) {
    test('encrypted loopback transfer delivers and saves $size bytes',
        () async {
      if (Uri.parse(relayUrl!).host != '127.0.0.1') {
        throw StateError('Local test relay required');
      }
      await NativeCrypto.ensureInitialized();
      final temp =
          await Directory.systemTemp.createTemp('vaultx-encrypted-test-');
      final alice = NativeCrypto.instance.generateIdentity();
      final bob = NativeCrypto.instance.generateIdentity();
      final a = RelayStream(baseUrl: relayUrl, deviceId: alice.deviceIdHex());
      final b = RelayStream(baseUrl: relayUrl, deviceId: bob.deviceIdHex());
      NativeSession? bobSession;
      final initial = NativeCrypto.instance
          .initiateSession(alice, bob.publicBundleBytes())!;
      final aliceSession = initial.session;
      final handshake = Completer<void>();
      final errors = <Object>[];
      IncomingFileTransfer? incoming;
      FileSender? sender;
      var packet = 0;
      Future<void> receiveChain = Future<void>.value();
      void sendEnvelope(RelayStream stream, String recipient,
          NativeSession session, MessageEnvelope envelope) {
        final plain = envelope.encode();
        try {
          final cipher = session.encrypt(plain);
          stream.send(recipient, 'test-packet-${packet++}',
              Uint8List.fromList([relayTagMessage, ...cipher]));
        } finally {
          plain.fillRange(0, plain.length, 0);
        }
      }

      b.deliveries.listen((delivery) {
        receiveChain = receiveChain.then((_) async {
          final body = Uint8List.sublistView(delivery.payload, 1);
          if (delivery.payload.first == relayTagHandshake) {
            bobSession = NativeCrypto.instance.respondSession(bob, body)!;
            b.ack(delivery.packetId);
            handshake.complete();
            return;
          }
          final plaintext = bobSession!.decrypt(body)!;
          MessageEnvelope? envelope;
          try {
            envelope = MessageEnvelope.decode(plaintext);
            switch (envelope) {
              case FileOfferEnvelope(
                  :final id,
                  :final name,
                  :final size,
                  :final chunkCount
                ):
                incoming = IncomingFileTransfer(
                    name: name, size: size, chunkCount: chunkCount);
                sendEnvelope(b, alice.deviceIdHex(), bobSession!,
                    FileReceiptEnvelope(id: id, bytes: 0, stage: 'ready'));
              case FileChunkEnvelope(:final id, :final index, :final data):
                incoming!.addChunk(index, data);
                sendEnvelope(
                    b,
                    alice.deviceIdHex(),
                    bobSession!,
                    FileReceiptEnvelope(
                        id: id,
                        bytes: incoming!.receivedBytes,
                        stage: 'received'));
              case FileDoneEnvelope(:final id):
                expect(incoming!.isComplete, isTrue);
                final output = await File('${temp.path}/received.bin')
                    .open(mode: FileMode.write);
                try {
                  for (final chunk in incoming!.orderedChunks) {
                    await output.writeFrom(chunk);
                  }
                  await output.flush();
                } finally {
                  await output.close();
                }
                sendEnvelope(
                    b,
                    alice.deviceIdHex(),
                    bobSession!,
                    FileReceiptEnvelope(
                        id: id,
                        bytes: incoming!.receivedBytes,
                        stage: 'saved'));
              default:
                throw StateError('Unexpected test envelope');
            }
            b.ack(delivery.packetId);
          } finally {
            plaintext.fillRange(0, plaintext.length, 0);
            if (envelope is FileChunkEnvelope) {
              envelope.data.fillRange(0, envelope.data.length, 0);
            }
          }
        }).catchError((Object e) {
          errors.add(e);
        });
      });
      a.deliveries.listen((delivery) {
        try {
          final plain =
              aliceSession.decrypt(Uint8List.sublistView(delivery.payload, 1))!;
          try {
            sender?.acceptReceipt(
                MessageEnvelope.decode(plain) as FileReceiptEnvelope);
          } finally {
            plain.fillRange(0, plain.length, 0);
          }
          a.ack(delivery.packetId);
        } catch (e) {
          errors.add(e);
        }
      });
      try {
        final http = RelayHttp(baseUrl: relayUrl);
        expect(
            await http.publishPreKeyBundle(
                bob.deviceIdHex(), bob.publicBundleBytes()),
            isTrue);
        expect(await http.fetchPreKeyBundle(bob.deviceIdHex()), isNotNull);
        await a.connect();
        await b.connect();
        a.send(
            bob.deviceIdHex(),
            'test-handshake',
            Uint8List.fromList(
                [relayTagHandshake, ...initial.initialMessageBytes]));
        await handshake.future.timeout(const Duration(seconds: 5));
        final data = Uint8List.fromList(List.generate(size, (i) => i % 251));
        final source = await File('${temp.path}/source.bin').writeAsBytes(data);
        sender = FileSender(
            id: 'test-transfer',
            file: source,
            name: 'synthetic.bin',
            size: size,
            send: (e) => sendEnvelope(a, bob.deviceIdHex(), aliceSession, e));
        await sender.run().timeout(const Duration(seconds: 15));
        await receiveChain;
        expect(errors, isEmpty);
        expect(sender.progress.phase, TransferPhase.complete);
        final received = await File('${temp.path}/received.bin').readAsBytes();
        expect(received, data);
        data.fillRange(0, data.length, 0);
        received.fillRange(0, received.length, 0);
      } finally {
        await a.close();
        await b.close();
        incoming?.clear();
        aliceSession.dispose();
        bobSession?.dispose();
        alice.dispose();
        bob.dispose();
        await temp.delete(recursive: true);
      }
    }, skip: relayUrl == null);
  }
}
