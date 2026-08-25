// ignore_for_file: avoid_print
// Manual smoke check for the relay + FFI session wiring, run directly via
// `dart run tool/manual_relay_smoke.dart` against a locally running
// transport_relay (see ../transport_relay). Not part of the auto-discovered
// `flutter test` suite (it needs a live relay and isn't named `*_test.dart`)
// — this is a one-off verification tool, exercising the exact classes
// conversation_screen.dart uses, without touching the GUI at all.
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:client_app/bridge/native_crypto.dart';
import 'package:client_app/services/relay_client.dart';

Future<void> main() async {
  await NativeCrypto.ensureInitialized();
  const relayUrl = 'http://127.0.0.1:8443';
  var failures = 0;

  void check(String label, bool condition) {
    if (condition) {
      print('[OK] $label');
    } else {
      print('[FAIL] $label');
      failures++;
    }
  }

  final alice = NativeCrypto.instance.generateIdentity();
  final bob = NativeCrypto.instance.generateIdentity();
  final aliceId = alice.deviceIdHex();
  final bobId = bob.deviceIdHex();
  check('generated distinct device IDs', aliceId != bobId && aliceId.length == 64);

  final http = RelayHttp(baseUrl: relayUrl);
  check('alice published bundle', await http.publishPreKeyBundle(aliceId, alice.publicBundleBytes()));
  check('bob published bundle', await http.publishPreKeyBundle(bobId, bob.publicBundleBytes()));

  final aliceStream = RelayStream(baseUrl: relayUrl, deviceId: aliceId);
  final bobStream = RelayStream(baseUrl: relayUrl, deviceId: bobId);
  await aliceStream.connect();
  await bobStream.connect();
  check('alice stream connected', aliceStream.isConnected);
  check('bob stream connected', bobStream.isConnected);

  final bobBundle = await http.fetchPreKeyBundle(bobId);
  check('alice fetched bob bundle', bobBundle != null);

  final initiateOutcome = NativeCrypto.instance.initiateSession(alice, bobBundle!);
  check('alice initiated session', initiateOutcome != null);
  final aliceSession = initiateOutcome!.session;

  NativeSession? bobSession;
  final bobGotHandshake = Completer();
  bobStream.deliveries.listen((delivery) {
    if (delivery.payload.isEmpty) return;
    final tag = delivery.payload[0];
    final body = delivery.payload.sublist(1);
    if (tag == relayTagHandshake && bobSession == null) {
      bobSession = NativeCrypto.instance.respondSession(bob, body);
      bobStream.ack(delivery.packetId);
      if (!bobGotHandshake.isCompleted) bobGotHandshake.complete();
    }
  });

  aliceStream.send(
    bobId,
    'handshake-1',
    Uint8List.fromList([relayTagHandshake, ...initiateOutcome.initialMessageBytes]),
  );
  await bobGotHandshake.future.timeout(const Duration(seconds: 5));
  check('bob established session from handshake', bobSession != null);

  const messageText = 'hello bob, from a real relay round trip';
  final ciphertext = aliceSession.encrypt(Uint8List.fromList(utf8.encode(messageText)));

  String? received;
  final bobGotMessage = Completer();
  bobStream.deliveries.listen((delivery) {
    if (delivery.payload.isEmpty) return;
    final tag = delivery.payload[0];
    final body = delivery.payload.sublist(1);
    if (tag == relayTagMessage) {
      final plaintext = bobSession!.decrypt(Uint8List.fromList(body));
      received = plaintext == null ? null : utf8.decode(plaintext);
      bobStream.ack(delivery.packetId);
      if (!bobGotMessage.isCompleted) bobGotMessage.complete();
    }
  });

  aliceStream.send(bobId, 'msg-1', Uint8List.fromList([relayTagMessage, ...ciphertext]));
  await bobGotMessage.future.timeout(const Duration(seconds: 5));
  check('bob decrypted alice\'s message correctly', received == messageText);

  await aliceStream.close();
  await bobStream.close();
  aliceSession.dispose();
  bobSession?.dispose();
  alice.dispose();
  bob.dispose();

  print(failures == 0 ? '\nALL CHECKS PASSED' : '\n$failures CHECK(S) FAILED');
  if (failures > 0) {
    throw StateError('$failures relay smoke check(s) failed');
  }
}
