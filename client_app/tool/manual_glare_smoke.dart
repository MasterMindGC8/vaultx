// ignore_for_file: avoid_print
// Manual smoke check reproducing the exact bug fixed in v1.6.0: both sides
// clicking "Add Contact" for each other at roughly the same time. Runs
// against the real production relay to prove the deployed fix actually
// converges both sides on one shared session, rather than each side
// silently ending up with a different, unrelated one (the original bug —
// see conversation_screen.dart's glare-resolution comment).
//
// This intentionally re-implements the same tie-break rule
// conversation_screen.dart applies in _handleDelivery, since that logic
// lives inside State methods that need a widget tree to run. Run via
// `flutter test tool/manual_glare_smoke.dart`.
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:client_app/bridge/native_crypto.dart';
import 'package:client_app/services/relay_client.dart';

const _relayUrl = 'http://51.81.84.85:8443';

class _Peer {
  _Peer(this.identity, this.deviceId, this.stream);
  final NativeIdentity identity;
  final String deviceId;
  final RelayStream stream;
  NativeSession? session;
  final Set<String> selfInitiated = {};
}

void _handleIncomingHandshake(_Peer me, _Peer other, Uint8List body) {
  final weSelfInitiated = me.selfInitiated.contains(other.deviceId);
  final weAreCanonicalInitiator = me.deviceId.compareTo(other.deviceId) < 0;
  if (weSelfInitiated && weAreCanonicalInitiator) {
    return; // glare: our own handshake wins, ignore theirs
  }
  me.session?.dispose();
  me.session = NativeCrypto.instance.respondSession(me.identity, body);
  me.selfInitiated.remove(other.deviceId);
}

Future<void> main() async {
  await NativeCrypto.ensureInitialized();
  var failures = 0;
  void check(String label, bool condition) {
    print(condition ? '[OK] $label' : '[FAIL] $label');
    if (!condition) failures++;
  }

  final aliceIdentity = NativeCrypto.instance.generateIdentity();
  final bobIdentity = NativeCrypto.instance.generateIdentity();
  final aliceId = aliceIdentity.deviceIdHex();
  final bobId = bobIdentity.deviceIdHex();

  final http = RelayHttp(baseUrl: _relayUrl);
  await http.publishPreKeyBundle(aliceId, aliceIdentity.publicBundleBytes());
  await http.publishPreKeyBundle(bobId, bobIdentity.publicBundleBytes());

  final alice = _Peer(aliceIdentity, aliceId, RelayStream(baseUrl: _relayUrl, deviceId: aliceId));
  final bob = _Peer(bobIdentity, bobId, RelayStream(baseUrl: _relayUrl, deviceId: bobId));
  await alice.stream.connect();
  await bob.stream.connect();

  final aliceReady = Completer<void>();
  final bobReady = Completer<void>();

  alice.stream.deliveries.listen((delivery) {
    if (delivery.payload.isEmpty) return;
    final tag = delivery.payload[0];
    final body = Uint8List.fromList(delivery.payload.sublist(1));
    if (tag == relayTagHandshake) {
      _handleIncomingHandshake(alice, bob, body);
      if (!aliceReady.isCompleted) aliceReady.complete();
    }
    alice.stream.ack(delivery.packetId);
  });
  bob.stream.deliveries.listen((delivery) {
    if (delivery.payload.isEmpty) return;
    final tag = delivery.payload[0];
    final body = Uint8List.fromList(delivery.payload.sublist(1));
    if (tag == relayTagHandshake) {
      _handleIncomingHandshake(bob, alice, body);
      if (!bobReady.isCompleted) bobReady.complete();
    }
    bob.stream.ack(delivery.packetId);
  });

  // Both sides click "Add Contact" for each other at (roughly) the same
  // time — this is the exact race that broke chats before the fix.
  final aliceInitiate = NativeCrypto.instance.initiateSession(
    aliceIdentity,
    (await http.fetchPreKeyBundle(bobId))!,
  );
  final bobInitiate = NativeCrypto.instance.initiateSession(
    bobIdentity,
    (await http.fetchPreKeyBundle(aliceId))!,
  );
  alice.session = aliceInitiate!.session;
  alice.selfInitiated.add(bobId);
  bob.session = bobInitiate!.session;
  bob.selfInitiated.add(aliceId);

  alice.stream.send(
    bobId,
    'glare-handshake-alice',
    Uint8List.fromList([relayTagHandshake, ...aliceInitiate.initialMessageBytes]),
  );
  bob.stream.send(
    aliceId,
    'glare-handshake-bob',
    Uint8List.fromList([relayTagHandshake, ...bobInitiate.initialMessageBytes]),
  );

  await Future.wait([
    aliceReady.future.timeout(const Duration(seconds: 8)),
    bobReady.future.timeout(const Duration(seconds: 8)),
  ]);

  check('alice has a session with bob after glare', alice.session != null);
  check('bob has a session with alice after glare', bob.session != null);

  // The real proof: encrypt on one side, decrypt on the other, both ways.
  const aliceText = 'hello from alice, sent right after the simultaneous add';
  final aliceCipher = alice.session!.encrypt(Uint8List.fromList(utf8.encode(aliceText)));
  final bobDecrypted = bob.session!.decrypt(aliceCipher);
  check(
    'bob decrypts alice\'s message correctly despite the glare',
    bobDecrypted != null && utf8.decode(bobDecrypted) == aliceText,
  );

  const bobText = 'hello back from bob, same broken-before scenario';
  final bobCipher = bob.session!.encrypt(Uint8List.fromList(utf8.encode(bobText)));
  final aliceDecrypted = alice.session!.decrypt(bobCipher);
  check(
    'alice decrypts bob\'s message correctly despite the glare',
    aliceDecrypted != null && utf8.decode(aliceDecrypted) == bobText,
  );

  await alice.stream.close();
  await bob.stream.close();
  alice.session?.dispose();
  bob.session?.dispose();
  aliceIdentity.dispose();
  bobIdentity.dispose();

  print(failures == 0 ? '\nALL CHECKS PASSED' : '\n$failures CHECK(S) FAILED');
  if (failures > 0) {
    throw StateError('$failures glare smoke check(s) failed');
  }
}
