// UX simulation: Add Contact validation, and the conversation screen's
// local UI (message reveal/hide, remove-contact, no-session messaging)
// driven through the real widgets.
//
// Real relay network calls are NOT exercised here: Flutter's test binding
// (TestWidgetsFlutterBinding) unconditionally stubs every HttpClient to
// return 400, and this holds true even inside `tester.runAsync()` (which
// escapes the fake *clock*, but not this stub) — confirmed empirically
// while building this file, not assumed. See tool/manual_glare_smoke.dart
// and tool/manual_relay_smoke.dart for the real, live-relay coverage of
// the handshake/message round trip itself (run via `flutter test
// tool/...`, which — unlike these `testWidgets` tests — never engages
// TestWidgetsFlutterBinding at all, so real network works there).
//
// What this file actually verifies:
//  - AddContactScreen's input validation (self-ID, malformed ID) and its
//    "no bundle published" state — which, given the point above, is
//    exactly what *every* lookup attempt here naturally produces, making
//    it a realistic stand-in for the actual "friend hasn't opened the app
//    yet" scenario.
//  - ConversationScreen's local-only UI: message reveal/hide-on-tap
//    (with auto-hide), remove-contact confirmation, and the
//    no-active-session messaging error — using a contact and message
//    history pre-seeded directly into the vault (the same on-disk format
//    ConversationScreen itself reads at startup), rather than a live
//    session, since establishing one for real needs the network above.
//
// Requires crypto_core.dll on the test process's search path and
// VAULTX_DATA_DIR pointed at an empty scratch directory — see
// ux_auth_flow_test.dart's header for the same setup.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:client_app/bridge/native_crypto.dart';
import 'package:client_app/models/contact.dart';
import 'package:client_app/screens/add_contact_screen.dart';
import 'package:client_app/screens/conversation_screen.dart';
import 'package:client_app/services/relay_client.dart';

import 'ux_test_helpers.dart';

const _fakeFriendId =
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

Map<String, dynamic> _fakeMessageJson({
  required String id,
  required bool fromSelf,
  String? text,
  String? cipherHex,
}) => {
  'id': id,
  'fromSelf': fromSelf,
  'sentAt': DateTime.now().toIso8601String(),
  if (text != null) 'text': text,
  if (cipherHex != null) 'cipherHex': cipherHex,
};

void main() {
  setUpAll(() async {
    await NativeCrypto.ensureInitialized();
  });

  group('AddContactScreen', () {
    late NativeIdentity myIdentity;

    setUp(() {
      myIdentity = NativeCrypto.instance.generateIdentity();
    });

    tearDown(() {
      myIdentity.dispose();
    });

    Future<void> pumpScreen(WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AddContactScreen(
            identity: myIdentity,
            relayHttp: RelayHttp(baseUrl: 'http://127.0.0.1:8443'),
            myDeviceId: myIdentity.deviceIdHex(),
          ),
        ),
      );
      await settleUi(tester, steps: 4, step: const Duration(milliseconds: 50));
    }

    testWidgets('shows own device id and copies it', (tester) async {
      await pumpScreen(tester);
      expect(find.text(myIdentity.deviceIdHex()), findsOneWidget);
      await tapAsciiButton(tester, 'Copy');
      // Clipboard.setData goes over a real platform channel — give it a
      // genuine turn rather than only fake-clock pumps.
      await settleReal(tester);
      expect(find.text('COPIED YOUR DEVICE ID TO CLIPBOARD'), findsOneWidget);
    });

    testWidgets('rejects a device id of the wrong length', (tester) async {
      await pumpScreen(tester);
      final fields = find.byType(TextField);
      await tester.enterText(fields.at(1), 'not-64-hex-chars');
      await tapAsciiButton(tester, 'Add');
      expect(find.text('DEVICE ID MUST BE 64 HEX CHARACTERS'), findsOneWidget);
    });

    testWidgets('rejects adding your own device id', (tester) async {
      await pumpScreen(tester);
      final fields = find.byType(TextField);
      await tester.enterText(fields.at(1), myIdentity.deviceIdHex());
      await tapAsciiButton(tester, 'Add');
      expect(find.text("THAT'S YOUR OWN DEVICE ID"), findsOneWidget);
    });

    testWidgets('a well-formed but unpublished id is reported clearly', (tester) async {
      await pumpScreen(tester);
      final fields = find.byType(TextField);
      await tester.enterText(fields.at(1), _fakeFriendId);
      await tapAsciiButton(tester, 'Add');
      // Real-world equivalent: your friend hasn't opened the app yet, so
      // no prekey bundle exists for their device id.
      expect(
        find.text('NO BUNDLE PUBLISHED FOR THIS ID YET — ASK THEM TO OPEN THE APP'),
        findsOneWidget,
      );
    });
  });

  group('ConversationScreen local UI (pre-seeded vault, no live session)', () {
    late NativeVault vault;
    late NativeIdentity identity;

    setUp(() {
      final tempPath =
          '${VaultPathsForTest.dir()}/msg_test_${DateTime.now().microsecondsSinceEpoch}.vaultxvault';
      vault = NativeCrypto.instance.createVault(tempPath, utf8.encode('111111'))!;
      identity = NativeCrypto.instance.generateIdentity();

      vault.put(
        utf8.encode(Contact.vaultKey),
        Contact.encodeList([const Contact(deviceId: _fakeFriendId, label: 'Test Friend')]),
      );
      final history = [
        _fakeMessageJson(
          id: 'm1',
          fromSelf: true,
          text: 'hey, this is a pre-seeded message',
          cipherHex: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
        ),
        _fakeMessageJson(
          id: 'm2',
          fromSelf: false,
          text: 'and this one is from them',
          cipherHex: 'ffeeddccbbaa99887766554433221100',
        ),
      ];
      vault.put(
        utf8.encode('history:$_fakeFriendId'),
        Uint8List.fromList(utf8.encode(jsonEncode(history))),
      );
    });

    Future<void> pumpScreen(WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: ConversationScreen(vault: vault, identity: identity, isDecoy: false),
        ),
      );
      await settleUi(tester, steps: 6, step: const Duration(milliseconds: 50));
    }

    testWidgets('loads the pre-seeded contact and history on start', (tester) async {
      await pumpScreen(tester);
      expect(find.text('Test Friend'), findsOneWidget);
      // Both messages start hidden behind their ciphertext by default.
      expect(findTextContaining('a1b2c3d4e5f60718293a4b5c6d7e8f90'), findsWidgets);
      expect(findTextContaining('ffeeddccbbaa99887766554433221100'), findsWidgets);
      expect(find.text('hey, this is a pre-seeded message'), findsNothing);
    });

    testWidgets('tapping a hidden message reveals it, then auto-hides after 60s', (
      tester,
    ) async {
      await pumpScreen(tester);
      final hidden = findTextContaining('a1b2c3d4e5f60718293a4b5c6d7e8f90');
      expect(hidden, findsWidgets);
      await tester.tap(hidden.first);
      await tester.pump();

      expect(findTextContaining('hey, this is a pre-seeded message'), findsWidgets);

      // Auto-hide timer is a real 60s Timer — advance the fake clock past
      // it rather than waiting for real time.
      await tester.pump(const Duration(seconds: 61));
      expect(findTextContaining('hey, this is a pre-seeded message'), findsNothing);
      expect(findTextContaining('a1b2c3d4e5f60718293a4b5c6d7e8f90'), findsWidgets);
    });

    testWidgets('sending with no active session shows a clear error, not silence', (
      tester,
    ) async {
      await pumpScreen(tester);
      await tester.enterText(find.byType(TextField), 'hello?');
      await tapAsciiButton(tester, 'Send');
      expect(find.text('NO ACTIVE SESSION WITH THIS CONTACT'), findsOneWidget);
    });

    testWidgets('remove contact: Cancel keeps it, Remove clears it', (tester) async {
      await pumpScreen(tester);
      expect(find.text('Test Friend'), findsOneWidget);

      await tester.tap(find.text('[x]'));
      await settleUi(tester, steps: 4, step: const Duration(milliseconds: 50));
      expect(find.text('REMOVE CONTACT?'), findsOneWidget);

      await tapAsciiButton(tester, 'Cancel');
      expect(find.text('Test Friend'), findsOneWidget);

      await tester.tap(find.text('[x]'));
      await settleUi(tester, steps: 4, step: const Duration(milliseconds: 50));
      await tapAsciiButton(tester, 'Remove');

      expect(find.text('Test Friend'), findsNothing);
      expect(findTextContaining('NO CONTACTS YET'), findsWidgets);
    });
  });
}

/// Small helper so the message-UI test group can put its own temp vault
/// file next to the ones VAULTX_DATA_DIR already points at, without
/// depending on duress_vault_screen.dart's VaultPaths (which is about the
/// app's *own* two fixed vault files, not a place to stash test fixtures).
class VaultPathsForTest {
  static String dir() => Platform.environment['VAULTX_DATA_DIR'] ?? '.';
}
