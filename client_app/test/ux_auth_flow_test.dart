// UX simulation: the full boot -> authenticate -> vault flow, driven the
// same way a real user drives it (tap/type through the actual widgets, not
// calling internal methods directly). Uses the real crypto_core native
// library and real on-disk vault files under VAULTX_DATA_DIR (see
// duress_vault_screen.dart's VaultPaths) — this is an integration test of
// the actual FFI-backed vault, not a mock.
//
// Requires:
//  - crypto_core.dll on the test process's library search path (copy the
//    release build into client_app/ before running, matching tool/manual_*
//    smoke scripts' setup).
//  - VAULTX_DATA_DIR set to an empty scratch directory, so this never
//    touches a real user's vault.
//
// Tests within this file share that one VAULTX_DATA_DIR and run in
// declaration order (package:test's default) — later tests deliberately
// depend on earlier ones having provisioned the vault, simulating closing
// and reopening the app rather than starting fresh every time.
//
// Run with: flutter test test/ux_auth_flow_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:client_app/bridge/native_crypto.dart';
import 'package:client_app/main.dart';
import 'package:client_app/screens/conversation_screen.dart';

import 'ux_test_helpers.dart';

void main() {
  // Normally done once by main.dart's own main() before runApp() — tests
  // bypass main() entirely (pumping VaultXApp directly), so every FFI call
  // (vault create/unlock, identity generation) would otherwise hit
  // NativeCrypto.instance before the native library is loaded.
  setUpAll(() async {
    await NativeCrypto.ensureInitialized();
  });

  testWidgets('boot sequence reveals all lines then shows Continue', (tester) async {
    await tester.pumpWidget(
      const VaultXApp(enableCrtOverlay: false, bootLineDelay: Duration.zero),
    );
    await settleUi(tester);

    expect(findTextContaining('VAULT X SECURE TERMINAL'), findsWidgets);
    expect(findTextContaining('ALL SYSTEMS NOMINAL'), findsWidgets);
    expect(find.text('[ CONTINUE ]'), findsOneWidget);

    // Tear down before the next test to release the boot screen's
    // periodic cursor-blink Timer.
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('first-run provisioning rejects empty and matching PINs, then succeeds', (
    tester,
  ) async {
    await tester.pumpWidget(
      const VaultXApp(enableCrtOverlay: false, bootLineDelay: Duration.zero),
    );
    await settleUi(tester);
    await tapAsciiButton(tester, 'Continue');
    // DuressVaultScreen.initState kicks off a real Directory.create call
    // (VaultPaths.ensureDirectoryExists) — genuine dart:io I/O, which a
    // fake-clock pump() never resolves; needs runAsync.
    await settleReal(tester);

    // First run: this scratch VAULTX_DATA_DIR has no vault files yet.
    expect(findTextContaining('FIRST RUN'), findsWidgets);

    // Submitting with both PIN fields empty.
    await tapAsciiButton(tester, 'Provision');
    expect(find.text('BOTH PINS ARE REQUIRED'), findsOneWidget);

    // Real and decoy PINs must differ.
    final pinFields = find.byType(TextField);
    expect(pinFields, findsNWidgets(2));
    await tester.enterText(pinFields.at(0), '123456');
    await tester.enterText(pinFields.at(1), '123456');
    await tapAsciiButton(tester, 'Provision');
    expect(find.text('REAL AND DECOY PINS MUST DIFFER'), findsOneWidget);

    // Valid, distinct PINs: should provision both vaults and land in the
    // conversation screen with an empty contact list.
    await tester.enterText(pinFields.at(0), '111111');
    await tester.enterText(pinFields.at(1), '999999');
    await tapAsciiButton(tester, 'Provision');

    expect(find.byType(ConversationScreen), findsOneWidget);
    expect(findTextContaining('NO CONTACTS YET'), findsWidgets);
    expect(find.text('[ START CHAT ]'), findsOneWidget);

    // Tear down so ConversationScreen.dispose() releases its vault file
    // handle (widget.vault.dispose()) — otherwise the next test's attempt
    // to open the same on-disk vault file fails with a real OS file lock
    // conflict, which shows up as a spurious "ACCESS DENIED"/missing
    // ConversationScreen with no obvious cause.
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('relaunch: wrong PIN is denied, correct real PIN unlocks the same vault', (
    tester,
  ) async {
    // Depends on the previous test having provisioned real=111111 /
    // decoy=999999 in this run's shared VAULTX_DATA_DIR — simulating the
    // user closing and reopening the app.
    await tester.pumpWidget(
      const VaultXApp(enableCrtOverlay: false, bootLineDelay: Duration.zero),
    );
    await settleUi(tester);
    await tapAsciiButton(tester, 'Continue');
    // DuressVaultScreen.initState kicks off a real Directory.create call
    // (VaultPaths.ensureDirectoryExists) — genuine dart:io I/O, which a
    // fake-clock pump() never resolves; needs runAsync.
    await settleReal(tester);

    expect(find.text('ENTER PIN TO UNLOCK'), findsOneWidget);

    final pinField = find.byType(TextField);
    expect(pinField, findsOneWidget);

    await tester.enterText(pinField, 'wrong-pin');
    await tapAsciiButton(tester, 'Unlock');
    expect(find.text('ACCESS DENIED'), findsOneWidget);

    await tester.enterText(pinField, '111111');
    await tapAsciiButton(tester, 'Unlock');
    expect(find.byType(ConversationScreen), findsOneWidget);

    // See the previous test's teardown comment — release the vault file
    // handle before the decoy test tries to open the same files.
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('decoy PIN opens a separate, indistinguishable vault', (tester) async {
    await tester.pumpWidget(
      const VaultXApp(enableCrtOverlay: false, bootLineDelay: Duration.zero),
    );
    await settleUi(tester);
    await tapAsciiButton(tester, 'Continue');
    // DuressVaultScreen.initState kicks off a real Directory.create call
    // (VaultPaths.ensureDirectoryExists) — genuine dart:io I/O, which a
    // fake-clock pump() never resolves; needs runAsync.
    await settleReal(tester);

    final pinField = find.byType(TextField);
    await tester.enterText(pinField, '999999');
    await tapAsciiButton(tester, 'Unlock');

    // Per CLAUDE.md: the decoy path must render identically to the real
    // one — same ConversationScreen, no "you're in the decoy" tell.
    final screen = tester.widget<ConversationScreen>(find.byType(ConversationScreen));
    expect(screen.isDecoy, isTrue);
    expect(findTextContaining('NO CONTACTS YET'), findsWidgets);
  });
}
