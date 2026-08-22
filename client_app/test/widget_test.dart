// Smoke test: the app builds and mounts the boot terminal screen without
// throwing. Deliberately does not pump time forward past the first frame —
// doing so would trigger the boot sequence's identity-generation FFI call,
// which needs crypto_core's native library on the test process's library
// search path and is exercised separately (see crypto_core's own Rust
// tests for the crypto itself).
//
// Runs with the CRT shader overlay disabled: `flutter_tester`'s headless
// engine doesn't compile fragment shaders the same way a real target does
// (confirmed separately via `flutter build windows`, where the shader
// compiles and renders correctly), so this test exercises the same widget
// tree minus that one shader-dependent layer.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:client_app/main.dart';

void main() {
  testWidgets('Vault X boots into the terminal screen without throwing', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      const VaultXApp(enableCrtOverlay: false, bootLineDelay: Duration.zero),
    );

    expect(find.byType(MaterialApp), findsOneWidget);
    expect(find.byType(Scaffold), findsOneWidget);

    // Let the (near-instant, with bootLineDelay: zero) boot sequence run to
    // completion, including the blinking-cursor prompt it ends on, then
    // unmount everything so its periodic Timer is cancelled before the test
    // ends — flutter_test asserts no Timer is left pending at teardown.
    await tester.pump(const Duration(seconds: 1));
    await tester.pumpWidget(const SizedBox());
  });
}
