import 'package:flutter/material.dart';

import 'screens/terminal_screen.dart';
import 'theme/cypher_theme.dart';

void main() {
  runApp(const VaultXApp());
}

class VaultXApp extends StatelessWidget {
  const VaultXApp({
    super.key,
    this.enableCrtOverlay = true,
    this.bootLineDelay = const Duration(milliseconds: 220),
  });

  /// Disabling the CRT shader overlay is a test seam only: the
  /// `flutter_tester` headless engine used by `flutter test` doesn't run
  /// the same shader-compilation pipeline as a real device/desktop target
  /// (verified separately — `flutter build windows` compiles and runs the
  /// shader fine), so widget tests construct `VaultXApp` with this off rather
  /// than fighting the test harness. Real builds always leave it on.
  final bool enableCrtOverlay;

  /// Forwarded to [TerminalScreen.bootLineDelay]; see there.
  final Duration bootLineDelay;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Vault X',
      debugShowCheckedModeBanner: false,
      theme: buildVaultXThemeData(),
      builder: (context, child) =>
          enableCrtOverlay ? CrtOverlay(child: child!) : child!,
      home: TerminalScreen(bootLineDelay: bootLineDelay),
    );
  }
}
