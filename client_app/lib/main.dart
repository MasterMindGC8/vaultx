import 'dart:io';

import 'package:flutter/material.dart';

import 'bridge/native_crypto.dart';
import 'screens/terminal_screen.dart';
import 'services/app_logger.dart';
import 'theme/cypher_theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await AppLogger.ensureInitialized();
  await AppLogger.info('app starting on ${Platform.operatingSystem}');
  // On macOS/Linux this extracts the bundled native library to a real file
  // on first run (see NativeCrypto.ensureInitialized's doc); on Windows it
  // resolves immediately. Either way, nothing in the app may touch
  // NativeCrypto.instance before this completes.
  try {
    await NativeCrypto.ensureInitialized();
    await AppLogger.info('crypto_core native library loaded');
  } catch (e) {
    await AppLogger.error('failed to load crypto_core native library', e);
    rethrow;
  }
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
