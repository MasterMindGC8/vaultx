// ignore_for_file: avoid_print
// Manual smoke check for UpdateChecker against the real, live manifest URL
// the app ships with — verifies the fetch actually resolves (and how fast)
// rather than hanging, independent of the GUI. Run via
// `flutter test tool/manual_update_check_smoke.dart` (needs `flutter test`,
// not plain `dart run`, since update_checker.dart pulls in
// package:flutter/foundation.dart transitively through package_info_plus).
//
// Deliberately does not call dart:io's exit() — doing so here races the
// flutter test harness's own VM service handshake and produces a spurious
// "Connection closed before test suite loaded" failure instead of a real
// result, even when the check itself succeeded.
import 'package:client_app/services/update_checker.dart';

const _manifestUrl =
    'https://raw.githubusercontent.com/MasterMindGC8/vaultx/master/update-manifest.json';

Future<void> main() async {
  final stopwatch = Stopwatch()..start();
  final result = await UpdateChecker.checkForUpdate(
    _manifestUrl,
  ).timeout(const Duration(seconds: 15));
  stopwatch.stop();

  print('elapsed: ${stopwatch.elapsedMilliseconds}ms');
  print(
    result == null
        ? '[OK] resolved: no update available for this (test-runner) version'
        : '[OK] resolved: update available -> v${result.version} (${result.installerUrl})',
  );
}
