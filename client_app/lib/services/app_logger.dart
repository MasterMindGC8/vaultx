// A minimal on-disk log, so that when something goes wrong for a specific
// user (relay unreachable, a handshake failing, a file transfer dropping),
// there's a plain-text file they can look at or send along rather than the
// failure just vanishing. Deliberately never logs plaintext message
// content, key material, or PINs — see CLAUDE.md's logging constraint —
// only structural facts (what operation, which contact's opaque device
// ID, what error).
import 'dart:io';

import 'package:path_provider/path_provider.dart';

class AppLogger {
  static File? _file;

  static Future<void> ensureInitialized() async {
    if (_file != null) return;
    final dir = await getApplicationSupportDirectory();
    _file = File('${dir.path}/vaultx.log');
    await _file!.parent.create(recursive: true);
    await _append('--- session start (${DateTime.now().toIso8601String()}) ---');
  }

  static Future<void> info(String message) => _append('[INFO] $message');

  static Future<void> warn(String message) => _append('[WARN] $message');

  static Future<void> error(String message, [Object? error]) =>
      _append('[ERROR] $message${error != null ? ' — $error' : ''}');

  static Future<void> _append(String line) async {
    final file = _file;
    if (file == null) return; // not yet initialized — drop rather than crash
    try {
      await file.writeAsString(
        '${DateTime.now().toIso8601String()} $line\n',
        mode: FileMode.append,
        flush: true,
      );
    } catch (_) {
      // Logging must never be the thing that crashes the app.
    }
  }

  /// Path to the log file, for a "reveal log" UI action.
  static String? get path => _file?.path;
}
