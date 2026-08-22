// Checks a hosted JSON manifest for a newer Vault X release and helps the
// user get it. On Windows this is fully one-click: download the Inno Setup
// installer (same fixed AppId as this build — see installer/vaultx.iss —
// so it upgrades in place) and launch it. macOS/Linux releases are a
// zipped .app / a tarball, not something that can be silently "launched"
// as a replacement for the running app without a proper updater framework
// (e.g. Sparkle) that this project doesn't have yet — for those platforms
// this opens the release page in the browser instead, so the user can
// download and replace the app manually. Still much simpler than hunting
// for the download link themselves.
//
// Manifest format (hosted wherever `manifestUrl` points — GitHub Releases,
// a plain web host, anything serving static JSON over HTTPS): one entry
// per platform, keyed "windows" / "macos" / "linux":
// {
//   "windows": {"version": "1.3.0", "installer_url": "https://.../VaultXSetup-1.3.0.exe", "notes": "..."},
//   "macos":   {"version": "1.3.0", "installer_url": "https://.../VaultX-macOS.zip", "notes": "..."},
//   "linux":   {"version": "1.3.0", "installer_url": "https://.../VaultX-linux-x86_64.tar.gz", "notes": "..."}
// }
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:package_info_plus/package_info_plus.dart';

class UpdateInfo {
  const UpdateInfo({required this.version, required this.installerUrl, this.notes});

  final String version;
  final String installerUrl;
  final String? notes;
}

class UpdateChecker {
  static String get _platformKey {
    if (Platform.isWindows) return 'windows';
    if (Platform.isMacOS) return 'macos';
    return 'linux';
  }

  /// True only on platforms where [downloadAndLaunchInstaller] can silently
  /// download-and-run a true in-place update. On other platforms, callers
  /// should send the user to [UpdateInfo.installerUrl] in a browser instead.
  static bool get canAutoInstall => Platform.isWindows;

  /// Fetches [manifestUrl] and returns [UpdateInfo] for this platform if it
  /// describes a version newer than the app currently running, else `null`.
  /// Never throws — network/parse failures are treated the same as "no
  /// update available" (a failed update check should never block using the
  /// app).
  static Future<UpdateInfo?> checkForUpdate(String manifestUrl) async {
    try {
      final response = await http
          .get(Uri.parse(manifestUrl))
          .timeout(const Duration(seconds: 8));
      if (response.statusCode != 200) return null;

      final json = jsonDecode(response.body) as Map<String, dynamic>;
      final platformEntry = json[_platformKey] as Map<String, dynamic>?;
      if (platformEntry == null) return null;

      final remoteVersion = platformEntry['version'] as String?;
      final installerUrl = platformEntry['installer_url'] as String?;
      if (remoteVersion == null || installerUrl == null) return null;

      final currentVersion = (await PackageInfo.fromPlatform()).version;
      if (!_isNewer(remoteVersion, currentVersion)) return null;

      return UpdateInfo(
        version: remoteVersion,
        installerUrl: installerUrl,
        notes: platformEntry['notes'] as String?,
      );
    } catch (_) {
      return null;
    }
  }

  /// Windows only (see [canAutoInstall]): downloads the installer at
  /// [installerUrl] to a temp file and launches it. The installer runs its
  /// own (fast, familiar) wizard — this does not silently replace the app
  /// out from under the user without them seeing what's happening.
  static Future<void> downloadAndLaunchInstaller(String installerUrl) async {
    final response = await http.get(Uri.parse(installerUrl));
    if (response.statusCode != 200) {
      throw Exception('Failed to download installer (${response.statusCode})');
    }
    final tempDir = await Directory.systemTemp.createTemp('vaultx_update_');
    final installerPath = '${tempDir.path}\\VaultXUpdate.exe';
    await File(installerPath).writeAsBytes(response.bodyBytes);
    await Process.start(installerPath, [], mode: ProcessStartMode.detached);
  }

  /// macOS/Linux: opens [url] (the release download link) in the system
  /// browser, since there's no safe way to self-replace a running .app
  /// bundle or extracted Linux tarball without a real updater framework.
  static Future<void> openInBrowser(String url) async {
    if (Platform.isMacOS) {
      await Process.run('open', [url]);
    } else {
      await Process.run('xdg-open', [url]);
    }
  }

  static bool _isNewer(String remote, String current) {
    final remoteParts = _parseVersion(remote);
    final currentParts = _parseVersion(current);
    for (var i = 0; i < 3; i++) {
      if (remoteParts[i] != currentParts[i]) return remoteParts[i] > currentParts[i];
    }
    return false;
  }

  static List<int> _parseVersion(String version) {
    final parts = version.split('+').first.split('.');
    return List.generate(
      3,
      (i) => i < parts.length ? (int.tryParse(parts[i]) ?? 0) : 0,
    );
  }
}
