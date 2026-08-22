// Checks a hosted JSON manifest for a newer Vault X release and, if found,
// downloads and launches its installer (an Inno Setup .exe with the same
// fixed AppId as this build — see installer/vaultx.iss — so running it just
// upgrades this install in place rather than creating a second one).
//
// Manifest format (hosted wherever `manifestUrl` points — GitHub Releases,
// a plain web host, anything serving static JSON over HTTPS):
// {
//   "version": "1.2.0",
//   "installer_url": "https://.../VaultXSetup-1.2.0.exe",
//   "notes": "optional human-readable changelog line"
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
  /// Fetches [manifestUrl] and returns [UpdateInfo] if it describes a
  /// version newer than the app currently running, else `null`. Never
  /// throws — network/parse failures are treated the same as "no update
  /// available" (a failed update check should never block using the app).
  static Future<UpdateInfo?> checkForUpdate(String manifestUrl) async {
    try {
      final response = await http
          .get(Uri.parse(manifestUrl))
          .timeout(const Duration(seconds: 8));
      if (response.statusCode != 200) return null;

      final json = jsonDecode(response.body) as Map<String, dynamic>;
      final remoteVersion = json['version'] as String?;
      final installerUrl = json['installer_url'] as String?;
      if (remoteVersion == null || installerUrl == null) return null;

      final currentVersion = (await PackageInfo.fromPlatform()).version;
      if (!_isNewer(remoteVersion, currentVersion)) return null;

      return UpdateInfo(
        version: remoteVersion,
        installerUrl: installerUrl,
        notes: json['notes'] as String?,
      );
    } catch (_) {
      return null;
    }
  }

  /// Downloads the installer at [installerUrl] to a temp file and launches
  /// it. The installer runs its own (fast, familiar) wizard — this does not
  /// silently replace the app out from under the user without them seeing
  /// what's happening.
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
