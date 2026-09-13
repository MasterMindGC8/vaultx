import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:client_app/bridge/native_crypto.dart';

void main() {
  test('installed and rebuilt crypto libraries share the vault format',
      () async {
    final path = Platform.environment['VAULTX_COMPAT_DIR'];
    if (path == null) {
      throw StateError('An isolated compatibility directory is required');
    }
    await NativeCrypto.ensureInitialized();
    await Directory(path).create(recursive: true);
    final pin = Uint8List.fromList([49, 50, 51, 52, 53, 54]);
    final decoyPin = Uint8List.fromList([57, 56, 55, 54, 53, 52]);
    final key = Uint8List.fromList([1, 2, 3]);
    final marker = Uint8List.fromList([4, 5, 6]);
    NativeVault? vault;
    try {
      if (Platform.environment['VAULTX_COMPAT_MODE'] == 'create') {
        NativeCrypto.instance
            .createVault('$path/decoy.vault', decoyPin)!
            .dispose();
        vault = NativeCrypto.instance.createVault('$path/real.vault', pin)!;
        expect(vault.put(key, marker), isTrue);
      } else {
        vault = NativeCrypto.instance
            .unlockVault('$path/real.vault', '$path/decoy.vault', pin)!
            .vault;
        final stored = vault.get(key)!;
        final match = stored.length == marker.length &&
            List.generate(marker.length, (i) => stored[i] == marker[i])
                .every((v) => v);
        stored.fillRange(0, stored.length, 0);
        expect(match, isTrue,
            reason: 'Synthetic vault data did not round-trip');
        expect(vault.put(key, marker), isTrue);
      }
    } finally {
      vault?.dispose();
      pin.fillRange(0, pin.length, 0);
      decoyPin.fillRange(0, decoyPin.length, 0);
      key.fillRange(0, key.length, 0);
      marker.fillRange(0, marker.length, 0);
    }
  });
}
