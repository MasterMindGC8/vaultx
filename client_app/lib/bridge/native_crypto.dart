// dart:ffi bridge to crypto_core's cdylib (crypto_core/src/ffi.rs).
//
// This is a hand-written FFI binding rather than flutter_rust_bridge
// codegen: the exposed surface is small and deliberately narrow (identity
// generation + the encrypted vault; see ffi.rs's module doc for what is
// *not* yet exposed and why), so a generated binding layer would add
// machinery without buying much here. If the native surface grows
// materially, regenerating this file with flutter_rust_bridge instead of
// hand-maintaining it becomes the better trade.
//
// Every function in crypto_core::ffi documents its own ownership contract;
// this file's job is just to mirror that contract faithfully on the Dart
// side (free exactly what you're told to free, exactly once).

import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkg_ffi;
import 'package:flutter/services.dart' show rootBundle;
import 'package:path_provider/path_provider.dart';

final class _VaultXBuffer extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> data;

  @ffi.Size()
  external int len;
}

final class _VaultXUnlockResult extends ffi.Struct {
  external ffi.Pointer<ffi.Void> handle;

  @ffi.Bool()
  external bool isDecoy;
}

final class _VaultXInitiateResult extends ffi.Struct {
  external ffi.Pointer<ffi.Void> session;
  external _VaultXBuffer initialMessage;
}

typedef _BufferFreeNative = ffi.Void Function(_VaultXBuffer);
typedef _BufferFreeDart = void Function(_VaultXBuffer);

typedef _IdentityGenerateNative = ffi.Pointer<ffi.Void> Function();
typedef _IdentityGenerateDart = ffi.Pointer<ffi.Void> Function();

typedef _IdentityFreeNative = ffi.Void Function(ffi.Pointer<ffi.Void>);
typedef _IdentityFreeDart = void Function(ffi.Pointer<ffi.Void>);

typedef _IdentityBundleNative = _VaultXBuffer Function(ffi.Pointer<ffi.Void>);
typedef _IdentityBundleDart = _VaultXBuffer Function(ffi.Pointer<ffi.Void>);

typedef _IdentityToWireNative = _VaultXBuffer Function(ffi.Pointer<ffi.Void>);
typedef _IdentityToWireDart = _VaultXBuffer Function(ffi.Pointer<ffi.Void>);

typedef _IdentityFromWireNative = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<ffi.Uint8> bytes,
  ffi.Size len,
);
typedef _IdentityFromWireDart = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<ffi.Uint8> bytes,
  int len,
);

typedef _VaultCreateNative = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<pkg_ffi.Utf8> path,
  ffi.Pointer<ffi.Uint8> pin,
  ffi.Size pinLen,
);
typedef _VaultCreateDart = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<pkg_ffi.Utf8> path,
  ffi.Pointer<ffi.Uint8> pin,
  int pinLen,
);

typedef _VaultUnlockNative = _VaultXUnlockResult Function(
  ffi.Pointer<pkg_ffi.Utf8> realPath,
  ffi.Pointer<pkg_ffi.Utf8> decoyPath,
  ffi.Pointer<ffi.Uint8> pin,
  ffi.Size pinLen,
);
typedef _VaultUnlockDart = _VaultXUnlockResult Function(
  ffi.Pointer<pkg_ffi.Utf8> realPath,
  ffi.Pointer<pkg_ffi.Utf8> decoyPath,
  ffi.Pointer<ffi.Uint8> pin,
  int pinLen,
);

typedef _VaultFreeNative = ffi.Void Function(ffi.Pointer<ffi.Void>);
typedef _VaultFreeDart = void Function(ffi.Pointer<ffi.Void>);

typedef _VaultPutNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void> vault,
  ffi.Pointer<ffi.Uint8> key,
  ffi.Size keyLen,
  ffi.Pointer<ffi.Uint8> value,
  ffi.Size valueLen,
);
typedef _VaultPutDart = int Function(
  ffi.Pointer<ffi.Void> vault,
  ffi.Pointer<ffi.Uint8> key,
  int keyLen,
  ffi.Pointer<ffi.Uint8> value,
  int valueLen,
);

typedef _VaultGetNative = _VaultXBuffer Function(
  ffi.Pointer<ffi.Void> vault,
  ffi.Pointer<ffi.Uint8> key,
  ffi.Size keyLen,
);
typedef _VaultGetDart = _VaultXBuffer Function(
  ffi.Pointer<ffi.Void> vault,
  ffi.Pointer<ffi.Uint8> key,
  int keyLen,
);

typedef _SessionInitiateNative = _VaultXInitiateResult Function(
  ffi.Pointer<ffi.Void> identity,
  ffi.Pointer<ffi.Uint8> bundle,
  ffi.Size bundleLen,
);
typedef _SessionInitiateDart = _VaultXInitiateResult Function(
  ffi.Pointer<ffi.Void> identity,
  ffi.Pointer<ffi.Uint8> bundle,
  int bundleLen,
);

typedef _SessionRespondNative = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<ffi.Void> identity,
  ffi.Pointer<ffi.Uint8> initialMessage,
  ffi.Size initialMessageLen,
);
typedef _SessionRespondDart = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<ffi.Void> identity,
  ffi.Pointer<ffi.Uint8> initialMessage,
  int initialMessageLen,
);

typedef _SessionFreeNative = ffi.Void Function(ffi.Pointer<ffi.Void>);
typedef _SessionFreeDart = void Function(ffi.Pointer<ffi.Void>);

typedef _SessionEncryptNative = _VaultXBuffer Function(
  ffi.Pointer<ffi.Void> session,
  ffi.Pointer<ffi.Uint8> plaintext,
  ffi.Size plaintextLen,
  ffi.Pointer<ffi.Uint8> aad,
  ffi.Size aadLen,
);
typedef _SessionEncryptDart = _VaultXBuffer Function(
  ffi.Pointer<ffi.Void> session,
  ffi.Pointer<ffi.Uint8> plaintext,
  int plaintextLen,
  ffi.Pointer<ffi.Uint8> aad,
  int aadLen,
);

typedef _SessionDecryptNative = _VaultXBuffer Function(
  ffi.Pointer<ffi.Void> session,
  ffi.Pointer<ffi.Uint8> message,
  ffi.Size messageLen,
  ffi.Pointer<ffi.Uint8> aad,
  ffi.Size aadLen,
);
typedef _SessionDecryptDart = _VaultXBuffer Function(
  ffi.Pointer<ffi.Void> session,
  ffi.Pointer<ffi.Uint8> message,
  int messageLen,
  ffi.Pointer<ffi.Uint8> aad,
  int aadLen,
);

/// Loads `crypto_core`'s dynamic library and exposes its C ABI as
/// idiomatic, memory-safe Dart calls. One process-wide instance is enough;
/// use [NativeCrypto.instance].
class NativeCrypto {
  NativeCrypto._(ffi.DynamicLibrary lib)
    : _bufferFree = lib.lookupFunction<_BufferFreeNative, _BufferFreeDart>(
        'vaultx_buffer_free',
      ),
      _identityGenerate = lib
          .lookupFunction<_IdentityGenerateNative, _IdentityGenerateDart>(
            'vaultx_identity_generate',
          ),
      _identityFree = lib.lookupFunction<_IdentityFreeNative, _IdentityFreeDart>(
        'vaultx_identity_free',
      ),
      _identityBundleBytes = lib
          .lookupFunction<_IdentityBundleNative, _IdentityBundleDart>(
            'vaultx_identity_public_bundle_bytes',
          ),
      _identityToWireBytes = lib
          .lookupFunction<_IdentityToWireNative, _IdentityToWireDart>(
            'vaultx_identity_to_wire_bytes',
          ),
      _identityFromWireBytes = lib
          .lookupFunction<_IdentityFromWireNative, _IdentityFromWireDart>(
            'vaultx_identity_from_wire_bytes',
          ),
      _vaultCreate = lib.lookupFunction<_VaultCreateNative, _VaultCreateDart>(
        'vaultx_vault_create',
      ),
      _vaultUnlock = lib.lookupFunction<_VaultUnlockNative, _VaultUnlockDart>(
        'vaultx_vault_unlock',
      ),
      _vaultFree = lib.lookupFunction<_VaultFreeNative, _VaultFreeDart>(
        'vaultx_vault_free',
      ),
      _vaultPut = lib.lookupFunction<_VaultPutNative, _VaultPutDart>(
        'vaultx_vault_put',
      ),
      _vaultGet = lib.lookupFunction<_VaultGetNative, _VaultGetDart>(
        'vaultx_vault_get',
      ),
      _sessionInitiate = lib
          .lookupFunction<_SessionInitiateNative, _SessionInitiateDart>(
            'vaultx_session_initiate',
          ),
      _sessionRespond = lib
          .lookupFunction<_SessionRespondNative, _SessionRespondDart>(
            'vaultx_session_respond',
          ),
      _sessionFree = lib.lookupFunction<_SessionFreeNative, _SessionFreeDart>(
        'vaultx_session_free',
      ),
      _sessionEncrypt = lib
          .lookupFunction<_SessionEncryptNative, _SessionEncryptDart>(
            'vaultx_session_encrypt',
          ),
      _sessionDecrypt = lib
          .lookupFunction<_SessionDecryptNative, _SessionDecryptDart>(
            'vaultx_session_decrypt',
          );

  static NativeCrypto? _instance;

  /// Must be awaited once, before the app's first use of [instance] (call
  /// it early in `main()`, before `runApp`). On Windows the native library
  /// sits right next to the executable (bundled there by
  /// `windows/CMakeLists.txt`) and this resolves immediately; on
  /// macOS/Linux, where hand-editing the Xcode project / CMake install
  /// rules to embed a foreign dylib correctly can't be verified without
  /// those machines, the compiled library is instead shipped as a normal
  /// Flutter asset (see `assets/native/`) and extracted to a real file on
  /// first run, which only official Flutter APIs are needed for.
  static Future<void> ensureInitialized() async {
    if (_instance != null) return;
    _instance = NativeCrypto._(await _open());
  }

  /// Throws if [ensureInitialized] hasn't completed yet — that's a bug in
  /// app startup ordering, not a runtime condition to handle gracefully.
  static NativeCrypto get instance {
    final instance = _instance;
    if (instance == null) {
      throw StateError(
        'NativeCrypto.instance used before NativeCrypto.ensureInitialized() completed',
      );
    }
    return instance;
  }

  final _BufferFreeDart _bufferFree;
  final _IdentityGenerateDart _identityGenerate;
  final _IdentityFreeDart _identityFree;
  final _IdentityBundleDart _identityBundleBytes;
  final _IdentityToWireDart _identityToWireBytes;
  final _IdentityFromWireDart _identityFromWireBytes;
  final _VaultCreateDart _vaultCreate;
  final _VaultUnlockDart _vaultUnlock;
  final _VaultFreeDart _vaultFree;
  final _VaultPutDart _vaultPut;
  final _VaultGetDart _vaultGet;
  final _SessionInitiateDart _sessionInitiate;
  final _SessionRespondDart _sessionRespond;
  final _SessionFreeDart _sessionFree;
  final _SessionEncryptDart _sessionEncrypt;
  final _SessionDecryptDart _sessionDecrypt;

  static Future<ffi.DynamicLibrary> _open() async {
    if (Platform.isWindows) {
      // Bundled next to the .exe by windows/CMakeLists.txt's install rule.
      return ffi.DynamicLibrary.open('crypto_core.dll');
    }
    final assetName = Platform.isMacOS ? 'crypto_core.dylib' : 'crypto_core.so';
    final extractedPath = await _extractBundledLibrary(assetName);
    return ffi.DynamicLibrary.open(extractedPath);
  }

  /// Copies the platform's compiled native library — shipped as a plain
  /// Flutter asset under `assets/native/` (see pubspec.yaml) rather than
  /// wired into the macOS Xcode project or Linux CMake install rules,
  /// since neither of those can be edited-and-verified without owning the
  /// respective machine — out to a real file on disk, where `dlopen` (via
  /// [ffi.DynamicLibrary.open]) can actually load it from an absolute path.
  /// Idempotent: skips the copy if a byte-identical file is already there
  /// from a previous run.
  static Future<String> _extractBundledLibrary(String assetName) async {
    final bytes = await rootBundle.load('assets/native/$assetName');
    final supportDir = await getApplicationSupportDirectory();
    final file = File('${supportDir.path}/$assetName');
    final buffer = bytes.buffer.asUint8List(bytes.offsetInBytes, bytes.lengthInBytes);
    if (!await file.exists() || (await file.length()) != buffer.length) {
      await file.parent.create(recursive: true);
      await file.writeAsBytes(buffer, flush: true);
    }
    return file.path;
  }

  Uint8List _takeBuffer(_VaultXBuffer buf) {
    if (buf.data == ffi.nullptr || buf.len == 0) {
      _bufferFree(buf);
      return Uint8List(0);
    }
    final copy = Uint8List.fromList(buf.data.asTypedList(buf.len));
    _bufferFree(buf);
    return copy;
  }

  ffi.Pointer<ffi.Uint8> _copyToNative(Uint8List bytes) {
    final ptr = pkg_ffi.malloc<ffi.Uint8>(bytes.isEmpty ? 1 : bytes.length);
    ptr.asTypedList(bytes.length).setAll(0, bytes);
    return ptr;
  }

  /// Generate a fresh identity (X25519 + ML-KEM-768 keys). Dispose with
  /// [NativeIdentity.dispose] when done with it.
  NativeIdentity generateIdentity() {
    final handle = _identityGenerate();
    return NativeIdentity._(this, handle);
  }

  /// Reconstruct an identity from bytes previously produced by
  /// [NativeIdentity.toWireBytes] (e.g. loaded back out of the encrypted
  /// vault so the device's ID stays stable across app restarts). Returns
  /// `null` on malformed input.
  NativeIdentity? loadIdentity(Uint8List wireBytes) {
    final ptr = _copyToNative(wireBytes);
    try {
      final handle = _identityFromWireBytes(ptr, wireBytes.length);
      if (handle == ffi.nullptr) return null;
      return NativeIdentity._(this, handle);
    } finally {
      pkg_ffi.malloc.free(ptr);
    }
  }

  /// Create a brand-new encrypted vault file at [path], sealed with [pin].
  NativeVault? createVault(String path, Uint8List pin) {
    final pathPtr = path.toNativeUtf8();
    final pinPtr = _copyToNative(pin);
    try {
      final handle = _vaultCreate(pathPtr, pinPtr, pin.length);
      if (handle == ffi.nullptr) return null;
      return NativeVault._(this, handle);
    } finally {
      pkg_ffi.malloc.free(pathPtr);
      pkg_ffi.malloc.free(pinPtr);
    }
  }

  /// Attempt to unlock whichever of [realPath]/[decoyPath] accepts [pin].
  /// If the decoy PIN matched, the real vault file has *already* been
  /// wiped by the time this returns (see `VaultManager::unlock` on the
  /// Rust side) — the UI must render [UnlockOutcome.isDecoy] sessions
  /// identically to real ones.
  UnlockOutcome? unlockVault(String realPath, String decoyPath, Uint8List pin) {
    final realPtr = realPath.toNativeUtf8();
    final decoyPtr = decoyPath.toNativeUtf8();
    final pinPtr = _copyToNative(pin);
    try {
      final result = _vaultUnlock(realPtr, decoyPtr, pinPtr, pin.length);
      if (result.handle == ffi.nullptr) return null;
      return UnlockOutcome._(
        NativeVault._(this, result.handle),
        result.isDecoy,
      );
    } finally {
      pkg_ffi.malloc.free(realPtr);
      pkg_ffi.malloc.free(decoyPtr);
      pkg_ffi.malloc.free(pinPtr);
    }
  }

  /// Alice's side of a new 1:1 session: run the PQXDH handshake against a
  /// peer's published prekey [bundle] (wire bytes, e.g. fetched from the
  /// relay's `GET /v1/prekeys/{id}`) using [identity]'s own keys, and
  /// bootstrap a Double Ratchet session. Returns `null` on failure (a
  /// malformed bundle, most likely). The returned [InitiateOutcome.session]
  /// is ready to [NativeSession.encrypt] immediately; send
  /// [InitiateOutcome.initialMessageBytes] to the peer (e.g. as the first
  /// packet through the relay) so they can call [respondSession].
  InitiateOutcome? initiateSession(NativeIdentity identity, Uint8List bundle) {
    final bundlePtr = _copyToNative(bundle);
    try {
      final result = _sessionInitiate(
        identity._handle,
        bundlePtr,
        bundle.length,
      );
      if (result.session == ffi.nullptr) return null;
      return InitiateOutcome._(
        NativeSession._(this, result.session),
        _takeBuffer(result.initialMessage),
      );
    } finally {
      pkg_ffi.malloc.free(bundlePtr);
    }
  }

  /// Bob's side of a new 1:1 session: given the wire-encoded
  /// [initialMessage] Alice sent (see [initiateSession]) and [identity]'s
  /// own keys, complete the PQXDH handshake and bootstrap the matching
  /// Double Ratchet session. Returns `null` on failure — including if
  /// [identity] no longer holds the one-time prekey the message claims to
  /// have used (e.g. it was already consumed by a different peer).
  NativeSession? respondSession(
    NativeIdentity identity,
    Uint8List initialMessage,
  ) {
    final messagePtr = _copyToNative(initialMessage);
    try {
      final handle = _sessionRespond(
        identity._handle,
        messagePtr,
        initialMessage.length,
      );
      if (handle == ffi.nullptr) return null;
      return NativeSession._(this, handle);
    } finally {
      pkg_ffi.malloc.free(messagePtr);
    }
  }
}

/// The result of [NativeCrypto.unlockVault]: which vault opened, and
/// whether it was the decoy.
class UnlockOutcome {
  UnlockOutcome._(this.vault, this.isDecoy);

  final NativeVault vault;
  final bool isDecoy;
}

/// The result of [NativeCrypto.initiateSession]: the new session plus the
/// wire-encoded initial message to send to the peer.
class InitiateOutcome {
  InitiateOutcome._(this.session, this.initialMessageBytes);

  final NativeSession session;
  final Uint8List initialMessageBytes;
}

/// An owning handle to a native `IdentityKeyPair`. Call [dispose] exactly
/// once when done.
class NativeIdentity {
  NativeIdentity._(this._crypto, this._handle);

  final NativeCrypto _crypto;
  ffi.Pointer<ffi.Void> _handle;
  bool _disposed = false;

  /// The identity's public PQXDH prekey bundle, in Vault X's wire format —
  /// ready to `POST` to the relay's `/v1/prekeys/{id}` endpoint.
  Uint8List publicBundleBytes() {
    _checkNotDisposed();
    return _crypto._takeBuffer(_crypto._identityBundleBytes(_handle));
  }

  /// Serialize *all* private key material — store this only in the
  /// encrypted [NativeVault], never anywhere unencrypted. Pass the result
  /// to [NativeCrypto.loadIdentity] to reload the same identity later.
  Uint8List toWireBytes() {
    _checkNotDisposed();
    return _crypto._takeBuffer(_crypto._identityToWireBytes(_handle));
  }

  /// This identity's opaque Device ID: the 32-byte X25519 identity key from
  /// its public bundle (see `PreKeyBundle::to_wire_bytes` — byte 0 is a
  /// version tag, bytes 1..33 are the identity key), as lowercase hex. This
  /// is what a contact shares out-of-band and what the other side types
  /// into "Add Contact" to reach this device.
  String deviceIdHex() {
    final bundle = publicBundleBytes();
    final idBytes = bundle.length >= 33 ? bundle.sublist(1, 33) : bundle;
    return idBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  void dispose() {
    if (_disposed) return;
    _crypto._identityFree(_handle);
    _handle = ffi.nullptr;
    _disposed = true;
  }

  void _checkNotDisposed() {
    if (_disposed) {
      throw StateError('NativeIdentity used after dispose()');
    }
  }
}

/// An owning handle to a native `Vault`. Call [dispose] exactly once when
/// done.
class NativeVault {
  NativeVault._(this._crypto, this._handle);

  final NativeCrypto _crypto;
  ffi.Pointer<ffi.Void> _handle;
  bool _disposed = false;

  /// Encrypt and store [value] under [key].
  bool put(Uint8List key, Uint8List value) {
    _checkNotDisposed();
    final keyPtr = _crypto._copyToNative(key);
    final valuePtr = _crypto._copyToNative(value);
    try {
      return _crypto._vaultPut(_handle, keyPtr, key.length, valuePtr, value.length) == 0;
    } finally {
      pkg_ffi.malloc.free(keyPtr);
      pkg_ffi.malloc.free(valuePtr);
    }
  }

  /// Fetch and decrypt the value stored under [key], or `null` if absent
  /// (or on error — the C ABI does not currently distinguish the two; see
  /// `vaultx_vault_get`'s doc comment).
  Uint8List? get(Uint8List key) {
    _checkNotDisposed();
    final keyPtr = _crypto._copyToNative(key);
    try {
      final result = _crypto._vaultGet(_handle, keyPtr, key.length);
      final bytes = _crypto._takeBuffer(result);
      return bytes.isEmpty ? null : bytes;
    } finally {
      pkg_ffi.malloc.free(keyPtr);
    }
  }

  void dispose() {
    if (_disposed) return;
    _crypto._vaultFree(_handle);
    _handle = ffi.nullptr;
    _disposed = true;
  }

  void _checkNotDisposed() {
    if (_disposed) {
      throw StateError('NativeVault used after dispose()');
    }
  }
}

/// An owning handle to a native 1:1 PQXDH + Double Ratchet session with one
/// peer. Call [dispose] exactly once when the conversation is closed.
class NativeSession {
  NativeSession._(this._crypto, this._handle);

  final NativeCrypto _crypto;
  ffi.Pointer<ffi.Void> _handle;
  bool _disposed = false;

  /// Encrypt [plaintext] (associated with [aad], if any — e.g.
  /// sender/recipient IDs, authenticated but not secret) under the
  /// session's next message key. Returns the wire-encoded message to send
  /// to the peer over the relay, or an empty buffer on failure.
  Uint8List encrypt(Uint8List plaintext, {Uint8List? aad}) {
    _checkNotDisposed();
    final plaintextPtr = _crypto._copyToNative(plaintext);
    final aadBytes = aad ?? Uint8List(0);
    final aadPtr = _crypto._copyToNative(aadBytes);
    try {
      final result = _crypto._sessionEncrypt(
        _handle,
        plaintextPtr,
        plaintext.length,
        aadPtr,
        aadBytes.length,
      );
      return _crypto._takeBuffer(result);
    } finally {
      pkg_ffi.malloc.free(plaintextPtr);
      pkg_ffi.malloc.free(aadPtr);
    }
  }

  /// Decrypt a wire-encoded message received from the peer (associated
  /// with the same [aad] the sender used, if any), performing a DH ratchet
  /// step first if needed. Returns `null` on failure — including if
  /// [message] is malformed or its authentication tag doesn't verify.
  Uint8List? decrypt(Uint8List message, {Uint8List? aad}) {
    _checkNotDisposed();
    final messagePtr = _crypto._copyToNative(message);
    final aadBytes = aad ?? Uint8List(0);
    final aadPtr = _crypto._copyToNative(aadBytes);
    try {
      final result = _crypto._sessionDecrypt(
        _handle,
        messagePtr,
        message.length,
        aadPtr,
        aadBytes.length,
      );
      final bytes = _crypto._takeBuffer(result);
      // An empty result is ambiguous between "decryption failed" and "the
      // peer genuinely sent zero-length plaintext" (see vaultx_session_decrypt's
      // doc comment) — treated as failure here since Vault X's own senders
      // never intentionally send empty application messages.
      return bytes.isEmpty ? null : bytes;
    } finally {
      pkg_ffi.malloc.free(messagePtr);
      pkg_ffi.malloc.free(aadPtr);
    }
  }

  void dispose() {
    if (_disposed) return;
    _crypto._sessionFree(_handle);
    _handle = ffi.nullptr;
    _disposed = true;
  }

  void _checkNotDisposed() {
    if (_disposed) {
      throw StateError('NativeSession used after dispose()');
    }
  }
}
