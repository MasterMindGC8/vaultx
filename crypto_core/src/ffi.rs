//! C ABI surface for the Flutter/Dart bridge
//! (`client_app/lib/bridge/native_crypto.dart`), compiled into the cdylib
//! target declared in `Cargo.toml`.
//!
//! Scope note: this exposes identity/prekey generation, the encrypted
//! [`Vault`], and now a 1:1 PQXDH + Double Ratchet session (a `VaultXSession`
//! handle, opened via [`vaultx_session_initiate`] or
//! [`vaultx_session_respond`] and driven with [`vaultx_session_encrypt`] /
//! [`vaultx_session_decrypt`]). It deliberately does *not* yet expose MLS
//! group sessions — those need a separate handle type (an
//! `MlsGroupSession`, per member *and* per group, versus one ratchet handle
//! per 1:1 peer) and their own wire-serialization story for commits and
//! welcomes, which is a large enough surface to design on its own rather
//! than bolt on here.
//!
//! # Safety contract (binding on every function below)
//! - Every `*mut T` returned by a `_generate`/`_create`/`_open` function is
//!   an opaque owning handle. The caller (Dart) must pass it to exactly one
//!   matching `_free` call, exactly once, when done. Using a handle after
//!   freeing it, or freeing it twice, is undefined behavior — same as any
//!   C API of this shape.
//! - Every [`VaultXBuffer`] returned by value owns heap memory the caller
//!   must release via [`vaultx_buffer_free`] exactly once. A `VaultXBuffer`
//!   with `data == null` carries no memory to free.
//! - No function in this file panics across the FFI boundary on caller
//!   error (bad UTF-8, null pointers, wrong lengths): all such cases return
//!   a null pointer / empty buffer / negative status code instead.

use std::ffi::{c_char, CStr};
use std::ptr;
use std::slice;

use crate::pqxdh::{self, IdentityKeyPair, InitialMessage, PreKeyBundle};
use crate::ratchet::{DoubleRatchet, RatchetMessage};
use crate::storage::{Session, Vault};

/// A heap-allocated byte buffer handed across the FFI boundary. Must be
/// released with [`vaultx_buffer_free`].
#[repr(C)]
pub struct VaultXBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl VaultXBuffer {
    fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
        }
    }

    fn from_vec(bytes: Vec<u8>) -> Self {
        let mut boxed = bytes.into_boxed_slice();
        let data = boxed.as_mut_ptr();
        let len = boxed.len();
        std::mem::forget(boxed);
        Self { data, len }
    }
}

/// Release a [`VaultXBuffer`] previously returned by this library. Safe to
/// call on an empty buffer (`data == null`); does nothing in that case.
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_buffer_free(buf: VaultXBuffer) {
    if buf.data.is_null() {
        return;
    }
    unsafe {
        drop(Vec::from_raw_parts(buf.data, buf.len, buf.len));
    }
}

// ---------------------------------------------------------------------
// Identity / PQXDH prekey bundles
// ---------------------------------------------------------------------

/// Generate a fresh identity (X25519 identity + signed prekey + one-time
/// prekey + ML-KEM-768 keypair). Returns an owning handle, or null if
/// allocation somehow fails.
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_identity_generate() -> *mut IdentityKeyPair {
    Box::into_raw(Box::new(IdentityKeyPair::generate()))
}

/// Free a handle returned by [`vaultx_identity_generate`].
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_identity_free(ptr: *mut IdentityKeyPair) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

/// Export the identity's public prekey bundle in Vault X's wire format (see
/// `crate::pqxdh::PreKeyBundle::to_wire_bytes`), ready to `POST` to the
/// relay's `/v1/prekeys/{id}` endpoint. Returns an empty buffer if `ptr` is
/// null.
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_identity_public_bundle_bytes(ptr: *const IdentityKeyPair) -> VaultXBuffer {
    let Some(identity) = (unsafe { ptr.as_ref() }) else {
        return VaultXBuffer::empty();
    };
    VaultXBuffer::from_vec(identity.public_bundle().to_wire_bytes())
}

/// Serialize *all* private key material for this identity so the caller can
/// store it in the encrypted [`Vault`] and reload the same identity (same
/// Device ID) on the next app launch via [`vaultx_identity_from_wire_bytes`]
/// — without this, a fresh random identity would be generated every
/// restart, which is unusable (a device's ID must stay stable for its
/// contacts to keep reaching it). Returns an empty buffer if `ptr` is null.
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_identity_to_wire_bytes(ptr: *const IdentityKeyPair) -> VaultXBuffer {
    let Some(identity) = (unsafe { ptr.as_ref() }) else {
        return VaultXBuffer::empty();
    };
    VaultXBuffer::from_vec(identity.to_wire_bytes())
}

/// Reconstruct an identity from bytes previously returned by
/// [`vaultx_identity_to_wire_bytes`] (e.g. loaded back out of the encrypted
/// vault). Returns null on malformed input.
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_identity_from_wire_bytes(
    bytes: *const u8,
    len: usize,
) -> *mut IdentityKeyPair {
    if bytes.is_null() {
        return ptr::null_mut();
    }
    let slice = unsafe { slice::from_raw_parts(bytes, len) };
    match IdentityKeyPair::from_wire_bytes(slice) {
        Ok(identity) => Box::into_raw(Box::new(identity)),
        Err(_) => ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------
// Encrypted vault / duress system
// ---------------------------------------------------------------------

/// Result of an unlock attempt. `handle` is null on failure (wrong PIN for
/// both vaults). `is_decoy` is meaningless when `handle` is null.
#[repr(C)]
pub struct VaultXUnlockResult {
    pub handle: *mut Vault,
    pub is_decoy: bool,
}

unsafe fn str_from_c(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok().map(str::to_owned)
}

/// Create a brand-new vault file at `path` (UTF-8, NUL-terminated) sealed
/// with `pin` (raw bytes, not necessarily UTF-8 — treat as opaque secret
/// material). Returns an owning handle, or null on failure.
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_vault_create(
    path: *const c_char,
    pin: *const u8,
    pin_len: usize,
) -> *mut Vault {
    let Some(path) = (unsafe { str_from_c(path) }) else {
        return ptr::null_mut();
    };
    if pin.is_null() {
        return ptr::null_mut();
    }
    let pin_bytes = unsafe { slice::from_raw_parts(pin, pin_len) };
    match Vault::create(&path, pin_bytes) {
        Ok(vault) => Box::into_raw(Box::new(vault)),
        Err(_) => ptr::null_mut(),
    }
}

/// Attempt to unlock whichever of the real/decoy vault pair at
/// `real_path`/`decoy_path` accepts `pin`. If the decoy PIN is what
/// matched, this call has *already* triggered the panic-wipe of the real
/// vault file before returning — see `crate::storage::VaultManager::unlock`.
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_vault_unlock(
    real_path: *const c_char,
    decoy_path: *const c_char,
    pin: *const u8,
    pin_len: usize,
) -> VaultXUnlockResult {
    let none = VaultXUnlockResult {
        handle: ptr::null_mut(),
        is_decoy: false,
    };
    let (Some(real_path), Some(decoy_path)) =
        (unsafe { str_from_c(real_path) }, unsafe { str_from_c(decoy_path) })
    else {
        return none;
    };
    if pin.is_null() {
        return none;
    }
    let pin_bytes = unsafe { slice::from_raw_parts(pin, pin_len) };
    let manager = crate::storage::VaultManager::new(real_path, decoy_path);
    match manager.unlock(pin_bytes) {
        Ok(Session::Real(vault)) => VaultXUnlockResult {
            handle: Box::into_raw(Box::new(vault)),
            is_decoy: false,
        },
        Ok(Session::Decoy(vault)) => VaultXUnlockResult {
            handle: Box::into_raw(Box::new(vault)),
            is_decoy: true,
        },
        Err(_) => none,
    }
}

/// Free a handle returned by [`vaultx_vault_create`] or carried in a
/// [`VaultXUnlockResult`].
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_vault_free(ptr: *mut Vault) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

/// Encrypt and store `value` under `key` in the vault. Returns `0` on
/// success, `-1` on failure (including a null handle).
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_vault_put(
    vault: *const Vault,
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
) -> i32 {
    let Some(vault) = (unsafe { vault.as_ref() }) else {
        return -1;
    };
    if key.is_null() || value.is_null() {
        return -1;
    }
    let key_bytes = unsafe { slice::from_raw_parts(key, key_len) };
    let value_bytes = unsafe { slice::from_raw_parts(value, value_len) };
    match vault.put(key_bytes, value_bytes) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Fetch and decrypt the value stored under `key`. Returns an empty buffer
/// both when the key is absent and on error (the caller cannot distinguish
/// those cases from this call alone; a richer status-carrying variant is
/// straightforward to add if the client needs to tell them apart).
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_vault_get(vault: *const Vault, key: *const u8, key_len: usize) -> VaultXBuffer {
    let Some(vault) = (unsafe { vault.as_ref() }) else {
        return VaultXBuffer::empty();
    };
    if key.is_null() {
        return VaultXBuffer::empty();
    }
    let key_bytes = unsafe { slice::from_raw_parts(key, key_len) };
    match vault.get(key_bytes) {
        Ok(Some(value)) => VaultXBuffer::from_vec(value),
        Ok(None) | Err(_) => VaultXBuffer::empty(),
    }
}

// ---------------------------------------------------------------------
// 1:1 sessions (PQXDH handshake + Double Ratchet)
// ---------------------------------------------------------------------

/// Result of [`vaultx_session_initiate`]. `session` is null on failure (bad
/// bundle bytes, or the handshake itself failing), in which case
/// `initial_message` is meaningless (empty).
#[repr(C)]
pub struct VaultXInitiateResult {
    pub session: *mut DoubleRatchet,
    pub initial_message: VaultXBuffer,
}

/// Alice's side of a new 1:1 session: consume the peer's prekey bundle
/// (wire bytes from `GET /v1/prekeys/{id}`) and `identity`'s own keys to run
/// the PQXDH handshake and bootstrap a Double Ratchet session. Returns the
/// session handle plus the wire-encoded [`InitialMessage`] to send to the
/// peer (e.g. as the first packet through the relay).
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_session_initiate(
    identity: *const IdentityKeyPair,
    bundle_bytes: *const u8,
    bundle_len: usize,
) -> VaultXInitiateResult {
    let none = VaultXInitiateResult {
        session: ptr::null_mut(),
        initial_message: VaultXBuffer::empty(),
    };
    let Some(identity) = (unsafe { identity.as_ref() }) else {
        return none;
    };
    if bundle_bytes.is_null() {
        return none;
    }
    let bundle_slice = unsafe { slice::from_raw_parts(bundle_bytes, bundle_len) };
    let Ok(bundle) = PreKeyBundle::from_wire_bytes(bundle_slice) else {
        return none;
    };
    let Ok((initial_message, root_key)) = pqxdh::initiate(&bundle, identity) else {
        return none;
    };
    let ratchet = DoubleRatchet::init_alice(root_key, bundle.signed_prekey);
    VaultXInitiateResult {
        session: Box::into_raw(Box::new(ratchet)),
        initial_message: VaultXBuffer::from_vec(initial_message.to_wire_bytes()),
    }
}

/// Bob's side of a new 1:1 session: given the wire-encoded
/// [`InitialMessage`] Alice sent (see [`vaultx_session_initiate`]) and
/// `identity`'s own keys, complete the PQXDH handshake and bootstrap the
/// matching Double Ratchet session. Returns null on failure (including if
/// `identity` no longer holds the one-time prekey Alice's message claims to
/// have used).
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_session_respond(
    identity: *const IdentityKeyPair,
    initial_message_bytes: *const u8,
    initial_message_len: usize,
) -> *mut DoubleRatchet {
    let Some(identity) = (unsafe { identity.as_ref() }) else {
        return ptr::null_mut();
    };
    if initial_message_bytes.is_null() {
        return ptr::null_mut();
    }
    let message_slice = unsafe { slice::from_raw_parts(initial_message_bytes, initial_message_len) };
    let Ok(initial) = InitialMessage::from_wire_bytes(message_slice) else {
        return ptr::null_mut();
    };
    let Ok(root_key) = pqxdh::respond(&initial, identity) else {
        return ptr::null_mut();
    };
    let ratchet = DoubleRatchet::init_bob(root_key, identity.signed_prekey_secret());
    Box::into_raw(Box::new(ratchet))
}

/// Free a handle returned by [`vaultx_session_initiate`] or
/// [`vaultx_session_respond`].
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_session_free(ptr: *mut DoubleRatchet) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

/// Encrypt `plaintext` (associated with `aad`, e.g. sender/recipient IDs —
/// authenticated but not secret) under the session's next message key.
/// Returns the wire-encoded [`RatchetMessage`] to send to the peer, or an
/// empty buffer on failure (including a null `session`).
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_session_encrypt(
    session: *mut DoubleRatchet,
    plaintext: *const u8,
    plaintext_len: usize,
    aad: *const u8,
    aad_len: usize,
) -> VaultXBuffer {
    let Some(session) = (unsafe { session.as_mut() }) else {
        return VaultXBuffer::empty();
    };
    if plaintext.is_null() && plaintext_len != 0 {
        return VaultXBuffer::empty();
    }
    let plaintext_slice = if plaintext_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(plaintext, plaintext_len) }
    };
    let aad_slice = if aad_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(aad, aad_len) }
    };
    match session.encrypt(plaintext_slice, aad_slice) {
        Ok(message) => VaultXBuffer::from_vec(message.to_wire_bytes()),
        Err(_) => VaultXBuffer::empty(),
    }
}

/// Decrypt a wire-encoded [`RatchetMessage`] received from the peer
/// (associated with the same `aad` the sender used), performing a DH
/// ratchet step first if needed. Returns the plaintext, or an empty buffer
/// on failure (including a null `session`) — note this makes empty
/// plaintext and failure indistinguishable from this call alone; callers
/// that need to send genuinely empty messages should use a non-empty
/// sentinel payload at the application layer.
#[unsafe(no_mangle)]
pub extern "C" fn vaultx_session_decrypt(
    session: *mut DoubleRatchet,
    message_bytes: *const u8,
    message_len: usize,
    aad: *const u8,
    aad_len: usize,
) -> VaultXBuffer {
    let Some(session) = (unsafe { session.as_mut() }) else {
        return VaultXBuffer::empty();
    };
    if message_bytes.is_null() {
        return VaultXBuffer::empty();
    }
    let message_slice = unsafe { slice::from_raw_parts(message_bytes, message_len) };
    let Ok(message) = RatchetMessage::from_wire_bytes(message_slice) else {
        return VaultXBuffer::empty();
    };
    let aad_slice = if aad_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(aad, aad_len) }
    };
    match session.decrypt(&message, aad_slice) {
        Ok(plaintext) => VaultXBuffer::from_vec(plaintext),
        Err(_) => VaultXBuffer::empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises the raw `extern "C"` functions directly (real pointers,
    /// real marshalling) rather than the safe Rust API underneath, since
    /// that's the surface a Dart FFI bug would actually trip over.
    #[test]
    fn full_session_round_trip_through_raw_ffi() {
        unsafe {
            let alice = vaultx_identity_generate();
            let bob = vaultx_identity_generate();
            assert!(!alice.is_null());
            assert!(!bob.is_null());

            let bob_bundle = vaultx_identity_public_bundle_bytes(bob);
            assert!(!bob_bundle.data.is_null());

            let init_result =
                vaultx_session_initiate(alice, bob_bundle.data, bob_bundle.len);
            assert!(!init_result.session.is_null());
            assert!(!init_result.initial_message.data.is_null());

            let bob_session = vaultx_session_respond(
                bob,
                init_result.initial_message.data,
                init_result.initial_message.len,
            );
            assert!(!bob_session.is_null());

            let plaintext = b"hello from raw ffi";
            let ciphertext = vaultx_session_encrypt(
                init_result.session,
                plaintext.as_ptr(),
                plaintext.len(),
                ptr::null(),
                0,
            );
            assert!(!ciphertext.data.is_null());

            let decrypted = vaultx_session_decrypt(
                bob_session,
                ciphertext.data,
                ciphertext.len,
                ptr::null(),
                0,
            );
            assert!(!decrypted.data.is_null());
            let decrypted_slice = slice::from_raw_parts(decrypted.data, decrypted.len);
            assert_eq!(decrypted_slice, plaintext);

            vaultx_buffer_free(bob_bundle);
            vaultx_buffer_free(init_result.initial_message);
            vaultx_buffer_free(ciphertext);
            vaultx_buffer_free(decrypted);
            vaultx_session_free(init_result.session);
            vaultx_session_free(bob_session);
            vaultx_identity_free(alice);
            vaultx_identity_free(bob);
        }
    }

    #[test]
    fn session_initiate_with_garbage_bundle_returns_null() {
        let alice = vaultx_identity_generate();
        let garbage = [0u8, 1, 2, 3];
        let result = vaultx_session_initiate(alice, garbage.as_ptr(), garbage.len());
        assert!(result.session.is_null());
        assert!(result.initial_message.data.is_null());
        vaultx_identity_free(alice);
    }
}
