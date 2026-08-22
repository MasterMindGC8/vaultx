# Vault X — Repository Security Rules & Execution Constraints

Vault X is a zero-knowledge, hybrid post-quantum end-to-end encrypted
messenger (Rust crypto core + Go relay + Flutter client). This file is
binding for any agent or contributor working in this repository.

## Non-negotiable constraints

1. **Never store or log unencrypted payload buffers.** No `println!`/`log::*`/
   `fmt.Println`/`print()` call may include plaintext message content, key
   material, PINs, or derived secrets — not even at `debug` level, not even
   temporarily "for testing". Logging structure (lengths, timestamps, opaque
   IDs) is fine; logging content is not.
2. **Always scrub private key buffers from memory.** Any type holding a
   private key, symmetric key, root/chain/message key, PIN, or passphrase
   must implement `Zeroize` (and typically `ZeroizeOnDrop`) in Rust. Dart-side
   sensitive buffers must be explicitly overwritten after use; do not rely on
   GC alone.
3. **Never use system-native UI components.** All Flutter widgets must be
   built from the Matrix terminal spec (`cypher_theme.dart`): phosphor green
   `#00FF66` on `#050505`, monospaced type, CRT scanline shader overlay, ASCII
   framed controls. No `Material`/`Cupertino` default chrome, no native
   dialogs/snackbars/date pickers.
4. **The relay is a zero-knowledge courier, not a party.** `transport_relay`
   must never persist plaintext, sender/recipient identity, or IP-linked
   metadata to disk. Packets live only in ephemeral in-RAM queues and are
   deleted immediately on delivery ACK or TTL expiry.
5. **No hand-rolled cryptographic primitives.** Use audited, maintained
   crates (`ml-kem`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `argon2`,
   `openmls`) for anything security-critical. Do not reimplement AEAD, KDF,
   or KEM math by hand.
6. **Duress/decoy paths must be indistinguishable from the true path** at the
   UI layer, and must physically zeroize true master key material in the
   background rather than merely hiding it.
7. **Status labeling:** code in this repo is a working engineering scaffold,
   not a formally audited product. Do not describe any component as
   "audited" or "production-hardened" in commit messages, comments, or docs
   unless an actual third-party audit has occurred. The Sphinx/Nym multi-hop
   mixnet layer is explicitly out of scope for the current milestone — the
   relay currently provides single-hop, zero-knowledge, RAM-only relaying
   only; treat any mixnet claims in older docs as aspirational until that
   milestone lands.

## Layout

- `crypto_core/` — Rust: PQXDH (X25519 + ML-KEM-768), Double Ratchet, MLS
  (RFC 9420, via `openmls`), Argon2id-keyed encrypted vault storage (`redb` +
  ChaCha20Poly1305 — see `storage.rs`'s module doc for why this isn't
  SQLCipher, as originally specified).
- `transport_relay/` — Go: WebSocket relay, ephemeral RAM-only packet queues,
  prekey bundle endpoints.
- `client_app/` — Flutter: Matrix CRT terminal UI, calling into
  `crypto_core` via a hand-written `dart:ffi` bridge
  (`lib/bridge/native_crypto.dart`) — not `flutter_rust_bridge` codegen, since
  the exposed surface is currently small (identity + vault only).
