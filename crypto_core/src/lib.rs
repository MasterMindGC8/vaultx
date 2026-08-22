//! Vault X cryptographic core.
//!
//! This crate is the only place in the Vault X monorepo allowed to touch
//! key material directly. See `CLAUDE.md` at the repo root for the binding
//! constraints (no plaintext logging, mandatory zeroization, no hand-rolled
//! primitives).

pub mod ffi;
pub mod mls;
pub mod pqxdh;
pub mod ratchet;
pub mod storage;

/// Errors surfaced across the crypto core's public API.
#[derive(Debug, thiserror::Error)]
pub enum VaultXError {
    #[error("handshake failed: {0}")]
    Handshake(&'static str),
    #[error("ratchet state error: {0}")]
    Ratchet(&'static str),
    #[error("mls error: {0}")]
    Mls(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("aead operation failed")]
    Aead,
}

pub type Result<T> = core::result::Result<T, VaultXError>;
