//! Double Ratchet (Signal-style) symmetric-key ratchet, seeded by the root
//! key produced by [`crate::pqxdh`].
//!
//! Each message advances a per-direction symmetric-key (KDF) chain, and each
//! DH-ratchet step (triggered whenever the peer sends a new ratchet public
//! key) mixes a fresh X25519 shared secret back into the root chain. This
//! gives forward secrecy (compromising a chain key does not reveal past
//! message keys, since chain keys are one-way derived) and post-compromise
//! security (a subsequent DH ratchet step heals the session even after a
//! chain key leaks).

use std::collections::HashMap;

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::pqxdh::RootKey;
use crate::{VaultXError, Result};

const ROOT_KDF_INFO: &[u8] = b"VAULTX-RATCHET-ROOT-v1";
const CHAIN_KDF_INFO: &[u8] = b"VAULTX-RATCHET-CHAIN-v1";
const MAX_SKIPPED_MESSAGE_KEYS: usize = 2000;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct ChainKey([u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct MessageKey([u8; 32]);

/// One encrypted message on the wire: the sender's current ratchet public
/// key, the chain-step counters needed to locate/derive the message key on
/// the receiving side, and the AEAD ciphertext (which includes its auth
/// tag).
pub struct RatchetMessage {
    pub sender_ratchet_key: PublicKey,
    pub previous_chain_length: u32,
    pub message_number: u32,
    pub ciphertext: Vec<u8>,
}

const WIRE_HEADER_LEN: usize = 32 + 4 + 4 + 4;

impl RatchetMessage {
    /// Serialize for transport over the relay. Format:
    /// `[sender_ratchet_key:32][previous_chain_length:4 LE]
    ///  [message_number:4 LE][ciphertext_len:4 LE][ciphertext]`.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WIRE_HEADER_LEN + self.ciphertext.len());
        out.extend_from_slice(self.sender_ratchet_key.as_bytes());
        out.extend_from_slice(&self.previous_chain_length.to_le_bytes());
        out.extend_from_slice(&self.message_number.to_le_bytes());
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse the format produced by [`Self::to_wire_bytes`].
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < WIRE_HEADER_LEN {
            return Err(VaultXError::Ratchet("wire message truncated before header end"));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes[0..32]);
        let previous_chain_length = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let message_number = u32::from_le_bytes(bytes[36..40].try_into().unwrap());
        let ciphertext_len = u32::from_le_bytes(bytes[40..44].try_into().unwrap()) as usize;
        let ciphertext = bytes
            .get(WIRE_HEADER_LEN..WIRE_HEADER_LEN + ciphertext_len)
            .ok_or(VaultXError::Ratchet("wire message ciphertext truncated"))?
            .to_vec();
        Ok(Self {
            sender_ratchet_key: PublicKey::from(key_bytes),
            previous_chain_length,
            message_number,
            ciphertext,
        })
    }
}

/// A single party's Double Ratchet session state. Every field that carries
/// key material zeroizes on drop; `Drop` on the struct additionally clears
/// the skipped-key cache explicitly since `HashMap`'s own drop glue does not
/// zeroize its entries.
pub struct DoubleRatchet {
    root_key: [u8; 32],
    dh_self: StaticSecret,
    dh_self_public: PublicKey,
    dh_remote: Option<PublicKey>,
    sending_chain: Option<ChainKey>,
    receiving_chain: Option<ChainKey>,
    send_message_number: u32,
    recv_message_number: u32,
    previous_sending_chain_length: u32,
    // Keyed by (remote ratchet public key bytes, message number) so
    // out-of-order or dropped-then-recovered messages can still be
    // decrypted once their key was derived and cached.
    skipped_message_keys: HashMap<([u8; 32], u32), MessageKey>,
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
        for (_, key) in self.skipped_message_keys.drain() {
            drop(key); // MessageKey's own ZeroizeOnDrop clears it here.
        }
    }
}

impl DoubleRatchet {
    /// Initialize as the handshake initiator ("Alice"). `bob_ratchet_public`
    /// is the responder's signed-prekey public value, used as the first DH
    /// ratchet public key so Alice can derive a sending chain immediately
    /// without waiting for Bob's first reply.
    pub fn init_alice(root_key: RootKey, bob_ratchet_public: PublicKey) -> Self {
        let dh_self = StaticSecret::random();
        let dh_self_public = PublicKey::from(&dh_self);
        let dh_output = dh_self.diffie_hellman(&bob_ratchet_public);

        let (new_root, sending_chain) = kdf_root(root_key.as_bytes(), dh_output.as_bytes());

        Self {
            root_key: new_root,
            dh_self,
            dh_self_public,
            dh_remote: Some(bob_ratchet_public),
            sending_chain: Some(sending_chain),
            receiving_chain: None,
            send_message_number: 0,
            recv_message_number: 0,
            previous_sending_chain_length: 0,
            skipped_message_keys: HashMap::new(),
        }
    }

    /// Initialize as the handshake responder ("Bob"). `own_ratchet_secret`
    /// is Bob's signed-prekey private value (the counterpart of the public
    /// key Alice used in [`Self::init_alice`]); Bob's sending chain is
    /// created lazily on first send, once Alice's ratchet key is known.
    pub fn init_bob(root_key: RootKey, own_ratchet_secret: StaticSecret) -> Self {
        let dh_self_public = PublicKey::from(&own_ratchet_secret);
        Self {
            root_key: root_key.0,
            dh_self: own_ratchet_secret,
            dh_self_public,
            dh_remote: None,
            sending_chain: None,
            receiving_chain: None,
            send_message_number: 0,
            recv_message_number: 0,
            previous_sending_chain_length: 0,
            skipped_message_keys: HashMap::new(),
        }
    }

    pub fn ratchet_public_key(&self) -> PublicKey {
        self.dh_self_public
    }

    /// Encrypt `plaintext` under the next message key in the current
    /// sending chain, associated with `aad` (e.g. sender/recipient IDs,
    /// which are authenticated but not secret).
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<RatchetMessage> {
        if self.sending_chain.is_none() {
            return Err(VaultXError::Ratchet(
                "no sending chain established; call ratchet_send_side_dh first if responder",
            ));
        }
        let chain = self.sending_chain.take().unwrap();
        let (next_chain, message_key) = kdf_chain(&chain);
        drop(chain);
        self.sending_chain = Some(next_chain);

        let nonce = Nonce::default(); // message keys are single-use, so an all-zero nonce is safe
        let cipher = ChaCha20Poly1305::new(&Key::from(message_key.0));
        let ciphertext = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .map_err(|_| VaultXError::Aead)?;
        drop(message_key);

        let message = RatchetMessage {
            sender_ratchet_key: self.dh_self_public,
            previous_chain_length: self.previous_sending_chain_length,
            message_number: self.send_message_number,
            ciphertext,
        };
        self.send_message_number += 1;
        Ok(message)
    }

    /// Decrypt an incoming [`RatchetMessage`], performing a DH ratchet step
    /// first if the sender's ratchet key has changed since the last message
    /// we received from them.
    pub fn decrypt(&mut self, message: &RatchetMessage, aad: &[u8]) -> Result<Vec<u8>> {
        let remote_key_bytes = message.sender_ratchet_key.to_bytes();

        if let Some(key) = self
            .skipped_message_keys
            .remove(&(remote_key_bytes, message.message_number))
        {
            return self.open(&key, &message.ciphertext, aad);
        }

        let is_new_ratchet_key = self.dh_remote.map(|k| k.to_bytes()) != Some(remote_key_bytes);
        if is_new_ratchet_key {
            if let Some(chain) = self.receiving_chain.take() {
                self.skip_message_keys(&chain, message.previous_chain_length)?;
            }
            self.dh_ratchet_step(message.sender_ratchet_key);
        }

        let chain = self.receiving_chain.take().ok_or(VaultXError::Ratchet(
            "no receiving chain after ratchet step",
        ))?;
        self.skip_message_keys_into(&chain, message.message_number, remote_key_bytes)?;

        let key = self
            .skipped_message_keys
            .remove(&(remote_key_bytes, message.message_number))
            .ok_or(VaultXError::Ratchet("message key missing after derivation"))?;

        self.open(&key, &message.ciphertext, aad)
    }

    fn open(&self, key: &MessageKey, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::default();
        let cipher = ChaCha20Poly1305::new(&Key::from(key.0));
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| VaultXError::Aead)
    }

    /// Advance `chain` up to (but not including) `message.message_number`,
    /// caching every skipped message key so late or reordered messages can
    /// still be decrypted, and leaves the resulting chain + final message
    /// key derivation to the caller.
    fn skip_message_keys_into(
        &mut self,
        chain: &ChainKey,
        target_message_number: u32,
        remote_key_bytes: [u8; 32],
    ) -> Result<()> {
        let mut current = chain.clone();
        let mut n = self.recv_message_number;
        while n < target_message_number {
            let (next_chain, key) = kdf_chain(&current);
            self.cache_skipped_key(remote_key_bytes, n, key)?;
            current = next_chain;
            n += 1;
        }
        let (next_chain, final_key) = kdf_chain(&current);
        self.cache_skipped_key(remote_key_bytes, target_message_number, final_key)?;
        self.receiving_chain = Some(next_chain);
        self.recv_message_number = target_message_number + 1;
        Ok(())
    }

    /// Used only when a DH ratchet step just occurred: skip forward through
    /// the *old* receiving chain up to `until`, caching keys for messages
    /// from the previous sending chain that may still be in flight.
    fn skip_message_keys(&mut self, chain: &ChainKey, until: u32) -> Result<()> {
        let remote_key_bytes = match self.dh_remote {
            Some(k) => k.to_bytes(),
            None => return Ok(()),
        };
        let mut current = chain.clone();
        let mut n = self.recv_message_number;
        while n < until {
            let (next_chain, key) = kdf_chain(&current);
            self.cache_skipped_key(remote_key_bytes, n, key)?;
            current = next_chain;
            n += 1;
        }
        Ok(())
    }

    fn cache_skipped_key(
        &mut self,
        remote_key_bytes: [u8; 32],
        message_number: u32,
        key: MessageKey,
    ) -> Result<()> {
        if self.skipped_message_keys.len() >= MAX_SKIPPED_MESSAGE_KEYS {
            return Err(VaultXError::Ratchet(
                "too many skipped message keys cached; refusing to grow further (possible DoS)",
            ));
        }
        self.skipped_message_keys
            .insert((remote_key_bytes, message_number), key);
        Ok(())
    }

    fn dh_ratchet_step(&mut self, remote_public: PublicKey) {
        self.previous_sending_chain_length = self.send_message_number;
        self.send_message_number = 0;
        self.recv_message_number = 0;
        self.dh_remote = Some(remote_public);

        let recv_dh = self.dh_self.diffie_hellman(&remote_public);
        let (root_after_recv, receiving_chain) = kdf_root(&self.root_key, recv_dh.as_bytes());
        self.root_key = root_after_recv;
        self.receiving_chain = Some(receiving_chain);

        self.dh_self = StaticSecret::random();
        self.dh_self_public = PublicKey::from(&self.dh_self);
        let send_dh = self.dh_self.diffie_hellman(&remote_public);
        let (root_after_send, sending_chain) = kdf_root(&self.root_key, send_dh.as_bytes());
        self.root_key = root_after_send;
        self.sending_chain = Some(sending_chain);
    }
}

fn kdf_root(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], ChainKey) {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut okm = [0u8; 64];
    hk.expand(ROOT_KDF_INFO, &mut okm)
        .expect("64 <= 255*32 output for HKDF-SHA256");
    let mut new_root = [0u8; 32];
    let mut chain = [0u8; 32];
    new_root.copy_from_slice(&okm[..32]);
    chain.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (new_root, ChainKey(chain))
}

fn kdf_chain(chain: &ChainKey) -> (ChainKey, MessageKey) {
    let hk = Hkdf::<Sha256>::new(None, &chain.0);
    let mut okm = [0u8; 64];
    hk.expand(CHAIN_KDF_INFO, &mut okm)
        .expect("64 <= 255*32 output for HKDF-SHA256");
    let mut next_chain = [0u8; 32];
    let mut message_key = [0u8; 32];
    next_chain.copy_from_slice(&okm[..32]);
    message_key.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (ChainKey(next_chain), MessageKey(message_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_key_pair() -> ([u8; 32], [u8; 32]) {
        ([7u8; 32], [7u8; 32])
    }

    #[test]
    fn ratchet_message_wire_round_trip() {
        let secret = StaticSecret::random();
        let message = RatchetMessage {
            sender_ratchet_key: PublicKey::from(&secret),
            previous_chain_length: 3,
            message_number: 42,
            ciphertext: b"some ciphertext bytes".to_vec(),
        };
        let bytes = message.to_wire_bytes();
        let parsed = RatchetMessage::from_wire_bytes(&bytes).unwrap();
        assert_eq!(
            parsed.sender_ratchet_key.to_bytes(),
            message.sender_ratchet_key.to_bytes()
        );
        assert_eq!(parsed.previous_chain_length, message.previous_chain_length);
        assert_eq!(parsed.message_number, message.message_number);
        assert_eq!(parsed.ciphertext, message.ciphertext);
    }

    #[test]
    fn alice_and_bob_exchange_messages_in_order() {
        let bob_ratchet_secret = StaticSecret::random();
        let bob_ratchet_public = PublicKey::from(&bob_ratchet_secret);

        let (a, b) = root_key_pair();
        let mut alice = DoubleRatchet::init_alice(RootKey(a), bob_ratchet_public);
        let mut bob = DoubleRatchet::init_bob(RootKey(b), bob_ratchet_secret);

        let msg = alice.encrypt(b"hello bob", b"aad").unwrap();
        let plaintext = bob.decrypt(&msg, b"aad").unwrap();
        assert_eq!(plaintext, b"hello bob");

        let reply = bob.encrypt(b"hello alice", b"aad").unwrap();
        let plaintext = alice.decrypt(&reply, b"aad").unwrap();
        assert_eq!(plaintext, b"hello alice");
    }

    #[test]
    fn out_of_order_messages_still_decrypt() {
        let bob_ratchet_secret = StaticSecret::random();
        let bob_ratchet_public = PublicKey::from(&bob_ratchet_secret);
        let (a, b) = root_key_pair();
        let mut alice = DoubleRatchet::init_alice(RootKey(a), bob_ratchet_public);
        let mut bob = DoubleRatchet::init_bob(RootKey(b), bob_ratchet_secret);

        let m1 = alice.encrypt(b"one", b"").unwrap();
        let m2 = alice.encrypt(b"two", b"").unwrap();
        let m3 = alice.encrypt(b"three", b"").unwrap();

        assert_eq!(bob.decrypt(&m3, b"").unwrap(), b"three");
        assert_eq!(bob.decrypt(&m1, b"").unwrap(), b"one");
        assert_eq!(bob.decrypt(&m2, b"").unwrap(), b"two");
    }

    #[test]
    fn many_round_trips_advance_the_dh_ratchet() {
        let bob_ratchet_secret = StaticSecret::random();
        let bob_ratchet_public = PublicKey::from(&bob_ratchet_secret);
        let (a, b) = root_key_pair();
        let mut alice = DoubleRatchet::init_alice(RootKey(a), bob_ratchet_public);
        let mut bob = DoubleRatchet::init_bob(RootKey(b), bob_ratchet_secret);

        for i in 0..20u32 {
            let from_alice = alice.encrypt(format!("a{i}").as_bytes(), b"").unwrap();
            let got = bob.decrypt(&from_alice, b"").unwrap();
            assert_eq!(got, format!("a{i}").as_bytes());

            let from_bob = bob.encrypt(format!("b{i}").as_bytes(), b"").unwrap();
            let got = alice.decrypt(&from_bob, b"").unwrap();
            assert_eq!(got, format!("b{i}").as_bytes());
        }
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let bob_ratchet_secret = StaticSecret::random();
        let bob_ratchet_public = PublicKey::from(&bob_ratchet_secret);
        let (a, b) = root_key_pair();
        let mut alice = DoubleRatchet::init_alice(RootKey(a), bob_ratchet_public);
        let mut bob = DoubleRatchet::init_bob(RootKey(b), bob_ratchet_secret);

        let mut msg = alice.encrypt(b"integrity check", b"aad").unwrap();
        let last = msg.ciphertext.len() - 1;
        msg.ciphertext[last] ^= 0x01;

        assert!(bob.decrypt(&msg, b"aad").is_err());
    }
}
