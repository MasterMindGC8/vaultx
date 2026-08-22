//! Hybrid PQXDH-style key agreement: classical X25519 Diffie-Hellman combined
//! with a post-quantum ML-KEM-768 key encapsulation, folded into a single
//! root secret via HKDF-SHA256.
//!
//! This follows the shape of Signal's X3DH (Bob publishes an identity key, a
//! signed prekey, and an optional one-time prekey; Alice contributes a fresh
//! ephemeral key) with an ML-KEM-768 encapsulation added alongside the DH
//! terms, in the spirit of the PQXDH extension. It is a from-scratch
//! implementation of that *shape*, not a byte-for-byte port of Signal's wire
//! format — treat it as Vault X's own hybrid handshake, not as interop with any
//! external PQXDH deployment.
//!
//! The resulting [`RootKey`] seeds the Double Ratchet in [`crate::ratchet`].

use hkdf::Hkdf;
use ml_kem::{
    Ciphertext, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, TryKeyInit,
    kem::{Decapsulate, Encapsulate, Kem},
};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{VaultXError, Result};

const HANDSHAKE_INFO: &[u8] = b"VAULTX-PQXDH-v1";

/// A 32-byte root secret derived from a completed handshake. Feeds directly
/// into [`crate::ratchet::DoubleRatchet::init_alice`] /
/// [`crate::ratchet::DoubleRatchet::init_bob`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootKey(pub [u8; 32]);

impl RootKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A party's long-term identity plus the prekeys it publishes to the relay.
/// The private halves are held only by the owning device and are zeroized
/// on drop.
pub struct IdentityKeyPair {
    identity: StaticSecret,
    identity_public: PublicKey,
    signed_prekey: StaticSecret,
    signed_prekey_public: PublicKey,
    one_time_prekey: Option<StaticSecret>,
    one_time_prekey_public: Option<PublicKey>,
    kem_decap: DecapsulationKey<MlKem768>,
    kem_encap_public: EncapsulationKey<MlKem768>,
}

impl IdentityKeyPair {
    /// Generate a fresh identity, signed prekey, one-time prekey, and
    /// ML-KEM-768 keypair. In production the signed prekey and one-time
    /// prekeys are rotated independently of the identity key; this
    /// constructor is a convenience for creating a complete fresh set (e.g.
    /// on first run or when replenishing one-time prekeys).
    pub fn generate() -> Self {
        let identity = StaticSecret::random();
        let identity_public = PublicKey::from(&identity);
        let signed_prekey = StaticSecret::random();
        let signed_prekey_public = PublicKey::from(&signed_prekey);
        let one_time_prekey = StaticSecret::random();
        let one_time_prekey_public = PublicKey::from(&one_time_prekey);
        let (kem_decap, kem_encap_public) = MlKem768::generate_keypair();

        Self {
            identity,
            identity_public,
            signed_prekey,
            signed_prekey_public,
            one_time_prekey: Some(one_time_prekey),
            one_time_prekey_public: Some(one_time_prekey_public),
            kem_decap,
            kem_encap_public,
        }
    }

    /// The public prekey bundle to publish to the relay's `/v1/prekeys`
    /// endpoint. Contains no private material.
    pub fn public_bundle(&self) -> PreKeyBundle {
        PreKeyBundle {
            identity_key: self.identity_public,
            signed_prekey: self.signed_prekey_public,
            one_time_prekey: self.one_time_prekey_public,
            kem_encap_key: self.kem_encap_public.clone(),
        }
    }

    /// Consume the published one-time prekey after a peer has used it. The
    /// relay should also drop the corresponding entry so it is never handed
    /// out twice.
    pub fn consume_one_time_prekey(&mut self) {
        self.one_time_prekey = None;
        self.one_time_prekey_public = None;
    }

    /// A clone of this identity's signed-prekey private value. The
    /// responder side of a handshake needs this to bootstrap its Double
    /// Ratchet session (see [`crate::ratchet::DoubleRatchet::init_bob`]) —
    /// it's the private counterpart of the public key the initiator used as
    /// the ratchet's first DH public value.
    pub fn signed_prekey_secret(&self) -> StaticSecret {
        self.signed_prekey.clone()
    }

    /// Serialize *all* private key material so this identity can be
    /// reloaded across app restarts (store the result in the encrypted
    /// [`crate::storage::Vault`] — never anywhere unencrypted). Format:
    /// `[version:1][identity_secret:32][signed_prekey_secret:32]
    ///  [has_otp:1][one_time_prekey_secret:32 if has_otp][kem_decap_seed:64]`.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 32 + 1 + 32 + 64);
        out.push(WIRE_VERSION);
        out.extend_from_slice(self.identity.to_bytes().as_slice());
        out.extend_from_slice(self.signed_prekey.to_bytes().as_slice());
        match &self.one_time_prekey {
            Some(otp) => {
                out.push(1);
                out.extend_from_slice(otp.to_bytes().as_slice());
            }
            None => out.push(0),
        }
        let seed = self
            .kem_decap
            .to_seed()
            .expect("decapsulation key generated via generate_keypair always has a seed");
        out.extend_from_slice(&seed);
        out
    }

    /// Reconstruct an identity from the bytes produced by
    /// [`Self::to_wire_bytes`].
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cursor = WireCursor::new(bytes);
        let version = cursor.take_u8()?;
        if version != WIRE_VERSION {
            return Err(VaultXError::Handshake("unsupported IdentityKeyPair wire version"));
        }
        let identity = StaticSecret::from(cursor.take_array::<X25519_KEY_LEN>()?);
        let identity_public = PublicKey::from(&identity);
        let signed_prekey = StaticSecret::from(cursor.take_array::<X25519_KEY_LEN>()?);
        let signed_prekey_public = PublicKey::from(&signed_prekey);
        let has_otp = cursor.take_u8()?;
        let (one_time_prekey, one_time_prekey_public) = match has_otp {
            0 => (None, None),
            1 => {
                let otp = StaticSecret::from(cursor.take_array::<X25519_KEY_LEN>()?);
                let otp_public = PublicKey::from(&otp);
                (Some(otp), Some(otp_public))
            }
            _ => return Err(VaultXError::Handshake("invalid one-time-prekey flag")),
        };
        let seed_bytes = cursor.take_array::<64>()?;
        let seed = ml_kem::Seed::try_from(seed_bytes.as_slice())
            .map_err(|_| VaultXError::Handshake("malformed ML-KEM seed"))?;
        let kem_decap = DecapsulationKey::<MlKem768>::from_seed(seed);
        let kem_encap_public = kem_decap.encapsulation_key().clone();
        Ok(Self {
            identity,
            identity_public,
            signed_prekey,
            signed_prekey_public,
            one_time_prekey,
            one_time_prekey_public,
            kem_decap,
            kem_encap_public,
        })
    }
}

/// The public prekey material a party publishes so others can initiate a
/// handshake with it without an interactive round trip.
#[derive(Clone)]
pub struct PreKeyBundle {
    pub identity_key: PublicKey,
    pub signed_prekey: PublicKey,
    pub one_time_prekey: Option<PublicKey>,
    pub kem_encap_key: EncapsulationKey<MlKem768>,
}

const WIRE_VERSION: u8 = 1;
const X25519_KEY_LEN: usize = 32;

impl PreKeyBundle {
    /// Serialize for transport to the relay's `/v1/prekeys/{id}` endpoint or
    /// for handing to the FFI layer. Format:
    /// `[version:1][identity_key:32][signed_prekey:32][has_otp:1]
    ///  [one_time_prekey:32 if has_otp][kem_encap_key_len:4 LE][kem_encap_key]`.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let kem_bytes = self.kem_encap_key.to_bytes();
        let mut out = Vec::with_capacity(
            1 + X25519_KEY_LEN * 2 + 1 + X25519_KEY_LEN + 4 + kem_bytes.len(),
        );
        out.push(WIRE_VERSION);
        out.extend_from_slice(self.identity_key.as_bytes());
        out.extend_from_slice(self.signed_prekey.as_bytes());
        match &self.one_time_prekey {
            Some(otp) => {
                out.push(1);
                out.extend_from_slice(otp.as_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&(kem_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&kem_bytes);
        out
    }

    /// Parse the format produced by [`Self::to_wire_bytes`].
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cursor = WireCursor::new(bytes);
        let version = cursor.take_u8()?;
        if version != WIRE_VERSION {
            return Err(VaultXError::Handshake("unsupported PreKeyBundle wire version"));
        }
        let identity_key = PublicKey::from(cursor.take_array::<X25519_KEY_LEN>()?);
        let signed_prekey = PublicKey::from(cursor.take_array::<X25519_KEY_LEN>()?);
        let has_otp = cursor.take_u8()?;
        let one_time_prekey = match has_otp {
            0 => None,
            1 => Some(PublicKey::from(cursor.take_array::<X25519_KEY_LEN>()?)),
            _ => return Err(VaultXError::Handshake("invalid one-time-prekey flag")),
        };
        let kem_len = cursor.take_u32_le()? as usize;
        let kem_bytes = cursor.take_slice(kem_len)?;
        let kem_encap_key = EncapsulationKey::<MlKem768>::new_from_slice(kem_bytes)
            .map_err(|_| VaultXError::Handshake("malformed ML-KEM encapsulation key"))?;
        Ok(Self {
            identity_key,
            signed_prekey,
            one_time_prekey,
            kem_encap_key,
        })
    }
}

/// The message Alice sends Bob to complete the handshake asynchronously
/// (Bob need not be online). Carries no plaintext — only the public values
/// needed for Bob to derive the same root key.
pub struct InitialMessage {
    pub alice_identity_key: PublicKey,
    pub alice_ephemeral_key: PublicKey,
    pub kem_ciphertext: Ciphertext<MlKem768>,
    pub used_one_time_prekey: bool,
}

impl InitialMessage {
    /// Serialize for transport alongside the first ratchet-encrypted
    /// message. Format:
    /// `[version:1][alice_identity_key:32][alice_ephemeral_key:32]
    ///  [used_otp:1][kem_ciphertext_len:4 LE][kem_ciphertext]`.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + X25519_KEY_LEN * 2 + 1 + 4 + self.kem_ciphertext.len());
        out.push(WIRE_VERSION);
        out.extend_from_slice(self.alice_identity_key.as_bytes());
        out.extend_from_slice(self.alice_ephemeral_key.as_bytes());
        out.push(self.used_one_time_prekey as u8);
        out.extend_from_slice(&(self.kem_ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.kem_ciphertext);
        out
    }

    /// Parse the format produced by [`Self::to_wire_bytes`].
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cursor = WireCursor::new(bytes);
        let version = cursor.take_u8()?;
        if version != WIRE_VERSION {
            return Err(VaultXError::Handshake(
                "unsupported InitialMessage wire version",
            ));
        }
        let alice_identity_key = PublicKey::from(cursor.take_array::<X25519_KEY_LEN>()?);
        let alice_ephemeral_key = PublicKey::from(cursor.take_array::<X25519_KEY_LEN>()?);
        let used_one_time_prekey = match cursor.take_u8()? {
            0 => false,
            1 => true,
            _ => return Err(VaultXError::Handshake("invalid used-one-time-prekey flag")),
        };
        let ct_len = cursor.take_u32_le()? as usize;
        let ct_bytes = cursor.take_slice(ct_len)?;
        let kem_ciphertext = Ciphertext::<MlKem768>::try_from(ct_bytes)
            .map_err(|_| VaultXError::Handshake("malformed ML-KEM ciphertext"))?;
        Ok(Self {
            alice_identity_key,
            alice_ephemeral_key,
            kem_ciphertext,
            used_one_time_prekey,
        })
    }
}

/// Minimal byte-slice cursor for the fixed, hand-rolled wire formats above.
/// Not a general parser — deliberately narrow so the format stays easy to
/// audit by inspection.
struct WireCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> WireCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(VaultXError::Handshake("wire format length overflow"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(VaultXError::Handshake("wire format truncated"))?;
        self.pos = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8> {
        Ok(self.take_slice(1)?[0])
    }

    fn take_u32_le(&mut self) -> Result<u32> {
        let s = self.take_slice(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.take_slice(N)?;
        s.try_into()
            .map_err(|_| VaultXError::Handshake("wire format array length mismatch"))
    }
}

/// Alice's side: consume Bob's published bundle and her own identity key to
/// derive a shared [`RootKey`], producing the [`InitialMessage`] to send to
/// Bob over the zero-knowledge relay.
pub fn initiate(
    bundle: &PreKeyBundle,
    alice_identity: &IdentityKeyPair,
) -> Result<(InitialMessage, RootKey)> {
    // Reusable (not single-use) so it can participate in multiple DH terms;
    // it still zeroizes on drop.
    let alice_ephemeral = StaticSecret::random();
    let alice_ephemeral_public = PublicKey::from(&alice_ephemeral);

    let dh1 = alice_identity.identity.diffie_hellman(&bundle.signed_prekey);
    let dh2 = alice_ephemeral.diffie_hellman(&bundle.identity_key);
    let dh3 = alice_ephemeral.diffie_hellman(&bundle.signed_prekey);
    let dh4 = bundle
        .one_time_prekey
        .as_ref()
        .map(|otp| alice_ephemeral.diffie_hellman(otp));

    let (kem_ciphertext, kem_shared_secret) = bundle.kem_encap_key.encapsulate();

    let mut ikm = Vec::with_capacity(32 * 5);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(dh4) = &dh4 {
        ikm.extend_from_slice(dh4.as_bytes());
    }
    ikm.extend_from_slice(&kem_shared_secret);

    let root_key = derive_root_key(&ikm)?;
    ikm.zeroize();

    Ok((
        InitialMessage {
            alice_identity_key: alice_identity.identity_public,
            alice_ephemeral_key: alice_ephemeral_public,
            kem_ciphertext,
            used_one_time_prekey: dh4.is_some(),
        },
        root_key,
    ))
}

/// Bob's side: given Alice's [`InitialMessage`] and Bob's own identity
/// keypair (which must still hold the matching one-time prekey if
/// `used_one_time_prekey` is set), derive the same [`RootKey`] Alice
/// derived.
pub fn respond(initial: &InitialMessage, bob_identity: &IdentityKeyPair) -> Result<RootKey> {
    let dh1 = bob_identity
        .signed_prekey
        .diffie_hellman(&initial.alice_identity_key);
    let dh2 = bob_identity
        .identity
        .diffie_hellman(&initial.alice_ephemeral_key);
    let dh3 = bob_identity
        .signed_prekey
        .diffie_hellman(&initial.alice_ephemeral_key);
    let dh4 = if initial.used_one_time_prekey {
        let otp = bob_identity
            .one_time_prekey
            .as_ref()
            .ok_or(VaultXError::Handshake(
                "peer claims one-time prekey use but it is no longer held",
            ))?;
        Some(otp.diffie_hellman(&initial.alice_ephemeral_key))
    } else {
        None
    };

    let kem_shared_secret = bob_identity.kem_decap.decapsulate(&initial.kem_ciphertext);

    let mut ikm = Vec::with_capacity(32 * 5);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(dh4) = &dh4 {
        ikm.extend_from_slice(dh4.as_bytes());
    }
    ikm.extend_from_slice(&kem_shared_secret);

    let root_key = derive_root_key(&ikm)?;
    ikm.zeroize();
    Ok(root_key)
}

fn derive_root_key(ikm: &[u8]) -> Result<RootKey> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(HANDSHAKE_INFO, &mut okm)
        .map_err(|_| VaultXError::Handshake("HKDF expand failed"))?;
    Ok(RootKey(okm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_wire_round_trip_preserves_handshake_behavior() {
        let alice = IdentityKeyPair::generate();
        let bytes = alice.to_wire_bytes();
        let reloaded_alice = IdentityKeyPair::from_wire_bytes(&bytes).unwrap();

        // The reloaded identity's public bundle must match the original's
        // exactly (this is what keeps a device's ID/bundle stable across
        // app restarts).
        let original_bundle = alice.public_bundle();
        let reloaded_bundle = reloaded_alice.public_bundle();
        assert_eq!(
            original_bundle.identity_key.to_bytes(),
            reloaded_bundle.identity_key.to_bytes()
        );
        assert_eq!(
            original_bundle.kem_encap_key.to_bytes(),
            reloaded_bundle.kem_encap_key.to_bytes()
        );

        // And it must still work as a real identity in a handshake.
        let bob = IdentityKeyPair::generate();
        let bob_bundle = bob.public_bundle();
        let (initial, alice_root) = initiate(&bob_bundle, &reloaded_alice).unwrap();
        let bob_root = respond(&initial, &bob).unwrap();
        assert_eq!(alice_root.as_bytes(), bob_root.as_bytes());
    }

    #[test]
    fn prekey_bundle_wire_round_trip_with_otp() {
        let bob = IdentityKeyPair::generate();
        let bundle = bob.public_bundle();
        let bytes = bundle.to_wire_bytes();
        let parsed = PreKeyBundle::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed.identity_key.to_bytes(), bundle.identity_key.to_bytes());
        assert_eq!(parsed.signed_prekey.to_bytes(), bundle.signed_prekey.to_bytes());
        assert_eq!(
            parsed.one_time_prekey.map(|k| k.to_bytes()),
            bundle.one_time_prekey.map(|k| k.to_bytes())
        );
        assert_eq!(parsed.kem_encap_key.to_bytes(), bundle.kem_encap_key.to_bytes());
    }

    #[test]
    fn prekey_bundle_wire_round_trip_without_otp() {
        let mut bob = IdentityKeyPair::generate();
        bob.consume_one_time_prekey();
        let bundle = bob.public_bundle();
        let bytes = bundle.to_wire_bytes();
        let parsed = PreKeyBundle::from_wire_bytes(&bytes).unwrap();
        assert!(parsed.one_time_prekey.is_none());
        assert_eq!(parsed.kem_encap_key.to_bytes(), bundle.kem_encap_key.to_bytes());
    }

    #[test]
    fn initial_message_wire_round_trip_and_handshake_still_agrees() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let bob_bundle = bob.public_bundle();

        let (initial, alice_root) = initiate(&bob_bundle, &alice).unwrap();
        let bytes = initial.to_wire_bytes();
        let parsed = InitialMessage::from_wire_bytes(&bytes).unwrap();

        assert_eq!(parsed.used_one_time_prekey, initial.used_one_time_prekey);
        assert_eq!(
            parsed.alice_identity_key.to_bytes(),
            initial.alice_identity_key.to_bytes()
        );

        // The parsed (wire round-tripped) message must still work as input
        // to Bob's side of the handshake and produce the same root.
        let bob_root = respond(&parsed, &bob).unwrap();
        assert_eq!(alice_root.as_bytes(), bob_root.as_bytes());
    }

    #[test]
    fn handshake_agrees_with_one_time_prekey() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let bob_bundle = bob.public_bundle();
        let (initial_message, alice_root) = initiate(&bob_bundle, &alice).unwrap();
        assert!(initial_message.used_one_time_prekey);

        let bob_root = respond(&initial_message, &bob).unwrap();
        assert_eq!(alice_root.as_bytes(), bob_root.as_bytes());
    }

    #[test]
    fn handshake_agrees_without_one_time_prekey() {
        let alice = IdentityKeyPair::generate();
        let mut bob = IdentityKeyPair::generate();
        bob.consume_one_time_prekey();

        let bob_bundle = bob.public_bundle();
        assert!(bob_bundle.one_time_prekey.is_none());

        let (initial_message, alice_root) = initiate(&bob_bundle, &alice).unwrap();
        assert!(!initial_message.used_one_time_prekey);

        let bob_root = respond(&initial_message, &bob).unwrap();
        assert_eq!(alice_root.as_bytes(), bob_root.as_bytes());
    }

    #[test]
    fn different_peers_derive_different_roots() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let mallory = IdentityKeyPair::generate();

        let bob_bundle = bob.public_bundle();
        let (_, alice_root_vs_bob) = initiate(&bob_bundle, &alice).unwrap();

        let mallory_bundle = mallory.public_bundle();
        let (_, alice_root_vs_mallory) = initiate(&mallory_bundle, &alice).unwrap();

        assert_ne!(alice_root_vs_bob.as_bytes(), alice_root_vs_mallory.as_bytes());
    }
}
