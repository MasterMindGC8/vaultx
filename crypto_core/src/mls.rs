//! RFC 9420 Messaging Layer Security (MLS) wrapper for Vault X group chats.
//!
//! This wraps the [`openmls`] crate (a community-maintained, spec-tracking
//! implementation of RFC 9420) rather than hand-rolling TreeKEM, commit
//! processing, and epoch secret derivation from scratch — that state
//! machine is exactly the kind of security-critical protocol code where a
//! from-scratch, single-session implementation would be indefensible. This
//! module only adds the Vault X-specific surface: creating a group, inviting
//! members, and sending/receiving application messages, all in terms of
//! `openmls`'s own types.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls::treesync::RatchetTree;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{VaultXError, Result};

/// The ciphersuite Vault X standardizes on for MLS groups: X25519 HPKE key
/// exchange, ChaCha20-Poly1305 AEAD, SHA-256, Ed25519 signatures.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

fn map_err<E: std::fmt::Display>(e: E) -> VaultXError {
    VaultXError::Mls(e.to_string())
}

/// One Vault X member's MLS identity: their crypto provider (holding the
/// in-memory key store), their long-term MLS signature keypair, and the
/// credential that binds a display name to that signature key.
///
/// In production the `OpenMlsRustCrypto` provider's key store should be
/// backed by the encrypted [`crate::storage::Vault`] rather than kept
/// in-memory only; wiring that persistence layer is the next milestone
/// after this in-memory version is verified correct.
pub struct MlsMember {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
}

impl MlsMember {
    /// Create a fresh MLS identity for a member with the given display
    /// name. `name` becomes a `BasicCredential` — Vault X does not use MLS's
    /// X.509 credential mode, since identities are hex device IDs, not
    /// certificate-issued names.
    pub fn new(name: &str) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(map_err)?;
        let credential = BasicCredential::new(name.as_bytes().to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self {
            provider,
            signer,
            credential_with_key,
        })
    }

    /// Build a `KeyPackage` this member can publish so others can add them
    /// to a group asynchronously (the MLS equivalent of a prekey bundle).
    pub fn key_package(&self) -> Result<KeyPackage> {
        Ok(KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .map_err(map_err)?
            .key_package()
            .clone())
    }
}

/// A Vault X group chat's MLS ratchet state for one member's device.
pub struct MlsGroupSession {
    group: MlsGroup,
}

impl MlsGroupSession {
    /// Create a brand-new group with `creator` as its sole initial member.
    pub fn create(creator: &MlsMember, group_id: &[u8]) -> Result<Self> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .build();
        let group = MlsGroup::new_with_group_id(
            &creator.provider,
            &creator.signer,
            &config,
            GroupId::from_slice(group_id),
            creator.credential_with_key.clone(),
        )
        .map_err(map_err)?;
        Ok(Self { group })
    }

    /// Add `new_members`' key packages to the group. Returns the MLS Commit
    /// (broadcast to existing members so they advance their tree state) and
    /// the Welcome message (sent privately to the new members so they can
    /// join). The commit is merged into `adder`'s own state before
    /// returning.
    /// `RatchetTree` isn't included in the Welcome message by default (Vault X
    /// doesn't enable the ratchet-tree extension, to keep Welcome messages
    /// small), so the exported tree must additionally be sent to new
    /// members out of band alongside the Welcome — see the third element of
    /// the returned tuple.
    pub fn add_members(
        &mut self,
        adder: &MlsMember,
        new_members: &[KeyPackage],
    ) -> Result<(MlsMessageOut, MlsMessageOut, RatchetTree)> {
        let (commit, welcome, _group_info) = self
            .group
            .add_members(&adder.provider, &adder.signer, new_members)
            .map_err(map_err)?;
        self.group
            .merge_pending_commit(&adder.provider)
            .map_err(map_err)?;
        let ratchet_tree = self.group.export_ratchet_tree();
        Ok((commit, welcome, ratchet_tree))
    }

    /// Join a group as a new member, given the Welcome message an existing
    /// member sent after adding you plus the ratchet tree they exported
    /// alongside it (see [`Self::add_members`]). The Welcome is
    /// round-tripped through its wire (`tls_codec`) serialization rather
    /// than converted in-memory, matching how it actually arrives over the
    /// relay.
    pub fn join_from_welcome(
        joiner: &MlsMember,
        welcome: MlsMessageOut,
        ratchet_tree: RatchetTree,
    ) -> Result<Self> {
        let bytes = welcome.tls_serialize_detached().map_err(map_err)?;
        let welcome_in = MlsMessageIn::tls_deserialize_exact(&bytes).map_err(map_err)?;
        let welcome = match welcome_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(VaultXError::Mls("expected a Welcome message".into())),
        };
        let join_config = MlsGroupJoinConfig::default();
        let group = StagedWelcome::new_from_welcome(
            &joiner.provider,
            &join_config,
            welcome,
            Some(ratchet_tree.into()),
        )
        .map_err(map_err)?
        .into_group(&joiner.provider)
        .map_err(map_err)?;
        Ok(Self { group })
    }

    /// Encrypt an application message under the group's current epoch keys.
    pub fn encrypt(&mut self, sender: &MlsMember, plaintext: &[u8]) -> Result<MlsMessageOut> {
        self.group
            .create_message(&sender.provider, &sender.signer, plaintext)
            .map_err(map_err)
    }

    /// Process an incoming MLS message. Application messages return their
    /// plaintext bytes; Commit messages are merged into this member's group
    /// state and `None` is returned (there is no application plaintext to
    /// surface for a commit).
    pub fn process(&mut self, receiver: &MlsMember, message: MlsMessageOut) -> Result<Option<Vec<u8>>> {
        let bytes = message.tls_serialize_detached().map_err(map_err)?;
        let message_in = MlsMessageIn::tls_deserialize_exact(&bytes).map_err(map_err)?;
        let protocol_message = message_in
            .try_into_protocol_message()
            .map_err(|_| VaultXError::Mls("not a protocol message".into()))?;
        let processed = self
            .group
            .process_message(&receiver.provider, protocol_message)
            .map_err(map_err)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => Ok(Some(app_msg.into_bytes())),
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.group
                    .merge_staged_commit(&receiver.provider, *staged_commit)
                    .map_err(map_err)?;
                Ok(None)
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                self.group
                    .store_pending_proposal(receiver.provider.storage(), *proposal)
                    .map_err(map_err)?;
                Ok(None)
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                self.group
                    .store_pending_proposal(receiver.provider.storage(), *proposal)
                    .map_err(map_err)?;
                Ok(None)
            }
        }
    }

    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_member_group_exchanges_application_messages() {
        let alice = MlsMember::new("alice").unwrap();
        let bob = MlsMember::new("bob").unwrap();

        let mut alice_group = MlsGroupSession::create(&alice, b"vaultx-test-group").unwrap();
        let bob_key_package = bob.key_package().unwrap();

        let (_commit, welcome, tree) = alice_group.add_members(&alice, &[bob_key_package]).unwrap();
        let mut bob_group = MlsGroupSession::join_from_welcome(&bob, welcome, tree).unwrap();

        assert_eq!(alice_group.member_count(), 2);
        assert_eq!(bob_group.member_count(), 2);

        let ciphertext = alice_group.encrypt(&alice, b"hello group").unwrap();
        let plaintext = bob_group.process(&bob, ciphertext).unwrap();
        assert_eq!(plaintext, Some(b"hello group".to_vec()));

        let reply = bob_group.encrypt(&bob, b"hi alice").unwrap();
        let plaintext = alice_group.process(&alice, reply).unwrap();
        assert_eq!(plaintext, Some(b"hi alice".to_vec()));
    }

    #[test]
    fn three_member_group_add_after_creation() {
        let alice = MlsMember::new("alice").unwrap();
        let bob = MlsMember::new("bob").unwrap();
        let carol = MlsMember::new("carol").unwrap();

        let mut alice_group = MlsGroupSession::create(&alice, b"vaultx-test-group-2").unwrap();
        let (_commit, welcome, tree) = alice_group
            .add_members(&alice, &[bob.key_package().unwrap()])
            .unwrap();
        let mut bob_group = MlsGroupSession::join_from_welcome(&bob, welcome, tree).unwrap();

        let (commit, welcome, tree) = alice_group
            .add_members(&alice, &[carol.key_package().unwrap()])
            .unwrap();
        // Bob must process the commit that added Carol to stay in sync.
        bob_group.process(&bob, commit).unwrap();
        let mut carol_group = MlsGroupSession::join_from_welcome(&carol, welcome, tree).unwrap();

        assert_eq!(alice_group.member_count(), 3);
        assert_eq!(bob_group.member_count(), 3);
        assert_eq!(carol_group.member_count(), 3);

        let ciphertext = carol_group.encrypt(&carol, b"hi from carol").unwrap();
        assert_eq!(
            alice_group.process(&alice, ciphertext.clone()).unwrap(),
            Some(b"hi from carol".to_vec())
        );
    }
}
