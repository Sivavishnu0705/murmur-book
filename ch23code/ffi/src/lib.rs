// lib.rs
//! Listing 23.4 — Rust + UniFFI (proc-macro): Murmur's MLS wrapper. The Kotlin
//! and Swift apps see only this narrow, byte-oriented interface; all MLS state
//! machines stay in Rust. (Here the storage provider is OpenMLS's in-memory
//! one; Murmur's implements OpenMLS's StorageProvider trait over the SQLCipher
//! database, with the transaction rules of Ch 19 §19.9.)
use std::sync::{Arc, Mutex};

use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

uniffi::setup_scaffolding!();

const CS: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MlsError {
    #[error("invalid input: {msg}")]
    Invalid { msg: String },
    #[error("no active group")]
    NoGroup,
}
fn inv<E: std::fmt::Debug>(e: E) -> MlsError { MlsError::Invalid { msg: format!(
    "{e:?}") } }

#[derive(uniffi::Record)]
pub struct CommitOutput { pub commit: Vec<u8>, pub welcome: Option<Vec<u8>> }

#[derive(uniffi::Enum)]
pub enum Processed {
    Application { sender: Vec<u8>, plaintext: Vec<u8> },
    CommitMerged { epoch: u64 },
    Other,
}

struct State {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    cred: CredentialWithKey,
    group: Option<MlsGroup>,
}

#[derive(uniffi::Object)]
// one mutex: MLS group state is never touched concurrently
pub struct MurmurMls { s: Mutex<State> }

#[uniffi::export]
impl MurmurMls {
    /// `identity` is the device's credential content (account + device ID, Ch
    /// 20).
    #[uniffi::constructor]
    pub fn new(identity: Vec<u8>) -> Result<Arc<Self>, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CS.signature_algorithm()).map_err(
            inv)?;
        signer.store(provider.storage()).map_err(inv)?;
        let cred = CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: signer.public().into(),
        };
        Ok(Arc::new(Self { s: Mutex::new(State { provider, signer, cred,
            group: None }) }))
    }

    /// Serialized KeyPackage (as an MlsMessage) for the DS directory.
    pub fn key_package(&self) -> Result<Vec<u8>, MlsError> {
        let s = self.s.lock().unwrap();
        let bundle = KeyPackage::builder().build(CS, &s.provider, &s.signer,
            s.cred.clone()).map_err(inv)?;
        MlsMessageOut::from(
            bundle.key_package().clone()).tls_serialize_detached().map_err(inv)
    }

    pub fn create_group(&self) -> Result<Vec<u8>, MlsError> {
        let mut s = self.s.lock().unwrap();
        let cfg = MlsGroupCreateConfig::builder().ciphersuite(
            CS).use_ratchet_tree_extension(true).build();
        let g = MlsGroup::new(&s.provider, &s.signer, &cfg,
            s.cred.clone()).map_err(inv)?;
        let id = g.group_id().as_slice().to_vec();
        s.group = Some(g);
        Ok(id)
    }

    /// Add a member from its KeyPackage. The commit is MERGED only after the DS
    /// accepts it: call `merge_pending` on success, `clear_pending` on a 409
    /// (§23.8).
    pub fn add_member(&self, key_package: Vec<u8>) -> Result<CommitOutput,
        MlsError> {
        let mut st = self.s.lock().unwrap();
        let s = &mut *st;
        let MlsMessageBodyIn::KeyPackage(kp) = MlsMessageIn::tls_deserialize(
            &mut &key_package[..]).map_err(inv)?.extract()
        else { return Err(MlsError::Invalid {
            msg: "not a KeyPackage".into() }) };
        // validate(): signature, ciphersuite, lifetime — then the AS check of
        // the credential against the account's verified device list happens in
        // the caller before this point.
        let kp = kp.validate(s.provider.crypto(),
            ProtocolVersion::Mls10).map_err(inv)?;
        let g = s.group.as_mut().ok_or(MlsError::NoGroup)?;
        let (commit, welcome, _) = g.add_members(&s.provider, &s.signer,
            &[kp]).map_err(inv)?;
        Ok(CommitOutput { commit: commit.tls_serialize_detached().map_err(inv)?,
                          welcome: Some(
                          welcome.tls_serialize_detached().map_err(inv)?) })
    }

    pub fn self_update(&self) -> Result<CommitOutput, MlsError> {
        let mut st = self.s.lock().unwrap();
        let s = &mut *st;
        let g = s.group.as_mut().ok_or(MlsError::NoGroup)?;
        let b = g.self_update(&s.provider, &s.signer,
            LeafNodeParameters::default()).map_err(inv)?;
        Ok(CommitOutput { commit: b.commit().tls_serialize_detached().map_err(
            inv)?, welcome: None })
    }

    pub fn merge_pending(&self) -> Result<u64, MlsError> {
        let mut st = self.s.lock().unwrap();
        let s = &mut *st;
        let g = s.group.as_mut().ok_or(MlsError::NoGroup)?;
        g.merge_pending_commit(&s.provider).map_err(inv)?;
        Ok(g.epoch().as_u64())
    }

    pub fn clear_pending(&self) -> Result<(), MlsError> {
        let mut st = self.s.lock().unwrap();
        let s = &mut *st;
        let g = s.group.as_mut().ok_or(MlsError::NoGroup)?;
        g.clear_pending_commit(s.provider.storage()).map_err(inv)
    }

    pub fn join(&self, welcome: Vec<u8>) -> Result<u64, MlsError> {
        let mut st = self.s.lock().unwrap();
        let s = &mut *st;
        let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize(
            &mut &welcome[..]).map_err(inv)?.extract()
        else { return Err(MlsError::Invalid { msg: "not a Welcome".into() }) };
        let g = StagedWelcome::new_from_welcome(&s.provider,
            &MlsGroupJoinConfig::default(), w, None)
            .map_err(inv)?.into_group(&s.provider).map_err(inv)?;
        let e = g.epoch().as_u64();
        s.group = Some(g);
        Ok(e)
    }

    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        let mut st = self.s.lock().unwrap();
        let s = &mut *st;
        let g = s.group.as_mut().ok_or(MlsError::NoGroup)?;
        g.create_message(&s.provider, &s.signer, &plaintext).map_err(inv)?
            .tls_serialize_detached().map_err(inv)
    }

    /// Process anything the DS delivers. Commits are verified (signature,
    /// confirmation tag, path secrets) and merged; application messages are
    /// decrypted with the secret tree.
    pub fn process(&self, wire: Vec<u8>) -> Result<Processed, MlsError> {
        let mut st = self.s.lock().unwrap();
        let s = &mut *st;
        let g = s.group.as_mut().ok_or(MlsError::NoGroup)?;
        let pm = MlsMessageIn::tls_deserialize(&mut &wire[..]).map_err(inv)?
            .try_into_protocol_message().map_err(inv)?;
        let msg = g.process_message(&s.provider, pm).map_err(inv)?;
        let sender = msg.credential().serialized_content().to_vec();
        Ok(match msg.into_content() {
            ProcessedMessageContent::ApplicationMessage(
            a) => Processed::Application { sender, plaintext: a.into_bytes() },
            ProcessedMessageContent::StagedCommitMessage(sc) => {
                g.merge_staged_commit(&s.provider, *sc).map_err(inv)?;
                Processed::CommitMerged { epoch: g.epoch().as_u64() }
            }
            _ => Processed::Other,
        })
    }

    /// Shown to users for out-of-band comparison ("group safety code"), and
    /// compared by clients to detect forks (§23.7).
    pub fn epoch_authenticator(&self) -> Result<Vec<u8>, MlsError> {
        let s = self.s.lock().unwrap();
        Ok(s.group.as_ref().ok_or(
            MlsError::NoGroup)?.epoch_authenticator().as_slice().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn two_devices_through_the_wrapper() {
        let a = MurmurMls::new(b"alice/1".to_vec()).unwrap();
        let b = MurmurMls::new(b"bob/1".to_vec()).unwrap();
        a.create_group().unwrap();
        let out = a.add_member(b.key_package().unwrap()).unwrap();
        // DS accepted the commit
        a.merge_pending().unwrap();
        b.join(out.welcome.unwrap()).unwrap();
        assert_eq!(a.epoch_authenticator().unwrap(),
            b.epoch_authenticator().unwrap());
        let ct = a.encrypt(b"hi bob".to_vec()).unwrap();
        match b.process(ct).unwrap() {
            Processed::Application { sender, plaintext } => {
                assert_eq!(sender, b"alice/1"); assert_eq!(plaintext,
                    b"hi bob");
            }
            _ => panic!("expected application message"),
        }
        let upd = b.self_update().unwrap();
        b.merge_pending().unwrap();
        assert!(matches!(a.process(upd.commit).unwrap(),
            Processed::CommitMerged { epoch: 2 }));
        assert_eq!(a.epoch_authenticator().unwrap(),
            b.epoch_authenticator().unwrap());
    }
}
