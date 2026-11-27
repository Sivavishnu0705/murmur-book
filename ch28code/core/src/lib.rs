// lib.rs
//! Listing 28.3 — Rust: murmur-core's identity-key creation with a platform
//! wrapping callback. X25519 keys cannot be generated in StrongBox or the
//! Secure Enclave (neither supports the curve), so the core generates them in
//! software and IMMEDIATELY hands them to the platform's hardware key for
//! wrapping. Only the wrapped blob is stored; the plaintext copy is zeroized.
use std::{collections::HashMap, sync::{Arc, Mutex}};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;
uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    // e.g. KeyPermanentlyInvalidatedException
    #[error("hardware key unavailable")] KeyUnavailable,
    #[error("storage: {msg}")] Storage { msg: String },
    #[error("identity already exists")] Exists,
    // from the platform API client
    #[error("network: {msg}")] Network { msg: String },
}

/// Implemented in Kotlin (Keystore/StrongBox AES-256-GCM key, Listing 28.4) and
/// Swift (Secure Enclave P-256 key with ECIES, Listing 28.5). The label is
/// authenticated data, so a blob wrapped for one purpose cannot be unwrapped as
/// another.
#[uniffi::export(with_foreign)]
pub trait PlatformKeyWrap: Send + Sync {
    fn wrap(&self, label: String, secret: Vec<u8>) -> Result<Vec<u8>,
        CoreError>;
    fn unwrap(&self, label: String, blob: Vec<u8>) -> Result<Vec<u8>,
        CoreError>;
}

const IK_LABEL: &str = "murmur/v1/identity-key-wrap/device_identity";

#[derive(uniffi::Object)]
pub struct MurmurCore {
    wrap: Arc<dyn PlatformKeyWrap>,
    // Stand-in for the SQLCipher `identity` table (rusqlite + SQLCipher in the
    // full core).
    // name → (public, wrapped private)
    table: Mutex<HashMap<String, (Vec<u8>, Vec<u8>)>>,
}

#[uniffi::export]
impl MurmurCore {
    #[uniffi::constructor]
    pub fn new(wrap: Arc<dyn PlatformKeyWrap>) -> Arc<Self> {
        Arc::new(MurmurCore { wrap, table: Mutex::new(HashMap::new()) })
    }

    /// Creates the device identity key once. Returns the public key for upload
    /// (Listing 27.4).
    pub fn create_identity(&self) -> Result<Vec<u8>, CoreError> {
        let mut t = self.table.lock().unwrap();
        if t.contains_key("device_identity") {
            // Murmur never replaces an identity key (Ch 27 §27.3)
            return Err(CoreError::Exists);
        }
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).as_bytes().to_vec();
        // wiped on drop, even on the error path
        let raw = Zeroizing::new(secret.to_bytes());
        let wrapped = self.wrap.wrap(IK_LABEL.into(), raw.to_vec())?;
        t.insert("device_identity".into(), (public.clone(), wrapped));
        // `secret` (ZeroizeOnDrop in x25519-dalek) and `raw` are wiped here
        Ok(public)
    }

    /// Used for each DH with the identity key; the unwrapped key lives only for
    /// the operation.
    pub fn identity_dh(&self, peer_public: Vec<u8>) -> Result<Vec<u8>,
        CoreError> {
        let (_,
            wrapped) = self.table.lock().unwrap().get(
            "device_identity").cloned().ok_or(CoreError::KeyUnavailable)?;
        let raw = Zeroizing::new(self.wrap.unwrap(IK_LABEL.into(), wrapped)?);
        let bytes: [u8;
            32] = raw.as_slice().try_into().map_err(
            |_| CoreError::KeyUnavailable)?;
        let secret = StaticSecret::from(bytes);
        let peer: [u8;
            32] = peer_public.try_into().map_err(|_| CoreError::Storage {
            msg: "bad key".into() })?;
        Ok(secret.diffie_hellman(&PublicKey::from(peer)).as_bytes().to_vec())
    }

    pub fn stored_blob(&self) -> Option<Vec<u8>> {
        self.table.lock().unwrap().get("device_identity").map(|(_,
            w)| w.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};

    /// Test double for the hardware key: AES-256-GCM with the label as AAD; can
    /// be "deleted".
    struct FakeHardware { key: Mutex<Option<[u8; 32]>> }
    impl PlatformKeyWrap for FakeHardware {
        fn wrap(&self, label: String, secret: Vec<u8>) -> Result<Vec<u8>,
            CoreError> {
            let k = self.key.lock().unwrap().ok_or(CoreError::KeyUnavailable)?;
            let mut n = [0u8; 12];
            // fresh nonce per wrap
            rand_core::RngCore::fill_bytes(&mut OsRng, &mut n);
            let mut out = n.to_vec();
            out.extend(Aes256Gcm::new(&k.into()).encrypt(Nonce::from_slice(&n),
                Payload { msg: &secret, aad: label.as_bytes() }).unwrap());
            Ok(out)
        }
        fn unwrap(&self, label: String, blob: Vec<u8>) -> Result<Vec<u8>,
            CoreError> {
            let k = self.key.lock().unwrap().ok_or(CoreError::KeyUnavailable)?;
            Aes256Gcm::new(&k.into()).decrypt(Nonce::from_slice(&blob[..12]),
                Payload { msg: &blob[12..], aad: label.as_bytes() })
                .map_err(|_| CoreError::KeyUnavailable)
        }
    }

    #[test]
    fn identity_is_stored_only_wrapped_and_dies_with_the_hardware_key() {
        let hw = Arc::new(FakeHardware { key: Mutex::new(Some([42u8; 32])) });
        let core = MurmurCore::new(hw.clone());
        let ik_pub = core.create_identity().unwrap();
        let blob = core.stored_blob().unwrap();
        println!(
            "identity public key {} B; stored blob {} B (nonce 12 + \
            ciphertext 32 + tag 16)", ik_pub.len(), blob.len());
        assert_eq!(blob.len(), 12 + 32 + 16);
        assert!(matches!(core.create_identity(), Err(CoreError::Exists)));

        // DH through the wrapped key equals DH computed by the peer.
        let peer = StaticSecret::random_from_rng(OsRng);
        let ours = core.identity_dh(PublicKey::from(
            &peer).as_bytes().to_vec()).unwrap();
        let theirs = peer.diffie_hellman(&PublicKey::from(<[u8;
            32]>::try_from(ik_pub).unwrap()));
        assert_eq!(ours, theirs.as_bytes().to_vec());
        println!(
            "DH through the wrapped identity key matches the peer's: true");

        // A blob unwrapped under a different label fails (AAD binding).
        assert!(hw.unwrap("murmur/v1/db-key-wrap".into(), blob).is_err());
        println!("unwrap under another label: rejected");

        // Remote wipe: delete the hardware key, and the stored blob is useless.
        *hw.key.lock().unwrap() = None;
        assert!(matches!(core.identity_dh(vec![9u8; 32]),
            Err(CoreError::KeyUnavailable)));
        println!(
            "after the hardware key is deleted: identity_dh → KeyUnavailable");
    }
}
