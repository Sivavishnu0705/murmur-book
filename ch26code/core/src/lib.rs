// lib.rs
//! Listing 26.2 — Rust: murmur-core's UniFFI interface (signatures only; implementations are the
//! subject of Chapters 27–30). Everything crossing the boundary is bytes, strings, records and
//! enums: no key material leaves Rust except public keys and encrypted envelopes.
use std::sync::Arc;
uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("malformed input")] Malformed,
    #[error("decryption failed")] DecryptionFailed,          // uniform: no oracle (spec §26.3)
    #[error("identity key changed for {device}")] IdentityChanged { device: String },
    #[error("untrusted device list")] UntrustedDeviceList,
    #[error("storage: {msg}")] Storage { msg: String },
    #[error("stale epoch")] StaleEpoch,
}

#[derive(uniffi::Record)] pub struct Decrypted { pub sender_account: String, pub sender_device: String, pub content: Vec<u8>, pub server_guid: Vec<u8> }
#[derive(uniffi::Record)] pub struct Outgoing { pub recipient_device: String, pub envelope: Vec<u8> }
#[derive(uniffi::Record)] pub struct KeyUpload { pub request: Vec<u8> }          // IdentityKeyUpload protobuf
#[derive(uniffi::Enum)] pub enum Trust { Unverified, Verified, ChangedUnverified, ChangedFromVerified }

#[derive(uniffi::Object)]
pub struct MurmurCore;

#[uniffi::export]
impl MurmurCore {
    /// Opens the SQLCipher database (canonical storage stack). `db_key` comes from the Keychain
    /// (iOS) or is unwrapped by the Keystore (Android); the core never stores it.
    #[uniffi::constructor]
    pub fn open(db_path: String, db_key: Vec<u8>, account: String, device: String) -> Result<Arc<Self>, CoreError> { let _ = (db_path, db_key, account, device); unimplemented!() }

    // ── device identity and prekeys (Ch 18, 24) ──
    /// New identity key + signed/one-time/PQ prekeys; returns the bound upload statement for the
    /// given TLS exporter, signed with the DPoP key via the platform callback.
    pub fn prepare_key_upload(&self, tls_exporter: Vec<u8>, dpop: Arc<dyn PlatformSigner>) -> Result<KeyUpload, CoreError> { let _ = (tls_exporter, dpop); unimplemented!() }
    pub fn replenish_prekeys(&self, count: u32) -> Result<Vec<u8>, CoreError> { let _ = count; unimplemented!() }

    // ── device lists and trust (Ch 20) ──
    pub fn accept_device_list(&self, account: String, signed_list: Vec<u8>) -> Result<Vec<String>, CoreError> { let _ = (account, signed_list); unimplemented!() }
    pub fn sign_device_list_adding(&self, new_device: String, identity_key: Vec<u8>) -> Result<Vec<u8>, CoreError> { let _ = (new_device, identity_key); unimplemented!() }
    pub fn safety_number(&self, account: String) -> Result<String, CoreError> { let _ = account; unimplemented!() }
    pub fn trust(&self, account: String) -> Trust { let _ = account; unimplemented!() }
    pub fn mark_verified(&self, account: String, scanned_qr: Vec<u8>) -> Result<bool, CoreError> { let _ = (account, scanned_qr); unimplemented!() }

    // ── 1:1 messaging (Ch 18, 19, 21) ──
    /// Fan-out (Ch 20): one Outgoing per verified recipient device and per own other device;
    /// starts PQXDH sessions from bundles where needed. Persists sending state BEFORE returning.
    pub fn encrypt_to_account(&self, account: String, content: Vec<u8>, bundles: Vec<Vec<u8>>) -> Result<Vec<Outgoing>, CoreError> { let _ = (account, content, bundles); unimplemented!() }
    /// Decrypt + persist in ONE IMMEDIATE transaction (Ch 19 §19.9); ack only after this returns.
    pub fn decrypt(&self, envelope: Vec<u8>) -> Result<Decrypted, CoreError> { let _ = envelope; unimplemented!() }

    // ── attachments (Ch 21) ──
    pub fn encrypt_attachment(&self, src_path: String, dst_path: String) -> Result<Vec<u8>, CoreError> { let _ = (src_path, dst_path); unimplemented!() }
    pub fn decrypt_attachment(&self, pointer: Vec<u8>, src_path: String, dst_tmp_path: String) -> Result<(), CoreError> { let _ = (pointer, src_path, dst_tmp_path); unimplemented!() }
}

/// Implemented in Kotlin/Swift: signs with a hardware key the core never sees
/// (Keystore/StrongBox P-256 or Secure Enclave), for DPoP and attestation-bound statements.
#[uniffi::export(with_foreign)]
pub trait PlatformSigner: Send + Sync {
    fn public_key(&self) -> Vec<u8>;
    fn sign(&self, message: Vec<u8>) -> Vec<u8>;
}
// Groups: the MurmurMls object of Listing 23.4 is exported from the same crate.
