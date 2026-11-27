// murmur-core/src/pairing.rs — exposed to Kotlin/Swift via UniFFI.
use snow::{Builder, HandshakeState};
use std::sync::Mutex;

const PATTERN: &str = "Noise_XXpsk3_25519_ChaChaPoly_SHA256";

/// What the new device's QR code carries (§17.7). UniFFI records cannot hold
/// fixed-size arrays, so the 16-byte fingerprint crosses the boundary as bytes
/// and is checked here.
#[derive(uniffi::Record)]
pub struct QrPayload { pub rendezvous: String, pub psk: Vec<u8>,
    pub fingerprint: Vec<u8> }

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PairingError {
    #[error("handshake failed")] Handshake,
    #[error("malformed QR payload")] Malformed,
    #[error("handshake already finished")] Done,
    #[error("peer static key not received yet")] NoPeerKey,
    #[error("peer key does not match the QR fingerprint")] FingerprintMismatch,
}
impl From<snow::Error> for PairingError {
    // no detail: no oracle
    fn from(_: snow::Error) -> Self { PairingError::Handshake }
}

fn prologue(rendezvous: &str) -> Vec<u8> { [b"murmur-pairing/v1|".as_slice(),
    rendezvous.as_bytes()].concat() }
fn sha256(b: &[u8]) -> [u8; 32] { use sha2::Digest;
    sha2::Sha256::digest(b).into() }

/// Same derivation as Listing 17.4's Python: HKDF-SHA256(handshake hash), 4
/// bytes, mod 10^6.
fn sas_from(h: &[u8]) -> String {
    let mut d = [0u8; 4];
    hkdf::Hkdf::<sha2::Sha256>::new(None, h).expand(b"murmur pairing SAS v1",
        &mut d).expect("4 bytes");
    let n = u32::from_be_bytes(d) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

#[derive(uniffi::Object)]
pub struct Pairing { hs: Mutex<Option<HandshakeState>>, expected_fp: Option<[u8;
    16]> }

#[uniffi::export]
impl Pairing {
    /// Existing device: scanned the QR code (rendezvous id, psk, fingerprint of
    /// the new device's key).
    #[uniffi::constructor]
    pub fn initiator(static_key: Vec<u8>, qr: QrPayload) -> Result<Self,
        PairingError> {
        let psk: [u8;
            32] = qr.psk.as_slice().try_into().map_err(
            |_| PairingError::Malformed)?;
        let fp: [u8;
            16] = qr.fingerprint.as_slice().try_into().map_err(
            |_| PairingError::Malformed)?;
        let hs = Builder::new(PATTERN.parse()?)
            // from the Keystore/Keychain-wrapped store
            .local_private_key(&static_key)?
            // one-time secret from the QR code
            .psk(3, &psk)?
            // "murmur-pairing/v1|" + rendezvous id
            .prologue(&prologue(&qr.rendezvous))?
            .build_initiator()?;
        Ok(Self { hs: Mutex::new(Some(hs)), expected_fp: Some(fp) })
    }

    /// Writes the next handshake message (payload may be empty).
    pub fn write(&self, payload: Vec<u8>) -> Result<Vec<u8>, PairingError> {
        let mut g = self.hs.lock().unwrap();
        let mut buf = vec![0u8; 65535];
        let n = g.as_mut().ok_or(PairingError::Done)?.write_message(&payload,
            &mut buf)?;
        buf.truncate(n); Ok(buf)
    }

    /// Reads a handshake message. After message 2 the initiator MUST call
    /// `verify_peer` before writing message 3 (which carries account data).
    pub fn read(&self, msg: Vec<u8>) -> Result<Vec<u8>, PairingError> {
        let mut g = self.hs.lock().unwrap();
        let mut buf = vec![0u8; 65535];
        let n = g.as_mut().ok_or(PairingError::Done)?.read_message(&msg,
            &mut buf)?;
        buf.truncate(n); Ok(buf)
    }

    pub fn verify_peer(&self) -> Result<(), PairingError> {
        let g = self.hs.lock().unwrap();
        let rs = g.as_ref().and_then(|h| h.get_remote_static()).ok_or(
            PairingError::NoPeerKey)?;
        match self.expected_fp {
            Some(fp) if sha256(rs)[..16] == fp => Ok(()),
            // abort: wrong device
            Some(_) => Err(PairingError::FingerprintMismatch),
            None => Ok(()),
        }
    }

    /// Six-digit short authentication string from the handshake hash (§17.7).
    pub fn sas(&self) -> Result<String, PairingError> {
        let g = self.hs.lock().unwrap();
        Ok(sas_from(g.as_ref().ok_or(PairingError::Done)?.get_handshake_hash()))
    }
}
