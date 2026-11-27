// ── Chapter 29 changes to Listing 26.2's interface (signatures; Listing 29.2
// is the same logic, executable). `open` now takes Chapter 28's wrap callback;
// `decrypt` reports what happened; the outbox and session-reset calls below are
// what the pipelines (Listings 29.3, 29.4) use. CoreError is now one enum:
// Listing 26.2's cases, Listing 28.3's KeyUnavailable, Exists and Network, and
// KeyChangeBlocked { account } (a verified contact's key changed). ──
#[derive(uniffi::Enum)]
// replaces Listing 26.2's Decrypted record
pub enum Decrypted {
    // committed to the core inbox
    Message { sender: String, text: String, client_message_id: String },
    // already processed (by the NSE, or a redelivery)
    Duplicate,
    // failure recorded; a session reset is scheduled (§29.7)
    Undecryptable { sender: String },
    // session reset, delivery receipt: handled in the core
    Control,
}

/// One committed outbox entry: the envelopes are fixed, so a retry never
/// re-encrypts.
#[derive(uniffi::Record)]
pub struct OutboxRow { pub id: i64, pub account: String, pub sealed: bool,
    pub delivery_token: Vec<u8>, pub envelopes: HashMap<String, Vec<u8>> }

/// Implemented by the app's API client, for session resets and re-sends
/// (§29.7). Chapter 29's MurmurApiClient adds sendSealed, fetchMessages,
/// deviceList and ack to Listing 28.12's call().
#[uniffi::export(with_foreign)]
pub trait ResetTransport: Send + Sync {
    fn fetch_bundles(&self, account: String) -> Result<Vec<Vec<u8>>, CoreError>;
    fn send(&self, account: String, envelopes: HashMap<String,
        Vec<u8>>) -> Result<(), CoreError>;
}

#[uniffi::export]
impl MurmurCore {
    #[uniffi::constructor]
    pub fn open(db_path: String, db_key: Vec<u8>,
        wrap: Arc<dyn PlatformKeyWrap>) -> Result<Arc<Self>,
        CoreError> { let _ = (db_path, db_key, wrap); unimplemented!() }
    // before an extension is suspended (§29.5)
    pub fn close_database(&self) { unimplemented!() }
    pub fn unread_count(&self) -> Result<u32, CoreError> { unimplemented!() }
    pub fn enqueue_outgoing(&self, account: String,
        content: Vec<u8>) -> Result<(), CoreError> { let _ = (account, content);
        unimplemented!() }
    pub fn pending_outbox(&self) -> Result<Vec<OutboxRow>,
        CoreError> { unimplemented!() }
    pub fn outbox_delivered(&self, id: i64) -> Result<(),
        CoreError> { let _ = id; unimplemented!() }
    pub fn outbox_use_identified_route(&self, id: i64) -> Result<(),
        CoreError> { let _ = id; unimplemented!() }
    /// §29.3: keeps envelopes for devices still listed, encrypts only for new
    /// ones.
    pub fn repair_fanout(&self, id: i64,
        signed_list: Vec<u8>) -> Result<HashMap<String, Vec<u8>>,
        CoreError> { let _ = (id, signed_list); unimplemented!() }
    pub fn run_pending_resets(&self,
        transport: Arc<dyn ResetTransport>) -> Result<(),
        CoreError> { let _ = transport; unimplemented!() }
    pub fn qr_payload(&self, account: String) -> Vec<u8> { let _ = account;
        unimplemented!() }
    pub fn acknowledge_key_change(&self, account: String) { let _ = account;
        unimplemented!() }
}
