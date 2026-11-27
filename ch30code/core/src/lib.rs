// lib.rs
//! Listing 30.1 — Rust: Murmur's MLS wrapper API (murmur-core, groups). It
//! grows Chapter 23's single-group wrapper (Listing 23.4) into what the apps
//! need: · many groups per device, PERSISTED through a platform `MlsStore` (the
//! SQLCipher `mls_kv` table): every state change is written as one atomic batch
//! before the call returns; · Murmur's Authentication Service check on every
//! credential the device ever accepts — the device must be in its account's
//! AIK-signed list, and that device's identity key must have signed the MLS
//! signature key; · admin roles in a group context extension, enforced on every
//! commit by every member; · DS-ordered commits: nothing is merged before the
//! DS accepts it (merge / clear pending). Kotlin and Swift (and the lab's
//! Python) see only bytes, strings and the records below.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

uniffi::setup_scaffolding!();

const CS: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
// private-use extension type: the group's admin accounts
const ADMINS_EXT: u16 = 0xff00;
const BINDING_LABEL: &[u8] = b"murmur/v1/mls-credential";

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum GroupError {
    #[error("invalid input: {msg}")]
    Invalid { msg: String },
    #[error("unknown group")]
    NoGroup,
    #[error("not authorized: {msg}")]
    NotAuthorized { msg: String },
    #[error("storage: {msg}")]
    Storage { msg: String },
}
fn inv<E: std::fmt::Debug>(e: E) -> GroupError { GroupError::Invalid {
    msg: format!("{e:?}") } }

#[derive(uniffi::Record, Clone)]
pub struct Kv { pub key: Vec<u8>, pub value: Vec<u8> }

/// Implemented by the platform over SQLCipher (`core.db`, table `mls_kv`).
/// `commit` MUST apply all puts and deletes in ONE transaction (BEGIN IMMEDIATE
/// … COMMIT), or none of them.
#[uniffi::export(with_foreign)]
pub trait MlsStore: Send + Sync {
    fn load_all(&self) -> Vec<Kv>;
    fn commit(&self, puts: Vec<Kv>, deletes: Vec<Vec<u8>>) -> Result<(),
        GroupError>;
}

/// The AS, from the app's verified state: the identity key of (account, device)
/// if — and only if — that device is in the account's AIK-signed device list
/// the app has verified (Ch 20).
#[uniffi::export(with_foreign)]
pub trait IdentityDirectory: Send + Sync {
    fn identity_key(&self, account: String, device: String) -> Option<Vec<u8>>;
}

/// Signs with this device's identity key (XEdDSA, Ch 18) — the key lives with
/// the platform.
#[uniffi::export(with_foreign)]
pub trait CredentialBinder: Send + Sync {
    fn bind(&self, message: Vec<u8>) -> Vec<u8>;
}

#[derive(uniffi::Record)]
pub struct CommitOutput { pub commit: Vec<u8>, pub welcome: Option<Vec<u8>>,
    pub epoch: u64 }

#[derive(uniffi::Enum)]
pub enum Processed {
    Application { group_id: Vec<u8>, sender: String, plaintext: Vec<u8> },
    CommitMerged { group_id: Vec<u8>, epoch: u64, added: Vec<String>,
        removed: Vec<String> },
    RemovedFromGroup { group_id: Vec<u8> },
    ProposalStored { group_id: Vec<u8>, from: String },
    Rejected { group_id: Vec<u8>, reason: String },
}

// ── credentials: account ‖ device ‖ XEdDSA(IK, Framed(label, account, device,
// sig_key)) ──
fn framed(label: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut b = (label.len() as u16).to_be_bytes().to_vec();
    b.extend_from_slice(label);
    for f in fields {
        b.extend_from_slice(&(f.len() as u32).to_be_bytes());
        b.extend_from_slice(f);
    }
    b
}

fn encode_identity(account: &str, device: &str, binding: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    for s in [account.as_bytes(), device.as_bytes()] {
        b.extend_from_slice(&(s.len() as u16).to_be_bytes());
        b.extend_from_slice(s);
    }
    b.extend_from_slice(binding);
    b
}

fn decode_identity(id: &[u8]) -> Option<(String, String, [u8; 64])> {
    let mut i = 0;
    let mut next = || -> Option<String> {
        let n = u16::from_be_bytes(id.get(i..i + 2)?.try_into().ok()?) as usize;
        let s = String::from_utf8(id.get(i + 2..i + 2 + n)?.to_vec()).ok()?;
        i += 2 + n;
        Some(s)
    };
    let (a, d) = (next()?, next()?);
    if a.is_empty() || d.is_empty() || a.contains('/') || d.contains('/') {
        // names are compared as "account/device": no empty or ambiguous parts
        return None;
    }
    // EXACTLY 64 bytes remain: trailing data → None
    let sig: [u8; 64] = id.get(i..)?.try_into().ok()?;
    Some((a, d, sig))
}

/// XEdDSA verification (as Listing 18.3's Go version): the X25519 key converted
/// to Ed25519 with sign bit 0, then ordinary Ed25519 verification.
fn xeddsa_verify(x_pub: &[u8], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(x): Result<[u8; 32], _> = x_pub.try_into() else { return false };
    let Some(ed) = MontgomeryPoint(x).to_edwards(0) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&ed.compress().to_bytes()) else {
        return false };
    vk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

struct Inner {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    cred: CredentialWithKey,
    account: String,
    groups: HashMap<Vec<u8>, MlsGroup>,
    persisted: HashMap<Vec<u8>, Vec<u8>>, // what the store holds now
}

#[derive(uniffi::Object)]
pub struct MurmurGroups {
    // one lock: MLS state is never touched concurrently in-process
    inner: Mutex<Inner>,
    store: Arc<dyn MlsStore>,
    directory: Arc<dyn IdentityDirectory>,
}

const META_SIGNER: &[u8] = b"\x01signer";
const META_IDENTITY: &[u8] = b"\x01identity";
const META_GROUPS: &[u8] = b"\x01groups";

fn caps() -> Capabilities {
    // LastResort must be listed for a last-resort KeyPackage to validate (RFC
    // 9420 §13.4).
    Capabilities::new(None, Some(&[CS]),
        Some(&[ExtensionType::Unknown(ADMINS_EXT), ExtensionType::LastResort]),
        None, None)
}

impl Inner {
    /// Everything that must be durable: OpenMLS's storage map (prefix 0x00) +
    /// our metadata.
    fn snapshot(&self) -> HashMap<Vec<u8>, Vec<u8>> {
        let mut m: HashMap<Vec<u8>, Vec<u8>> =
            self.provider.storage().values.read().unwrap().iter().map(|(k,
                v)| ([&[0u8][..], k].concat(), v.clone())).collect();
        m.insert(META_SIGNER.to_vec(), self.signer.public().to_vec());
        m.insert(META_IDENTITY.to_vec(),
            self.cred.credential.serialized_content().to_vec());
        let mut ids = Vec::new();
        let mut keys: Vec<_> = self.groups.keys().collect();
        keys.sort();
        for g in keys {
            ids.extend_from_slice(&(g.len() as u16).to_be_bytes());
            ids.extend_from_slice(g);
        }
        m.insert(META_GROUPS.to_vec(), ids);
        m
    }
}

impl MurmurGroups {
    /// Write the difference since the last persist as ONE batch. If the store
    /// fails, undo the in-memory change too, so memory never runs ahead of
    /// disk.
    fn persist(&self, s: &mut Inner) -> Result<(), GroupError> {
        let now = s.snapshot();
        let puts: Vec<Kv> = now.iter().filter(|(k,
            v)| s.persisted.get(*k) != Some(*v))
            .map(|(k, v)| Kv { key: k.clone(), value: v.clone() }).collect();
        let deletes: Vec<Vec<u8>> = s.persisted.keys().filter(
            |k| !now.contains_key(*k)).cloned().collect();
        if puts.is_empty() && deletes.is_empty() {
            return Ok(());
        }
        match self.store.commit(puts, deletes) {
            Ok(()) => { s.persisted = now; Ok(()) }
            Err(e) => { Self::restore(s); Err(e) }
        }
    }

    fn restore(s: &mut Inner) {
        let openmls: HashMap<Vec<u8>, Vec<u8>> =
            s.persisted.iter().filter(|(k, _)| k[0] == 0).map(|(k,
                v)| (k[1..].to_vec(), v.clone())).collect();
        *s.provider.storage().values.write().unwrap() = openmls;
        let ids: Vec<Vec<u8>> = s.groups.keys().cloned().collect();
        s.groups.clear();
        for id in ids {
            if let Ok(Some(g)) = MlsGroup::load(s.provider.storage(),
                &GroupId::from_slice(&id)) {
                s.groups.insert(id, g);
            }
        }
    }

    /// The AS check: credential → (account, device) → identity key from the
    /// VERIFIED device list → XEdDSA binding over this leaf's signature key.
    fn authenticate(&self, cred: &Credential, sig_key: &[u8]) -> Result<(String,
        String), String> {
        let (account, device,
            sig) = decode_identity(cred.serialized_content()).ok_or(
            "malformed credential")?;
        let ik = self.directory.identity_key(account.clone(), device.clone())
            .ok_or_else(
                || format!("{account}/{device} is not in {account}'s \
                verified device list"))?;
        let msg = framed(BINDING_LABEL, &[account.as_bytes(), device.as_bytes(),
            sig_key]);
        if !xeddsa_verify(&ik, &msg, &sig) {
            return Err(format!(
                "{account}/{device}: MLS key not signed by the device \
                identity key"));
        }
        Ok((account, device))
    }

    fn admins(g: &MlsGroup) -> Vec<String> {
        g.extensions().unknown(ADMINS_EXT).map(|u| {
            String::from_utf8_lossy(&u.0).split('\n').filter(
            |s| !s.is_empty()).map(String::from).collect()
        }).unwrap_or_default()
    }

    fn name_of(m: &Member) -> String {
        decode_identity(m.credential.serialized_content()).map(|(a, d,
            _)| format!("{a}/{d}")).unwrap_or_default()
    }
}

#[uniffi::export]
impl MurmurGroups {
    /// Opens (or creates) this device's MLS state from the store.
    #[uniffi::constructor]
    pub fn open(account: String, device: String, store: Arc<dyn MlsStore>,
        directory: Arc<dyn IdentityDirectory>,
        binder: Arc<dyn CredentialBinder>) -> Result<Arc<Self>, GroupError> {
        let provider = OpenMlsRustCrypto::default();
        let saved: HashMap<Vec<u8>,
            Vec<u8>> = store.load_all().into_iter().map(|kv| (kv.key,
            kv.value)).collect();
        let (signer, identity) = if let (Some(pub_key),
            Some(id)) = (saved.get(META_SIGNER), saved.get(META_IDENTITY)) {
            *provider.storage().values.write().unwrap() =
                saved.iter().filter(|(k, _)| k[0] == 0).map(|(k,
                    v)| (k[1..].to_vec(), v.clone())).collect();
            let s = SignatureKeyPair::read(provider.storage(), pub_key,
                CS.signature_algorithm())
                .ok_or(GroupError::Storage {
                    msg: "signature key missing".into() })?;
            (s, id.clone())
        } else {
            let s = SignatureKeyPair::new(CS.signature_algorithm()).map_err(
                inv)?;
            s.store(provider.storage()).map_err(inv)?;
            let binding = binder.bind(framed(BINDING_LABEL,
                &[account.as_bytes(), device.as_bytes(), s.public()]));
            (s, encode_identity(&account, &device, &binding))
        };
        let cred = CredentialWithKey { credential: BasicCredential::new(
            identity).into(), signature_key: signer.public().into() };
        let mut groups = HashMap::new();
        if let Some(ids) = saved.get(META_GROUPS) {
            let mut i = 0;
            while i + 2 <= ids.len() {
                let n = u16::from_be_bytes([ids[i], ids[i + 1]]) as usize;
                let id = ids[i + 2..i + 2 + n].to_vec();
                if let Ok(Some(g)) = MlsGroup::load(provider.storage(),
                    &GroupId::from_slice(&id)) {
                    groups.insert(id, g);
                }
                i += 2 + n;
            }
        }
        let me = Arc::new(Self { inner: Mutex::new(Inner { provider, signer,
            cred, account, groups, persisted: saved }),
            store, directory });
        { let mut s = me.inner.lock().unwrap(); me.persist(&mut s)?; }
        Ok(me)
    }

    /// `count` single-use KeyPackages, or one last-resort KeyPackage (Ch 23
    /// §23.8).
    pub fn key_packages(&self, count: u32,
        last_resort: bool) -> Result<Vec<Vec<u8>>, GroupError> {
        let mut st = self.inner.lock().unwrap();
        let s = &mut *st;
        let mut out = Vec::new();
        for _ in 0..count {
            let mut b = KeyPackage::builder().leaf_node_capabilities(caps());
            if last_resort { b = b.mark_as_last_resort(); }
            let kp = b.build(CS, &s.provider, &s.signer,
                s.cred.clone()).map_err(inv)?;
            out.push(MlsMessageOut::from(
                kp.key_package().clone()).tls_serialize_detached().map_err(
                inv)?);
        }
        // the KeyPackages' private keys must be durable before upload
        self.persist(s)?;
        Ok(out)
    }

    pub fn create_group(&self, admins: Vec<String>) -> Result<Vec<u8>,
        GroupError> {
        let mut st = self.inner.lock().unwrap();
        let s = &mut *st;
        let ext = Extensions::single(Extension::Unknown(ADMINS_EXT,
            UnknownExtension(admins.join("\n").into_bytes())));
        let cfg = MlsGroupCreateConfig::builder().ciphersuite(
            CS).use_ratchet_tree_extension(true)
            .capabilities(caps()).with_group_context_extensions(ext).map_err(
                inv)?.build();
        let g = MlsGroup::new(&s.provider, &s.signer, &cfg,
            s.cred.clone()).map_err(inv)?;
        let id = g.group_id().as_slice().to_vec();
        s.groups.insert(id.clone(), g);
        self.persist(s)?;
        Ok(id)
    }

    /// Add devices from claimed KeyPackages. Every credential passes the AS
    /// check; only admins may add other accounts' devices; any member may add
    /// devices of its OWN account (§30.5).
    pub fn add_members(&self, group_id: Vec<u8>,
        key_packages: Vec<Vec<u8>>) -> Result<CommitOutput, GroupError> {
        let mut st = self.inner.lock().unwrap();
        let s = &mut *st;
        let mut kps = Vec::new();
        for raw in key_packages {
            let MlsMessageBodyIn::KeyPackage(
                kp) = MlsMessageIn::tls_deserialize(&mut &raw[..]).map_err(
                inv)?.extract()
            else { return Err(GroupError::Invalid {
                msg: "not a KeyPackage".into() }) };
            // signature, suite, lifetime
            let kp = kp.validate(s.provider.crypto(),
                ProtocolVersion::Mls10).map_err(inv)?;
            let ln = kp.leaf_node();
            let (account, _) = self.authenticate(ln.credential(),
                ln.signature_key().as_slice())
                .map_err(|m| GroupError::NotAuthorized { msg: m })?;
            kps.push((account, kp));
        }
        let g = s.groups.get_mut(&group_id).ok_or(GroupError::NoGroup)?;
        let admin = Self::admins(g).contains(&s.account);
        if let Some((a, _)) = kps.iter().find(|(a,
            _)| *a != s.account && !admin) {
            return Err(GroupError::NotAuthorized { msg: format!(
                "only admins may add {a}") });
        }
        let kps: Vec<KeyPackage> = kps.into_iter().map(|(_, k)| k).collect();
        let (commit, welcome, _) = g.add_members(&s.provider, &s.signer,
            &kps).map_err(inv)?;
        let epoch = g.epoch().as_u64() + 1;
        let out = CommitOutput {
            commit: commit.tls_serialize_detached().map_err(inv)?,
            welcome: Some(welcome.tls_serialize_detached().map_err(inv)?),
            epoch };
        // the pending commit is durable: after a crash we can still merge or
        // clear it
        self.persist(s)?;
        Ok(out)
    }

    /// Remove devices ("account/device"). Admins may remove anyone; anyone may
    /// remove devices of its own account (a lost phone, §30.5).
    pub fn remove_members(&self, group_id: Vec<u8>,
        members: Vec<String>) -> Result<CommitOutput, GroupError> {
        let mut st = self.inner.lock().unwrap();
        let s = &mut *st;
        let g = s.groups.get_mut(&group_id).ok_or(GroupError::NoGroup)?;
        let admin = Self::admins(g).contains(&s.account);
        let mine = format!("{}/", s.account);
        if !admin && members.iter().any(|m| !m.starts_with(&mine)) {
            return Err(GroupError::NotAuthorized {
                msg: "only admins may remove other accounts".into() });
        }
        let idx: Vec<LeafNodeIndex> = g.members().filter(|m| members.contains(
            &Self::name_of(m))).map(|m| m.index).collect();
        if idx.is_empty() { return Err(GroupError::Invalid {
            msg: "no such member".into() }); }
        let (commit, welcome, _) = g.remove_members(&s.provider, &s.signer,
            &idx).map_err(inv)?;
        let out = CommitOutput {
            commit: commit.tls_serialize_detached().map_err(inv)?,
            welcome: welcome.map(
            |w| w.tls_serialize_detached()).transpose().map_err(inv)?,
            epoch: g.epoch().as_u64() + 1 };
        self.persist(s)?;
        Ok(out)
    }

    /// A fresh leaf key and path: post-compromise security for this device
    /// (§30.2).
    pub fn self_update(&self, group_id: Vec<u8>) -> Result<CommitOutput,
        GroupError> {
        let mut st = self.inner.lock().unwrap();
        let s = &mut *st;
        let g = s.groups.get_mut(&group_id).ok_or(GroupError::NoGroup)?;
        let b = g.self_update(&s.provider, &s.signer,
            LeafNodeParameters::default()).map_err(inv)?;
        let out = CommitOutput {
            commit: b.commit().tls_serialize_detached().map_err(inv)?,
            welcome: None,
            epoch: g.epoch().as_u64() + 1 };
        self.persist(s)?;
        Ok(out)
    }

    /// Call after the DS answered 202 for our commit.
    pub fn merge_pending(&self, group_id: Vec<u8>) -> Result<u64, GroupError> {
        let mut st = self.inner.lock().unwrap();
        let s = &mut *st;
        let g = s.groups.get_mut(&group_id).ok_or(GroupError::NoGroup)?;
        g.merge_pending_commit(&s.provider).map_err(inv)?;
        let e = g.epoch().as_u64();
        self.persist(s)?;
        Ok(e)
    }

    /// Call after the DS answered 409 STALE_EPOCH: drop our commit, process the
    /// winner, retry.
    pub fn clear_pending(&self, group_id: Vec<u8>) -> Result<(), GroupError> {
        let mut st = self.inner.lock().unwrap();
        let s = &mut *st;
        let g = s.groups.get_mut(&group_id).ok_or(GroupError::NoGroup)?;
        g.clear_pending_commit(s.provider.storage()).map_err(inv)?;
        self.persist(s)
    }

    /// Join from a Welcome. EVERY member already in the tree must pass the AS
    /// check, and the group must carry an admin list; otherwise the Welcome is
    /// refused and nothing is kept.
    pub fn join(&self, welcome: Vec<u8>) -> Result<Vec<u8>, GroupError> {
        let mut st = self.inner.lock().unwrap();
        let s = &mut *st;
        let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize(
            &mut &welcome[..]).map_err(inv)?.extract()
        else { return Err(GroupError::Invalid {
            msg: "not a Welcome".into() }) };
        // Joined members must also put the ratchet tree in the Welcomes THEY
        // create (§30.5).
        let join_cfg = MlsGroupJoinConfig::builder().use_ratchet_tree_extension(
            true).build();
        let staged = StagedWelcome::new_from_welcome(&s.provider, &join_cfg, w,
            None).map_err(inv)?;
        for m in staged.members() {
            self.authenticate(&m.credential,
                &m.signature_key).map_err(|e| GroupError::NotAuthorized {
                msg: e })?;
        }
        let g = staged.into_group(&s.provider).map_err(inv)?;
        if Self::admins(&g).is_empty() {
            return Err(GroupError::NotAuthorized {
                msg: "group has no admin list".into() });
        }
        let id = g.group_id().as_slice().to_vec();
        s.groups.insert(id.clone(), g);
        self.persist(s)?;
        Ok(id)
    }

    pub fn encrypt(&self, group_id: Vec<u8>,
        plaintext: Vec<u8>) -> Result<Vec<u8>, GroupError> {
        let mut st = self.inner.lock().unwrap();
        let s = &mut *st;
        let g = s.groups.get_mut(&group_id).ok_or(GroupError::NoGroup)?;
        let out = g.create_message(&s.provider, &s.signer,
            &plaintext).map_err(inv)?.tls_serialize_detached().map_err(inv)?;
        // the secret-tree ratchet advanced: durable BEFORE the bytes leave
        self.persist(s)?;
        Ok(out)
    }

    /// Process one message from the DS. Commits are checked (sender, adds,
    /// admin rule) BEFORE merging; a commit that fails a check is not merged
    /// and is reported.
    pub fn process(&self, wire: Vec<u8>) -> Result<Processed, GroupError> {
        let mut st = self.inner.lock().unwrap();
        let s = &mut *st;
        let pm = MlsMessageIn::tls_deserialize(&mut &wire[..]).map_err(
            inv)?.try_into_protocol_message().map_err(inv)?;
        let gid = pm.group_id().as_slice().to_vec();
        let g = s.groups.get_mut(&gid).ok_or(GroupError::NoGroup)?;
        let msg = g.process_message(&s.provider, pm).map_err(inv)?;
        let Sender::Member(sender_idx) = *msg.sender() else {
            return Ok(Processed::Rejected { group_id: gid,
                reason: "non-member sender".into() });
        };
        let sender_member = g.members().find(|m| m.index == sender_idx);
        let sender_name = sender_member.as_ref().map(
            Self::name_of).unwrap_or_default();
        let sender_ok = sender_member.as_ref().map(|m| self.authenticate(
            &m.credential, &m.signature_key)).transpose();
        let result = match msg.into_content() {
            ProcessedMessageContent::ApplicationMessage(a) => {
                if let Err(e) = sender_ok { Processed::Rejected {
                    group_id: gid.clone(), reason: e } }
                else { Processed::Application { group_id: gid.clone(),
                    sender: sender_name, plaintext: a.into_bytes() } }
            }
            ProcessedMessageContent::ProposalMessage(p) => {
                g.store_pending_proposal(s.provider.storage(),
                    *p).map_err(inv)?;
                Processed::ProposalStored { group_id: gid.clone(),
                    from: sender_name }
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let sender_account = sender_name.split('/').next().unwrap_or(
                    "").to_string();
                let admin = Self::admins(g).contains(&sender_account);
                let mut added = Vec::new();
                let mut problem = sender_ok.err();
                for a in staged.add_proposals() {
                    let ln = a.add_proposal().key_package().leaf_node();
                    match self.authenticate(ln.credential(),
                        ln.signature_key().as_slice()) {
                        Ok((acct, dev)) => {
                            if acct != sender_account && !admin {
                                problem.get_or_insert(format!(
                                "{sender_name} is not an admin")); }
                            added.push(format!("{acct}/{dev}"));
                        }
                        Err(e) => { problem.get_or_insert(e); }
                    }
                }
                let removed: Vec<String> = staged.remove_proposals().filter_map(
                    |r| {
                    g.members().find(
                    |m| m.index == r.remove_proposal().removed()).map(
                    |m| Self::name_of(&m))
                }).collect();
                let mine = format!("{sender_account}/");
                if !admin && removed.iter().any(|r| !r.starts_with(&mine)) {
                    // a member may commit its own removal proposal, or remove
                    // its own devices
                    let leaving_self = staged.remove_proposals().all(
                        |r| matches!(r.sender(), Sender::Member(i) if {
                        g.members().find(|m| m.index == *i).map(
                        |m| Self::name_of(&m)) ==
                        g.members().find(
                        |m| m.index == r.remove_proposal().removed()).map(
                        |m| Self::name_of(&m)) }));
                    if !leaving_self { problem.get_or_insert(format!(
                        "{sender_name} is not an admin")); }
                }
                if let Some(reason) = problem {
                    // NOT merged
                    Processed::Rejected { group_id: gid.clone(), reason }
                } else {
                    g.merge_staged_commit(&s.provider, *staged).map_err(inv)?;
                    if g.is_active() {
                        Processed::CommitMerged { group_id: gid.clone(),
                            epoch: g.epoch().as_u64(), added, removed }
                    } else {
                        // our leaf is gone: forget the group
                        g.delete(s.provider.storage()).map_err(inv)?;
                        s.groups.remove(&gid);
                        Processed::RemovedFromGroup { group_id: gid.clone() }
                    }
                }
            }
            _ => Processed::Rejected { group_id: gid.clone(),
                reason: "unsupported message".into() },
        };
        // state + merge are durable before the caller acknowledges
        self.persist(s)?;
        Ok(result)
    }

    /// Leave: a Remove proposal for our own leaf; another member commits it
    /// (§30.2).
    pub fn leave(&self, group_id: Vec<u8>) -> Result<Vec<u8>, GroupError> {
        let mut st = self.inner.lock().unwrap();
        let s = &mut *st;
        let g = s.groups.get_mut(&group_id).ok_or(GroupError::NoGroup)?;
        let p = g.leave_group(&s.provider,
            &s.signer).map_err(inv)?.tls_serialize_detached().map_err(inv)?;
        self.persist(s)?;
        Ok(p)
    }

    pub fn commit_pending_proposals(&self,
        group_id: Vec<u8>) -> Result<CommitOutput, GroupError> {
        let mut st = self.inner.lock().unwrap();
        let s = &mut *st;
        let g = s.groups.get_mut(&group_id).ok_or(GroupError::NoGroup)?;
        let (commit, welcome, _) = g.commit_to_pending_proposals(&s.provider,
            &s.signer).map_err(inv)?;
        let out = CommitOutput {
            commit: commit.tls_serialize_detached().map_err(inv)?,
            welcome: welcome.map(
            |w| w.tls_serialize_detached()).transpose().map_err(inv)?,
            epoch: g.epoch().as_u64() + 1 };
        self.persist(s)?;
        Ok(out)
    }

    pub fn group_ids(&self) -> Vec<Vec<u8>> {
        let mut v: Vec<_> =
            self.inner.lock().unwrap().groups.keys().cloned().collect();
        v.sort();
        v
    }
    pub fn members(&self, group_id: Vec<u8>) -> Result<Vec<String>,
        GroupError> {
        let s = self.inner.lock().unwrap();
        Ok(s.groups.get(&group_id).ok_or(GroupError::NoGroup)?.members().map(
            |m| Self::name_of(&m)).collect())
    }
    pub fn admins_of(&self, group_id: Vec<u8>) -> Result<Vec<String>,
        GroupError> {
        let s = self.inner.lock().unwrap();
        Ok(Self::admins(s.groups.get(&group_id).ok_or(GroupError::NoGroup)?))
    }
    pub fn epoch(&self, group_id: Vec<u8>) -> Result<u64, GroupError> {
        let s = self.inner.lock().unwrap();
        Ok(s.groups.get(&group_id).ok_or(GroupError::NoGroup)?.epoch().as_u64())
    }
    /// The "group safety code" (§30.4): equal on every member's device iff they
    /// share the epoch.
    pub fn epoch_authenticator(&self, group_id: Vec<u8>) -> Result<Vec<u8>,
        GroupError> {
        let s = self.inner.lock().unwrap();
        Ok(s.groups.get(&group_id).ok_or(
            GroupError::NoGroup)?.epoch_authenticator().as_slice().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_identity_parsing_is_strict() {
        let good = encode_identity("bob", "dev-1", &[7u8; 64]);
        assert!(decode_identity(&good).is_some());
        let mut trailing = good.clone(); trailing.push(0);
        assert!(decode_identity(&trailing).is_none(), "trailing bytes");
        assert!(decode_identity(&good[..good.len() - 1]).is_none(),
            "short signature");
        assert!(decode_identity(&good[..3]).is_none(), "truncated name");
        assert!(decode_identity(&encode_identity("", "dev-1", &[7u8;
            64])).is_none(), "empty account");
        assert!(decode_identity(&encode_identity("bob/x", "dev-1", &[7u8;
            64])).is_none(), "ambiguous name");
        // account length points past the end
        let mut long = good.clone(); long[1] = 0xff;
        assert!(decode_identity(&long).is_none(), "length past end");
        println!(
            "credential identity: valid accepted; trailing, short, \
            truncated, empty, ambiguous, overlong rejected");
    }
}
