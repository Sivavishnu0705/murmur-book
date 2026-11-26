// main.rs
//! Listing 23.1 — Rust: OpenMLS group creation, add member, commit, application message,
//! plus the lab: a 50-member group, updates, removal, sizes, and PCS after a leaf compromise.
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const CS: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct Client {
    name: String,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    cred: CredentialWithKey,
    group: Option<MlsGroup>,
}

impl Client {
    fn new(name: &str) -> Self {
        let provider = OpenMlsRustCrypto::default();
        // Basic credential = an identity string; Murmur binds it to the account/device and its
        // AIK-signed device list (Ch 20) — that check is the Authentication Service's job (§23.1).
        let credential = BasicCredential::new(name.as_bytes().to_vec());
        let signer = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let cred = CredentialWithKey { credential: credential.into(), signature_key: signer.public().into() };
        Client { name: name.into(), provider, signer, cred, group: None }
    }
    /// A KeyPackage: what the client uploads to the DS's KeyPackage directory (§23.8).
    fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .build(CS, &self.provider, &self.signer, self.cred.clone())
            .unwrap()
            .key_package()
            .clone()
    }
    fn g(&mut self) -> &mut MlsGroup { self.group.as_mut().unwrap() }
}

fn ser(m: &MlsMessageOut) -> Vec<u8> { m.tls_serialize_detached().unwrap() }

/// What every other member does with a message from the DS.
fn deliver(c: &mut Client, wire: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let msg = MlsMessageIn::tls_deserialize(&mut &wire[..]).map_err(|e| e.to_string())?;
    let pm = msg.try_into_protocol_message().map_err(|e| e.to_string())?;
    let (provider, group) = (&c.provider, c.group.as_mut().unwrap());
    let processed = group.process_message(provider, pm).map_err(|e| format!("{e:?}"))?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(a) => Ok(Some(a.into_bytes())),
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            // Commit processing (Fig 23.4): the staged commit has already verified the signature,
            // membership tag/AEAD, path decryption and the CONFIRMATION TAG; merge = enter epoch.
            group.merge_staged_commit(provider, *staged).map_err(|e| format!("{e:?}"))?;
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn main() {
    let group_cfg = MlsGroupCreateConfig::builder()
        .ciphersuite(CS)
        .use_ratchet_tree_extension(true) // Welcome carries the tree: joiners need no extra fetch
        .build();

    // ── Create the group and add 49 members in one Commit ──
    let mut clients: Vec<Client> = (0..50).map(|i| Client::new(&format!("member{i:02}"))).collect();
    let kps: Vec<KeyPackage> = clients[1..].iter().map(|c| c.key_package()).collect();
    let kp_size = kps[0].tls_serialize_detached().unwrap().len();
    let alice = &mut clients[0];
    alice.group = Some(MlsGroup::new(&alice.provider, &alice.signer, &group_cfg, alice.cred.clone()).unwrap());
    let (commit, welcome, _) = alice.group.as_mut().unwrap()
        .add_members(&alice.provider, &alice.signer, &kps).unwrap();
    alice.group.as_mut().unwrap().merge_pending_commit(&alice.provider).unwrap();
    let welcome_wire = ser(&welcome);
    for c in clients[1..].iter_mut() {
        let msg = MlsMessageIn::tls_deserialize(&mut &welcome_wire[..]).unwrap();
        let MlsMessageBodyIn::Welcome(w) = msg.extract() else { panic!("not a welcome") };
        let staged = StagedWelcome::new_from_welcome(&c.provider, &MlsGroupJoinConfig::default(), w, None).unwrap();
        c.group = Some(staged.into_group(&c.provider).unwrap());
    }
    println!("── 50-member group ──");
    println!("  KeyPackage: {kp_size} B   add-49 Commit: {} B   Welcome (with tree): {} B",
             ser(&commit).len(), welcome_wire.len());
    let ea = clients[0].g().epoch_authenticator().as_slice().to_vec();
    let agree = clients.iter_mut().all(|c| c.g().epoch_authenticator().as_slice() == ea.as_slice());
    println!("  epoch {}: all 50 members have the same epoch authenticator: {agree}", clients[0].g().epoch().as_u64());

    // ── Application message ──
    let app = { let c = &mut clients[7]; let (p, s) = (&c.provider, &c.signer); c.group.as_mut().unwrap().create_message(p, s, b"hello, 49 others").unwrap() };
    let app_wire = ser(&app);
    let ok = clients.iter_mut().enumerate().filter(|(i, _)| *i != 7)
        .all(|(_, c)| deliver(c, &app_wire).unwrap().as_deref() == Some(&b"hello, 49 others"[..]));
    println!("  one application message: {} B, decrypted by all 49 others: {ok}", app_wire.len());

    // ── Leaf compromise: an attacker copies member13's ENTIRE state (keys + group) ──
    let attacker_provider = clients[13].provider.clone();
    let gid = clients[13].g().group_id().clone();
    let mut attacker = Client { name: "attacker".into(), provider: attacker_provider, signer: SignatureKeyPair::new(CS.signature_algorithm()).unwrap(),
                                cred: clients[13].cred.clone(), group: None };
    attacker.group = Some(MlsGroup::load(attacker.provider.storage(), &gid).unwrap().unwrap());

    let broadcast = |clients: &mut Vec<Client>, attacker: &mut Client, from: usize, wire: &[u8]| -> bool {
        for (i, c) in clients.iter_mut().enumerate() { if i != from { deliver(c, wire).unwrap(); } }
        deliver(attacker, wire).is_ok()       // the attacker sees all DS traffic and tries to follow
    };
    let send = |clients: &mut Vec<Client>, attacker: &mut Client, from: usize, text: &str| -> String {
        let m = { let c = &mut clients[from]; let (p, s) = (&c.provider, &c.signer); ser(&c.group.as_mut().unwrap().create_message(p, s, text.as_bytes()).unwrap()) };
        for (i, c) in clients.iter_mut().enumerate() { if i != from { deliver(c, &m).unwrap(); } }
        match deliver(attacker, &m) { Ok(Some(pt)) => format!("READS {:?}", String::from_utf8_lossy(&pt)), Ok(None) => "?".into(), Err(_) => "cannot decrypt".into() }
    };
    println!("── PCS after a leaf compromise (member13's state copied) ──");
    println!("  epoch {} message from member02: attacker {}", clients[0].g().epoch().as_u64(), send(&mut clients, &mut attacker, 2, "plan A"));

    // An Update by ANOTHER member does not heal: the new path secret is encrypted to nodes whose
    // keys member13 (and so the attacker) holds.
    let upd = { let c = &mut clients[30]; let (p, s) = (&c.provider, &c.signer); let b = c.group.as_mut().unwrap().self_update(p, s, LeafNodeParameters::default()).unwrap(); c.group.as_mut().unwrap().merge_pending_commit(p).unwrap(); ser(b.commit()) };
    let followed = broadcast(&mut clients, &mut attacker, 30, &upd);
    println!("  member30 Update commit ({} B): attacker follows into the new epoch: {followed}", upd.len());
    println!("  epoch {} message from member02: attacker {}", clients[0].g().epoch().as_u64(), send(&mut clients, &mut attacker, 2, "plan B"));

    // The COMPROMISED member updates: fresh leaf key and path secrets the attacker never saw.
    let upd13 = { let c = &mut clients[13]; let (p, s) = (&c.provider, &c.signer); let b = c.group.as_mut().unwrap().self_update(p, s, LeafNodeParameters::default()).unwrap(); c.group.as_mut().unwrap().merge_pending_commit(p).unwrap(); ser(b.commit()) };
    let followed = broadcast(&mut clients, &mut attacker, 13, &upd13);
    println!("  member13 Update commit ({} B): attacker follows: {followed}", upd13.len());
    println!("  epoch {} message from member02: attacker {}  ← HEALED", clients[0].g().epoch().as_u64(), send(&mut clients, &mut attacker, 2, "plan C"));

    // ── Remove a member: one Commit, O(log n) path ──
    let leaf49 = clients[0].g().members().find(|m| m.credential.serialized_content() == b"member49").unwrap().index;
    let (rm, _, _) = { let c = &mut clients[0]; let (p, s) = (&c.provider, &c.signer); c.group.as_mut().unwrap().remove_members(p, s, &[leaf49]).unwrap() };
    { let c = &mut clients[0]; c.group.as_mut().unwrap().merge_pending_commit(&c.provider).unwrap(); }
    let rm_wire = ser(&rm);
    let mut removed = clients.pop().unwrap();
    for c in clients[1..].iter_mut() { deliver(c, &rm_wire).unwrap(); }
    let _ = deliver(&mut removed, &rm_wire);
    println!("── Remove member49 ──");
    println!("  Remove commit: {} B (one message for the whole group)", rm_wire.len());
    let m = { let c = &mut clients[5]; let (p, s) = (&c.provider, &c.signer); ser(&c.group.as_mut().unwrap().create_message(p, s, b"after removal").unwrap()) };
    println!("  removed member decrypts the next message: {}", deliver(&mut removed, &m).map(|_| "yes (!)".to_string()).unwrap_or_else(|_| "no".into()));
    let _ = &removed.name;

    // ── Size comparison with sender keys (Ch 22) ──
    let n = 49usize; // remaining members
    let skdm = 4 + 4 + 32 + 32 + 100; // chain id, iteration, chain key, signing key, + Double Ratchet framing
    println!("── Removal cost vs sender keys, 49 remaining single-device members ──");
    println!("  MLS:         1 Commit of {} B, fanned out by the DS", rm_wire.len());
    println!("  sender keys: {} pairwise messages of ~{} B ≈ {} KB in total", n * (n - 1), skdm, n * (n - 1) * skdm / 1024);
}
