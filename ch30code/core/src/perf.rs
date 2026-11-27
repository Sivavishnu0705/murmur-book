// perf.rs
//! Listing 30.6 — Rust: MLS cost by group size (release build, OpenMLS 0.7,
//! suite 0x0001): KeyPackage, Welcome, Commit and application-message sizes,
//! and the CPU time of the operations a phone performs. Timed on a reference
//! x86-64 machine; §30.6 scales them.
use std::time::Instant;
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

const CS: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct C { p: OpenMlsRustCrypto, s: SignatureKeyPair, c: CredentialWithKey,
    g: Option<MlsGroup> }
fn client(i: usize) -> C {
    let p = OpenMlsRustCrypto::default();
    let s = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
    s.store(p.storage()).unwrap();
    let c = CredentialWithKey { credential: BasicCredential::new(format!(
        "acct{i}/dev").into_bytes()).into(), signature_key: s.public().into() };
    C { p, s, c, g: None }
}
fn ms(t: Instant) -> f64 { t.elapsed().as_secs_f64() * 1e3 }

fn main() {
    let cfg = MlsGroupCreateConfig::builder().ciphersuite(
        CS).use_ratchet_tree_extension(true).build();
    print!("  members  KeyPackage  add-all Commit  Welcome   1st update  ");
    print!("full-tree update  app msg | create+add  join   ");
    println!("process update  encrypt");
    for n in [10usize, 50, 200] {
        let mut cs: Vec<C> = (0..n).map(client).collect();
        let kps: Vec<KeyPackage> = cs[1..].iter().map(
            |c| KeyPackage::builder().build(CS, &c.p, &c.s,
            c.c.clone()).unwrap().key_package().clone()).collect();
        let kp_size = kps[0].tls_serialize_detached().unwrap().len();
        let t = Instant::now();
        let a = &mut cs[0];
        a.g = Some(MlsGroup::new(&a.p, &a.s, &cfg, a.c.clone()).unwrap());
        let (commit, welcome, _) = a.g.as_mut().unwrap().add_members(&a.p, &a.s,
            &kps).unwrap();
        a.g.as_mut().unwrap().merge_pending_commit(&a.p).unwrap();
        let t_add = ms(t);
        let wire = welcome.tls_serialize_detached().unwrap();
        let mut t_join = 0.0;
        for c in cs[1..].iter_mut() {
            let t = Instant::now();
            let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize(
                &mut &wire[..]).unwrap().extract() else { panic!() };
            c.g = Some(StagedWelcome::new_from_welcome(&c.p,
                &MlsGroupJoinConfig::default(), w,
                None).unwrap().into_group(&c.p).unwrap());
            t_join += ms(t);
        }
        // a member in the middle of the tree updates; everyone else processes
        // it
        let k = n / 2;
        let upd = { let c = &mut cs[k]; let (p, s) = (&c.p, &c.s);
            let b = c.g.as_mut().unwrap().self_update(p, s,
            LeafNodeParameters::default()).unwrap();
            let w = b.commit().tls_serialize_detached().unwrap();
            c.g.as_mut().unwrap().merge_pending_commit(p).unwrap(); w };
        let mut t_proc = 0.0;
        for (i, c) in cs.iter_mut().enumerate() {
            if i == k { continue; }
            let t = Instant::now();
            let pm = MlsMessageIn::tls_deserialize(
                &mut &upd[..]).unwrap().try_into_protocol_message().unwrap();
            let g = c.g.as_mut().unwrap();
            if let ProcessedMessageContent::StagedCommitMessage(
                sc) = g.process_message(&c.p, pm).unwrap().into_content() {
                g.merge_staged_commit(&c.p, *sc).unwrap();
            }
            t_proc += ms(t);
        }
        // Fill the tree: every member updates once (as periodic updates do over
        // time), then measure again.
        for j in 0..n {
            let w = { let c = &mut cs[j]; let (p, s) = (&c.p, &c.s);
                let b = c.g.as_mut().unwrap().self_update(p, s,
                LeafNodeParameters::default()).unwrap();
                let w = b.commit().tls_serialize_detached().unwrap();
                c.g.as_mut().unwrap().merge_pending_commit(p).unwrap(); w };
            for (i, c) in cs.iter_mut().enumerate() {
                if i == j { continue; }
                let pm = MlsMessageIn::tls_deserialize(
                    &mut &w[..]).unwrap().try_into_protocol_message().unwrap();
                let g = c.g.as_mut().unwrap();
                if let ProcessedMessageContent::StagedCommitMessage(
                    sc) = g.process_message(&c.p,
                    pm).unwrap().into_content() { g.merge_staged_commit(&c.p,
                    *sc).unwrap(); }
            }
        }
        let full = { let c = &mut cs[k]; let (p, s) = (&c.p, &c.s);
            let b = c.g.as_mut().unwrap().self_update(p, s,
            LeafNodeParameters::default()).unwrap();
            b.commit().tls_serialize_detached().unwrap().len() };
        { let c = &mut cs[k]; let st = c.p.storage();
            c.g.as_mut().unwrap().clear_pending_commit(st).unwrap(); }
        let t = Instant::now();
        let app = { let c = &mut cs[1]; let (p, s) = (&c.p, &c.s);
            c.g.as_mut().unwrap().create_message(p, s, &[0u8;
            100]).unwrap().tls_serialize_detached().unwrap() };
        let t_enc = ms(t);
        let ea =
            cs[0].g.as_ref().unwrap().epoch_authenticator().as_slice().to_vec();
        assert!(cs.iter().all(
            |c| c.g.as_ref().unwrap().epoch_authenticator().as_slice() ==
            ea.as_slice()));
        println!(
            "  {n:>7}  {kp_size:>8} B  {:>12} B  {:>7} B  {:>8} B  \
            {full:>14} B  {:>5} B | {t_add:>8.1} ms  {:>4.1} ms  {:>9.2} ms  \
            {t_enc:>5.2} ms",
            commit.tls_serialize_detached().unwrap().len(), wire.len(),
            upd.len(), app.len(),
            t_join / (n - 1) as f64, t_proc / (n - 1) as f64);
    }
}
