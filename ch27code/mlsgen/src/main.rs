//! mlsgen — writes the OpenMLS messages that Chapter 27's selftest and lab
//! (step 9) send through the delivery service. Not a book listing: run it once
//! to (re)create ../server/mls_vectors.json. Usage: cargo run --release >
//! ../server/mls_vectors.json
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const CS: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct Member {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    cwk: CredentialWithKey,
}

impl Member {
    fn new(name: &str) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Member { provider, signer, cwk }
    }
    fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .build(CS, &self.provider, &self.signer, self.cwk.clone())
            .unwrap()
            .key_package()
            .clone()
    }
}

fn ser(m: &MlsMessageOut) -> String {
    hex::encode(m.tls_serialize_detached().unwrap())
}

fn main() {
    let (alice, bob, carol) = (Member::new("alice"), Member::new("bob"),
    Member::new("carol"));
    let cfg = MlsGroupCreateConfig::builder()
        .ciphersuite(CS)
        .use_ratchet_tree_extension(true)
        .build();
    let mut ga = MlsGroup::new(&alice.provider, &alice.signer, &cfg, alice.cwk
    .clone()).unwrap();

    // Epoch 0: Alice adds Bob.
    let (commit0, welcome, _) = ga
        .add_members(&alice.provider, &alice.signer, &[bob.key_package()])
        .unwrap();
    ga.merge_pending_commit(&alice.provider).unwrap();

    // Bob joins from the Welcome.
    let w_bytes = welcome.tls_serialize_detached().unwrap();
    let w_in = MlsMessageIn::tls_deserialize_exact(&w_bytes).unwrap();
    let w = match w_in.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("not a welcome"),
    };
    let join = MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true)
    .build();
    let mut gb = StagedWelcome::new_from_welcome(&bob.provider, &join, w, None)
        .unwrap()
        .into_group(&bob.provider)
        .unwrap();

    // Epoch 1: an application message, then two competing commits.
    let app1 = ga
        .create_message(&alice.provider, &alice.signer, b"hello group")
        .unwrap();
    let (commit1, _, _) = ga
        .add_members(&alice.provider, &alice.signer, &[carol.key_package()])
        .unwrap();
    let bob_commit = gb
        .self_update(&bob.provider, &bob.signer, LeafNodeParameters::default())
        .unwrap();

    // A second group whose handshake messages are PublicMessages.
    let pub_cfg = MlsGroupCreateConfig::builder()
        .ciphersuite(CS)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let dave = Member::new("dave");
    let mut gp = MlsGroup::new(&alice.provider, &alice.signer, &pub_cfg, alice
    .cwk.clone()).unwrap();
    let (pub_commit, _, _) = gp
        .add_members(&alice.provider, &alice.signer, &[dave.key_package()])
        .unwrap();

    println!("{{");
    println!("  \"group_id\": \"{}\",", hex::encode(ga.group_id().as_slice()));
    println!("  \"commit_epoch0\": \"{}\",", ser(&commit0));
    println!("  \"welcome\": \"{}\",", ser(&welcome));
    println!("  \"application_epoch1\": \"{}\",", ser(&app1));
    println!("  \"commit_epoch1\": \"{}\",", ser(&commit1));
    println!("  \"bob_commit_epoch1\": \"{}\",", ser(bob_commit.commit()));
    println!("  \"public_commit_epoch0\": \"{}\"", ser(&pub_commit));
    println!("}}");
}
