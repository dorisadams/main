#![cfg(test)]

use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Events as _, Ledger},
    Address, Bytes, Env,
};

#[contract]
struct MockNoirVerifier;

#[contractimpl]
impl MockNoirVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        let len = public_inputs.len();
        // Canonical frame shapes: 128 (revocation), 160 (silent witness),
        // 224 (scoped silent witness).
        if (len != 128 && len != 160 && len != 224) || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

#[contract]
struct MockNoirVerifierV2;

#[contractimpl]
impl MockNoirVerifierV2 {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        if public_inputs.len() != 160 || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

#[contract]
struct MockRejectingNoirVerifier;

#[contractimpl]
impl MockRejectingNoirVerifier {
    pub fn verify_proof(_env: Env, _public_inputs: Bytes, _proof: Bytes) {
        panic!("rejecting verifier");
    }
}

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn proof_bytes(env: &Env) -> Bytes {
    Bytes::from_array(env, &[1, 2, 3, 4])
}

fn silent_public_inputs(
    env: &Env,
    video_hash: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
    domain_tag: &BytesN<32>,
) -> Bytes {
    let mut video_hash_bytes = [0u8; 32];
    video_hash.copy_into_slice(&mut video_hash_bytes);

    let mut credential_root_bytes = [0u8; 32];
    credential_root.copy_into_slice(&mut credential_root_bytes);

    let mut nullifier_bytes = [0u8; 32];
    nullifier.copy_into_slice(&mut nullifier_bytes);

    let mut domain_tag_bytes = [0u8; 32];
    domain_tag.copy_into_slice(&mut domain_tag_bytes);

    // 5 public inputs × 32 bytes = 160 bytes
    let mut bytes = [0u8; 160];
    bytes[16..32].copy_from_slice(&video_hash_bytes[..16]);
    bytes[48..64].copy_from_slice(&video_hash_bytes[16..]);
    bytes[64..96].copy_from_slice(&credential_root_bytes);
    bytes[96..128].copy_from_slice(&nullifier_bytes);
    bytes[128..160].copy_from_slice(&domain_tag_bytes);

    Bytes::from_array(env, &bytes)
}

fn expected_domain_tag_test(env: &Env) -> BytesN<32> {
    expected_domain_tag(env)
}

#[test]
fn registers_all_identity_tiers() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);

    client.init(&admin);
    client.add_issuer(&admin, &issuer, &bytes32(&env, 9));
    client.add_credential_root(&admin, &bytes32(&env, 5), &bytes32(&env, 10));

    let anonymous = client.register_anonymous(
        &bytes32(&env, 1),
        &bytes32(&env, 2),
        &bytes32(&env, 3),
        &bytes32(&env, 4),
        &bytes32(&env, 5),
        &proof_bytes(&env),
    );
    assert_eq!(anonymous.tier, TIER_SILENT_WITNESS);
    assert_eq!(anonymous.nullifier, Some(bytes32(&env, 4)));
    assert!(client.has_nullifier(&bytes32(&env, 4)));

    let pseudonymous = client.register_source(
        &source,
        &bytes32(&env, 11),
        &bytes32(&env, 12),
        &bytes32(&env, 13),
    );
    assert_eq!(pseudonymous.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(pseudonymous.source, Some(source));

    let sealed = client.register_seal(
        &issuer,
        &bytes32(&env, 21),
        &bytes32(&env, 22),
        &bytes32(&env, 23),
    );
    assert_eq!(sealed.tier, TIER_PUBLIC_SEAL);
    assert_eq!(sealed.issuer, Some(issuer));
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn rejects_reused_nullifier() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.init(&admin);
    client.add_credential_root(&admin, &bytes32(&env, 5), &bytes32(&env, 10));
    client.register_anonymous(
        &bytes32(&env, 1),
        &bytes32(&env, 2),
        &bytes32(&env, 3),
        &bytes32(&env, 4),
        &bytes32(&env, 5),
        &proof_bytes(&env),
    );
    client.register_anonymous(
        &bytes32(&env, 6),
        &bytes32(&env, 7),
        &bytes32(&env, 8),
        &bytes32(&env, 4),
        &bytes32(&env, 5),
        &proof_bytes(&env),
    );
}

#[test]
fn can_lookup_by_video_hash() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let video_hash = bytes32(&env, 31);

    client.init(&admin);
    client.register_source(&source, &video_hash, &bytes32(&env, 32), &bytes32(&env, 33));

    let record = client.get_by_video(&video_hash).unwrap();
    assert_eq!(record.video_hash, video_hash);
    assert_eq!(record.status, STATUS_REGISTERED);
}

#[test]
fn registers_silent_witness_through_external_verifier() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockNoirVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = bytes32(&env, 41);
    let credential_root = bytes32(&env, 9);
    let nullifier = bytes32(&env, 42);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 45));
    assert_eq!(client.get_verifier(), Some(verifier_id));
    assert!(client.get_credential_root(&credential_root).unwrap().active);

    let record = client.register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 43),
        &bytes32(&env, 44),
        &silent_public_inputs(
            &env,
            &video_hash,
            &credential_root,
            &nullifier,
            &expected_domain_tag_test(&env),
        ),
        &proof_bytes(&env),
    );

    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert_eq!(record.video_hash, video_hash);
    assert_eq!(record.nullifier, Some(nullifier.clone()));
    assert!(client.has_nullifier(&nullifier));
    // Non-batch registration has batch_size = 0
    assert_eq!(record.batch_size, 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #12)")]
fn rejects_revoked_silent_witness_credential_root() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockNoirVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = bytes32(&env, 51);
    let credential_root = bytes32(&env, 52);
    let nullifier = bytes32(&env, 53);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 54));
    client.revoke_credential_root(&admin, &credential_root);

    client.register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 55),
        &bytes32(&env, 56),
        &silent_public_inputs(
            &env,
            &video_hash,
            &credential_root,
            &nullifier,
            &expected_domain_tag_test(&env),
        ),
        &proof_bytes(&env),
    );
}

#[test]
fn stages_verifier_rotation_and_rolls_back_within_window() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let initial_verifier = env.register(MockNoirVerifier, ());
    let replacement_verifier = env.register(MockNoirVerifierV2, ());

    client.init(&admin);
    client.set_verifier(&admin, &initial_verifier);
    client.schedule_verifier_rotation(&admin, &replacement_verifier, &10u64, &5u64, &3u64);

    let state = client.get_verifier_state();
    assert_eq!(state.pending_verifier, Some(replacement_verifier.clone()));
    assert_eq!(state.active_verifier, Some(initial_verifier.clone()));

    env.ledger().set_sequence_number(15);
    client.activate_verifier_rotation(&admin);

    let state = client.get_verifier_state();
    assert_eq!(state.active_verifier, Some(replacement_verifier.clone()));
    assert!(state.rollback_window_end >= 15);

    client.rollback_verifier_rotation(&admin);
    let state = client.get_verifier_state();
    assert_eq!(state.active_verifier, Some(initial_verifier.clone()));
}

#[test]
fn verifier_rotation_activates_only_after_overlap_window() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let initial_verifier = env.register(MockNoirVerifier, ());
    let replacement_verifier = env.register(MockNoirVerifierV2, ());

    client.init(&admin);
    client.set_verifier(&admin, &initial_verifier);
    client.schedule_verifier_rotation(&admin, &replacement_verifier, &10u64, &5u64, &3u64);

    env.ledger().set_sequence_number(14);
    let state = client.get_verifier_state();
    assert_eq!(state.pending_verifier, Some(replacement_verifier.clone()));

    client.activate_verifier_rotation(&admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #41)")] // RotationNotReady
fn verifier_rotation_cannot_activate_before_activation_ledger() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let initial_verifier = env.register(MockNoirVerifier, ());
    let replacement_verifier = env.register(MockNoirVerifierV2, ());

    client.init(&admin);
    client.set_verifier(&admin, &initial_verifier);
    client.schedule_verifier_rotation(&admin, &replacement_verifier, &100u64, &10u64, &5u64);

    env.ledger().set_sequence_number(99);
    client.activate_verifier_rotation(&admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #42)")] // RotationWindowClosed
fn verifier_rotation_is_rejected_after_rollback_window_closes() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let initial_verifier = env.register(MockNoirVerifier, ());
    let replacement_verifier = env.register(MockNoirVerifierV2, ());

    client.init(&admin);
    client.set_verifier(&admin, &initial_verifier);
    client.schedule_verifier_rotation(&admin, &replacement_verifier, &1u64, &1u64, &1u64);

    env.ledger().set_sequence_number(1);
    client.activate_verifier_rotation(&admin);

    env.ledger().set_sequence_number(3);
    client.rollback_verifier_rotation(&admin);
}

#[test]
fn verifier_rotation_supports_overlap_with_previous_verifier() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let initial_verifier = env.register(MockNoirVerifier, ());
    let replacement_verifier = env.register(MockRejectingNoirVerifier, ());

    client.init(&admin);
    client.set_verifier(&admin, &initial_verifier);
    client.add_credential_root(&admin, &bytes32(&env, 9), &bytes32(&env, 10));
    client.schedule_verifier_rotation(&admin, &replacement_verifier, &1u64, &1u64, &1u64);

    env.ledger().set_sequence_number(1);
    client.activate_verifier_rotation(&admin);

    let record = client.register_anonymous_verified(
        &bytes32(&env, 71),
        &bytes32(&env, 72),
        &bytes32(&env, 73),
        &silent_public_inputs(
            &env,
            &bytes32(&env, 71),
            &bytes32(&env, 9),
            &bytes32(&env, 74),
            &expected_domain_tag_test(&env),
        ),
        &proof_bytes(&env),
    );

    assert_eq!(record.tier, TIER_SILENT_WITNESS);
}

#[test]
fn transfers_admin_after_proposal_is_accepted() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let issuer = Address::generate(&env);

    client.init(&admin);
    client.propose_admin(&admin, &new_admin);
    assert_eq!(env.events().all().events().len(), 1);
    client.accept_admin(&new_admin);
    assert_eq!(env.events().all().events().len(), 1);

    client.add_issuer(&new_admin, &issuer, &bytes32(&env, 61));
    assert!(client.get_issuer(&issuer).unwrap().active);
}

#[test]
#[should_panic(expected = "Error(Contract, #20)")]
fn cancelled_admin_transfer_cannot_be_accepted() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let pending_admin = Address::generate(&env);

    client.init(&admin);
    client.propose_admin(&admin, &pending_admin);
    client.cancel_admin_transfer(&admin);
    assert_eq!(env.events().all().events().len(), 1);
    client.accept_admin(&pending_admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn replaced_admin_proposal_cannot_be_accepted() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let first_pending_admin = Address::generate(&env);
    let replacement_pending_admin = Address::generate(&env);

    client.init(&admin);
    client.propose_admin(&admin, &first_pending_admin);
    client.propose_admin(&admin, &replacement_pending_admin);
    client.accept_admin(&first_pending_admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn non_admin_cannot_propose_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let pending_admin = Address::generate(&env);

    client.init(&admin);
    client.propose_admin(&unauthorized, &pending_admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn non_pending_admin_cannot_accept_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let pending_admin = Address::generate(&env);
    let unauthorized = Address::generate(&env);

    client.init(&admin);
    client.propose_admin(&admin, &pending_admin);
    client.accept_admin(&unauthorized);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn non_admin_cannot_cancel_admin_transfer() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let pending_admin = Address::generate(&env);
    let unauthorized = Address::generate(&env);

    client.init(&admin);
    client.propose_admin(&admin, &pending_admin);
    client.cancel_admin_transfer(&unauthorized);
}

// ── Domain separation tests (NEW) ────────────────────────────────────────────

#[test]
#[should_panic(expected = "Error(Contract, #49)")]
fn rejects_wrong_domain_tag() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockNoirVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = bytes32(&env, 71);
    let credential_root = bytes32(&env, 72);
    let nullifier = bytes32(&env, 73);
    let wrong_tag = bytes32(&env, 99); // wrong — must equal expected_domain_tag

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 74));

    client.register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 75),
        &bytes32(&env, 76),
        &silent_public_inputs(&env, &video_hash, &credential_root, &nullifier, &wrong_tag),
        &proof_bytes(&env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #49)")]
fn rejects_zero_domain_tag() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockNoirVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = bytes32(&env, 81);
    let credential_root = bytes32(&env, 82);
    let nullifier = bytes32(&env, 83);
    let zero_tag = BytesN::from_array(&env, &[0u8; 32]);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 84));

    client.register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 85),
        &bytes32(&env, 86),
        &silent_public_inputs(&env, &video_hash, &credential_root, &nullifier, &zero_tag),
        &proof_bytes(&env),
    );
}

#[test]
fn accepts_correct_domain_tag() {
    // Positive: providing the correct domain tag allows registration.
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockNoirVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = bytes32(&env, 91);
    let credential_root = bytes32(&env, 92);
    let nullifier = bytes32(&env, 93);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 94));

    let record = client.register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 95),
        &bytes32(&env, 96),
        &silent_public_inputs(
            &env,
            &video_hash,
            &credential_root,
            &nullifier,
            &expected_domain_tag_test(&env),
        ),
        &proof_bytes(&env),
    );

    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert_eq!(record.video_hash, video_hash);
}
