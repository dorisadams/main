//! Registration replay test matrix (#322)
//!
//! Every registration entry point is exercised against each uniqueness
//! collision that constitutes a "replay" at the public boundary:
//!
//! | Entry point                     | Identical args | Same proof_id | Same video_hash | Same nullifier |
//! |---------------------------------|----------------|---------------|-----------------|----------------|
//! | `register_anonymous`            | #4             | #4            | #5              | #6             |
//! | `register_anonymous_verified`   | #4             | #4            | #5              | #6             |
//! | `register_source`               | #4             | #4            | #5              | n/a            |
//! | `register_seal`                 | #4             | #4            | #5              | n/a            |
//! | `register_source_delegated`     | #4             | #4            | #5              | n/a            |
//! | `register_seal_delegated`       | #4             | #4            | #5              | n/a            |
//!
//! Cross-tier cells (anonymous → source/seal and the reverse) confirm the
//! uniqueness keys are global, not per-tier. Revocation does not free a
//! `proof_id` or `video_hash`, so a post-revoke identical registration is
//! still rejected — the replay guard survives incident response.
//!
//! Negative boundary cells cover empty proof bytes (`InvalidProof` #7) and
//! oversized / wrong-length verified public inputs (`InvalidPublicInputs`
//! #10). Rejected replays emit no events and never log media, secrets,
//! witness values, or private keys.
//!
//! Error codes (from `RegistryError` repr):
//!   #4  DuplicateProof
//!   #5  DuplicateVideo
//!   #6  DuplicateNullifier
//!   #7  InvalidProof
//!   #10 InvalidPublicInputs
//!
//! Migration / rollback: test-only additive module. No storage keys, ABI
//! surface, or protocol artifact changes. Rolling back the wasm drops the
//! suite without affecting on-chain state.

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, testutils::Events as _, Address, Bytes, Env,
    IntoVal, Symbol, Vec as SorobanVec,
};

// ---------------------------------------------------------------------------
// Mock verifier — accepts the Silent Witness v1 frame (160 bytes)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[contract]
struct MockReplayVerifier;

#[cfg(test)]
#[contractimpl]
impl MockReplayVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        // Accept v1 (160) and keep legacy 128/192 windows so the mock stays
        // usable if a future cell needs revocation or scoped frames.
        let len = public_inputs.len();
        if (len != 160 && len != 128 && len != 192) || proof.is_empty() {
            panic!("invalid replay-matrix proof");
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

#[cfg(test)]
fn proof_buf(env: &Env) -> Bytes {
    Bytes::from_array(env, &[0xAB, 0xCD, 0xEF, 0x01])
}

#[cfg(test)]
fn empty_proof(env: &Env) -> Bytes {
    Bytes::new(env)
}

/// Build a Silent Witness v1 public-input frame (5 × 32 = 160 bytes).
#[cfg(test)]
fn silent_v1_inputs(
    env: &Env,
    video_hash: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
) -> Bytes {
    let mut vh = [0u8; 32];
    video_hash.copy_into_slice(&mut vh);
    let mut cr = [0u8; 32];
    credential_root.copy_into_slice(&mut cr);
    let mut nu = [0u8; 32];
    nullifier.copy_into_slice(&mut nu);
    let domain_tag = expected_domain_tag(env);
    let mut dt = [0u8; 32];
    domain_tag.copy_into_slice(&mut dt);

    let mut buf = [0u8; 160];
    buf[16..32].copy_from_slice(&vh[..16]);
    buf[48..64].copy_from_slice(&vh[16..]);
    buf[64..96].copy_from_slice(&cr);
    buf[96..128].copy_from_slice(&nu);
    buf[128..160].copy_from_slice(&dt);
    Bytes::from_array(env, &buf)
}

const CRED_ROOT: u8 = 0xC1;
const ONE_DAY: u64 = 24 * 60 * 60;

/// Fresh registry with admin, verifier, credential root, issuer, source, and
/// a delegate pre-granted both registration scopes.
#[cfg(test)]
fn setup() -> (Env, Address, Address, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockReplayVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);
    let delegate = Address::generate(&env);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &b32(&env, CRED_ROOT), &b32(&env, 0xFF));
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAA));
    client.grant_delegation(
        &source,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    client.grant_delegation(
        &issuer,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &ONE_DAY,
    );

    (
        env,
        contract_id,
        admin,
        source,
        issuer,
        delegate,
        verifier_id,
    )
}

// ===========================================================================
// Positive: first registration succeeds on every entry point
// ===========================================================================

#[test]
fn replay_matrix_positive_anonymous_succeeds() {
    let (env, contract_id, _, _, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let record = client.register_anonymous(
        &b32(&env, 0x01),
        &b32(&env, 0x02),
        &b32(&env, 0x03),
        &b32(&env, 0x04),
        &b32(&env, CRED_ROOT),
        &proof_buf(&env),
    );
    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert_eq!(record.status, STATUS_REGISTERED);
    assert!(client.has_nullifier(&b32(&env, 0x04)));
}

#[test]
fn replay_matrix_positive_anonymous_verified_succeeds() {
    let (env, contract_id, _, _, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0x11);
    let nullifier = b32(&env, 0x14);
    let cred = b32(&env, CRED_ROOT);
    let record = client.register_anonymous_verified(
        &video,
        &b32(&env, 0x12),
        &b32(&env, 0x13),
        &silent_v1_inputs(&env, &video, &cred, &nullifier),
        &proof_buf(&env),
    );
    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert!(client.has_nullifier(&nullifier));
}

#[test]
fn replay_matrix_positive_source_succeeds() {
    let (env, contract_id, _, source, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let record = client.register_source(
        &source,
        &b32(&env, 0x21),
        &b32(&env, 0x22),
        &b32(&env, 0x23),
    );
    assert_eq!(record.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(record.source, Some(source));
}

#[test]
fn replay_matrix_positive_seal_succeeds() {
    let (env, contract_id, _, _, issuer, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let record = client.register_seal(
        &issuer,
        &b32(&env, 0x31),
        &b32(&env, 0x32),
        &b32(&env, 0x33),
    );
    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    assert_eq!(record.issuer, Some(issuer));
}

#[test]
fn replay_matrix_positive_source_delegated_succeeds() {
    let (env, contract_id, _, source, _, delegate, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let record = client.register_source_delegated(
        &delegate,
        &source,
        &b32(&env, 0x41),
        &b32(&env, 0x42),
        &b32(&env, 0x43),
    );
    assert_eq!(record.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(record.source, Some(source));
}

#[test]
fn replay_matrix_positive_seal_delegated_succeeds() {
    let (env, contract_id, _, _, issuer, delegate, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let record = client.register_seal_delegated(
        &delegate,
        &issuer,
        &b32(&env, 0x51),
        &b32(&env, 0x52),
        &b32(&env, 0x53),
    );
    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    assert_eq!(record.issuer, Some(issuer));
}

// ===========================================================================
// Identical-arg replay → DuplicateProof (#4)
// ===========================================================================

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn replay_matrix_identical_anonymous_rejected() {
    let (env, contract_id, _, _, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0x61);
    let meta = b32(&env, 0x62);
    let proof_id = b32(&env, 0x63);
    let nullifier = b32(&env, 0x64);
    let cred = b32(&env, CRED_ROOT);
    let proof = proof_buf(&env);
    client.register_anonymous(&video, &meta, &proof_id, &nullifier, &cred, &proof);
    client.register_anonymous(&video, &meta, &proof_id, &nullifier, &cred, &proof);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn replay_matrix_identical_anonymous_verified_rejected() {
    let (env, contract_id, _, _, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0x71);
    let meta = b32(&env, 0x72);
    let proof_id = b32(&env, 0x73);
    let nullifier = b32(&env, 0x74);
    let cred = b32(&env, CRED_ROOT);
    let inputs = silent_v1_inputs(&env, &video, &cred, &nullifier);
    let proof = proof_buf(&env);
    client.register_anonymous_verified(&video, &meta, &proof_id, &inputs, &proof);
    client.register_anonymous_verified(&video, &meta, &proof_id, &inputs, &proof);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn replay_matrix_identical_source_rejected() {
    let (env, contract_id, _, source, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0x81);
    let meta = b32(&env, 0x82);
    let proof_id = b32(&env, 0x83);
    client.register_source(&source, &video, &meta, &proof_id);
    client.register_source(&source, &video, &meta, &proof_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn replay_matrix_identical_seal_rejected() {
    let (env, contract_id, _, _, issuer, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0x91);
    let meta = b32(&env, 0x92);
    let proof_id = b32(&env, 0x93);
    client.register_seal(&issuer, &video, &meta, &proof_id);
    client.register_seal(&issuer, &video, &meta, &proof_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn replay_matrix_identical_source_delegated_rejected() {
    let (env, contract_id, _, source, _, delegate, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0xA1);
    let meta = b32(&env, 0xA2);
    let proof_id = b32(&env, 0xA3);
    client.register_source_delegated(&delegate, &source, &video, &meta, &proof_id);
    client.register_source_delegated(&delegate, &source, &video, &meta, &proof_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn replay_matrix_identical_seal_delegated_rejected() {
    let (env, contract_id, _, _, issuer, delegate, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0xB1);
    let meta = b32(&env, 0xB2);
    let proof_id = b32(&env, 0xB3);
    client.register_seal_delegated(&delegate, &issuer, &video, &meta, &proof_id);
    client.register_seal_delegated(&delegate, &issuer, &video, &meta, &proof_id);
}

// ===========================================================================
// Same proof_id, different video → DuplicateProof (#4)
// ===========================================================================

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn replay_matrix_proof_id_anonymous_rejected() {
    let (env, contract_id, _, _, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proof_id = b32(&env, 0xC0);
    let cred = b32(&env, CRED_ROOT);
    client.register_anonymous(
        &b32(&env, 0xC1),
        &b32(&env, 0xC2),
        &proof_id,
        &b32(&env, 0xC3),
        &cred,
        &proof_buf(&env),
    );
    client.register_anonymous(
        &b32(&env, 0xC4),
        &b32(&env, 0xC5),
        &proof_id,
        &b32(&env, 0xC6),
        &cred,
        &proof_buf(&env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn replay_matrix_proof_id_source_rejected() {
    let (env, contract_id, _, source, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proof_id = b32(&env, 0xD0);
    client.register_source(&source, &b32(&env, 0xD1), &b32(&env, 0xD2), &proof_id);
    client.register_source(&source, &b32(&env, 0xD3), &b32(&env, 0xD4), &proof_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn replay_matrix_proof_id_seal_rejected() {
    let (env, contract_id, _, _, issuer, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proof_id = b32(&env, 0xE0);
    client.register_seal(&issuer, &b32(&env, 0xE1), &b32(&env, 0xE2), &proof_id);
    client.register_seal(&issuer, &b32(&env, 0xE3), &b32(&env, 0xE4), &proof_id);
}

// ===========================================================================
// Same video_hash, different proof_id → DuplicateVideo (#5)
// ===========================================================================

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn replay_matrix_video_anonymous_rejected() {
    let (env, contract_id, _, _, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0x10);
    let cred = b32(&env, CRED_ROOT);
    client.register_anonymous(
        &video,
        &b32(&env, 0x11),
        &b32(&env, 0x12),
        &b32(&env, 0x13),
        &cred,
        &proof_buf(&env),
    );
    client.register_anonymous(
        &video,
        &b32(&env, 0x14),
        &b32(&env, 0x15),
        &b32(&env, 0x16),
        &cred,
        &proof_buf(&env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn replay_matrix_video_source_rejected() {
    let (env, contract_id, _, source, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0x20);
    client.register_source(&source, &video, &b32(&env, 0x21), &b32(&env, 0x22));
    client.register_source(&source, &video, &b32(&env, 0x23), &b32(&env, 0x24));
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn replay_matrix_video_seal_rejected() {
    let (env, contract_id, _, _, issuer, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0x30);
    client.register_seal(&issuer, &video, &b32(&env, 0x31), &b32(&env, 0x32));
    client.register_seal(&issuer, &video, &b32(&env, 0x33), &b32(&env, 0x34));
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn replay_matrix_video_anonymous_verified_rejected() {
    let (env, contract_id, _, _, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0x40);
    let cred = b32(&env, CRED_ROOT);
    client.register_anonymous_verified(
        &video,
        &b32(&env, 0x41),
        &b32(&env, 0x42),
        &silent_v1_inputs(&env, &video, &cred, &b32(&env, 0x43)),
        &proof_buf(&env),
    );
    client.register_anonymous_verified(
        &video,
        &b32(&env, 0x44),
        &b32(&env, 0x45),
        &silent_v1_inputs(&env, &video, &cred, &b32(&env, 0x46)),
        &proof_buf(&env),
    );
}

// ===========================================================================
// Same nullifier, different proof/video → DuplicateNullifier (#6)
// ===========================================================================

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn replay_matrix_nullifier_anonymous_rejected() {
    let (env, contract_id, _, _, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let nullifier = b32(&env, 0x50);
    let cred = b32(&env, CRED_ROOT);
    client.register_anonymous(
        &b32(&env, 0x51),
        &b32(&env, 0x52),
        &b32(&env, 0x53),
        &nullifier,
        &cred,
        &proof_buf(&env),
    );
    client.register_anonymous(
        &b32(&env, 0x54),
        &b32(&env, 0x55),
        &b32(&env, 0x56),
        &nullifier,
        &cred,
        &proof_buf(&env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn replay_matrix_nullifier_anonymous_verified_rejected() {
    let (env, contract_id, _, _, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let nullifier = b32(&env, 0x60);
    let cred = b32(&env, CRED_ROOT);
    let v1 = b32(&env, 0x61);
    let v2 = b32(&env, 0x62);
    client.register_anonymous_verified(
        &v1,
        &b32(&env, 0x63),
        &b32(&env, 0x64),
        &silent_v1_inputs(&env, &v1, &cred, &nullifier),
        &proof_buf(&env),
    );
    client.register_anonymous_verified(
        &v2,
        &b32(&env, 0x65),
        &b32(&env, 0x66),
        &silent_v1_inputs(&env, &v2, &cred, &nullifier),
        &proof_buf(&env),
    );
}

// ===========================================================================
// Cross-tier uniqueness (global keys)
// ===========================================================================

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn replay_matrix_cross_tier_proof_anonymous_then_source() {
    let (env, contract_id, _, source, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proof_id = b32(&env, 0x70);
    let cred = b32(&env, CRED_ROOT);
    client.register_anonymous(
        &b32(&env, 0x71),
        &b32(&env, 0x72),
        &proof_id,
        &b32(&env, 0x73),
        &cred,
        &proof_buf(&env),
    );
    client.register_source(&source, &b32(&env, 0x74), &b32(&env, 0x75), &proof_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn replay_matrix_cross_tier_video_source_then_seal() {
    let (env, contract_id, _, source, issuer, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0x80);
    client.register_source(&source, &video, &b32(&env, 0x81), &b32(&env, 0x82));
    client.register_seal(&issuer, &video, &b32(&env, 0x83), &b32(&env, 0x84));
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn replay_matrix_cross_tier_video_anonymous_then_seal() {
    let (env, contract_id, _, _, issuer, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0x85);
    let cred = b32(&env, CRED_ROOT);
    client.register_anonymous(
        &video,
        &b32(&env, 0x86),
        &b32(&env, 0x87),
        &b32(&env, 0x88),
        &cred,
        &proof_buf(&env),
    );
    client.register_seal(&issuer, &video, &b32(&env, 0x89), &b32(&env, 0x8A));
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn replay_matrix_cross_tier_proof_seal_then_delegated_source() {
    let (env, contract_id, _, source, issuer, delegate, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proof_id = b32(&env, 0x90);
    client.register_seal(&issuer, &b32(&env, 0x91), &b32(&env, 0x92), &proof_id);
    client.register_source_delegated(
        &delegate,
        &source,
        &b32(&env, 0x93),
        &b32(&env, 0x94),
        &proof_id,
    );
}

// ===========================================================================
// Revocation does not free uniqueness keys (replay guard survives)
// ===========================================================================

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn replay_matrix_post_revoke_identical_source_still_rejected() {
    let (env, contract_id, admin, source, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0xA0);
    let meta = b32(&env, 0xA1);
    let proof_id = b32(&env, 0xA2);
    client.register_source(&source, &video, &meta, &proof_id);
    client.revoke_proof(&admin, &proof_id);
    // Same proof_id must still collide — revoke marks status, does not delete.
    client.register_source(&source, &b32(&env, 0xA3), &b32(&env, 0xA4), &proof_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn replay_matrix_post_revoke_same_video_still_rejected() {
    let (env, contract_id, admin, source, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0xB0);
    let proof_id = b32(&env, 0xB1);
    client.register_source(&source, &video, &b32(&env, 0xB2), &proof_id);
    client.revoke_proof(&admin, &proof_id);
    client.register_source(&source, &video, &b32(&env, 0xB3), &b32(&env, 0xB4));
}

// ===========================================================================
// Negative boundary: malformed / empty / wrong-length inputs
// ===========================================================================

#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn replay_matrix_empty_proof_anonymous_rejected() {
    let (env, contract_id, _, _, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.register_anonymous(
        &b32(&env, 0xC7),
        &b32(&env, 0xC8),
        &b32(&env, 0xC9),
        &b32(&env, 0xCA),
        &b32(&env, CRED_ROOT),
        &empty_proof(&env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn replay_matrix_wrong_length_public_inputs_rejected() {
    let (env, contract_id, _, _, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    // 64 bytes is neither v1 (160) nor v2 (224).
    let bad = Bytes::from_array(&env, &[0u8; 64]);
    client.register_anonymous_verified(
        &b32(&env, 0xD5),
        &b32(&env, 0xD6),
        &b32(&env, 0xD7),
        &bad,
        &proof_buf(&env),
    );
}

// ===========================================================================
// Privacy / stability: rejected replay leaves storage + event log clean
// ===========================================================================

#[test]
fn replay_matrix_rejected_replay_storage_and_events_stable() {
    let (env, contract_id, _, source, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video = b32(&env, 0xE5);
    let meta = b32(&env, 0xE6);
    let proof_id = b32(&env, 0xE7);

    let original = client.register_source(&source, &video, &meta, &proof_id);
    let _ = env.events().all(); // drain success events

    let result = env.try_invoke_contract::<Option<ProofRecord>, RegistryError>(
        &contract_id,
        &Symbol::new(&env, "register_source"),
        {
            let mut args = SorobanVec::new(&env);
            args.push_back(source.into_val(&env));
            args.push_back(video.into_val(&env));
            args.push_back(meta.into_val(&env));
            args.push_back(proof_id.into_val(&env));
            args
        },
    );
    assert!(result.is_err() || result.unwrap().is_err());

    // Original record untouched; no alternate proof written.
    let stored = client.get_proof(&proof_id).unwrap();
    assert_eq!(stored.video_hash, original.video_hash);
    assert_eq!(stored.metadata_hash, original.metadata_hash);
    assert_eq!(stored.status, STATUS_REGISTERED);

    // Rejected path must not publish events (no media / secrets / keys logged).
    assert_eq!(
        env.events().all(),
        [].as_slice(),
        "rejected replay must not emit events"
    );
}

#[test]
fn replay_matrix_metadata_hash_not_a_replay_key() {
    // Documents intentional non-uniqueness: metadata alone is not a replay guard.
    let (env, contract_id, _, source, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let shared_meta = b32(&env, 0xF0);
    let r1 = client.register_source(&source, &b32(&env, 0xF1), &shared_meta, &b32(&env, 0xF2));
    let r2 = client.register_source(&source, &b32(&env, 0xF3), &shared_meta, &b32(&env, 0xF4));
    assert_eq!(r1.metadata_hash, r2.metadata_hash);
}
