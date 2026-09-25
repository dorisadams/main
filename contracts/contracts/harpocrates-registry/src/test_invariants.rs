//! Duplicate-proof and video-hash invariant tests (#45)
//!
//! Uniqueness rules enforced by the registry:
//!
//! | Key             | Scope          | Error on collision    |
//! |-----------------|----------------|-----------------------|
//! | proof_id        | global         | DuplicateProof  (#4)  |
//! | video_hash      | global         | DuplicateVideo  (#5)  |
//! | nullifier       | global         | DuplicateNullifier(#6)|
//!
//! These rules apply identically across all three identity tiers.
//!
//! After every rejected call the suite verifies that:
//!   - The original record is unchanged in storage.
//!   - No new Video or Proof key was written.
//!
//! Events are verified via `env.events().all()`.
#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, testutils::Events as _, Address, Bytes, Env,
    IntoVal,
};

// ---------------------------------------------------------------------------
// Mock verifier (same pattern as test.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[contract]
struct MockVerifier2;

#[cfg(test)]
#[contractimpl]
impl MockVerifier2 {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        let len = public_inputs.len();
        // Canonical frame shapes: 128 (revocation), 160 (silent witness),
        // 224 (scoped silent witness).
        if (len != 128 && len != 160 && len != 224) || proof.is_empty() {
            panic!("invalid proof");
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
fn make_public_inputs(
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
    // Compute expected domain tag
    let domain_tag = expected_domain_tag_inv(env);
    let mut dt = [0u8; 32];
    domain_tag.copy_into_slice(&mut dt);
    // 5 public inputs × 32 bytes = 160 bytes
    let mut buf = [0u8; 160];
    buf[16..32].copy_from_slice(&vh[..16]);
    buf[48..64].copy_from_slice(&vh[16..]);
    buf[64..96].copy_from_slice(&cr);
    buf[96..128].copy_from_slice(&nu);
    buf[128..160].copy_from_slice(&dt);
    Bytes::from_array(env, &buf)
}

#[cfg(test)]
fn expected_domain_tag_inv(env: &Env) -> BytesN<32> {
    let protocol: [u8; 32] = [
        0x26, 0x1e, 0x9f, 0x6e, 0x39, 0xe3, 0xc1, 0xae, 0x6a, 0xca, 0x9f, 0x29, 0xe8, 0x4c, 0x10,
        0xd5, 0x9c, 0x82, 0xd5, 0xf4, 0xb4, 0x0c, 0x21, 0xc1, 0xb7, 0xe3, 0xc0, 0x1a, 0xd5, 0x71,
        0xc2, 0x1,
    ];
    let version: [u8; 32] = [
        0x0c, 0x89, 0xef, 0xf4, 0xec, 0x8e, 0x39, 0xa0, 0x1e, 0x9f, 0x19, 0x54, 0x7a, 0x0c, 0xc9,
        0xdd, 0x7f, 0xd2, 0xa9, 0x7d, 0x79, 0xba, 0x4d, 0x94, 0xfd, 0x32, 0xe9, 0x7a, 0x1f, 0x5a,
        0xc6, 0x23,
    ];
    let network: [u8; 32] = [
        0x2a, 0x2c, 0x3f, 0x48, 0xce, 0x2e, 0x3c, 0x2f, 0x1e, 0x6c, 0x89, 0xb1, 0x8d, 0x64, 0xb5,
        0xf5, 0xc1, 0xf8, 0x8a, 0x59, 0xa0, 0xd9, 0xbc, 0x82, 0xcb, 0x61, 0xa1, 0xe8, 0xcb, 0x77,
        0xa5, 0xf,
    ];
    let mut preimage = Bytes::new(env);
    preimage.extend_from_array(&protocol);
    preimage.extend_from_array(&version);
    preimage.extend_from_array(&network);
    env.crypto().sha256(&preimage).into()
}

/// The credential root used in anonymous-verified calls throughout this module.
const CRED_ROOT_BYTE: u8 = 0xC0;

/// Initialise a fresh registry and return (env, contract_id, admin, verifier_id).
#[cfg(test)]
fn init_registry() -> (Env, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockVerifier2, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    // Credential root used in anonymous-verified registrations
    client.add_credential_root(&admin, &b32(&env, CRED_ROOT_BYTE), &b32(&env, 0xFF));

    (env, contract_id, admin, verifier_id)
}

// ---------------------------------------------------------------------------
// Duplicate proof_id
// ---------------------------------------------------------------------------

/// DuplicateProof across register_source (same tier, same proof_id).
#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn invariant_duplicate_proof_id_same_tier() {
    let (env, contract_id, _, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x01);

    client.register_source(&source, &b32(&env, 0x02), &b32(&env, 0x03), &proof_id);
    // Different video_hash so that isn't the trigger, same proof_id → DuplicateProof
    client.register_source(&source, &b32(&env, 0x04), &b32(&env, 0x05), &proof_id);
}

/// DuplicateProof across different tiers (source then seal).
#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn invariant_duplicate_proof_id_cross_tier_source_then_seal() {
    let (env, contract_id, admin, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAA));
    let proof_id = b32(&env, 0x10);

    client.register_source(&source, &b32(&env, 0x11), &b32(&env, 0x12), &proof_id);
    client.register_seal(&issuer, &b32(&env, 0x13), &b32(&env, 0x14), &proof_id);
}

/// DuplicateProof across different tiers (seal then source).
#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn invariant_duplicate_proof_id_cross_tier_seal_then_source() {
    let (env, contract_id, admin, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAA));
    let proof_id = b32(&env, 0x20);

    client.register_seal(&issuer, &b32(&env, 0x21), &b32(&env, 0x22), &proof_id);
    client.register_source(&source, &b32(&env, 0x23), &b32(&env, 0x24), &proof_id);
}

/// After a rejected duplicate-proof call the original record is unchanged.
#[test]
fn invariant_duplicate_proof_storage_unchanged() {
    let (env, contract_id, _, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x30);
    let video_hash = b32(&env, 0x31);
    let metadata_hash = b32(&env, 0x32);

    let original = client.register_source(&source, &video_hash, &metadata_hash, &proof_id);

    // Attempt duplicate with a DIFFERENT metadata_hash to ensure only the original persists.
    // We call try_invoke_contract directly; the duplicate must be rejected.
    let result = env.try_invoke_contract::<Option<ProofRecord>, RegistryError>(
        &contract_id,
        &soroban_sdk::Symbol::new(&env, "register_source"),
        {
            let mut args = soroban_sdk::Vec::new(&env);
            args.push_back(source.into_val(&env));
            args.push_back(b32(&env, 0x33).into_val(&env)); // new video_hash (different)
            args.push_back(b32(&env, 0x34).into_val(&env)); // new metadata_hash
            args.push_back(proof_id.into_val(&env)); // same proof_id
            args
        },
    );
    // The call must fail
    assert!(result.is_err() || result.unwrap().is_err());

    // Storage must still hold the original record unchanged
    let stored = client.get_proof(&proof_id).unwrap();
    assert_eq!(stored.metadata_hash, original.metadata_hash);
    assert_eq!(stored.video_hash, original.video_hash);
}

// ---------------------------------------------------------------------------
// Duplicate video_hash
// ---------------------------------------------------------------------------

/// DuplicateVideo: same video_hash across two register_source calls.
#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn invariant_duplicate_video_hash_same_tier() {
    let (env, contract_id, _, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let video_hash = b32(&env, 0x40);

    client.register_source(&source, &video_hash, &b32(&env, 0x41), &b32(&env, 0x42));
    // Different proof_id so that isn't the trigger
    client.register_source(&source, &video_hash, &b32(&env, 0x43), &b32(&env, 0x44));
}

/// DuplicateVideo: same video_hash across source and seal tiers.
#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn invariant_duplicate_video_hash_cross_tier() {
    let (env, contract_id, admin, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAA));
    let video_hash = b32(&env, 0x50);

    client.register_source(&source, &video_hash, &b32(&env, 0x51), &b32(&env, 0x52));
    client.register_seal(&issuer, &video_hash, &b32(&env, 0x53), &b32(&env, 0x54));
}

/// After a rejected duplicate-video call the Video→ProofId mapping is unchanged.
#[test]
fn invariant_duplicate_video_storage_unchanged() {
    let (env, contract_id, _, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let video_hash = b32(&env, 0x60);
    let original_proof_id = b32(&env, 0x61);

    client.register_source(&source, &video_hash, &b32(&env, 0x62), &original_proof_id);

    // Try to overwrite with a different proof_id for the same video
    let result = env.try_invoke_contract::<Option<ProofRecord>, RegistryError>(
        &contract_id,
        &soroban_sdk::Symbol::new(&env, "register_source"),
        {
            let mut args = soroban_sdk::Vec::new(&env);
            args.push_back(source.into_val(&env));
            args.push_back(video_hash.into_val(&env)); // same video
            args.push_back(b32(&env, 0x63).into_val(&env));
            args.push_back(b32(&env, 0x64).into_val(&env)); // different proof_id
            args
        },
    );
    assert!(result.is_err() || result.unwrap().is_err());

    // get_by_video still returns the original record
    let stored = client.get_by_video(&video_hash).unwrap();
    assert_eq!(stored.video_hash, video_hash);
    // The second proof_id must not exist
    assert!(client.get_proof(&b32(&env, 0x64)).is_none());
}

// ---------------------------------------------------------------------------
// Duplicate nullifier
// ---------------------------------------------------------------------------

/// DuplicateNullifier within register_anonymous.
#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn invariant_duplicate_nullifier_anonymous() {
    let (env, contract_id, admin, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let nullifier = b32(&env, 0x70);
    let credential_root = b32(&env, 0x71);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x72));

    client.register_anonymous(
        &b32(&env, 0x73),
        &b32(&env, 0x74),
        &b32(&env, 0x75),
        &nullifier,
        &credential_root,
        &proof_buf(&env),
    );
    // Same nullifier, different proof_id and video_hash
    client.register_anonymous(
        &b32(&env, 0x76),
        &b32(&env, 0x77),
        &b32(&env, 0x78),
        &nullifier,
        &credential_root,
        &proof_buf(&env),
    );
}

/// DuplicateNullifier within register_anonymous_verified.
#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn invariant_duplicate_nullifier_anonymous_verified() {
    let (env, contract_id, _, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let credential_root = b32(&env, CRED_ROOT_BYTE);
    let nullifier = b32(&env, 0x80);
    let video_hash1 = b32(&env, 0x81);
    let video_hash2 = b32(&env, 0x82);

    client.register_anonymous_verified(
        &video_hash1,
        &b32(&env, 0x83),
        &b32(&env, 0x84),
        &make_public_inputs(&env, &video_hash1, &credential_root, &nullifier),
        &proof_buf(&env),
    );
    // Reuse nullifier with a different video hash
    client.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0x85),
        &b32(&env, 0x86),
        &make_public_inputs(&env, &video_hash2, &credential_root, &nullifier),
        &proof_buf(&env),
    );
}

/// After a rejected nullifier replay the first record is unchanged.
#[test]
fn invariant_nullifier_replay_storage_unchanged() {
    let (env, contract_id, admin, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let nullifier = b32(&env, 0x90);
    let credential_root = b32(&env, 0x91);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x92));

    let original = client.register_anonymous(
        &b32(&env, 0x93),
        &b32(&env, 0x94),
        &b32(&env, 0x95),
        &nullifier,
        &credential_root,
        &proof_buf(&env),
    );

    let result = env.try_invoke_contract::<Option<ProofRecord>, RegistryError>(
        &contract_id,
        &soroban_sdk::Symbol::new(&env, "register_anonymous"),
        {
            let mut args = soroban_sdk::Vec::new(&env);
            args.push_back(b32(&env, 0x96).into_val(&env)); // new video_hash
            args.push_back(b32(&env, 0x97).into_val(&env));
            args.push_back(b32(&env, 0x98).into_val(&env)); // new proof_id
            args.push_back(nullifier.into_val(&env)); // same nullifier → replay
            args.push_back(credential_root.into_val(&env));
            args.push_back(proof_buf(&env).into_val(&env));
            args
        },
    );
    assert!(result.is_err() || result.unwrap().is_err());

    // The nullifier flag is still present
    assert!(client.has_nullifier(&nullifier));
    // The new proof_id must not have been written
    assert!(client.get_proof(&b32(&env, 0x98)).is_none());
    // Original record intact (verify via video lookup)
    let stored = client.get_by_video(&original.video_hash).unwrap();
    assert_eq!(stored.nullifier, Some(nullifier));
}

// ---------------------------------------------------------------------------
// Metadata hash: intentionally NOT a uniqueness constraint
// ---------------------------------------------------------------------------

/// The registry does NOT enforce uniqueness on metadata_hash.
/// Two proofs for different videos may share the same metadata_hash.
/// This test documents the intended behavior.
#[test]
fn invariant_metadata_hash_is_not_unique() {
    let (env, contract_id, _, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let shared_metadata = b32(&env, 0xA0);

    let r1 = client.register_source(
        &source,
        &b32(&env, 0xA1),
        &shared_metadata,
        &b32(&env, 0xA2),
    );
    let r2 = client.register_source(
        &source,
        &b32(&env, 0xA3),
        &shared_metadata,
        &b32(&env, 0xA4),
    );
    // Both registrations succeed and share the metadata_hash
    assert_eq!(r1.metadata_hash, r2.metadata_hash);
}

// ---------------------------------------------------------------------------
// Event emission
// ---------------------------------------------------------------------------

/// A successful registration emits exactly one ProofRegistered event.
/// We check that at least one event appears after registration.
#[test]
fn invariant_registration_emits_event() {
    let (env, contract_id, _, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0xB0);

    client.register_source(&source, &b32(&env, 0xB1), &b32(&env, 0xB2), &proof_id);

    // ContractEvents implements PartialEq<[ContractEvent; 0]>; inequality means events were emitted.
    assert_ne!(
        env.events().all(),
        [].as_slice(),
        "expected at least one event after registration"
    );
}

/// A duplicate-proof rejection must NOT emit any new event.
#[test]
fn invariant_duplicate_rejection_emits_no_event() {
    let (env, contract_id, _, _) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0xC0);

    client.register_source(&source, &b32(&env, 0xC1), &b32(&env, 0xC2), &proof_id);

    // Drain the event log so it is empty before the next call.
    let _ = env.events().all();

    // Attempt duplicate — must fail
    let result = env.try_invoke_contract::<Option<ProofRecord>, RegistryError>(
        &contract_id,
        &soroban_sdk::Symbol::new(&env, "register_source"),
        {
            let mut args = soroban_sdk::Vec::new(&env);
            args.push_back(source.into_val(&env));
            args.push_back(b32(&env, 0xC3).into_val(&env));
            args.push_back(b32(&env, 0xC4).into_val(&env));
            args.push_back(proof_id.into_val(&env)); // duplicate
            args
        },
    );
    assert!(result.is_err() || result.unwrap().is_err());

    // env.events().all() is consumed per-call; after a failed call no new
    // contract events should appear (panics abort before any publish).
    assert_eq!(
        env.events().all(),
        [].as_slice(),
        "rejected call must not emit new events"
    );
}
