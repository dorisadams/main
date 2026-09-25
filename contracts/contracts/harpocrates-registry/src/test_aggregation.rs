/// Aggregation integration tests
///
/// ## Batch aggregation semantics
///
/// The `register_batch_verified` entry point accepts up to MAX_AGGREGATION_SIZE
/// video hashes bundled into a single aggregated UltraHonk proof.  A single
/// aggregated proof thus replaces N individual proofs, reducing on-chain
/// verification costs.
///
/// All credential roots in the batch must be identical (same identity).
/// Each video hash gets a deterministic sub-proof_id derived from the batch_id.
///
/// ## Test strategy
///
/// - Happy path: verify a valid batch registers all elements successfully.
/// - Size bounds: empty batch, oversized batch.
/// - Integrity: mismatched credential roots, duplicate video hashes,
///   duplicate nullifiers, reused batch_id.
/// - Domain binding: wrong domain separator in public inputs.
/// - Verifier rejection: verifier contract refuses the aggregated proof.

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Events as _},
    Address, Bytes, BytesN, Env, Vec as SorobanVec,
};

use std::vec::Vec as StdVec;

// ---------------------------------------------------------------------------
// Mock UltraHonk verifier for testing the aggregation proof boundary
// ---------------------------------------------------------------------------

#[cfg(test)]
#[contract]
struct MockAggregationVerifier;

#[cfg(test)]
#[contractimpl]
impl MockAggregationVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        if public_inputs.len() < 32 || proof.is_empty() {
            panic!("invalid aggregated proof");
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
fn proof_bytes(env: &Env) -> Bytes {
    Bytes::from_array(env, &[0xAA, 0xBB, 0xCC, 0xDD])
}

/// Build aggregated batch public inputs.
///
/// Layout:
///   [   0..  32)  domain_separator      – AGGREGATION_DOMAIN_SEPARATOR
///   [  32.. 160)  element_0             – 128 bytes
///   [ 160.. 288)  element_1             – 128 bytes
///   ...
///
/// Each element:
///   [  0.. 32)  video_hash_hi     → hi limb (bytes 16..32 used)
///   [ 32.. 64)  video_hash_lo     → lo limb (bytes 48..64 used)
///   [ 64.. 96)  credential_root
///   [ 96..128)  nullifier
#[cfg(test)]
fn build_aggregated_public_inputs(
    env: &Env,
    domain_separator: &BytesN<32>,
    elements: &[(BytesN<32>, BytesN<32>, BytesN<32>)], // (video_hash, credential_root, nullifier)
) -> Bytes {
    let count = elements.len() as u32;
    let total_len = 32 + (count * 128);
    let mut raw: StdVec<u8> = {
        let zeros: StdVec<u8> = core::iter::repeat(0u8).take(total_len as usize).collect();
        zeros
    };

    // Domain separator
    let mut ds = [0u8; 32];
    domain_separator.copy_into_slice(&mut ds);
    raw[0..32].copy_from_slice(&ds);

    for (i, (video_hash, credential_root, nullifier)) in elements.iter().enumerate() {
        let offset = 32 + (i * 128);

        let mut vh = [0u8; 32];
        video_hash.copy_into_slice(&mut vh);

        let mut cr = [0u8; 32];
        credential_root.copy_into_slice(&mut cr);

        let mut nf = [0u8; 32];
        nullifier.copy_into_slice(&mut nf);

        // Element layout matching silent_witness public inputs:
        // video_hash_hi low 16 bytes → raw[16..32]
        // video_hash_lo low 16 bytes → raw[48..64]
        raw[offset + 16..offset + 32].copy_from_slice(&vh[..16]);
        raw[offset + 48..offset + 64].copy_from_slice(&vh[16..]);
        raw[offset + 64..offset + 96].copy_from_slice(&cr);
        raw[offset + 96..offset + 128].copy_from_slice(&nf);
    }

    Bytes::from_slice(env, raw.as_slice())
}

/// Build the AGGREGATION_DOMAIN_SEPARATOR constant for tests.
#[cfg(test)]
fn aggregation_domain(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &AGGREGATION_DOMAIN_SEPARATOR)
}

// ---------------------------------------------------------------------------
// Tests — register_batch_verified
// ---------------------------------------------------------------------------

/// Happy path: register a batch of 3 video hashes under the same credential.
#[test]
fn test_batch_register_succeeds() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockAggregationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let batch_id = b32(&env, 0xBB);
    let metadata_hash = b32(&env, 0x6D); // 'm' — 0xMM is not valid hex
    let credential_root = b32(&env, 0xAA);
    let nullifier_0 = b32(&env, 0x10);
    let nullifier_1 = b32(&env, 0x20);
    let nullifier_2 = b32(&env, 0x30);
    let vh_0 = b32(&env, 0x01);
    let vh_1 = b32(&env, 0x02);
    let vh_2 = b32(&env, 0x03);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0xCF));

    let elements = &[
        (vh_0.clone(), credential_root.clone(), nullifier_0.clone()),
        (vh_1.clone(), credential_root.clone(), nullifier_1.clone()),
        (vh_2.clone(), credential_root.clone(), nullifier_2.clone()),
    ];
    let pi = build_aggregated_public_inputs(&env, &aggregation_domain(&env), elements);

    let mut video_hashes: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
    video_hashes.push_back(vh_0.clone());
    video_hashes.push_back(vh_1.clone());
    video_hashes.push_back(vh_2.clone());

    let results = client.register_batch_verified(
        &batch_id,
        &metadata_hash,
        &pi,
        &proof_bytes(&env),
        &video_hashes,
    );

    // Snapshot immediately: env.events().all() reflects only the most recent
    // invocation, and later queries below would clear the batch events.
    let events = env.events().all();

    assert_eq!(results.len(), 3, "expected 3 proof records");
    for (i, record) in results.iter().enumerate() {
        assert_eq!(record.tier, TIER_SILENT_WITNESS);
        assert_eq!(record.batch_size, 3);
        assert_eq!(record.status, STATUS_REGISTERED);
        // Each element's proof_id is derived deterministically from batch_id
        let expected_proof_id = derive_element_proof_id(&env, &batch_id, i as u32);
        let stored = client.get_proof(&expected_proof_id).unwrap();
        assert_eq!(
            stored.batch_size, 3,
            "element {} should have batch_size=3",
            i
        );
    }

    // Nullifiers should be consumed.
    assert!(client.has_nullifier(&nullifier_0));
    assert!(client.has_nullifier(&nullifier_1));
    assert!(client.has_nullifier(&nullifier_2));

    // Video hashes should be registered.
    for vh in [vh_0, vh_1, vh_2] {
        let record = client.get_by_video(&vh);
        assert!(record.is_some(), "video hash should be registered");
    }

    // Batch-level event should be emitted (captured right after the call).
    assert!(
        !events.events().is_empty(),
        "expected events after batch registration"
    );
}

/// Empty batch should be rejected.
#[test]
#[should_panic(expected = "Error(Contract, #54)")] // BatchSizeExceeded
fn test_batch_register_empty() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockAggregationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let batch_id = b32(&env, 0xBB);
    let metadata_hash = b32(&env, 0x6D); // 'm' — 0xMM is not valid hex
    let credential_root = b32(&env, 0xAA);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0xCF));

    // Empty public inputs (just domain separator = 32 bytes)
    let pi = Bytes::from_array(&env, &AGGREGATION_DOMAIN_SEPARATOR);
    let mut video_hashes: SorobanVec<BytesN<32>> = SorobanVec::new(&env);

    client.register_batch_verified(
        &batch_id,
        &metadata_hash,
        &pi,
        &proof_bytes(&env),
        &video_hashes,
    );
}

/// Oversized batch (MAX_AGGREGATION_SIZE + 1) should be rejected.
#[test]
#[should_panic(expected = "Error(Contract, #54)")] // BatchSizeExceeded
fn test_batch_register_oversized() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockAggregationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let batch_id = b32(&env, 0xBB);
    let metadata_hash = b32(&env, 0x6D); // 'm' — 0xMM is not valid hex
    let credential_root = b32(&env, 0xAA);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0xCF));

    // 9 elements (MAX = 8)
    let mut elements: StdVec<(BytesN<32>, BytesN<32>, BytesN<32>)> = StdVec::new();
    let mut video_hashes: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
    for i in 0..9u8 {
        video_hashes.push_back(b32(&env, i));
        elements.push((b32(&env, i), credential_root.clone(), b32(&env, i + 0x10)));
    }

    let pi = build_aggregated_public_inputs(&env, &aggregation_domain(&env), &elements);
    client.register_batch_verified(
        &batch_id,
        &metadata_hash,
        &pi,
        &proof_bytes(&env),
        &video_hashes,
    );
}

/// Rejects when credential roots within the batch are not all identical.
#[test]
#[should_panic(expected = "Error(Contract, #55)")] // BatchCredentialRootMismatch
fn test_batch_register_mismatched_credential_roots() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockAggregationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let batch_id = b32(&env, 0xBB);
    let metadata_hash = b32(&env, 0x6D); // 'm' — 0xMM is not valid hex
    let credential_root_a = b32(&env, 0xAA);
    let credential_root_b = b32(&env, 0xBB); // different
    let nullifier_0 = b32(&env, 0x10);
    let nullifier_1 = b32(&env, 0x20);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root_a, &b32(&env, 0xCF));

    let elements = &[
        (
            b32(&env, 0x01),
            credential_root_a.clone(),
            nullifier_0.clone(),
        ),
        (
            b32(&env, 0x02),
            credential_root_b.clone(),
            nullifier_1.clone(),
        ), // different root
    ];
    let pi = build_aggregated_public_inputs(&env, &aggregation_domain(&env), elements);

    let mut video_hashes: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
    video_hashes.push_back(b32(&env, 0x01));
    video_hashes.push_back(b32(&env, 0x02));

    client.register_batch_verified(
        &batch_id,
        &metadata_hash,
        &pi,
        &proof_bytes(&env),
        &video_hashes,
    );
}

/// Rejects when no verifier is configured.
#[test]
#[should_panic(expected = "Error(Contract, #9)")] // VerifierNotSet
fn test_batch_register_no_verifier() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let batch_id = b32(&env, 0xBB);
    let metadata_hash = b32(&env, 0x6D); // 'm' — 0xMM is not valid hex
    let credential_root = b32(&env, 0xAA);

    client.init(&admin);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0xCF));

    let elements = &[(b32(&env, 0x01), credential_root.clone(), b32(&env, 0x10))];
    let pi = build_aggregated_public_inputs(&env, &aggregation_domain(&env), elements);

    let mut video_hashes: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
    video_hashes.push_back(b32(&env, 0x01));

    client.register_batch_verified(
        &batch_id,
        &metadata_hash,
        &pi,
        &proof_bytes(&env),
        &video_hashes,
    );
}

/// Rejects when credential root is not registered.
#[test]
#[should_panic(expected = "Error(Contract, #11)")] // UnknownCredentialRoot
fn test_batch_register_unknown_credential_root() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockAggregationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let batch_id = b32(&env, 0xBB);
    let metadata_hash = b32(&env, 0x6D); // 'm' — 0xMM is not valid hex
    let unknown_credential_root = b32(&env, 0x5A); // never registered (0xZZ is not valid hex)

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);

    let elements = &[(
        b32(&env, 0x01),
        unknown_credential_root.clone(),
        b32(&env, 0x10),
    )];
    let pi = build_aggregated_public_inputs(&env, &aggregation_domain(&env), elements);

    let mut video_hashes: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
    video_hashes.push_back(b32(&env, 0x01));

    client.register_batch_verified(
        &batch_id,
        &metadata_hash,
        &pi,
        &proof_bytes(&env),
        &video_hashes,
    );
}

/// Rejects when the domain separator doesn't match.
#[test]
#[should_panic(expected = "Error(Contract, #10)")] // InvalidPublicInputs
fn test_batch_register_wrong_domain() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockAggregationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let batch_id = b32(&env, 0xBB);
    let metadata_hash = b32(&env, 0x6D); // 'm' — 0xMM is not valid hex
    let credential_root = b32(&env, 0xAA);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0xCF));

    // Wrong domain separator
    let wrong_domain = b32(&env, 0xFF);

    let elements = &[(b32(&env, 0x01), credential_root.clone(), b32(&env, 0x10))];
    let pi = build_aggregated_public_inputs(&env, &wrong_domain, elements);

    let mut video_hashes: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
    video_hashes.push_back(b32(&env, 0x01));

    client.register_batch_verified(
        &batch_id,
        &metadata_hash,
        &pi,
        &proof_bytes(&env),
        &video_hashes,
    );
}

/// Rejects when a duplicate nullifier is submitted.
#[test]
#[should_panic(expected = "Error(Contract, #6)")] // DuplicateNullifier
fn test_batch_register_duplicate_nullifier() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockAggregationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let batch_id = b32(&env, 0xBB);
    let metadata_hash = b32(&env, 0x6D); // 'm' — 0xMM is not valid hex
    let credential_root = b32(&env, 0xAA);
    let nullifier = b32(&env, 0x10);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0xCF));

    // Same nullifier for both elements
    let elements = &[
        (b32(&env, 0x01), credential_root.clone(), nullifier.clone()),
        (b32(&env, 0x02), credential_root.clone(), nullifier.clone()), // same nullifier
    ];
    let pi = build_aggregated_public_inputs(&env, &aggregation_domain(&env), elements);

    let mut video_hashes: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
    video_hashes.push_back(b32(&env, 0x01));
    video_hashes.push_back(b32(&env, 0x02));

    client.register_batch_verified(
        &batch_id,
        &metadata_hash,
        &pi,
        &proof_bytes(&env),
        &video_hashes,
    );
}

/// Rejects when public inputs length doesn't match the declared batch size.
#[test]
#[should_panic(expected = "Error(Contract, #10)")] // InvalidPublicInputs
fn test_batch_register_wrong_input_length() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockAggregationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let batch_id = b32(&env, 0xBB);
    let metadata_hash = b32(&env, 0x6D); // 'm' — 0xMM is not valid hex
    let credential_root = b32(&env, 0xAA);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0xCF));

    // Provide only 32 bytes (just domain separator, no elements)
    let pi = Bytes::from_array(&env, &AGGREGATION_DOMAIN_SEPARATOR);

    let mut video_hashes: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
    video_hashes.push_back(b32(&env, 0x01));
    // 1 video hash but 0-element public inputs

    client.register_batch_verified(
        &batch_id,
        &metadata_hash,
        &pi,
        &proof_bytes(&env),
        &video_hashes,
    );
}

/// Verifier contract rejects the aggregated proof.
#[test]
#[should_panic(expected = "Error(Contract, #7)")] // InvalidProof
fn test_batch_register_verifier_rejects() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    // Register a verifier that always rejects
    let verifier_id = env.register(MockRejectingVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let batch_id = b32(&env, 0xBB);
    let metadata_hash = b32(&env, 0x6D); // 'm' — 0xMM is not valid hex
    let credential_root = b32(&env, 0xAA);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0xCF));

    let elements = &[(b32(&env, 0x01), credential_root.clone(), b32(&env, 0x10))];
    let pi = build_aggregated_public_inputs(&env, &aggregation_domain(&env), elements);

    let mut video_hashes: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
    video_hashes.push_back(b32(&env, 0x01));

    client.register_batch_verified(
        &batch_id,
        &metadata_hash,
        &pi,
        &proof_bytes(&env),
        &video_hashes,
    );
}

/// Verifier contract that always rejects proofs.
#[cfg(test)]
#[contract]
struct MockRejectingVerifier;

#[cfg(test)]
#[contractimpl]
impl MockRejectingVerifier {
    pub fn verify_proof(_env: Env, _public_inputs: Bytes, _proof: Bytes) {
        panic!("mock verifier always rejects");
    }
}

/// MAX_AGGREGATION_SIZE batch (8 elements) should succeed.
#[test]
fn test_batch_register_max_size() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockAggregationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let batch_id = b32(&env, 0xFF);
    let metadata_hash = b32(&env, 0xDD);
    let credential_root = b32(&env, 0xAA);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0xCF));

    let mut elements: StdVec<(BytesN<32>, BytesN<32>, BytesN<32>)> = StdVec::new();
    let mut video_hashes: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
    for i in 0..MAX_AGGREGATION_SIZE {
        let vh = b32(&env, i as u8);
        let nf = b32(&env, (i + 0x10) as u8);
        video_hashes.push_back(vh.clone());
        elements.push((vh, credential_root.clone(), nf));
    }

    let pi = build_aggregated_public_inputs(&env, &aggregation_domain(&env), &elements);
    let results = client.register_batch_verified(
        &batch_id,
        &metadata_hash,
        &pi,
        &proof_bytes(&env),
        &video_hashes,
    );

    assert_eq!(results.len(), MAX_AGGREGATION_SIZE as u32);
    for (i, record) in results.iter().enumerate() {
        assert_eq!(record.batch_size, MAX_AGGREGATION_SIZE as u32);
        assert_eq!(record.tier, TIER_SILENT_WITNESS);
        assert_eq!(record.status, STATUS_REGISTERED);

        // Verify the element can be looked up by both proof_id and video hash
        let expected_proof_id = derive_element_proof_id(&env, &batch_id, i as u32);
        let by_proof = client.get_proof(&expected_proof_id);
        assert!(
            by_proof.is_some(),
            "element {} should be findable by proof_id",
            i
        );

        let vh = video_hashes.get(i as u32).unwrap();
        let by_video = client.get_by_video(&vh);
        assert!(
            by_video.is_some(),
            "element {} video hash should be registered",
            i
        );
    }
}
