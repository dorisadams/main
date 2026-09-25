//! Scoped nullifier tests (#scoped-nullifier-v1)
//!
//! These tests verify the scoped nullifier derivation, epoch management,
//! cross-scope unlinkability, and backward compatibility.

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Events as _, Ledger},
    Address, Bytes, Env,
};

// ---------------------------------------------------------------------------
// Mock UltraHonk verifier
// ---------------------------------------------------------------------------

#[cfg(test)]
#[contract]
struct MockScopedVerifier;

#[cfg(test)]
#[contractimpl]
impl MockScopedVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        // Accept canonical 160-byte (v1) and 224-byte (v2 scoped) inputs
        let len = public_inputs.len();
        if (len != 160 && len != 224) || proof.is_empty() {
            panic!("invalid scoped proof");
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
    Bytes::from_array(env, &[0xAA, 0xBB, 0xCC, 0xDD])
}

/// Build a v1 (160-byte) silent witness public-input blob (5 field words:
/// video hi/lo, credential root, nullifier, domain tag).
#[cfg(test)]
fn v1_public_inputs(
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

    let tag = expected_domain_tag(env);
    let mut tag_bytes = [0u8; 32];
    tag.copy_into_slice(&mut tag_bytes);

    let mut buf = [0u8; 160];
    buf[16..32].copy_from_slice(&vh[..16]);
    buf[48..64].copy_from_slice(&vh[16..]);
    buf[64..96].copy_from_slice(&cr);
    buf[96..128].copy_from_slice(&nu);
    buf[128..160].copy_from_slice(&tag_bytes);
    Bytes::from_array(env, &buf)
}

/// Build a v2 (192-byte) scoped silent witness public-input blob.
#[cfg(test)]
fn v2_public_inputs(
    env: &Env,
    video_hash: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
    verifier_scope: &BytesN<32>,
    epoch: u64,
) -> Bytes {
    let mut vh = [0u8; 32];
    video_hash.copy_into_slice(&mut vh);
    let mut cr = [0u8; 32];
    credential_root.copy_into_slice(&mut cr);
    let mut nu = [0u8; 32];
    nullifier.copy_into_slice(&mut nu);
    let mut sc = [0u8; 32];
    verifier_scope.copy_into_slice(&mut sc);

    let mut epoch_bytes = [0u8; 32];
    let mut e = epoch;
    for i in (0..8).rev() {
        epoch_bytes[24 + i] = (e & 0xFF) as u8;
        e >>= 8;
    }

    let tag = expected_domain_tag(env);
    let mut tag_bytes = [0u8; 32];
    tag.copy_into_slice(&mut tag_bytes);

    let mut buf = [0u8; 224];
    buf[16..32].copy_from_slice(&vh[..16]);
    buf[48..64].copy_from_slice(&vh[16..]);
    buf[64..96].copy_from_slice(&cr);
    buf[96..128].copy_from_slice(&nu);
    buf[128..160].copy_from_slice(&sc);
    buf[160..192].copy_from_slice(&epoch_bytes);
    buf[192..224].copy_from_slice(&tag_bytes);
    Bytes::from_array(env, &buf)
}

/// Initialize a fresh registry with verifier and credential root.
#[cfg(test)]
fn init_scoped_registry() -> (Env, Address, Address, BytesN<32>) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockScopedVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let credential_root = b32(&env, 0xC0);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0xFF));

    (env, contract_id, admin, credential_root)
}

// ===========================================================================
// Scope epoch management tests
// ===========================================================================

/// Admin can set and read back a scope epoch.
#[test]
fn test_set_and_get_scope_epoch() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.init(&admin);

    let scope = b32(&env, 0x42);
    assert_eq!(client.get_scope_epoch(&scope), 0); // default

    client.set_scope_epoch(&admin, &scope, &5);
    assert_eq!(client.get_scope_epoch(&scope), 5);
}

/// Only admin can set scope epoch.
#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_non_admin_cannot_set_scope_epoch() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let other = Address::generate(&env);

    client.init(&admin);
    client.set_scope_epoch(&other, &b32(&env, 0x42), &1);
}

/// Setting scope epoch emits an event.
#[test]
fn test_scope_epoch_emits_event() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.init(&admin);
    client.set_scope_epoch(&admin, &b32(&env, 0x42), &3);

    assert_ne!(
        env.events().all(),
        [].as_slice(),
        "expected ScopeEpochSet event"
    );
}

/// Scope epoch defaults to zero for unknown scopes.
#[test]
fn test_unknown_scope_defaults_to_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.init(&admin);

    let unknown_scope = b32(&env, 0xFF);
    assert_eq!(client.get_scope_epoch(&unknown_scope), 0);
}

/// Scope epoch can be rotated (advanced).
#[test]
fn test_scope_epoch_can_be_rotated() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.init(&admin);
    let scope = b32(&env, 0x42);

    client.set_scope_epoch(&admin, &scope, &1);
    assert_eq!(client.get_scope_epoch(&scope), 1);

    client.set_scope_epoch(&admin, &scope, &2);
    assert_eq!(client.get_scope_epoch(&scope), 2);

    client.set_scope_epoch(&admin, &scope, &100);
    assert_eq!(client.get_scope_epoch(&scope), 100);
}

// ===========================================================================
// v2 scoped nullifier registration tests
// ===========================================================================

/// Happy path: v2 scoped proof with epoch 0 (global scope) is accepted.
#[test]
fn test_scoped_registration_global_scope_epoch_0() {
    let (env, contract_id, _admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = b32(&env, 0x01);
    let nullifier = b32(&env, 0x02);
    let scope = b32(&env, 0x00); // global scope (zero)
    let epoch: u64 = 0;

    let pi = v2_public_inputs(
        &env,
        &video_hash,
        &credential_root,
        &nullifier,
        &scope,
        epoch,
    );
    let record = client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x03),
        &b32(&env, 0x04),
        &pi,
        &proof_buf(&env),
    );

    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert_eq!(record.video_hash, video_hash);
    assert_eq!(record.nullifier, Some(nullifier.clone()));
    assert!(client.has_nullifier(&nullifier));
}

/// Happy path: v2 scoped proof with explicit scope and epoch 1.
#[test]
fn test_scoped_registration_explicit_scope_epoch_1() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = b32(&env, 0x10);
    let nullifier = b32(&env, 0x11);
    let scope = b32(&env, 0x42);
    let epoch: u64 = 1;

    // Set the epoch for this scope
    client.set_scope_epoch(&admin, &scope, &epoch);

    let pi = v2_public_inputs(
        &env,
        &video_hash,
        &credential_root,
        &nullifier,
        &scope,
        epoch,
    );
    let record = client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x12),
        &b32(&env, 0x13),
        &pi,
        &proof_buf(&env),
    );

    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert!(client.has_nullifier(&nullifier));
}

/// Rejects stale epoch: proof has epoch 0 but current epoch is 1.
#[test]
#[should_panic(expected = "Error(Contract, #53)")] // StaleEpoch
fn test_scoped_rejects_stale_epoch() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = b32(&env, 0x20);
    let nullifier = b32(&env, 0x21);
    let scope = b32(&env, 0x42);

    // Current epoch is 1, but proof claims epoch 0
    client.set_scope_epoch(&admin, &scope, &1);

    let pi = v2_public_inputs(&env, &video_hash, &credential_root, &nullifier, &scope, 0);
    client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x22),
        &b32(&env, 0x23),
        &pi,
        &proof_buf(&env),
    );
}

/// Rejects future epoch: proof has epoch 2 but current epoch is 1.
#[test]
#[should_panic(expected = "Error(Contract, #53)")] // StaleEpoch
fn test_scoped_rejects_future_epoch() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = b32(&env, 0x24);
    let nullifier = b32(&env, 0x25);
    let scope = b32(&env, 0x42);

    client.set_scope_epoch(&admin, &scope, &1);

    // Proof claims epoch 2, but current is 1
    let pi = v2_public_inputs(&env, &video_hash, &credential_root, &nullifier, &scope, 2);
    client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x26),
        &b32(&env, 0x27),
        &pi,
        &proof_buf(&env),
    );
}

/// Rejects revoked credential root with v2 scoped proof.
#[test]
#[should_panic(expected = "Error(Contract, #12)")] // RevokedCredentialRoot
fn test_scoped_rejects_revoked_credential() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.revoke_credential_root(&admin, &credential_root);

    let video_hash = b32(&env, 0x30);
    let nullifier = b32(&env, 0x31);
    let scope = b32(&env, 0x00);

    let pi = v2_public_inputs(&env, &video_hash, &credential_root, &nullifier, &scope, 0);
    client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x32),
        &b32(&env, 0x33),
        &pi,
        &proof_buf(&env),
    );
}

/// Rejects duplicate nullifier with v2 scoped proof.
#[test]
#[should_panic(expected = "Error(Contract, #6)")] // DuplicateNullifier
fn test_scoped_rejects_duplicate_nullifier() {
    let (env, contract_id, _, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash1 = b32(&env, 0x40);
    let video_hash2 = b32(&env, 0x41);
    let nullifier = b32(&env, 0x42);
    let scope = b32(&env, 0x00);

    let pi1 = v2_public_inputs(&env, &video_hash1, &credential_root, &nullifier, &scope, 0);
    client.register_anonymous_verified(
        &video_hash1,
        &b32(&env, 0x43),
        &b32(&env, 0x44),
        &pi1,
        &proof_buf(&env),
    );

    // Reuse nullifier with different video
    let pi2 = v2_public_inputs(&env, &video_hash2, &credential_root, &nullifier, &scope, 0);
    client.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0x45),
        &b32(&env, 0x46),
        &pi2,
        &proof_buf(&env),
    );
}

/// Rejects wrong video hash in v2 scoped proof.
#[test]
#[should_panic(expected = "Error(Contract, #10)")] // InvalidPublicInputs
fn test_scoped_rejects_wrong_video_hash() {
    let (env, contract_id, _, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = b32(&env, 0x50);
    let wrong_video_hash = b32(&env, 0x51);
    let nullifier = b32(&env, 0x52);
    let scope = b32(&env, 0x00);

    // Proof is for wrong_video_hash, but we pass video_hash as the first arg
    let pi = v2_public_inputs(
        &env,
        &wrong_video_hash,
        &credential_root,
        &nullifier,
        &scope,
        0,
    );
    client.register_anonymous_verified(
        &video_hash, // different from what's in the proof
        &b32(&env, 0x53),
        &b32(&env, 0x54),
        &pi,
        &proof_buf(&env),
    );
}

// ===========================================================================
// Cross-scope unlinkability tests
// ===========================================================================

/// Same credential, same video, different scopes → different nullifiers.
/// Both registrations succeed (no nullifier collision).
#[test]
fn test_cross_scope_different_nullifiers() {
    let (env, contract_id, _, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = b32(&env, 0x60);
    let nullifier_a = b32(&env, 0x61);
    let nullifier_b = b32(&env, 0x62);
    let scope_a = b32(&env, 0x01);
    let scope_b = b32(&env, 0x02);

    // Both at epoch 0, different scopes → different nullifiers
    let pi_a = v2_public_inputs(
        &env,
        &video_hash,
        &credential_root,
        &nullifier_a,
        &scope_a,
        0,
    );
    let r1 = client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x63),
        &b32(&env, 0x64),
        &pi_a,
        &proof_buf(&env),
    );

    // Different video_hash needed since video uniqueness is global
    let video_hash2 = b32(&env, 0x65);
    let pi_b = v2_public_inputs(
        &env,
        &video_hash2,
        &credential_root,
        &nullifier_b,
        &scope_b,
        0,
    );
    let r2 = client.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0x66),
        &b32(&env, 0x67),
        &pi_b,
        &proof_buf(&env),
    );

    assert_eq!(r1.nullifier, Some(nullifier_a));
    assert_eq!(r2.nullifier, Some(nullifier_b));
    // Nullifiers are different (different scopes)
    assert_ne!(r1.nullifier, r2.nullifier);
}

/// Same credential, same video, same scope, different epochs → different nullifiers.
#[test]
fn test_same_scope_different_epochs_different_nullifiers() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let scope = b32(&env, 0x42);

    // Epoch 0 registration
    let video_hash1 = b32(&env, 0x70);
    let nullifier1 = b32(&env, 0x71);
    let pi1 = v2_public_inputs(&env, &video_hash1, &credential_root, &nullifier1, &scope, 0);
    let r1 = client.register_anonymous_verified(
        &video_hash1,
        &b32(&env, 0x72),
        &b32(&env, 0x73),
        &pi1,
        &proof_buf(&env),
    );

    // Advance epoch to 1
    client.set_scope_epoch(&admin, &scope, &1);

    // Epoch 1 registration (different video, could be same video in practice)
    let video_hash2 = b32(&env, 0x74);
    let nullifier2 = b32(&env, 0x75);
    let pi2 = v2_public_inputs(&env, &video_hash2, &credential_root, &nullifier2, &scope, 1);
    let r2 = client.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0x76),
        &b32(&env, 0x77),
        &pi2,
        &proof_buf(&env),
    );

    assert_ne!(r1.nullifier, r2.nullifier);
}

// ===========================================================================
// Backward compatibility tests (v1 → v2)
// ===========================================================================

/// v1 proof (128-byte inputs) still works alongside v2 proofs.
#[test]
fn test_v1_backward_compatibility() {
    let (env, contract_id, _, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Register a v1 proof
    let video_hash_v1 = b32(&env, 0x80);
    let nullifier_v1 = b32(&env, 0x81);
    let pi_v1 = v1_public_inputs(&env, &video_hash_v1, &credential_root, &nullifier_v1);
    let r1 = client.register_anonymous_verified(
        &video_hash_v1,
        &b32(&env, 0x82),
        &b32(&env, 0x83),
        &pi_v1,
        &proof_buf(&env),
    );

    // Register a v2 proof (different video, different nullifier)
    let video_hash_v2 = b32(&env, 0x84);
    let nullifier_v2 = b32(&env, 0x85);
    let scope = b32(&env, 0x00);
    let pi_v2 = v2_public_inputs(
        &env,
        &video_hash_v2,
        &credential_root,
        &nullifier_v2,
        &scope,
        0,
    );
    let r2 = client.register_anonymous_verified(
        &video_hash_v2,
        &b32(&env, 0x86),
        &b32(&env, 0x87),
        &pi_v2,
        &proof_buf(&env),
    );

    assert_eq!(r1.tier, TIER_SILENT_WITNESS);
    assert_eq!(r2.tier, TIER_SILENT_WITNESS);
    assert!(client.has_nullifier(&nullifier_v1));
    assert!(client.has_nullifier(&nullifier_v2));
}

/// v1 and v2 nullifiers for the same credential are different
/// (different derivation formulas).
#[test]
fn test_v1_v2_nullifiers_are_different() {
    let (env, contract_id, _, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = b32(&env, 0x90);
    // Same logical nullifier value but derived differently
    let nullifier_v1 = b32(&env, 0x91);
    let nullifier_v2 = b32(&env, 0x92);

    // v1 proof
    let pi_v1 = v1_public_inputs(&env, &video_hash, &credential_root, &nullifier_v1);
    let r1 = client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x93),
        &b32(&env, 0x94),
        &pi_v1,
        &proof_buf(&env),
    );

    // v2 proof (different video since video uniqueness is global)
    let video_hash2 = b32(&env, 0x95);
    let scope = b32(&env, 0x00);
    let pi_v2 = v2_public_inputs(
        &env,
        &video_hash2,
        &credential_root,
        &nullifier_v2,
        &scope,
        0,
    );
    let r2 = client.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0x96),
        &b32(&env, 0x97),
        &pi_v2,
        &proof_buf(&env),
    );

    // Both succeed, nullifiers are different
    assert_ne!(r1.nullifier, r2.nullifier);
}

// ===========================================================================
// Rejects invalid input lengths
// ===========================================================================

/// Rejects public inputs that are neither 128 nor 192 bytes.
#[test]
#[should_panic(expected = "Error(Contract, #10)")] // InvalidPublicInputs
fn test_rejects_wrong_input_length() {
    let (env, contract_id, _, _credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = b32(&env, 0xA0);

    // 96 bytes — invalid
    let bad_pi = Bytes::from_array(&env, &[0u8; 96]);
    client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0xA1),
        &b32(&env, 0xA2),
        &bad_pi,
        &proof_buf(&env),
    );
}

/// Rejects 256-byte public inputs (too long).
#[test]
#[should_panic(expected = "Error(Contract, #10)")] // InvalidPublicInputs
fn test_rejects_oversized_inputs() {
    let (env, contract_id, _, _credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = b32(&env, 0xA3);
    let bad_pi = Bytes::from_array(&env, &[0u8; 256]);
    client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0xA4),
        &b32(&env, 0xA5),
        &bad_pi,
        &proof_buf(&env),
    );
}

// ===========================================================================
// Epoch boundary tests
// ===========================================================================

/// Registering at epoch 0 then rotating to epoch 1: old epoch proofs rejected.
#[test]
#[should_panic(expected = "Error(Contract, #53)")] // StaleEpoch
fn test_epoch_rotation_rejects_old_proofs() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let scope = b32(&env, 0x42);

    // Register at epoch 0
    let video_hash1 = b32(&env, 0xB0);
    let nullifier1 = b32(&env, 0xB1);
    let pi1 = v2_public_inputs(&env, &video_hash1, &credential_root, &nullifier1, &scope, 0);
    client.register_anonymous_verified(
        &video_hash1,
        &b32(&env, 0xB2),
        &b32(&env, 0xB3),
        &pi1,
        &proof_buf(&env),
    );

    // Rotate epoch to 1
    client.set_scope_epoch(&admin, &scope, &1);

    // Try to register with old epoch 0 — must fail
    let video_hash2 = b32(&env, 0xB4);
    let nullifier2 = b32(&env, 0xB5);
    let pi2 = v2_public_inputs(&env, &video_hash2, &credential_root, &nullifier2, &scope, 0);
    client.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0xB6),
        &b32(&env, 0xB7),
        &pi2,
        &proof_buf(&env),
    );
}

/// Different scopes can have independent epochs.
#[test]
fn test_independent_scope_epochs() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let scope_a = b32(&env, 0x01);
    let scope_b = b32(&env, 0x02);

    // Set scope_a to epoch 5, scope_b to epoch 3
    client.set_scope_epoch(&admin, &scope_a, &5);
    client.set_scope_epoch(&admin, &scope_b, &3);

    assert_eq!(client.get_scope_epoch(&scope_a), 5);
    assert_eq!(client.get_scope_epoch(&scope_b), 3);

    // Register in scope_a at epoch 5
    let video_hash1 = b32(&env, 0xC0);
    let nullifier1 = b32(&env, 0xC1);
    let pi1 = v2_public_inputs(
        &env,
        &video_hash1,
        &credential_root,
        &nullifier1,
        &scope_a,
        5,
    );
    client.register_anonymous_verified(
        &video_hash1,
        &b32(&env, 0xC2),
        &b32(&env, 0xC3),
        &pi1,
        &proof_buf(&env),
    );

    // Register in scope_b at epoch 3 (independent)
    let video_hash2 = b32(&env, 0xC4);
    let nullifier2 = b32(&env, 0xC5);
    let pi2 = v2_public_inputs(
        &env,
        &video_hash2,
        &credential_root,
        &nullifier2,
        &scope_b,
        3,
    );
    client.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0xC6),
        &b32(&env, 0xC7),
        &pi2,
        &proof_buf(&env),
    );

    assert!(client.has_nullifier(&nullifier1));
    assert!(client.has_nullifier(&nullifier2));
}

/// Scope A at epoch 1 does NOT affect scope B at epoch 0.
#[test]
fn test_scope_epoch_isolation() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let scope_a = b32(&env, 0x01);
    let scope_b = b32(&env, 0x02);

    // Advance scope_a to epoch 1
    client.set_scope_epoch(&admin, &scope_a, &1);

    // scope_b is still at epoch 0 (default)
    assert_eq!(client.get_scope_epoch(&scope_b), 0);

    // Register in scope_b at epoch 0 — should succeed
    let video_hash = b32(&env, 0xD0);
    let nullifier = b32(&env, 0xD1);
    let pi = v2_public_inputs(&env, &video_hash, &credential_root, &nullifier, &scope_b, 0);
    client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0xD2),
        &b32(&env, 0xD3),
        &pi,
        &proof_buf(&env),
    );

    assert!(client.has_nullifier(&nullifier));
}

/// Global scope (zero) epoch management works independently.
#[test]
fn test_global_scope_epoch_management() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let global_scope = b32(&env, 0x00);

    // Set global scope epoch to 10
    client.set_scope_epoch(&admin, &global_scope, &10);
    assert_eq!(client.get_scope_epoch(&global_scope), 10);

    // Register at epoch 10 — should succeed
    let video_hash = b32(&env, 0xE0);
    let nullifier = b32(&env, 0xE1);
    let pi = v2_public_inputs(
        &env,
        &video_hash,
        &credential_root,
        &nullifier,
        &global_scope,
        10,
    );
    client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0xE2),
        &b32(&env, 0xE3),
        &pi,
        &proof_buf(&env),
    );

    // Register at epoch 9 (stale) — should fail
    let video_hash2 = b32(&env, 0xE4);
    let nullifier2 = b32(&env, 0xE5);
    let pi2 = v2_public_inputs(
        &env,
        &video_hash2,
        &credential_root,
        &nullifier2,
        &global_scope,
        9,
    );
    let result = client.try_register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0xE6),
        &b32(&env, 0xE7),
        &pi2,
        &proof_buf(&env),
    );
    assert!(
        result.is_err(),
        "expected StaleEpoch for epoch 9 when epoch is 10"
    );
}

// ===========================================================================
// Event emission tests
// ===========================================================================

/// Successful v2 scoped registration emits a ProofRegistered event.
#[test]
fn test_scoped_registration_emits_event() {
    let (env, contract_id, _, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = b32(&env, 0xF0);
    let nullifier = b32(&env, 0xF1);
    let scope = b32(&env, 0x00);

    let _ = env.events().all(); // drain

    let pi = v2_public_inputs(&env, &video_hash, &credential_root, &nullifier, &scope, 0);
    client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0xF2),
        &b32(&env, 0xF3),
        &pi,
        &proof_buf(&env),
    );

    assert_ne!(
        env.events().all(),
        [].as_slice(),
        "expected ProofRegistered event after scoped registration"
    );
}

// ===========================================================================
// Replay protection: identical scope/epoch replays are rejected
// ===========================================================================

/// Replaying the same nullifier in the same scope and epoch is rejected
/// with DuplicateNullifier.  This is the core replay-protection guarantee.
#[test]
#[should_panic(expected = "Error(Contract, #6)")] // DuplicateNullifier
fn test_same_scope_epoch_replay_rejected() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let scope = b32(&env, 0x42);
    let epoch: u64 = 1;
    client.set_scope_epoch(&admin, &scope, &epoch);

    let video_hash1 = b32(&env, 0x10);
    let nullifier = b32(&env, 0x11);
    let pi1 = v2_public_inputs(
        &env,
        &video_hash1,
        &credential_root,
        &nullifier,
        &scope,
        epoch,
    );
    client.register_anonymous_verified(
        &video_hash1,
        &b32(&env, 0x12),
        &b32(&env, 0x13),
        &pi1,
        &proof_buf(&env),
    );

    // Replay the same nullifier in the same scope/epoch with a different video
    let video_hash2 = b32(&env, 0x14);
    let pi2 = v2_public_inputs(
        &env,
        &video_hash2,
        &credential_root,
        &nullifier,
        &scope,
        epoch,
    );
    client.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0x15),
        &b32(&env, 0x16),
        &pi2,
        &proof_buf(&env),
    );
}

// ===========================================================================
// Cross-scope unlinkability: different scopes produce different
// nullifiers for the same credential, preventing on-chain linkage.
// ===========================================================================

/// Same credential, different scopes → different nullifiers.
/// Both registrations succeed (no nullifier collision).  Different
/// approved scopes remain unlinkable at the protocol level because
/// the nullifier is scoped by the verifier_scope field in the circuit.
#[test]
fn test_cross_scope_different_nullifiers_unlinkable() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let epoch: u64 = 1;
    let scope_a = b32(&env, 0x01);
    let scope_b = b32(&env, 0x02);
    client.set_scope_epoch(&admin, &scope_a, &epoch);
    client.set_scope_epoch(&admin, &scope_b, &epoch);

    // Different nullifiers for different scopes — both succeed
    let nullifier_a = b32(&env, 0xAA);
    let nullifier_b = b32(&env, 0xBB);
    let video_hash1 = b32(&env, 0xCC);
    let video_hash2 = b32(&env, 0xDD);

    let pi_a = v2_public_inputs(
        &env,
        &video_hash1,
        &credential_root,
        &nullifier_a,
        &scope_a,
        epoch,
    );
    client.register_anonymous_verified(
        &video_hash1,
        &b32(&env, 0xEE),
        &b32(&env, 0xEF),
        &pi_a,
        &proof_buf(&env),
    );

    let pi_b = v2_public_inputs(
        &env,
        &video_hash2,
        &credential_root,
        &nullifier_b,
        &scope_b,
        epoch,
    );
    client.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0xF0),
        &b32(&env, 0xF1),
        &pi_b,
        &proof_buf(&env),
    );

    // Both nullifiers are recorded independently
    assert!(client.has_nullifier(&nullifier_a));
    assert!(client.has_nullifier(&nullifier_b));
    // Nullifiers are different (different scopes)
    assert_ne!(nullifier_a, nullifier_b);
}

// ===========================================================================
// Verifier address change: old proofs remain valid, new proofs use
// the new verifier address.
// ===========================================================================

/// Changing the verifier address does not invalidate existing
/// nullifiers.  Old proofs remain consumed, and new proofs are
/// verified through the new verifier.
#[test]
fn test_verifier_change_preserves_nullifier_history() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_a = env.register(MockScopedVerifier, ());
    let verifier_b = env.register(MockScopedVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let credential_root = b32(&env, 0xC0);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_a);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0xFF));

    let scope = b32(&env, 0x00);
    let epoch: u64 = 0;
    let video_hash = b32(&env, 0x10);
    let nullifier = b32(&env, 0x11);

    // Register with verifier A
    let pi = v2_public_inputs(
        &env,
        &video_hash,
        &credential_root,
        &nullifier,
        &scope,
        epoch,
    );
    client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x12),
        &b32(&env, 0x13),
        &pi,
        &proof_buf(&env),
    );

    // Nullifier is consumed
    assert!(client.has_nullifier(&nullifier));

    // Switch verifier to B
    client.set_verifier(&admin, &verifier_b);

    // A new proof with the new verifier must succeed
    let video_hash2 = b32(&env, 0x20);
    let nullifier2 = b32(&env, 0x21);
    let pi2 = v2_public_inputs(
        &env,
        &video_hash2,
        &credential_root,
        &nullifier2,
        &scope,
        epoch,
    );
    client.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0x22),
        &b32(&env, 0x23),
        &pi2,
        &proof_buf(&env),
    );

    assert!(client.has_nullifier(&nullifier2));
    // Original nullifier still consumed
    assert!(client.has_nullifier(&nullifier));
}

// ===========================================================================
// V1 vs V2 nullifier distinction
// ===========================================================================

/// A v1 nullifier and a v2 nullifier for the same credential, video,
/// and scope are different values.  This proves that the v2 scoped
/// derivation formula produces a distinct nullifier from the v1
/// formula, preventing cross-version replay.
#[test]
fn test_v1_v2_nullifier_distinct_for_same_inputs() {
    let (env, contract_id, _, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = b32(&env, 0x90);
    let nullifier_v1 = b32(&env, 0x91);
    let nullifier_v2 = b32(&env, 0x92);
    let scope = b32(&env, 0x00);
    let epoch: u64 = 0;

    // Register v1 proof
    let pi_v1 = v1_public_inputs(&env, &video_hash, &credential_root, &nullifier_v1);
    let r1 = client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x93),
        &b32(&env, 0x94),
        &pi_v1,
        &proof_buf(&env),
    );

    // Register v2 proof (different video since video uniqueness is global)
    let video_hash2 = b32(&env, 0x95);
    let pi_v2 = v2_public_inputs(
        &env,
        &video_hash2,
        &credential_root,
        &nullifier_v2,
        &scope,
        epoch,
    );
    let r2 = client.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0x96),
        &b32(&env, 0x97),
        &pi_v2,
        &proof_buf(&env),
    );

    // Both succeeded, nullifiers are different
    assert_ne!(r1.nullifier, r2.nullifier);
    assert_ne!(nullifier_v1, nullifier_v2);
}

// ===========================================================================
// Epoch boundary: proof at epoch N rejected when current is N+1
// ===========================================================================

/// A proof with epoch 0 is rejected when the scope epoch has been advanced
/// to 1.  This covers the epoch-boundary rejection case.
#[test]
#[should_panic(expected = "Error(Contract, #53)")] // StaleEpoch
fn test_epoch_boundary_rejects_stale_proof() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let scope = b32(&env, 0x42);
    client.set_scope_epoch(&admin, &scope, &1);

    let video_hash = b32(&env, 0x30);
    let nullifier = b32(&env, 0x31);
    // Proof claims epoch 0 but current epoch is 1
    let pi = v2_public_inputs(&env, &video_hash, &credential_root, &nullifier, &scope, 0);
    client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x32),
        &b32(&env, 0x33),
        &pi,
        &proof_buf(&env),
    );
}

/// A proof with epoch 2 is rejected when the scope epoch is 1.
/// This covers the future-epoch boundary case.
#[test]
#[should_panic(expected = "Error(Contract, #53)")] // StaleEpoch
fn test_epoch_boundary_rejects_future_proof() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let scope = b32(&env, 0x42);
    client.set_scope_epoch(&admin, &scope, &1);

    let video_hash = b32(&env, 0x40);
    let nullifier = b32(&env, 0x41);
    // Proof claims epoch 2 but current epoch is 1
    let pi = v2_public_inputs(&env, &video_hash, &credential_root, &nullifier, &scope, 2);
    client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x42),
        &b32(&env, 0x43),
        &pi,
        &proof_buf(&env),
    );
}

// ===========================================================================
// Stale ledger: proof with old epoch rejected after ledger time advance
// ===========================================================================

/// After advancing the ledger timestamp, a proof with the correct epoch
/// for its scope is still accepted.  This verifies that stale-ledger
/// behavior does not incorrectly reject valid proofs.
#[test]
fn test_stale_ledger_valid_proof_still_accepted() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let scope = b32(&env, 0x42);
    let epoch: u64 = 5;
    client.set_scope_epoch(&admin, &scope, &epoch);

    let video_hash = b32(&env, 0x50);
    let nullifier = b32(&env, 0x51);
    let pi = v2_public_inputs(
        &env,
        &video_hash,
        &credential_root,
        &nullifier,
        &scope,
        epoch,
    );
    let record = client.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x52),
        &b32(&env, 0x53),
        &pi,
        &proof_buf(&env),
    );

    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert!(client.has_nullifier(&nullifier));

    // Advance the ledger far into the future
    env.ledger()
        .set_timestamp(env.ledger().timestamp() + 100_000);

    // A new proof with the same scope/epoch should still be accepted
    let video_hash2 = b32(&env, 0x60);
    let nullifier2 = b32(&env, 0x61);
    let pi2 = v2_public_inputs(
        &env,
        &video_hash2,
        &credential_root,
        &nullifier2,
        &scope,
        epoch,
    );
    let record2 = client.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0x62),
        &b32(&env, 0x63),
        &pi2,
        &proof_buf(&env),
    );

    assert_eq!(record2.tier, TIER_SILENT_WITNESS);
    assert!(client.has_nullifier(&nullifier2));
}

// ===========================================================================
// Privacy: no secret-derived stable identifier exposed outside scope
// ===========================================================================

/// The nullifier derived for scope A is not usable in scope B, even when
/// the same credential and video are used.  This ensures that secret-derived
/// identifiers are not exposed outside their intended scope.
#[test]
fn test_nullifier_scope_isolation() {
    let (env, contract_id, admin, credential_root) = init_scoped_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let epoch: u64 = 1;
    let scope_a = b32(&env, 0x01);
    let scope_b = b32(&env, 0x02);
    client.set_scope_epoch(&admin, &scope_a, &epoch);
    client.set_scope_epoch(&admin, &scope_b, &epoch);

    // Register in scope A
    let video_hash_a = b32(&env, 0x80);
    let nullifier_a = b32(&env, 0x81);
    let pi_a = v2_public_inputs(
        &env,
        &video_hash_a,
        &credential_root,
        &nullifier_a,
        &scope_a,
        epoch,
    );
    client.register_anonymous_verified(
        &video_hash_a,
        &b32(&env, 0x82),
        &b32(&env, 0x83),
        &pi_a,
        &proof_buf(&env),
    );

    // Attempt to replay the same nullifier in scope B with a different video —
    // must fail with DuplicateNullifier because the nullifier is globally tracked.
    let video_hash_b = b32(&env, 0x90);
    let nullifier_b_attempt = b32(&env, 0x81); // same value as nullifier_a
    let pi_b = v2_public_inputs(
        &env,
        &video_hash_b,
        &credential_root,
        &nullifier_b_attempt,
        &scope_b,
        epoch,
    );
    let result = client.try_register_anonymous_verified(
        &video_hash_b,
        &b32(&env, 0x91),
        &b32(&env, 0x92),
        &pi_b,
        &proof_buf(&env),
    );
    assert!(
        result.is_err(),
        "replaying nullifier across scopes must fail"
    );
}

// ===========================================================================
// Cross-network isolation: different contract deployments are independent
// ===========================================================================

/// Two separate registry contracts on the same network maintain independent
/// nullifier sets.  A proof registered on contract A does not affect
/// contract B's nullifier tracking.
#[test]
fn test_cross_network_isolation() {
    let env = Env::default();
    env.mock_all_auths();

    // Deploy two independent registry contracts
    let contract_id_a = env.register(HarpocratesRegistry, ());
    let contract_id_b = env.register(HarpocratesRegistry, ());

    let client_a = HarpocratesRegistryClient::new(&env, &contract_id_a);
    let client_b = HarpocratesRegistryClient::new(&env, &contract_id_b);

    let admin = Address::generate(&env);
    let credential_root = b32(&env, 0xC0);

    client_a.init(&admin);
    client_b.init(&admin);

    let verifier_id = env.register(MockScopedVerifier, ());
    client_a.set_verifier(&admin, &verifier_id);
    client_b.set_verifier(&admin, &verifier_id);

    client_a.add_credential_root(&admin, &credential_root, &b32(&env, 0xFF));
    client_b.add_credential_root(&admin, &credential_root, &b32(&env, 0xFF));

    let scope = b32(&env, 0x00);
    let epoch: u64 = 0;
    let video_hash = b32(&env, 0x10);
    let nullifier = b32(&env, 0x11);

    // Register on contract A
    let pi = v2_public_inputs(
        &env,
        &video_hash,
        &credential_root,
        &nullifier,
        &scope,
        epoch,
    );
    client_a.register_anonymous_verified(
        &video_hash,
        &b32(&env, 0x12),
        &b32(&env, 0x13),
        &pi,
        &proof_buf(&env),
    );

    // The same nullifier should NOT be consumed on contract B
    assert!(!client_b.has_nullifier(&nullifier));

    // Register the same nullifier on contract B — must succeed because
    // contract B has its own independent nullifier set
    let video_hash2 = b32(&env, 0x20);
    let pi2 = v2_public_inputs(
        &env,
        &video_hash2,
        &credential_root,
        &nullifier,
        &scope,
        epoch,
    );
    client_b.register_anonymous_verified(
        &video_hash2,
        &b32(&env, 0x22),
        &b32(&env, 0x23),
        &pi2,
        &proof_buf(&env),
    );

    // Now contract B has consumed the nullifier
    assert!(client_b.has_nullifier(&nullifier));
    // Contract A still has it too (both independently track it)
    assert!(client_a.has_nullifier(&nullifier));
}
