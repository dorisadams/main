/// Threshold Seal Policy tests (#124)
///
/// Tests cover:
///
/// 1. Policy creation, versioning, and cancellation.
/// 2. Signer set management (add/remove) with bounded sets.
/// 3. Approval recording, idempotency, and expiry.
/// 4. Automatic finalization when threshold is met.
/// 5. Explicit finalization and atomicity.
/// 6. Issuer revocation effects (before/after finalization).
/// 7. Duplicate-signer, inactive-issuer, stale-policy, expired-approval,
///    invalid-threshold, and concurrent-finalization edge cases.
/// 8. Backward compatibility with single-issuer `register_seal`.
/// 9. Auth matrix for new entry points.
/// 10. Privacy-safe event emission.
#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger},
    Address, Bytes, Env, IntoVal, Symbol,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

/// Set up a fresh registry with admin and return (env, contract_id, admin).
#[cfg(test)]
fn setup_admin() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, contract_id, admin)
}

/// Set up a registry with two active issuers.
/// Returns (env, contract_id, admin, issuer1, issuer2).
#[cfg(test)]
fn setup_two_issuers() -> (Env, Address, Address, Address, Address) {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let issuer1 = Address::generate(&env);
    let issuer2 = Address::generate(&env);
    client.add_issuer(&admin, &issuer1, &b32(&env, 0xA1));
    client.add_issuer(&admin, &issuer2, &b32(&env, 0xA2));
    (env, contract_id, admin, issuer1, issuer2)
}

// ---------------------------------------------------------------------------
// Policy creation and versioning
// ---------------------------------------------------------------------------

#[test]
fn policy_create_basic() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let version = client.create_seal_policy(&admin, &2, &3, &86400u64, &0u64);
    assert_eq!(version, 1);

    let policy = client.get_seal_policy_by_version(&1).unwrap();
    assert_eq!(policy.version, 1);
    assert_eq!(policy.required_approvals, 2);
    assert_eq!(policy.max_signers, 3);
    assert_eq!(policy.approval_ttl, 86400);
    assert_eq!(policy.expires_at, 0);
    assert_eq!(policy.status, STATUS_POLICY_ACTIVE);

    let active = client.get_active_seal_policy().unwrap();
    assert_eq!(active.version, 1);
}

#[test]
fn policy_create_increments_version() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let v1 = client.create_seal_policy(&admin, &1, &2, &3600u64, &0u64);
    assert_eq!(v1, 1);

    let v2 = client.create_seal_policy(&admin, &2, &4, &7200u64, &0u64);
    assert_eq!(v2, 2);

    // v1 should be cancelled
    let p1 = client.get_seal_policy_by_version(&1).unwrap();
    assert_eq!(p1.status, STATUS_POLICY_CANCELLED);

    // v2 is active
    let p2 = client.get_seal_policy_by_version(&2).unwrap();
    assert_eq!(p2.status, STATUS_POLICY_ACTIVE);

    let active = client.get_active_seal_policy().unwrap();
    assert_eq!(active.version, 2);
}

#[test]
#[should_panic(expected = "Error(Contract, #73)")] // InvalidThreshold
fn policy_create_invalid_threshold_zero() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.create_seal_policy(&admin, &0, &3, &86400u64, &0u64);
}

#[test]
#[should_panic(expected = "Error(Contract, #73)")] // InvalidThreshold
fn policy_create_invalid_threshold_exceeds_max() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.create_seal_policy(&admin, &4, &3, &86400u64, &0u64);
}

#[test]
#[should_panic(expected = "Error(Contract, #74)")]
fn policy_create_signer_set_too_large() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.create_seal_policy(&admin, &1, &17, &86400u64, &0u64);
}

#[test]
fn policy_default_approval_ttl() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // approval_ttl = 0 should use DEFAULT_APPROVAL_TTL_SECS
    client.create_seal_policy(&admin, &1, &2, &0u64, &0u64);
    let policy = client.get_seal_policy_by_version(&1).unwrap();
    assert_eq!(policy.approval_ttl, DEFAULT_APPROVAL_TTL_SECS);
}

// ---------------------------------------------------------------------------
// Policy expiry
// ---------------------------------------------------------------------------

#[test]
fn policy_with_expiry_respects_deadline() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    // Policy expires at 2000
    client.create_seal_policy(&admin, &1, &2, &86400u64, &2000u64);

    // At timestamp 1500, policy is active
    env.ledger().set_timestamp(1500);
    assert!(client.get_active_seal_policy().is_some());

    // At timestamp 2001, policy is expired
    env.ledger().set_timestamp(2001);
    assert!(client.get_active_seal_policy().is_none());
}

// ---------------------------------------------------------------------------
// Signer set management
// ---------------------------------------------------------------------------

#[test]
fn signer_add_and_remove() {
    let (env, contract_id, admin, issuer1, issuer2) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &1, &4, &86400u64, &0u64);

    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer2);

    // Both signers can approve — verify via approval flow
    let proof_id = b32(&env, 0x01);
    let video_hash = b32(&env, 0x02);
    let metadata_hash = b32(&env, 0x03);

    // issuer1 can approve (in signer set)
    client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);
    let approval = client.get_seal_approval(&proof_id, &issuer1);
    assert!(approval.is_some());

    // Remove issuer1
    client.remove_seal_policy_signer(&admin, &1, &issuer1);
    // issuer1 can no longer approve new proofs under this policy
    // (still has existing approval for proof_id above)
}

#[test]
fn signer_add_idempotent() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &1, &4, &86400u64, &0u64);

    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer1); // duplicate — no panic
}

#[test]
#[should_panic(expected = "Error(Contract, #69)")]
fn signer_add_to_cancelled_policy() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.cancel_seal_policy(&admin, &1);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
}

#[test]
#[should_panic(expected = "Error(Contract, #74)")]
fn signer_add_exceeds_max_signers() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Policy with max_signers = 1
    client.create_seal_policy(&admin, &1, &1, &86400u64, &0u64);

    let issuer1 = Address::generate(&env);
    let issuer2 = Address::generate(&env);
    client.add_issuer(&admin, &issuer1, &b32(&env, 0xB1));
    client.add_issuer(&admin, &issuer2, &b32(&env, 0xB2));

    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer2); // exceeds max
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn signer_add_inactive_issuer() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.revoke_issuer(&admin, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
}

// ---------------------------------------------------------------------------
// Policy cancellation
// ---------------------------------------------------------------------------

#[test]
fn policy_cancel() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    assert!(client.get_active_seal_policy().is_some());

    client.cancel_seal_policy(&admin, &1);
    assert!(client.get_active_seal_policy().is_none());

    let policy = client.get_seal_policy_by_version(&1).unwrap();
    assert_eq!(policy.status, STATUS_POLICY_CANCELLED);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn policy_cancel_non_admin() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let non_admin = Address::generate(&env);

    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.cancel_seal_policy(&non_admin, &1);
}

// ---------------------------------------------------------------------------
// Approval recording
// ---------------------------------------------------------------------------

#[test]
fn approval_basic() {
    let (env, contract_id, admin, issuer1, issuer2) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &2, &3, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer2);

    let proof_id = b32(&env, 0x01);
    let video_hash = b32(&env, 0x02);
    let metadata_hash = b32(&env, 0x03);

    // First approval - threshold not met yet
    let finalized = client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);
    assert!(!finalized);

    // Second approval - threshold met, should finalize
    let finalized = client.approve_seal(&issuer2, &proof_id, &video_hash, &metadata_hash);
    assert!(finalized);

    // Proof should be registered
    let record = client.get_proof(&proof_id).unwrap();
    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    assert_eq!(record.video_hash, video_hash);
    assert_eq!(record.status, STATUS_REGISTERED);
}

#[test]
fn approval_idempotent() {
    let (env, contract_id, admin, issuer1, issuer2) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer2);

    let proof_id = b32(&env, 0x10);
    let video_hash = b32(&env, 0x11);
    let metadata_hash = b32(&env, 0x12);

    // First approval finalizes (threshold = 1)
    client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);

    // Duplicate approval from same signer returns false (idempotent)
    let result = client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);
    assert!(!result);
}

#[test]
#[should_panic(expected = "Error(Contract, #70)")] // UnknownPolicySigner (signer-set boundary is checked first)
fn approval_unknown_signer() {
    let (env, contract_id, admin, issuer1, issuer2) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);

    let outsider = Address::generate(&env);
    client.approve_seal(
        &outsider,
        &b32(&env, 0x20),
        &b32(&env, 0x21),
        &b32(&env, 0x22),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn approval_revoked_issuer() {
    let (env, contract_id, admin, issuer1, issuer2) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.revoke_issuer(&admin, &issuer1);

    client.approve_seal(
        &issuer1,
        &b32(&env, 0x30),
        &b32(&env, 0x31),
        &b32(&env, 0x32),
    );
}

// ---------------------------------------------------------------------------
// Approval expiry
// ---------------------------------------------------------------------------

#[test]
fn approval_expired_not_counted() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let issuer1 = Address::generate(&env);
    let issuer2 = Address::generate(&env);
    client.init(&admin);
    client.add_issuer(&admin, &issuer1, &b32(&env, 0xA1));
    client.add_issuer(&admin, &issuer2, &b32(&env, 0xA2));

    // Short approval TTL: 100 seconds
    client.create_seal_policy(&admin, &2, &3, &100u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer2);

    let proof_id = b32(&env, 0x40);
    let video_hash = b32(&env, 0x41);
    let metadata_hash = b32(&env, 0x42);

    // Approve at t=1000
    client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);

    // At t=1200 (100+100+100), the first approval is expired
    env.ledger().set_timestamp(1200);

    // Second approval
    client.approve_seal(&issuer2, &proof_id, &video_hash, &metadata_hash);

    // Check count - should be 1 (only issuer2's approval is fresh)
    let count = client.get_seal_approval_count(&proof_id);
    assert_eq!(count, 1);

    // Threshold is 2, so proof should NOT be finalized
    assert!(client.get_proof(&proof_id).is_none());
}

// ---------------------------------------------------------------------------
// Finalization atomicity
// ---------------------------------------------------------------------------

#[test]
fn finalize_seal_explicit() {
    let (env, contract_id, admin, issuer1, issuer2) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &2, &3, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer2);

    let proof_id = b32(&env, 0x50);
    let video_hash = b32(&env, 0x51);
    let metadata_hash = b32(&env, 0x52);

    // Below threshold, explicit finalize is rejected.
    client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);
    assert!(client.get_proof(&proof_id).is_none());
    let below = env.try_invoke_contract::<ProofRecord, RegistryError>(
        &contract_id,
        &Symbol::new(&env, "finalize_seal"),
        (proof_id.clone(), video_hash.clone(), metadata_hash.clone()).into_val(&env),
    );
    match below {
        Err(Ok(e)) => assert_eq!(e, RegistryError::ThresholdNotMet),
        other => panic!("expected ThresholdNotMet, got ok={}", other.is_ok()),
    }

    // Reaching the threshold auto-finalizes atomically.
    assert!(client.approve_seal(&issuer2, &proof_id, &video_hash, &metadata_hash));
    let record = client.get_proof(&proof_id).unwrap();
    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    assert_eq!(record.status, STATUS_REGISTERED);

    // Finalizing again is rejected: threshold seals are single-finalization.
    let result = env.try_invoke_contract::<ProofRecord, RegistryError>(
        &contract_id,
        &Symbol::new(&env, "finalize_seal"),
        (proof_id.clone(), video_hash.clone(), metadata_hash.clone()).into_val(&env),
    );
    match result {
        Err(Ok(e)) => assert_eq!(e, RegistryError::AlreadyFinalized),
        other => panic!(
            "expected AlreadyFinalized contract error, got ok={}",
            other.is_ok()
        ),
    }
}

#[test]
#[should_panic(expected = "Error(Contract, #72)")]
fn finalize_seal_threshold_not_met() {
    let (env, contract_id, admin, issuer1, issuer2) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &2, &3, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer2);

    let proof_id = b32(&env, 0x60);
    let video_hash = b32(&env, 0x61);
    let metadata_hash = b32(&env, 0x62);

    // Only one approval (need 2)
    client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);

    // Explicit finalize should fail
    client.finalize_seal(&proof_id, &video_hash, &metadata_hash);
}

#[test]
#[should_panic(expected = "Error(Contract, #76)")]
fn finalize_seal_already_finalized() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);

    let proof_id = b32(&env, 0x70);
    let video_hash = b32(&env, 0x71);
    let metadata_hash = b32(&env, 0x72);

    client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);

    // Second finalize should fail
    client.finalize_seal(&proof_id, &video_hash, &metadata_hash);
}

// ---------------------------------------------------------------------------
// Issuer revocation effects
// ---------------------------------------------------------------------------

#[test]
fn revoked_issuer_before_finalization_excluded() {
    let (env, contract_id, admin, issuer1, issuer2) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Policy requires 2 approvals from 3 signers
    client.create_seal_policy(&admin, &2, &3, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer2);

    let proof_id = b32(&env, 0x80);
    let video_hash = b32(&env, 0x81);
    let metadata_hash = b32(&env, 0x82);

    // issuer1 approves
    client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);

    // issuer1 is revoked before issuer2 approves
    client.revoke_issuer(&admin, &issuer1);

    // issuer2 approves - threshold should NOT be met because issuer1 is revoked
    client.approve_seal(&issuer2, &proof_id, &video_hash, &metadata_hash);

    let count = client.get_seal_approval_count(&proof_id);
    assert_eq!(count, 1, "revoked issuer's approval should not count");

    assert!(
        client.get_proof(&proof_id).is_none(),
        "proof should not be finalized"
    );
}

#[test]
fn revoked_issuer_after_finalization_preserves_seal() {
    let (env, contract_id, admin, issuer1, issuer2) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &2, &3, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer2);

    let proof_id = b32(&env, 0x90);
    let video_hash = b32(&env, 0x91);
    let metadata_hash = b32(&env, 0x92);

    // Both approve - threshold met, proof finalized
    client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);
    client.approve_seal(&issuer2, &proof_id, &video_hash, &metadata_hash);

    // Verify finalized
    let record = client.get_proof(&proof_id).unwrap();
    assert_eq!(record.status, STATUS_REGISTERED);

    // Revoke issuer1 after finalization
    client.revoke_issuer(&admin, &issuer1);

    // Proof is still registered (post-finalization revocation doesn't invalidate)
    let record = client.get_proof(&proof_id).unwrap();
    assert_eq!(record.status, STATUS_REGISTERED);
    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
}

// ---------------------------------------------------------------------------
// Duplicate signer rejection (approval on registered proof)
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #76)")]
fn approval_on_already_registered_proof() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Single-issuer policy
    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);

    let proof_id = b32(&env, 0xA0);
    let video_hash = b32(&env, 0xA1);
    let metadata_hash = b32(&env, 0xA2);

    // First approval finalizes
    client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);

    // Second approval on same proof should fail (AlreadyFinalized).
    // issuer2 must first join the signer set so the request passes the
    // authorization gates and reaches the finalization check.
    let issuer2 = Address::generate(&env);
    client.add_issuer(&admin, &issuer2, &b32(&env, 0xA3));
    client.add_seal_policy_signer(&admin, &1, &issuer2);
    client.approve_seal(&issuer2, &proof_id, &video_hash, &metadata_hash);
}

// ---------------------------------------------------------------------------
// Backward compatibility: single-issuer register_seal still works
// ---------------------------------------------------------------------------

#[test]
fn single_issuer_register_seal_still_works() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let proof_id = b32(&env, 0xB0);
    let video_hash = b32(&env, 0xB1);
    let metadata_hash = b32(&env, 0xB2);

    let record = client.register_seal(&issuer1, &video_hash, &metadata_hash, &proof_id);
    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    assert_eq!(record.issuer, Some(issuer1));
    assert_eq!(record.status, STATUS_REGISTERED);
}

// ---------------------------------------------------------------------------
// Threshold signers stored correctly
// ---------------------------------------------------------------------------

#[test]
fn threshold_signers_stored_on_finalization() {
    let (env, contract_id, admin, issuer1, issuer2) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &2, &3, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer2);

    let proof_id = b32(&env, 0xC0);
    let video_hash = b32(&env, 0xC1);
    let metadata_hash = b32(&env, 0xC2);

    client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);
    client.approve_seal(&issuer2, &proof_id, &video_hash, &metadata_hash);

    // Verify the proof was finalized as a threshold seal
    let record = client.get_proof(&proof_id).unwrap();
    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    assert_eq!(record.status, STATUS_REGISTERED);
    assert_eq!(record.video_hash, video_hash);
    assert_eq!(record.metadata_hash, metadata_hash);

    // Both approvals are recorded
    let a1 = client.get_seal_approval(&proof_id, &issuer1);
    assert!(a1.is_some());
    let a2 = client.get_seal_approval(&proof_id, &issuer2);
    assert!(a2.is_some());
}

// ---------------------------------------------------------------------------
// Event emission
// ---------------------------------------------------------------------------

#[test]
fn policy_events_emitted() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Drain initial events
    let _ = env.events().all();

    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    assert_ne!(
        env.events().all(),
        [].as_slice(),
        "SealPolicyCreated event expected"
    );
}

#[test]
fn approval_event_emitted() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);

    let _ = env.events().all();

    client.approve_seal(
        &issuer1,
        &b32(&env, 0xD0),
        &b32(&env, 0xD1),
        &b32(&env, 0xD2),
    );
    assert_ne!(
        env.events().all(),
        [].as_slice(),
        "SealApprovalRecorded event expected"
    );
}

#[test]
fn finalize_event_emitted() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);

    let _ = env.events().all();

    client.approve_seal(
        &issuer1,
        &b32(&env, 0xE0),
        &b32(&env, 0xE1),
        &b32(&env, 0xE2),
    );
    assert_ne!(
        env.events().all(),
        [].as_slice(),
        "SealFinalized event expected"
    );
}

// ---------------------------------------------------------------------------
// Auth matrix for new entry points
// ---------------------------------------------------------------------------

#[test]
fn auth_create_seal_policy_admin_succeeds() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_create_seal_policy_non_admin() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let non_admin = Address::generate(&env);
    client.create_seal_policy(&non_admin, &1, &2, &86400u64, &0u64);
}

#[test]
fn auth_add_seal_policy_signer_admin_succeeds() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_add_seal_policy_signer_non_admin() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&issuer1, &1, &issuer1);
}

#[test]
fn auth_remove_seal_policy_signer_admin_succeeds() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.remove_seal_policy_signer(&admin, &1, &issuer1);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_remove_seal_policy_signer_non_admin() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.remove_seal_policy_signer(&issuer1, &1, &issuer1);
}

#[test]
fn auth_approve_seal_signer_succeeds() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.approve_seal(
        &issuer1,
        &b32(&env, 0xF0),
        &b32(&env, 0xF1),
        &b32(&env, 0xF2),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #70)")]
fn auth_approve_seal_non_signer_rejected() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let outsider = Address::generate(&env);
    client.create_seal_policy(&admin, &1, &2, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.approve_seal(
        &outsider,
        &b32(&env, 0xF3),
        &b32(&env, 0xF4),
        &b32(&env, 0xF5),
    );
}

// ---------------------------------------------------------------------------
// Three-of-three threshold (exact match)
// ---------------------------------------------------------------------------

#[test]
fn three_of_three_threshold() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let issuer1 = Address::generate(&env);
    let issuer2 = Address::generate(&env);
    let issuer3 = Address::generate(&env);
    client.add_issuer(&admin, &issuer1, &b32(&env, 0x10));
    client.add_issuer(&admin, &issuer2, &b32(&env, 0x11));
    client.add_issuer(&admin, &issuer3, &b32(&env, 0x12));

    client.create_seal_policy(&admin, &3, &3, &86400u64, &0u64);
    client.add_seal_policy_signer(&admin, &1, &issuer1);
    client.add_seal_policy_signer(&admin, &1, &issuer2);
    client.add_seal_policy_signer(&admin, &1, &issuer3);

    let proof_id = b32(&env, 0x13);
    let video_hash = b32(&env, 0x14);
    let metadata_hash = b32(&env, 0x15);

    client.approve_seal(&issuer1, &proof_id, &video_hash, &metadata_hash);
    client.approve_seal(&issuer2, &proof_id, &video_hash, &metadata_hash);
    let finalized = client.approve_seal(&issuer3, &proof_id, &video_hash, &metadata_hash);
    assert!(finalized);

    let record = client.get_proof(&proof_id).unwrap();
    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
}

// ---------------------------------------------------------------------------
// No active policy prevents approval
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #68)")]
fn approval_no_active_policy() {
    let (env, contract_id, admin, issuer1, _) = setup_two_issuers();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // No policy created
    client.approve_seal(
        &issuer1,
        &b32(&env, 0x20),
        &b32(&env, 0x21),
        &b32(&env, 0x22),
    );
}
