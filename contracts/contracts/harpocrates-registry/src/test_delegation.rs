//! Constrained issuer and source delegation (#192)
//!
//! Rules under test:
//!
//! 1. A delegation grants exactly the scopes named, for exactly the window
//!    granted, and nothing else.
//! 2. Delegation is not authority: a delegate cannot reach admin, issuer, or
//!    credential-root entry points, and cannot register outside its scope.
//! 3. Delegation is not transitive: a delegate cannot create, extend, or pass
//!    on the authority it received.
//! 4. Delegations expire on their own; a forgotten grant cannot become
//!    permanent authority.
//! 5. Revocation is immediate and available to both the grantor and the admin;
//!    revoking something absent is a no-op, not an error.
//! 6. Storage is bounded: a grantor holds at most
//!    `MAX_DELEGATIONS_PER_GRANTOR` distinct delegates, and re-granting to an
//!    existing delegate is idempotent in storage.
//! 7. Attribution survives: the proof names the grantor, the history names the
//!    delegate.
//! 8. Delegated registration obeys every rule direct registration obeys —
//!    pause domains, uniqueness, and issuer standing.

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{testutils::Address as _, testutils::Ledger, Address, Env};

#[cfg(test)]
fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

/// Returns (env, contract_id, admin, grantor, delegate) at `start_ts`.
#[cfg(test)]
fn setup(start_ts: u64) -> (Env, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(start_ts);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let grantor = Address::generate(&env);
    let delegate = Address::generate(&env);

    client.init(&admin);

    (env, contract_id, admin, grantor, delegate)
}

#[cfg(test)]
const ONE_DAY: u64 = 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Granting
// ---------------------------------------------------------------------------

#[test]
fn grant_stores_a_scoped_expiring_record() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let expires_at = client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    assert_eq!(expires_at, 1_000 + ONE_DAY);

    let record = client.get_delegation(&grantor, &delegate).unwrap();
    assert_eq!(record.grantor, grantor);
    assert_eq!(record.delegate, delegate);
    assert_eq!(record.scope, DELEGATION_SCOPE_REGISTER_SOURCE);
    assert_eq!(record.granted_at, 1_000);
    assert_eq!(record.expires_at, 1_000 + ONE_DAY);
    assert_eq!(client.get_delegation_count(&grantor), 1);
}

#[test]
fn is_delegation_active_reports_scope_precisely() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    assert!(client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SOURCE));
    assert!(!client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SEAL));
    assert!(!client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_ALL));
    // Unknown and empty scopes answer false rather than erroring, so a caller
    // can pre-flight without risking a reverted transaction.
    assert!(!client.is_delegation_active(&grantor, &delegate, &0));
    assert!(!client.is_delegation_active(&grantor, &delegate, &0xffff_ffff));
}

#[test]
fn a_grant_can_carry_several_scopes_at_once() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &DELEGATION_SCOPE_ALL, &ONE_DAY);

    assert!(client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SOURCE));
    assert!(client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SEAL));
}

#[test]
fn regranting_overwrites_without_consuming_another_slot() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &DELEGATION_SCOPE_ALL, &ONE_DAY);
    assert_eq!(client.get_delegation_count(&grantor), 1);

    // Narrow the scope and shorten the window on the same delegate.
    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &(ONE_DAY / 2),
    );

    assert_eq!(client.get_delegation_count(&grantor), 1);
    let record = client.get_delegation(&grantor, &delegate).unwrap();
    assert_eq!(record.scope, DELEGATION_SCOPE_REGISTER_SEAL);
    assert_eq!(record.expires_at, 1_000 + ONE_DAY / 2);
    assert!(!client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SOURCE));
}

#[test]
#[should_panic(expected = "Error(Contract, #30)")] // SelfDelegation
fn a_grantor_cannot_delegate_to_itself() {
    let (env, contract_id, _, grantor, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &grantor,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #24)")] // InvalidDelegationScope
fn a_zero_scope_is_rejected() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &0, &ONE_DAY);
}

#[test]
#[should_panic(expected = "Error(Contract, #24)")] // InvalidDelegationScope
fn an_unknown_scope_bit_is_rejected() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &(DELEGATION_SCOPE_REGISTER_SOURCE | 1 << 20),
        &ONE_DAY,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #25)")] // InvalidDelegationDuration
fn a_zero_duration_is_rejected() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SOURCE, &0);
}

#[test]
#[should_panic(expected = "Error(Contract, #25)")] // InvalidDelegationDuration
fn a_duration_past_the_cap_is_rejected() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &(MAX_DELEGATION_DURATION_SECS + 1),
    );
}

#[test]
fn a_duration_exactly_at_the_cap_is_accepted() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let expires_at = client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &MAX_DELEGATION_DURATION_SECS,
    );

    assert_eq!(expires_at, 1_000 + MAX_DELEGATION_DURATION_SECS);
}

// ---------------------------------------------------------------------------
// Storage bounds
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #29)")] // DelegationsSaturated
fn a_grantor_cannot_exceed_the_delegate_cap() {
    let (env, contract_id, _, grantor, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    for _ in 0..MAX_DELEGATIONS_PER_GRANTOR {
        client.grant_delegation(
            &grantor,
            &Address::generate(&env),
            &DELEGATION_SCOPE_REGISTER_SOURCE,
            &ONE_DAY,
        );
    }
    assert_eq!(
        client.get_delegation_count(&grantor),
        MAX_DELEGATIONS_PER_GRANTOR
    );

    client.grant_delegation(
        &grantor,
        &Address::generate(&env),
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
}

#[test]
fn revoking_frees_a_slot() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    assert_eq!(client.get_delegation_count(&grantor), 1);

    client.revoke_delegation(&grantor, &grantor, &delegate);

    assert_eq!(client.get_delegation_count(&grantor), 0);
    assert_eq!(client.get_delegation(&grantor, &delegate), None);
}

#[test]
fn one_grantors_cap_does_not_affect_another() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let other_grantor = Address::generate(&env);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    assert_eq!(client.get_delegation_count(&grantor), 1);
    assert_eq!(client.get_delegation_count(&other_grantor), 0);
    assert!(!client.is_delegation_active(
        &other_grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE
    ));
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

#[test]
fn a_delegation_lapses_at_its_expiry_without_a_transaction() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    env.ledger().set_timestamp(1_000 + ONE_DAY - 1);
    assert!(client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SOURCE));

    // `expires_at` itself is already outside the window.
    env.ledger().set_timestamp(1_000 + ONE_DAY);
    assert!(!client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SOURCE));

    // The record remains readable so an operator can see and prune it.
    assert!(client.get_delegation(&grantor, &delegate).is_some());
}

#[test]
#[should_panic(expected = "Error(Contract, #27)")] // DelegationExpired
fn an_expired_delegation_cannot_register() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    env.ledger().set_timestamp(1_000 + ONE_DAY + 1);

    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

// ---------------------------------------------------------------------------
// Revocation authorization
// ---------------------------------------------------------------------------

#[test]
fn the_admin_can_revoke_a_delegation_it_did_not_grant() {
    let (env, contract_id, admin, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    client.revoke_delegation(&admin, &grantor, &delegate);

    assert_eq!(client.get_delegation(&grantor, &delegate), None);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn a_stranger_cannot_revoke_a_delegation() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let stranger = Address::generate(&env);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    client.revoke_delegation(&stranger, &grantor, &delegate);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn a_delegate_cannot_revoke_its_own_delegation_on_the_grantors_behalf() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    client.revoke_delegation(&delegate, &grantor, &delegate);
}

#[test]
fn revoking_an_absent_delegation_is_a_no_op() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Idempotent: a retried or duplicated revocation converges rather than
    // erroring, and never drives the slot counter below zero.
    client.revoke_delegation(&grantor, &grantor, &delegate);
    client.revoke_delegation(&grantor, &grantor, &delegate);

    assert_eq!(client.get_delegation_count(&grantor), 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #26)")] // DelegationNotFound
fn a_revoked_delegation_stops_working_immediately() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    client.revoke_delegation(&grantor, &grantor, &delegate);

    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

// ---------------------------------------------------------------------------
// Delegated registration — Tier 2
// ---------------------------------------------------------------------------

#[test]
fn a_delegate_registers_a_source_proof_attributed_to_the_grantor() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    let video_hash = b32(&env, 1);
    let proof_id = b32(&env, 3);
    let record = client.register_source_delegated(
        &delegate,
        &grantor,
        &video_hash,
        &b32(&env, 2),
        &proof_id,
    );

    // Authority is attributed to the grantor…
    assert_eq!(record.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(record.source, Some(grantor.clone()));
    assert_eq!(client.get_proof(&proof_id).unwrap().source, Some(grantor));
    assert_eq!(
        client.get_by_video(&video_hash).unwrap().video_hash,
        video_hash
    );

    // …while the history names the actor, so the two are never conflated.
    let entry = client.get_proof_history_at(&proof_id, &1).unwrap();
    assert_eq!(entry.action, ProofLifecycleAction::Registered as u32);
    assert_eq!(entry.actor, Some(delegate));
}

#[test]
#[should_panic(expected = "Error(Contract, #26)")] // DelegationNotFound
fn a_delegate_without_a_grant_cannot_register() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #28)")] // DelegationScopeExceeded
fn a_seal_scoped_delegate_cannot_register_a_source_proof() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &ONE_DAY,
    );

    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #21)")] // Paused
fn delegated_registration_respects_the_tier_2_pause() {
    let (env, contract_id, admin, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    client.pause(&admin, &PAUSE_DOMAIN_TIER2_REGISTRATION, &3_600);

    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")] // DuplicateProof
fn delegated_registration_still_enforces_proof_uniqueness() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 9),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

// ---------------------------------------------------------------------------
// Delegated registration — Tier 3
// ---------------------------------------------------------------------------

#[test]
fn a_delegate_registers_a_seal_for_an_active_issuer() {
    let (env, contract_id, admin, issuer, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.add_issuer(&admin, &issuer, &b32(&env, 7));
    client.grant_delegation(
        &issuer,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &ONE_DAY,
    );

    let proof_id = b32(&env, 3);
    let record =
        client.register_seal_delegated(&delegate, &issuer, &b32(&env, 1), &b32(&env, 2), &proof_id);

    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    assert_eq!(record.issuer, Some(issuer));
    assert_eq!(
        client.get_proof_history_at(&proof_id, &1).unwrap().actor,
        Some(delegate)
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn a_delegation_does_not_substitute_for_issuer_standing() {
    let (env, contract_id, _, issuer, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // The grantor delegates a seal scope but was never registered as an issuer.
    client.grant_delegation(
        &issuer,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &ONE_DAY,
    );

    client.register_seal_delegated(
        &delegate,
        &issuer,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn revoking_the_issuer_stops_its_delegates_too() {
    let (env, contract_id, admin, issuer, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.add_issuer(&admin, &issuer, &b32(&env, 7));
    client.grant_delegation(
        &issuer,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &ONE_DAY,
    );
    client.revoke_issuer(&admin, &issuer);

    client.register_seal_delegated(
        &delegate,
        &issuer,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #28)")] // DelegationScopeExceeded
fn a_source_scoped_delegate_cannot_register_a_seal() {
    let (env, contract_id, admin, issuer, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.add_issuer(&admin, &issuer, &b32(&env, 7));
    client.grant_delegation(
        &issuer,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    client.register_seal_delegated(
        &delegate,
        &issuer,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

// ---------------------------------------------------------------------------
// Non-transitivity and privilege containment
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #26)")] // DelegationNotFound
fn a_delegate_cannot_pass_the_grantors_authority_to_a_third_party() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let third_party = Address::generate(&env);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    // The delegate can only ever grant its *own* authority. Even with auths
    // mocked, the resulting record is keyed (delegate -> third_party) and says
    // nothing about the original grantor.
    client.grant_delegation(
        &delegate,
        &third_party,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    assert!(!client.is_delegation_active(
        &grantor,
        &third_party,
        &DELEGATION_SCOPE_REGISTER_SOURCE
    ));

    // So the third party cannot register for the original grantor.
    client.register_source_delegated(
        &third_party,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
fn a_second_hop_delegation_only_binds_its_own_grantor() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let third_party = Address::generate(&env);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    client.grant_delegation(
        &delegate,
        &third_party,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    // The second hop registers proofs attributed to the delegate, never to the
    // original grantor.
    let proof_id = b32(&env, 3);
    let record = client.register_source_delegated(
        &third_party,
        &delegate,
        &b32(&env, 1),
        &b32(&env, 2),
        &proof_id,
    );

    assert_eq!(record.source, Some(delegate));
    assert_ne!(record.source, Some(grantor));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn a_delegate_cannot_reach_admin_entry_points() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &DELEGATION_SCOPE_ALL, &ONE_DAY);

    // A maximally scoped delegation still confers nothing outside registration.
    client.add_issuer(&delegate, &delegate, &b32(&env, 7));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn a_delegate_cannot_revoke_a_proof() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &DELEGATION_SCOPE_ALL, &ONE_DAY);
    let proof_id = b32(&env, 3);
    client.register_source_delegated(&delegate, &grantor, &b32(&env, 1), &b32(&env, 2), &proof_id);

    client.revoke_proof(&delegate, &proof_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn a_delegate_cannot_pause_a_domain() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &DELEGATION_SCOPE_ALL, &ONE_DAY);

    client.pause(&delegate, &PAUSE_DOMAIN_TIER2_REGISTRATION, &3_600);
}

#[test]
fn direct_registration_is_unaffected_by_the_delegation_feature() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Backwards compatibility: a source with no delegations at all still
    // registers exactly as before.
    let proof_id = b32(&env, 3);
    let record = client.register_source(&grantor, &b32(&env, 1), &b32(&env, 2), &proof_id);

    assert_eq!(record.source, Some(grantor.clone()));
    assert_eq!(client.get_delegation_count(&grantor), 0);
    assert!(!client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_ALL));
    assert_eq!(
        client.get_proof_history_at(&proof_id, &1).unwrap().actor,
        Some(grantor)
    );
}
