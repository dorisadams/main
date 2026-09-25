#![cfg(test)]

use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Events as _, Ledger},
    Address, Bytes, BytesN, Env,
};

use soroban_sdk::xdr::ContractEventBody;
use soroban_sdk::{TryFromVal as _, TryIntoVal as _, Val};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn zero_payload(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

fn ttl_payload(env: &Env, ttl_secs: u64) -> BytesN<32> {
    let mut arr = [0u8; 32];
    let ttl_bytes = ttl_secs.to_be_bytes();
    arr[..8].copy_from_slice(&ttl_bytes);
    BytesN::from_array(env, &arr)
}

fn setup_env() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, admin)
}

fn advance_time(env: &Env, secs: u64) {
    env.ledger().set_timestamp(env.ledger().timestamp() + secs);
}

// ---------------------------------------------------------------------------
// Proposal lifecycle tests
// ---------------------------------------------------------------------------

#[test]
fn test_propose_and_query_timelocked_action() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));

    // Re-init with the same admin
    client.init(&admin);

    let target = Address::generate(&env);
    let payload = zero_payload(&env);

    let proposal_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &target,
        &payload,
    );

    assert_eq!(proposal_id, 1, "first proposal should have ID 1");

    let proposal = client.get_timelock_proposal(&proposal_id).unwrap();
    assert_eq!(proposal.action, ProposalAction::SetVerifier as u32);
    assert_eq!(proposal.proposer, admin);
    assert_eq!(proposal.target, target);
    assert!(!proposal.executed);
    assert!(!proposal.cancelled);
    assert!(
        proposal.min_execution_at >= proposal.created_at + DEFAULT_TIMELOCK_MIN_DELAY_SECS,
        "min_execution_at should be at least created_at + min_delay"
    );

    let count = client.get_timelock_proposal_count();
    assert_eq!(count, 1, "proposal count should be 1");
}

#[test]
fn test_cancel_timelocked_proposal() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let target = Address::generate(&env);
    let proposal_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &target,
        &zero_payload(&env),
    );

    // Cancel before execution
    client.cancel_timelocked_proposal(&admin, &proposal_id);

    // Snapshot immediately: env.events().all() reflects only the most recent
    // invocation, so later client calls would clear the cancel event.
    let events = env.events().all();

    let proposal = client.get_timelock_proposal(&proposal_id).unwrap();
    assert!(proposal.cancelled);
    assert!(!proposal.executed);
    let mut has_cancel = false;
    for e in events.events() {
        if let ContractEventBody::V0(v0) = &e.body {
            let t0: Option<Symbol> = v0.topics.first().and_then(|v| {
                let val = Val::try_from_val(&env, v).ok()?;
                Symbol::try_from_val(&env, &val).ok()
            });
            if t0 == Some(Symbol::new(&env, "timelock")) {
                has_cancel = true;
            }
        }
    }
    assert!(has_cancel, "should have timelock events");
}

#[test]
fn test_execute_timelocked_proposal_after_delay() {
    let (env, admin) = setup_env();
    let env_clone = env.clone();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    // Initially no verifier set
    assert!(client.get_verifier().is_none());

    let new_verifier = Address::generate(&env);
    let proposal_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &new_verifier,
        &zero_payload(&env),
    );

    // Advance time past the minimum delay (24h default)
    advance_time(&env, DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);

    // Execute with a non-admin caller
    let executor = Address::generate(&env);
    client.execute_timelocked_proposal(&executor, &proposal_id);

    let proposal = client.get_timelock_proposal(&proposal_id).unwrap();
    assert!(proposal.executed);

    // Verifier should now be set
    let verifier = client.get_verifier().unwrap();
    assert_eq!(
        verifier, new_verifier,
        "verifier should be updated by timelock"
    );
}

#[test]
fn test_cannot_execute_before_min_delay() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let target = Address::generate(&env);
    let proposal_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &target,
        &zero_payload(&env),
    );

    // Try to execute immediately (should fail)
    let executor = Address::generate(&env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.execute_timelocked_proposal(&executor, &proposal_id);
    }));
    assert!(result.is_err(), "execution before delay should panic");
}

#[test]
fn test_cannot_execute_cancelled_proposal() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let target = Address::generate(&env);
    let proposal_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &target,
        &zero_payload(&env),
    );

    client.cancel_timelocked_proposal(&admin, &proposal_id);

    advance_time(&env, DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);

    let executor = Address::generate(&env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.execute_timelocked_proposal(&executor, &proposal_id);
    }));
    assert!(
        result.is_err(),
        "execution of cancelled proposal should panic"
    );
}

#[test]
fn test_cannot_execute_already_executed_proposal() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let target = Address::generate(&env);
    let proposal_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &target,
        &zero_payload(&env),
    );

    advance_time(&env, DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);

    let executor = Address::generate(&env);
    client.execute_timelocked_proposal(&executor, &proposal_id);

    // Try to execute again
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.execute_timelocked_proposal(&executor, &proposal_id);
    }));
    assert!(result.is_err(), "double execution should panic");
}

// ---------------------------------------------------------------------------
// Emergency execution tests
// ---------------------------------------------------------------------------

#[test]
fn test_emergency_execute_before_delay() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let new_verifier = Address::generate(&env);
    let proposal_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &new_verifier,
        &zero_payload(&env),
    );

    // Emergency execute immediately (skip timelock)
    client.emergency_execute_proposal(&admin, &proposal_id);

    let verifier = client.get_verifier().unwrap();
    assert_eq!(
        verifier, new_verifier,
        "verifier should be set by emergency"
    );
}

#[test]
fn test_emergency_execute_only_admin() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let target = Address::generate(&env);
    let proposal_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &target,
        &zero_payload(&env),
    );

    // Disable mock all auths to test authorization
    env.mock_all_auths(); // re-enable for standard flow

    // Non-admin trying emergency execute (should fail)
    let non_admin = Address::generate(&env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.emergency_execute_proposal(&non_admin, &proposal_id);
    }));
    assert!(result.is_err(), "non-admin emergency execute should panic");
}

// ---------------------------------------------------------------------------
// Timelock delay configuration tests
// ---------------------------------------------------------------------------

#[test]
fn test_set_timelock_min_delay() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let default_delay = client.get_timelock_min_delay_secs();
    assert_eq!(default_delay, DEFAULT_TIMELOCK_MIN_DELAY_SECS);

    let new_delay = 3600u64; // 1 hour
    client.set_timelock_min_delay_secs(&admin, &new_delay);

    let updated_delay = client.get_timelock_min_delay_secs();
    assert_eq!(updated_delay, new_delay);
}

#[test]
fn test_cannot_set_zero_timelock_delay() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_timelock_min_delay_secs(&admin, &0u64);
    }));
    assert!(result.is_err(), "zero delay should be rejected");
}

#[test]
fn test_cannot_set_excessive_timelock_delay() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_timelock_min_delay_secs(&admin, &(MAX_TIMELOCK_MIN_DELAY_SECS + 1));
    }));
    assert!(result.is_err(), "excessive delay should be rejected");
}

// ---------------------------------------------------------------------------
// Multiple proposals and limits
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_proposals_increment_id() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let target1 = Address::generate(&env);
    let target2 = Address::generate(&env);

    let id1 = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &target1,
        &zero_payload(&env),
    );
    let id2 = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &target2,
        &zero_payload(&env),
    );

    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
    assert_eq!(client.get_timelock_proposal_count(), 2);
}

// ---------------------------------------------------------------------------
// Timelocked issuer revocation test
// ---------------------------------------------------------------------------

#[test]
fn test_timelocked_revoke_issuer() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let issuer = Address::generate(&env);
    client.add_issuer(&admin, &issuer, &bytes32(&env, 1));

    // Verify issuer exists and is active
    let record = client.get_issuer(&issuer).unwrap();
    assert!(record.active);

    // Propose revocation
    let proposal_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::RevokeIssuer as u32),
        &issuer,
        &zero_payload(&env),
    );

    advance_time(&env, DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);

    let executor = Address::generate(&env);
    client.execute_timelocked_proposal(&executor, &proposal_id);

    // Verify issuer is now revoked
    let record = client.get_issuer(&issuer).unwrap();
    assert!(!record.active);
}

// ---------------------------------------------------------------------------
// Proposal events verification
// ---------------------------------------------------------------------------

#[test]
fn test_timelock_proposal_events_emitted() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let target = Address::generate(&env);
    let proposal_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &target,
        &zero_payload(&env),
    );

    // Snapshot right after the propose call: env.events().all() reflects
    // only the most recent invocation.
    let propose_events = env.events().all();

    advance_time(&env, DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);

    let executor = Address::generate(&env);
    client.execute_timelocked_proposal(&executor, &proposal_id);

    // Snapshot the exec events right after the execute call.
    let exec_events = env.events().all();

    let mut has_propose = false;
    let mut has_exec = false;
    for e in propose_events.events().iter().chain(exec_events.events()) {
        if let ContractEventBody::V0(v0) = &e.body {
            let t0: Option<Symbol> = v0.topics.first().and_then(|v| {
                let val = Val::try_from_val(&env, v).ok()?;
                Symbol::try_from_val(&env, &val).ok()
            });
            let t1: Option<Symbol> = v0.topics.get(1).and_then(|v| {
                let val = Val::try_from_val(&env, v).ok()?;
                Symbol::try_from_val(&env, &val).ok()
            });
            if t0 == Some(Symbol::new(&env, "timelock")) {
                if t1 == Some(Symbol::new(&env, "propose")) {
                    has_propose = true;
                }
                if t1 == Some(Symbol::new(&env, "exec")) {
                    has_exec = true;
                }
            }
        }
    }
    assert!(has_propose, "should have TimelockProposalCreated event");
    assert!(has_exec, "should have TimelockProposalExecuted event");
}

// ---------------------------------------------------------------------------
// Invalid proposal action test
// ---------------------------------------------------------------------------

#[test]
fn test_reject_invalid_proposal_action() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let target = Address::generate(&env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.propose_timelocked_action(
            &admin,
            &0u32, // invalid action
            &target,
            &zero_payload(&env),
        );
    }));
    assert!(result.is_err(), "invalid action should be rejected");
}

#[test]
fn test_reject_unknown_proposal_action() {
    let (env, admin) = setup_env();
    let client = HarpocratesRegistryClient::new(&env, &env.register(HarpocratesRegistry, ()));
    client.init(&admin);

    let target = Address::generate(&env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.propose_timelocked_action(
            &admin,
            &99u32, // unknown action
            &target,
            &zero_payload(&env),
        );
    }));
    assert!(result.is_err(), "unknown action should be rejected");
}
