/// Proof-lifecycle history tests (#90)
///
/// Tests cover:
///   - History is recorded for every registration tier.
///   - History is recorded for revocation, verification, explicit expiry,
///     and administrative correction.
///   - `get_proof_history_at` retrieves entries by sequence number.
///   - `get_proof_history_count` returns the correct count.
///   - History entries contain no sensitive data (no video_hash,
///     metadata_hash, nullifier, or proof bytes).
///   - Abuse limits: MAX_HISTORY_ENTRIES_PER_PROOF saturation.
///   - Idempotency: re-expiring an already-expired proof and re-correcting
///     with the same metadata both fail deterministically.
///   - Authorization: only admin can call privileged lifecycle functions.
///   - Backward compatibility: proofs registered before this feature have
///     zero history entries.
#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, testutils::Events as _, Address, Bytes, Env,
    IntoVal, Symbol, Val, Vec as SorobanVec,
};

// ---------------------------------------------------------------------------
// Mock verifier
// ---------------------------------------------------------------------------

#[cfg(test)]
#[contract]
struct MockVerifierLifecycle;

#[cfg(test)]
#[contractimpl]
impl MockVerifierLifecycle {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        if public_inputs.len() != 160 || proof.is_empty() {
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
fn make_pi(env: &Env, vh: &BytesN<32>, cr: &BytesN<32>, nu: &BytesN<32>) -> Bytes {
    let mut v = [0u8; 32];
    vh.copy_into_slice(&mut v);
    let mut c = [0u8; 32];
    cr.copy_into_slice(&mut c);
    let mut n = [0u8; 32];
    nu.copy_into_slice(&mut n);
    let tag = expected_domain_tag(env);
    let mut t = [0u8; 32];
    tag.copy_into_slice(&mut t);
    let mut buf = [0u8; 160];
    buf[16..32].copy_from_slice(&v[..16]);
    buf[48..64].copy_from_slice(&v[16..]);
    buf[64..96].copy_from_slice(&c);
    buf[96..128].copy_from_slice(&n);
    buf[128..160].copy_from_slice(&t);
    Bytes::from_array(env, &buf)
}

#[cfg(test)]
fn init_registry() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);
    (env, contract_id, admin)
}

#[cfg(test)]
fn init_with_verifier() -> (Env, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockVerifierLifecycle, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    (env, contract_id, admin, verifier_id)
}

#[cfg(test)]
fn collect_history(
    env: &Env,
    client: &HarpocratesRegistryClient,
    proof_id: &BytesN<32>,
) -> SorobanVec<ProofHistoryEntry> {
    let count = client.get_proof_history_count(proof_id);
    let mut out = SorobanVec::new(env);
    for seq in 1..=count {
        if let Some(entry) = client.get_proof_history_at(proof_id, &seq) {
            out.push_back(entry);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Registration emits history
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_anonymous_emits_history() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let proof_id = b32(&env, 0x01);

    client.init(&admin);
    client.add_credential_root(&admin, &b32(&env, 0x05), &b32(&env, 0x06));

    client.register_anonymous(
        &b32(&env, 0x02),
        &b32(&env, 0x03),
        &proof_id,
        &b32(&env, 0x04),
        &b32(&env, 0x05),
        &proof_buf(&env),
    );

    assert_eq!(client.get_proof_history_count(&proof_id), 1);
    let history = collect_history(&env, &client, &proof_id);
    assert_eq!(history.len(), 1);
    assert_eq!(
        history.get(0).unwrap().action,
        ProofLifecycleAction::Registered as u32
    );
    assert_eq!(history.get(0).unwrap().actor, None);
    assert_eq!(history.get(0).unwrap().reason_code, TIER_SILENT_WITNESS);
}

#[test]
fn lifecycle_anonymous_verified_emits_history() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockVerifierLifecycle, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let proof_id = b32(&env, 0x11);
    let cr = b32(&env, 0x12);
    let nu = b32(&env, 0x13);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &cr, &b32(&env, 0x14));

    client.register_anonymous_verified(
        &b32(&env, 0x15),
        &b32(&env, 0x16),
        &proof_id,
        &make_pi(&env, &b32(&env, 0x15), &cr, &nu),
        &proof_buf(&env),
    );

    assert_eq!(client.get_proof_history_count(&proof_id), 1);
    let history = collect_history(&env, &client, &proof_id);
    assert_eq!(history.len(), 1);
    assert_eq!(
        history.get(0).unwrap().action,
        ProofLifecycleAction::Registered as u32
    );
    assert_eq!(history.get(0).unwrap().actor, None);
    assert_eq!(history.get(0).unwrap().reason_code, TIER_SILENT_WITNESS);
}

#[test]
fn lifecycle_source_emits_history() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x21);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x22), &b32(&env, 0x23), &proof_id);

    // Snapshot immediately: env.events().all() reflects only the most recent
    // invocation, so later client calls would clear these events.
    let events = env.events().all();

    assert_eq!(client.get_proof_history_count(&proof_id), 1);
    let history = collect_history(&env, &client, &proof_id);
    assert_eq!(history.len(), 1);
    assert_eq!(
        history.get(0).unwrap().action,
        ProofLifecycleAction::Registered as u32
    );
    assert_eq!(history.get(0).unwrap().actor, Some(source));
    assert_eq!(history.get(0).unwrap().reason_code, TIER_CONSISTENT_SOURCE);

    // Registration has one stable observable order: ProofRegistered first,
    // then its append-only lifecycle history entry. This also guards the
    // batch path, which uses the same save_record helper.
    assert_eq!(events.events().len(), 2);
    use soroban_sdk::xdr::ContractEventBody;
    use soroban_sdk::{TryFromVal as _, TryIntoVal as _};

    fn topics_of(env: &Env, event: &soroban_sdk::xdr::ContractEvent) -> soroban_sdk::Vec<Val> {
        match &event.body {
            ContractEventBody::V0(v0) => {
                let mut topics = soroban_sdk::Vec::new(env);
                for t in v0.topics.iter() {
                    topics.push_back(Val::try_from_val(env, t).unwrap());
                }
                topics
            }
            _ => soroban_sdk::Vec::new(env),
        }
    }

    let registration_topics = topics_of(&env, events.events().get(0).unwrap());
    let history_topics = topics_of(&env, events.events().get(1).unwrap());
    let as_symbol = |v: Val| -> Symbol { Symbol::try_from_val(&env, &v).unwrap() };
    assert_eq!(
        as_symbol(registration_topics.get(0).unwrap()),
        Symbol::new(&env, "proof")
    );
    assert_eq!(
        as_symbol(registration_topics.get(1).unwrap()),
        Symbol::new(&env, "reg")
    );
    assert_eq!(
        as_symbol(history_topics.get(0).unwrap()),
        Symbol::new(&env, "proof")
    );
    assert_eq!(
        as_symbol(history_topics.get(1).unwrap()),
        Symbol::new(&env, "history")
    );
}

#[test]
fn lifecycle_seal_emits_history() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);

    client.init(&admin);
    client.add_issuer(&admin, &issuer, &b32(&env, 0x31));
    let proof_id = b32(&env, 0x32);

    client.register_seal(&issuer, &b32(&env, 0x33), &b32(&env, 0x34), &proof_id);

    assert_eq!(client.get_proof_history_count(&proof_id), 1);
    let history = collect_history(&env, &client, &proof_id);
    assert_eq!(history.len(), 1);
    assert_eq!(
        history.get(0).unwrap().action,
        ProofLifecycleAction::Registered as u32
    );
    assert_eq!(history.get(0).unwrap().actor, Some(issuer));
    assert_eq!(history.get(0).unwrap().reason_code, TIER_PUBLIC_SEAL);
}

// ---------------------------------------------------------------------------
// Revocation emits history
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_revoke_emits_history() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x41);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x42), &b32(&env, 0x43), &proof_id);
    client.revoke_proof(&admin, &proof_id);

    assert_eq!(client.get_proof_history_count(&proof_id), 2);
    let history = collect_history(&env, &client, &proof_id);
    assert_eq!(history.len(), 2);
    assert_eq!(
        history.get(0).unwrap().action,
        ProofLifecycleAction::Registered as u32
    );
    assert_eq!(
        history.get(1).unwrap().action,
        ProofLifecycleAction::Revoked as u32
    );
    assert_eq!(history.get(1).unwrap().actor, Some(admin));
}

// ---------------------------------------------------------------------------
// Explicit verification
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_verify_emits_history() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x51);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x52), &b32(&env, 0x53), &proof_id);
    client.verify_proof(&admin, &proof_id, &1);

    assert_eq!(client.get_proof_history_count(&proof_id), 2);
    let history = collect_history(&env, &client, &proof_id);
    assert_eq!(history.len(), 2);
    assert_eq!(
        history.get(1).unwrap().action,
        ProofLifecycleAction::Verified as u32
    );
    assert_eq!(history.get(1).unwrap().actor, Some(admin));
    assert_eq!(history.get(1).unwrap().reason_code, 1);
}

// ---------------------------------------------------------------------------
// Explicit expiry
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_expire_emits_history_and_updates_status() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x61);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x62), &b32(&env, 0x63), &proof_id);
    client.expire_proof(&admin, &proof_id, &2);

    assert_eq!(client.get_proof_history_count(&proof_id), 2);
    let history = collect_history(&env, &client, &proof_id);
    assert_eq!(history.len(), 2);
    assert_eq!(
        history.get(1).unwrap().action,
        ProofLifecycleAction::Expired as u32
    );
    assert_eq!(history.get(1).unwrap().actor, Some(admin));
    assert_eq!(history.get(1).unwrap().reason_code, 2);

    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Expired
    );
}

// ---------------------------------------------------------------------------
// Administrative correction
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_correct_emits_history_and_updates_metadata() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x71);
    let new_meta = b32(&env, 0x72);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x73), &b32(&env, 0x74), &proof_id);
    client.correct_proof(&admin, &proof_id, &new_meta, &3);

    assert_eq!(client.get_proof_history_count(&proof_id), 2);
    let history = collect_history(&env, &client, &proof_id);
    assert_eq!(history.len(), 2);
    assert_eq!(
        history.get(1).unwrap().action,
        ProofLifecycleAction::Corrected as u32
    );
    assert_eq!(history.get(1).unwrap().actor, Some(admin));
    assert_eq!(history.get(1).unwrap().reason_code, 3);

    let stored = client.get_proof(&proof_id).unwrap();
    assert_eq!(stored.metadata_hash, new_meta);
}

// ---------------------------------------------------------------------------
// Pagination via sequence-number lookup
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_history_pagination() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x81);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x82), &b32(&env, 0x83), &proof_id);
    client.revoke_proof(&admin, &proof_id);
    client.verify_proof(&admin, &proof_id, &1);

    assert_eq!(client.get_proof_history_count(&proof_id), 3);

    let entry1 = client.get_proof_history_at(&proof_id, &1).unwrap();
    assert_eq!(entry1.action, ProofLifecycleAction::Registered as u32);

    let entry2 = client.get_proof_history_at(&proof_id, &2).unwrap();
    assert_eq!(entry2.action, ProofLifecycleAction::Revoked as u32);

    let entry3 = client.get_proof_history_at(&proof_id, &3).unwrap();
    assert_eq!(entry3.action, ProofLifecycleAction::Verified as u32);

    assert!(client.get_proof_history_at(&proof_id, &4).is_none());
    assert!(client.get_proof_history_at(&proof_id, &0).is_none());
}

// ---------------------------------------------------------------------------
// Abuse limits
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #13)")]
fn lifecycle_history_saturation_rejects_new_entries() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x92);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x93), &b32(&env, 0x94), &proof_id);

    for _ in 0..MAX_HISTORY_ENTRIES_PER_PROOF {
        client.verify_proof(&admin, &proof_id, &1);
    }

    client.verify_proof(&admin, &proof_id, &1);
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #17)")]
fn lifecycle_already_expired_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0xA1);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0xA2), &b32(&env, 0xA3), &proof_id);
    client.expire_proof(&admin, &proof_id, &1);
    client.expire_proof(&admin, &proof_id, &1);
}

#[test]
#[should_panic(expected = "Error(Contract, #18)")]
fn lifecycle_correct_no_change_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0xB1);
    let meta = b32(&env, 0xB2);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0xB3), &meta, &proof_id);
    client.correct_proof(&admin, &proof_id, &meta, &1);
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn lifecycle_verify_non_admin_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0xC1);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0xC2), &b32(&env, 0xC3), &proof_id);
    client.verify_proof(&source, &proof_id, &1);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn lifecycle_expire_non_admin_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0xD1);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0xD2), &b32(&env, 0xD3), &proof_id);
    client.expire_proof(&source, &proof_id, &1);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn lifecycle_correct_non_admin_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0xE1);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0xE2), &b32(&env, 0xE3), &proof_id);
    client.correct_proof(&source, &proof_id, &b32(&env, 0xE4), &1);
}

// ---------------------------------------------------------------------------
// Privacy: no sensitive data in history or events
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_history_contains_no_sensitive_fields() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0xF1);
    let video_hash = b32(&env, 0xF2);
    let metadata_hash = b32(&env, 0xF3);

    client.init(&admin);
    client.register_source(&source, &video_hash, &metadata_hash, &proof_id);
    client.revoke_proof(&admin, &proof_id);

    let history = collect_history(&env, &client, &proof_id);
    assert_eq!(history.len(), 2);
    for entry in history.iter() {
        let ProofHistoryEntry {
            action: _,
            timestamp: _,
            actor: _,
            reason_code: _,
        } = entry;
    }
}

// ---------------------------------------------------------------------------
// Backward compatibility
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_unknown_proof_has_empty_history() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let unknown = b32(&env, 0xFF);

    client.init(&admin);
    assert_eq!(client.get_proof_history_count(&unknown), 0);
    assert!(client.get_proof_history_at(&unknown, &1).is_none());
}

// ---------------------------------------------------------------------------
// Reason code bounds
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #15)")]
fn lifecycle_invalid_reason_code_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x10);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x11), &b32(&env, 0x12), &proof_id);
    client.verify_proof(&admin, &proof_id, &256);
}
