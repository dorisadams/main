//! Upgrade compatibility harness (#347)
//!
//! Focused positive, negative, boundary, and regression coverage for the
//! registry storage-schema upgrade path so Harpocrates stays safe at its
//! public boundaries across wasm replacements.
//!
//! Coverage:
//!   - `init` stamps `SchemaVersion::V1` and `get_storage_schema_version` reads it.
//!   - `upgrade_storage` is admin-only (Unauthorized for outsiders).
//!   - Idempotent no-op at V1: no `SchemaUpgraded` event, version unchanged.
//!   - Legacy registries missing `SchemaVersion` are stamped to V1 without an
//!     upgrade event (privacy-safe; no proof payload logged).
//!   - Existing Tier-2 source proofs remain readable and status-stable across
//!     an upgrade call (compatible callers / stored evidence preserved).
//!   - Verifier pointer survives an upgrade call (integration boundary).
//!
//! Threat / migration notes (see also contracts/README.md):
//!   - Trust boundary: only admin may mutate schema version.
//!   - Privacy: harness asserts schema topics only; never prints proof bytes,
//!     public inputs, witnesses, media, or keys.
//!   - Rollback: stamping V1 is additive; prior wasm ignoring the key is fine.
//!
//! Run: `cargo test -p harpocrates-registry upgrade_compat -- --nocapture`

#![cfg(test)]

use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Events as _},
    Address, Bytes, BytesN, Env, IntoVal, Symbol, Val, Vec as SorobanVec,
};

#[contract]
struct MockVerifierUpgrade;

#[contractimpl]
impl MockVerifierUpgrade {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        if public_inputs.len() != 128 || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

fn schema_upgrade_event_count(env: &Env, contract_id: &Address) -> u32 {
    use soroban_sdk::xdr::ContractEventBody;
    use soroban_sdk::{TryFromVal as _, Val};

    let mut count = 0u32;
    for e in env.events().all().events() {
        if let ContractEventBody::V0(v0) = &e.body {
            if v0.topics.len() < 2 {
                continue;
            }
            let t0: Option<Symbol> = v0
                .topics
                .first()
                .and_then(|v| Symbol::try_from_val(env, &Val::try_from_val(env, v).unwrap()).ok());
            let t1: Option<Symbol> = v0
                .topics
                .get(1)
                .and_then(|v| Symbol::try_from_val(env, &Val::try_from_val(env, v).unwrap()).ok());
            if t0 == Some(Symbol::new(env, "schema")) && t1 == Some(Symbol::new(env, "upgrade")) {
                count = count.saturating_add(1);
            }
        }
    }
    let _ = contract_id;
    count
}

fn init_registry() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, contract_id, admin)
}

#[test]
fn upgrade_compat_init_stamps_v1() {
    let (env, contract_id, _admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V1 as u32
    );

    let present = env.as_contract(&contract_id, || {
        env.storage().persistent().has(&DataKey::SchemaVersion)
    });
    assert!(present, "init must persist SchemaVersion");
}

#[test]
fn upgrade_compat_idempotent_noop_at_v1() {
    let (env, contract_id, admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let before = schema_upgrade_event_count(&env, &contract_id);
    client.upgrade_storage(&admin);
    client.upgrade_storage(&admin);
    let after = schema_upgrade_event_count(&env, &contract_id);

    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V1 as u32
    );
    assert_eq!(
        after, before,
        "idempotent V1 upgrade must not emit SchemaUpgraded"
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn upgrade_compat_rejects_non_admin() {
    let (env, contract_id, _admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let outsider = Address::generate(&env);
    client.upgrade_storage(&outsider);
}

#[test]
fn upgrade_compat_stamps_legacy_missing_schema_version() {
    let (env, contract_id, admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Simulate a pre-#85 deployment: admin present, SchemaVersion absent.
    env.as_contract(&contract_id, || {
        env.storage().persistent().remove(&DataKey::SchemaVersion);
    });
    assert!(
        !env.as_contract(&contract_id, || {
            env.storage().persistent().has(&DataKey::SchemaVersion)
        }),
        "fixture must clear SchemaVersion"
    );
    // Getter remains compatible (treats missing as V1).
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V1 as u32
    );

    let before = schema_upgrade_event_count(&env, &contract_id);
    client.upgrade_storage(&admin);
    let after = schema_upgrade_event_count(&env, &contract_id);

    assert!(
        env.as_contract(&contract_id, || {
            env.storage().persistent().has(&DataKey::SchemaVersion)
        }),
        "upgrade_storage must stamp SchemaVersion on legacy registries"
    );
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V1 as u32
    );
    assert_eq!(
        after, before,
        "legacy stamp must not emit SchemaUpgraded (no layout migration)"
    );
}

#[test]
fn upgrade_compat_preserves_registered_source_proof() {
    let (env, contract_id, admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);

    let video = b32(&env, 0x11);
    let meta = b32(&env, 0x22);
    let proof_id = b32(&env, 0x33);
    let record = client.register_source(&source, &video, &meta, &proof_id);
    assert_eq!(record.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(record.status, STATUS_REGISTERED);

    client.upgrade_storage(&admin);

    let after = client
        .get_proof(&proof_id)
        .expect("proof must survive upgrade");
    assert_eq!(after.video_hash, video);
    assert_eq!(after.metadata_hash, meta);
    assert_eq!(after.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(after.status, STATUS_REGISTERED);
    let by_video = client
        .get_by_video(&video)
        .expect("video index must survive upgrade");
    assert_eq!(by_video.video_hash, video);
    assert_eq!(by_video.metadata_hash, meta);
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V1 as u32
    );
}

#[test]
fn upgrade_compat_preserves_verifier_boundary() {
    let (env, contract_id, admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let verifier_id = env.register(MockVerifierUpgrade, ());
    client.set_verifier(&admin, &verifier_id);

    client.upgrade_storage(&admin);

    assert_eq!(
        client.get_verifier(),
        Some(verifier_id),
        "verifier integration pointer must survive upgrade_storage"
    );
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V1 as u32
    );
}

#[test]
fn upgrade_compat_repeated_legacy_stamp_stays_idempotent() {
    let (env, contract_id, admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    env.as_contract(&contract_id, || {
        env.storage().persistent().remove(&DataKey::SchemaVersion);
    });

    client.upgrade_storage(&admin);
    let mid = schema_upgrade_event_count(&env, &contract_id);
    client.upgrade_storage(&admin);
    let end = schema_upgrade_event_count(&env, &contract_id);

    assert_eq!(end, mid);
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V1 as u32
    );
}
