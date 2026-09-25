#![cfg(test)]

//! On-chain metadata envelope versioning (#317).
//!
//! Covers positive registration stamping, explicit V2 bind/upgrade, unsupported
//! version rejection, hash mismatch, unauthorized actors, correct_proof sync,
//! and resolve_* backward-compat defaults.

use super::*;
use soroban_sdk::{
    testutils::Address as _,
    Address, BytesN, Env,
};

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn setup() -> (Env, HarpocratesRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, client, admin)
}

fn register_source_proof(
    env: &Env,
    client: &HarpocratesRegistryClient<'static>,
) -> (Address, BytesN<32>, BytesN<32>) {
    let source = Address::generate(env);
    let video = bytes32(env, 0x11);
    let meta = bytes32(env, 0x22);
    let proof_id = bytes32(env, 0x33);
    client.register_source(&source, &video, &meta, &proof_id);
    (source, proof_id, meta)
}

#[test]
fn registration_stamps_default_v1_envelope() {
    let (env, client, _) = setup();
    let (_source, proof_id, meta) = register_source_proof(&env, &client);

    let envelope = client.get_metadata_envelope(&proof_id).unwrap();
    assert_eq!(envelope.proof_id, proof_id);
    assert_eq!(envelope.version, METADATA_ENVELOPE_V1);
    assert_eq!(envelope.metadata_hash, meta);
    assert_eq!(
        client.resolve_envelope_version(&proof_id),
        METADATA_ENVELOPE_V1
    );
}

#[test]
fn bind_upgrade_to_v2_succeeds() {
    let (env, client, _) = setup();
    let (source, proof_id, meta) = register_source_proof(&env, &client);

    let upgraded = client.bind_metadata_envelope(&source, &proof_id, &METADATA_ENVELOPE_V2, &meta);
    assert_eq!(upgraded.version, METADATA_ENVELOPE_V2);
    assert_eq!(upgraded.metadata_hash, meta);

    let stored = client.get_metadata_envelope(&proof_id).unwrap();
    assert_eq!(stored.version, METADATA_ENVELOPE_V2);
    assert_eq!(
        client.resolve_envelope_version(&proof_id),
        METADATA_ENVELOPE_V2
    );
}

#[test]
fn bind_v2_is_idempotent() {
    let (env, client, admin) = setup();
    let (_source, proof_id, meta) = register_source_proof(&env, &client);

    let first = client.bind_metadata_envelope(&admin, &proof_id, &METADATA_ENVELOPE_V2, &meta);
    let second = client.bind_metadata_envelope(&admin, &proof_id, &METADATA_ENVELOPE_V2, &meta);
    assert_eq!(first, second);
}

#[test]
#[should_panic(expected = "Error(Contract, #77)")]
fn unsupported_version_zero_rejected() {
    let (env, client, admin) = setup();
    let (_source, proof_id, meta) = register_source_proof(&env, &client);
    client.bind_metadata_envelope(&admin, &proof_id, &0u32, &meta);
}

#[test]
#[should_panic(expected = "Error(Contract, #77)")]
fn unsupported_version_above_max_rejected() {
    let (env, client, admin) = setup();
    let (_source, proof_id, meta) = register_source_proof(&env, &client);
    let bad = METADATA_ENVELOPE_VERSION_MAX + 1;
    client.bind_metadata_envelope(&admin, &proof_id, &bad, &meta);
}

#[test]
#[should_panic(expected = "Error(Contract, #77)")]
fn downgrade_v2_to_v1_rejected() {
    let (env, client, admin) = setup();
    let (_source, proof_id, meta) = register_source_proof(&env, &client);
    client.bind_metadata_envelope(&admin, &proof_id, &METADATA_ENVELOPE_V2, &meta);
    client.bind_metadata_envelope(&admin, &proof_id, &METADATA_ENVELOPE_V1, &meta);
}

#[test]
#[should_panic(expected = "Error(Contract, #78)")]
fn zero_metadata_hash_rejected_on_bind() {
    let (env, client, admin) = setup();
    let (_source, proof_id, _meta) = register_source_proof(&env, &client);
    let zero = bytes32(&env, 0x00);
    client.bind_metadata_envelope(&admin, &proof_id, &METADATA_ENVELOPE_V2, &zero);
}

#[test]
#[should_panic(expected = "Error(Contract, #80)")]
fn hash_mismatch_rejected_on_bind() {
    let (env, client, admin) = setup();
    let (_source, proof_id, _meta) = register_source_proof(&env, &client);
    let other = bytes32(&env, 0xAB);
    client.bind_metadata_envelope(&admin, &proof_id, &METADATA_ENVELOPE_V2, &other);
}

#[test]
#[should_panic(expected = "Error(Contract, #79)")]
fn bind_unknown_proof_rejected() {
    let (env, client, admin) = setup();
    let missing = bytes32(&env, 0xFF);
    let meta = bytes32(&env, 0x22);
    client.bind_metadata_envelope(&admin, &missing, &METADATA_ENVELOPE_V1, &meta);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn unauthorized_actor_cannot_bind() {
    let (env, client, _) = setup();
    let (_source, proof_id, meta) = register_source_proof(&env, &client);
    let stranger = Address::generate(&env);
    client.bind_metadata_envelope(&stranger, &proof_id, &METADATA_ENVELOPE_V2, &meta);
}

#[test]
fn correct_proof_syncs_envelope_hash() {
    let (env, client, admin) = setup();
    let (_source, proof_id, meta) = register_source_proof(&env, &client);
    client.bind_metadata_envelope(&admin, &proof_id, &METADATA_ENVELOPE_V2, &meta);

    let new_meta = bytes32(&env, 0x44);
    client.correct_proof(&admin, &proof_id, &new_meta, &1u32);

    let proof = client.get_proof(&proof_id).unwrap();
    assert_eq!(proof.metadata_hash, new_meta);

    let envelope = client.get_metadata_envelope(&proof_id).unwrap();
    assert_eq!(envelope.version, METADATA_ENVELOPE_V2);
    assert_eq!(envelope.metadata_hash, new_meta);
}

#[test]
fn resolve_version_unknown_proof_is_zero() {
    let (env, client, _) = setup();
    let missing = bytes32(&env, 0xFE);
    assert_eq!(client.resolve_envelope_version(&missing), 0);
    assert!(client.get_metadata_envelope(&missing).is_none());
}

#[test]
fn is_supported_version_bounds() {
    let (_env, client, _) = setup();
    assert!(!client.is_supported_envelope_version(&0u32));
    assert!(client.is_supported_envelope_version(&METADATA_ENVELOPE_V1));
    assert!(client.is_supported_envelope_version(&METADATA_ENVELOPE_V2));
    assert!(!client.is_supported_envelope_version(&(METADATA_ENVELOPE_VERSION_MAX + 1)));
}

#[test]
fn seal_registration_also_stamps_v1() {
    let (env, client, admin) = setup();
    let issuer = Address::generate(&env);
    let issuer_meta = bytes32(&env, 0x01);
    client.add_issuer(&admin, &issuer, &issuer_meta);

    let video = bytes32(&env, 0x71);
    let meta = bytes32(&env, 0x72);
    let proof_id = bytes32(&env, 0x73);
    client.register_seal(&issuer, &video, &meta, &proof_id);

    let envelope = client.get_metadata_envelope(&proof_id).unwrap();
    assert_eq!(envelope.version, METADATA_ENVELOPE_V1);
    assert_eq!(envelope.metadata_hash, meta);
}
