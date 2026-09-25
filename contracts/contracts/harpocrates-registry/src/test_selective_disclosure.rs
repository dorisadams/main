#![cfg(test)]

use super::*;
use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Bytes, BytesN, Env};

#[contract]
struct MockNoirVerifier;

#[contractimpl]
impl MockNoirVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        if public_inputs.len() != 352 || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn copy_field(bytes: &mut [u8; 352], pos: &mut usize, src: &BytesN<32>) {
    let mut arr = [0u8; 32];
    src.copy_into_slice(&mut arr);
    bytes[*pos..*pos + 32].copy_from_slice(&arr);
    *pos += 32;
}

fn make_selective_disclosure_inputs(
    env: &Env,
    schema_hash: &BytesN<32>,
    issuer_namespace: &BytesN<32>,
    schema_version: u32,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
    evidence_digest: &BytesN<32>,
    circuit_version: u32,
) -> Bytes {
    let mut bytes = [0u8; 352];
    let mut pos: usize = 0;

    copy_field(&mut bytes, &mut pos, schema_hash);
    copy_field(&mut bytes, &mut pos, issuer_namespace);
    bytes[92..96].copy_from_slice(&schema_version.to_be_bytes());
    pos += 32;
    copy_field(&mut bytes, &mut pos, credential_root);
    copy_field(&mut bytes, &mut pos, nullifier);

    let dummy_hi = bytes32(env, 0xAA);
    let dummy_lo = bytes32(env, 0xAB);
    let verifier_digest = bytes32(env, 0xBB);
    copy_field(&mut bytes, &mut pos, &dummy_hi);
    copy_field(&mut bytes, &mut pos, &dummy_lo);
    copy_field(&mut bytes, &mut pos, &verifier_digest);

    bytes[284..288].copy_from_slice(&circuit_version.to_be_bytes());
    pos += 32;
    copy_field(&mut bytes, &mut pos, evidence_digest);

    let pred_comm = bytes32(env, 0xCC);
    copy_field(&mut bytes, &mut pos, &pred_comm);

    Bytes::from_array(env, &bytes)
}

fn valid_proof(env: &Env) -> Bytes {
    Bytes::from_array(env, &[1, 2, 3, 4, 5])
}

fn setup_env() -> (Env, HarpocratesRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockNoirVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    (env, client, admin)
}

#[test]
fn test_verify_selective_disclosure_valid() {
    let (env, client, admin) = setup_env();

    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    let credential_root = bytes32(&env, 0xAA);
    let nullifier = bytes32(&env, 0xBB);
    let evidence_digest = bytes32(&env, 0xCC);

    client.add_schema(&admin, &schema_hash, &ns, &1, &3);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 0xDD));

    let inputs = make_selective_disclosure_inputs(
        &env,
        &schema_hash,
        &ns,
        1,
        &credential_root,
        &nullifier,
        &evidence_digest,
        1,
    );

    client.verify_selective_disclosure(&inputs, &valid_proof(&env));

    assert!(client.has_nullifier(&nullifier));
}

#[test]
#[should_panic(expected = "Error(Contract, #50)")]
fn test_verify_selective_disclosure_unknown_schema() {
    let (env, client, admin) = setup_env();

    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    let credential_root = bytes32(&env, 0xAA);
    let nullifier = bytes32(&env, 0xBB);
    let evidence_digest = bytes32(&env, 0xCC);

    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 0xDD));

    let inputs = make_selective_disclosure_inputs(
        &env,
        &schema_hash,
        &ns,
        1,
        &credential_root,
        &nullifier,
        &evidence_digest,
        1,
    );
    client.verify_selective_disclosure(&inputs, &valid_proof(&env));
}

#[test]
#[should_panic(expected = "Error(Contract, #51)")]
fn test_verify_selective_disclosure_inactive_schema() {
    let (env, client, admin) = setup_env();

    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    let credential_root = bytes32(&env, 0xAA);
    let nullifier = bytes32(&env, 0xBB);
    let evidence_digest = bytes32(&env, 0xCC);

    client.add_schema(&admin, &schema_hash, &ns, &1, &3);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 0xDD));
    client.deprecate_schema(&admin, &schema_hash);

    let inputs = make_selective_disclosure_inputs(
        &env,
        &schema_hash,
        &ns,
        1,
        &credential_root,
        &nullifier,
        &evidence_digest,
        1,
    );
    client.verify_selective_disclosure(&inputs, &valid_proof(&env));
}

#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn test_verify_selective_disclosure_wrong_namespace() {
    let (env, client, admin) = setup_env();

    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    let wrong_ns = bytes32(&env, 0xFF);
    let credential_root = bytes32(&env, 0xAA);
    let nullifier = bytes32(&env, 0xBB);
    let evidence_digest = bytes32(&env, 0xCC);

    client.add_schema(&admin, &schema_hash, &ns, &1, &3);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 0xDD));

    let inputs = make_selective_disclosure_inputs(
        &env,
        &schema_hash,
        &wrong_ns,
        1,
        &credential_root,
        &nullifier,
        &evidence_digest,
        1,
    );
    client.verify_selective_disclosure(&inputs, &valid_proof(&env));
}

#[test]
#[should_panic(expected = "Error(Contract, #52)")]
fn test_verify_selective_disclosure_schema_version_mismatch() {
    let (env, client, admin) = setup_env();

    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    let credential_root = bytes32(&env, 0xAA);
    let nullifier = bytes32(&env, 0xBB);
    let evidence_digest = bytes32(&env, 0xCC);

    client.add_schema(&admin, &schema_hash, &ns, &2, &3);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 0xDD));

    let inputs = make_selective_disclosure_inputs(
        &env,
        &schema_hash,
        &ns,
        1,
        &credential_root,
        &nullifier,
        &evidence_digest,
        1,
    );
    client.verify_selective_disclosure(&inputs, &valid_proof(&env));
}

#[test]
#[should_panic(expected = "Error(Contract, #52)")]
fn test_circuit_version_downgrade() {
    let (env, client, admin) = setup_env();

    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    let credential_root = bytes32(&env, 0xAA);
    let nullifier = bytes32(&env, 0xBB);
    let evidence_digest = bytes32(&env, 0xCC);

    client.add_schema(&admin, &schema_hash, &ns, &1, &3);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 0xDD));

    let inputs = make_selective_disclosure_inputs(
        &env,
        &schema_hash,
        &ns,
        1,
        &credential_root,
        &nullifier,
        &evidence_digest,
        0,
    );
    client.verify_selective_disclosure(&inputs, &valid_proof(&env));
}

#[test]
#[should_panic(expected = "Error(Contract, #11)")]
fn test_verify_selective_disclosure_unknown_credential_root() {
    let (env, client, admin) = setup_env();

    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    client.add_schema(&admin, &schema_hash, &ns, &1, &3);

    let credential_root = bytes32(&env, 0xAA);
    let nullifier = bytes32(&env, 0xBB);
    let evidence_digest = bytes32(&env, 0xCC);

    let inputs = make_selective_disclosure_inputs(
        &env,
        &schema_hash,
        &ns,
        1,
        &credential_root,
        &nullifier,
        &evidence_digest,
        1,
    );
    client.verify_selective_disclosure(&inputs, &valid_proof(&env));
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn test_verify_selective_disclosure_duplicate_nullifier() {
    let (env, client, admin) = setup_env();

    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    let credential_root = bytes32(&env, 0xAA);
    let nullifier = bytes32(&env, 0xBB);
    let evidence_digest = bytes32(&env, 0xCC);

    client.add_schema(&admin, &schema_hash, &ns, &1, &3);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 0xDD));

    let inputs = make_selective_disclosure_inputs(
        &env,
        &schema_hash,
        &ns,
        1,
        &credential_root,
        &nullifier,
        &evidence_digest,
        1,
    );

    client.verify_selective_disclosure(&inputs, &valid_proof(&env));
    client.verify_selective_disclosure(&inputs, &valid_proof(&env));
}

#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn test_verify_selective_disclosure_wrong_input_length() {
    let (env, client, _) = setup_env();
    let bad_inputs = Bytes::from_array(&env, &[0u8; 100]);
    client.verify_selective_disclosure(&bad_inputs, &valid_proof(&env));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_add_schema_unauthorized() {
    let (env, client, _) = setup_env();
    let attacker = Address::generate(&env);
    client.add_schema(&attacker, &bytes32(&env, 1), &bytes32(&env, 2), &1, &2);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_deprecate_schema_unauthorized() {
    let (env, client, admin) = setup_env();
    client.add_schema(&admin, &bytes32(&env, 1), &bytes32(&env, 2), &1, &2);
    let attacker = Address::generate(&env);
    client.deprecate_schema(&attacker, &bytes32(&env, 1));
}
