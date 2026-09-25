#![cfg(test)]

use super::*;
use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Bytes, Env};

#[contract]
struct MockLineageVerifier;

#[contractimpl]
impl MockLineageVerifier {
    pub fn verify_proof(_env: Env, _public_inputs: Bytes, _proof: Bytes) {}
}

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

#[test]
fn registers_lineage_with_bounded_validation() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let parent = bytes32(&env, 1);

    client.init(&admin);
    client.register_source(&actor, &bytes32(&env, 2), &bytes32(&env, 3), &parent);

    let lineage = client.register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [parent.clone()]),
        &bytes32(&env, 4),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 5),
        &1u32,
    );

    assert_eq!(lineage.output_digest, bytes32(&env, 5));
    assert_eq!(lineage.depth, 1);
}

#[test]
#[should_panic(expected = "Error(Contract, #60)")]
fn rejects_excessive_fanout() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    client.init(&admin);

    let parents = soroban_sdk::Vec::from_array(
        &env,
        [
            bytes32(&env, 1),
            bytes32(&env, 2),
            bytes32(&env, 3),
            bytes32(&env, 4),
            bytes32(&env, 5),
        ],
    );

    client.register_lineage(
        &actor,
        &parents,
        &bytes32(&env, 6),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 7),
        &1u32,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #58)")]
fn rejects_self_referential_lineage() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    client.init(&admin);

    client.register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [bytes32(&env, 1)]),
        &bytes32(&env, 2),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 1),
        &1u32,
    );
}
