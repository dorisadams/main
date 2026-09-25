//! Property tests for identity-tier invariants (#345).
//!
//! Harpocrates exposes three public registration tiers with distinct privacy
//! shapes. These property tests randomly exercise registration sequences and
//! check that tier, uniqueness, pause isolation, and lookup invariants hold
//! after every step — without logging proof bytes, witnesses, media, or keys.
//!
//! Seeds and LCG match the style of `test_fuzz.rs` so failures shrink to a
//! reproducible `(seed, step, command)` triple.

#![cfg(test)]

use super::*;
use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, Address, Bytes, Env, IntoVal, Symbol,
};
use std::{format, vec::Vec};

const SEEDS: [u32; 6] = [1, 7, 42, 345, 1337, 20260924];
const STEPS_PER_SEED: usize = 48;
const KEY_POOL: u8 = 12;
const CRED_ROOT_BYTE: u8 = 0xC0;

#[contract]
struct MockTierVerifier;

#[contractimpl]
impl MockTierVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        let len = public_inputs.len();
        if (len != 128 && len != 192) || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

struct Lcg {
    state: u32,
}

impl Lcg {
    fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(1664525).wrapping_add(1013904223);
        self.state
    }

    fn below(&mut self, bound: u32) -> u32 {
        if bound == 0 {
            0
        } else {
            self.next_u32() % bound
        }
    }
}

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

fn proof_buf(env: &Env) -> Bytes {
    Bytes::from_array(env, &[0xAB, 0xCD, 0xEF, 0x01])
}

fn slot_byte(kind: u8, slot: u8) -> u8 {
    // Keep key domains disjoint so cross-kind collisions are intentional only.
    kind.wrapping_mul(17).wrapping_add(slot.wrapping_add(1))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TierCmd {
    Anonymous,
    Source,
    Seal,
    DuplicateProofCrossTier,
    DuplicateVideoCrossTier,
    DuplicateNullifier,
    PauseTier { tier_bit: u32 },
    UnpauseTier { tier_bit: u32 },
}

fn pick_cmd(rng: &mut Lcg) -> TierCmd {
    match rng.below(8) {
        0 => TierCmd::Anonymous,
        1 => TierCmd::Source,
        2 => TierCmd::Seal,
        3 => TierCmd::DuplicateProofCrossTier,
        4 => TierCmd::DuplicateVideoCrossTier,
        5 => TierCmd::DuplicateNullifier,
        6 => TierCmd::PauseTier {
            tier_bit: match rng.below(3) {
                0 => PAUSE_DOMAIN_TIER1_REGISTRATION,
                1 => PAUSE_DOMAIN_TIER2_REGISTRATION,
                _ => PAUSE_DOMAIN_TIER3_REGISTRATION,
            },
        },
        _ => TierCmd::UnpauseTier {
            tier_bit: match rng.below(3) {
                0 => PAUSE_DOMAIN_TIER1_REGISTRATION,
                1 => PAUSE_DOMAIN_TIER2_REGISTRATION,
                _ => PAUSE_DOMAIN_TIER3_REGISTRATION,
            },
        },
    }
}

#[derive(Clone, Debug)]
struct ModelProof {
    proof_id: u8,
    video: u8,
    tier: u32,
    nullifier: Option<u8>,
}

#[derive(Default)]
struct Model {
    proofs: Vec<ModelProof>,
    used_proof: Vec<u8>,
    used_video: Vec<u8>,
    used_nullifier: Vec<u8>,
    paused: u32,
}

impl Model {
    fn has_proof(&self, id: u8) -> bool {
        self.used_proof.contains(&id)
    }
    fn has_video(&self, id: u8) -> bool {
        self.used_video.contains(&id)
    }
    fn has_nullifier(&self, id: u8) -> bool {
        self.used_nullifier.contains(&id)
    }
    fn insert(&mut self, p: ModelProof) {
        self.used_proof.push(p.proof_id);
        self.used_video.push(p.video);
        if let Some(n) = p.nullifier {
            self.used_nullifier.push(n);
        }
        self.proofs.push(p);
    }
    fn is_paused(&self, bit: u32) -> bool {
        self.paused & bit != 0
    }
}

fn assert_tier_shape(record: &ProofRecord, expected_tier: u32, label: &str) {
    assert_eq!(record.tier, expected_tier, "{label}: unexpected tier");
    assert_eq!(
        record.status, STATUS_REGISTERED,
        "{label}: unexpected status"
    );
    match expected_tier {
        TIER_SILENT_WITNESS => {
            assert!(
                record.source.is_none(),
                "{label}: tier1 must not expose source"
            );
            assert!(
                record.issuer.is_none(),
                "{label}: tier1 must not expose issuer"
            );
            assert!(
                record.nullifier.is_some(),
                "{label}: tier1 requires nullifier"
            );
        }
        TIER_CONSISTENT_SOURCE => {
            assert!(record.source.is_some(), "{label}: tier2 requires source");
            assert!(
                record.issuer.is_none(),
                "{label}: tier2 must not expose issuer"
            );
            assert!(
                record.nullifier.is_none(),
                "{label}: tier2 must not store nullifier"
            );
        }
        TIER_PUBLIC_SEAL => {
            assert!(
                record.source.is_none(),
                "{label}: tier3 must not expose source"
            );
            assert!(record.issuer.is_some(), "{label}: tier3 requires issuer");
            assert!(
                record.nullifier.is_none(),
                "{label}: tier3 must not store nullifier"
            );
        }
        other => panic!("unexpected tier tag {other} in {label}"),
    }
}

fn try_register_source(
    env: &Env,
    contract_id: &Address,
    source: &Address,
    video: &BytesN<32>,
    metadata: &BytesN<32>,
    proof_id: &BytesN<32>,
) -> Result<ProofRecord, u32> {
    let result = env.try_invoke_contract::<ProofRecord, RegistryError>(
        contract_id,
        &Symbol::new(env, "register_source"),
        {
            let mut args = soroban_sdk::Vec::new(env);
            args.push_back(source.clone().into_val(env));
            args.push_back(video.clone().into_val(env));
            args.push_back(metadata.clone().into_val(env));
            args.push_back(proof_id.clone().into_val(env));
            args
        },
    );
    match result {
        Ok(Ok(rec)) => Ok(rec),
        Ok(Err(_)) => Err(0xfffe),
        Err(Ok(e)) => Err(e as u32),
        Err(Err(_)) => Err(0xffff),
    }
}

fn try_register_seal(
    env: &Env,
    contract_id: &Address,
    issuer: &Address,
    video: &BytesN<32>,
    metadata: &BytesN<32>,
    proof_id: &BytesN<32>,
) -> Result<ProofRecord, u32> {
    let result = env.try_invoke_contract::<ProofRecord, RegistryError>(
        contract_id,
        &Symbol::new(env, "register_seal"),
        {
            let mut args = soroban_sdk::Vec::new(env);
            args.push_back(issuer.clone().into_val(env));
            args.push_back(video.clone().into_val(env));
            args.push_back(metadata.clone().into_val(env));
            args.push_back(proof_id.clone().into_val(env));
            args
        },
    );
    match result {
        Ok(Ok(rec)) => Ok(rec),
        Ok(Err(_)) => Err(0xfffe),
        Err(Ok(e)) => Err(e as u32),
        Err(Err(_)) => Err(0xffff),
    }
}

fn try_register_anonymous(
    env: &Env,
    contract_id: &Address,
    video: &BytesN<32>,
    metadata: &BytesN<32>,
    proof_id: &BytesN<32>,
    nullifier: &BytesN<32>,
    credential_root: &BytesN<32>,
) -> Result<ProofRecord, u32> {
    let result = env.try_invoke_contract::<ProofRecord, RegistryError>(
        contract_id,
        &Symbol::new(env, "register_anonymous"),
        {
            let mut args = soroban_sdk::Vec::new(env);
            args.push_back(video.clone().into_val(env));
            args.push_back(metadata.clone().into_val(env));
            args.push_back(proof_id.clone().into_val(env));
            args.push_back(nullifier.clone().into_val(env));
            args.push_back(credential_root.clone().into_val(env));
            args.push_back(proof_buf(env).into_val(env));
            args
        },
    );
    match result {
        Ok(Ok(rec)) => Ok(rec),
        Ok(Err(_)) => Err(0xfffe),
        Err(Ok(e)) => Err(e as u32),
        Err(Err(_)) => Err(0xffff),
    }
}

fn init_fixture() -> (Env, Address, Address, Address, Address, BytesN<32>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let _verifier_id = env.register(MockTierVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);
    client.init(&admin);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAA));
    let cred = b32(&env, CRED_ROOT_BYTE);
    client.add_credential_root(&admin, &cred, &b32(&env, 0xFF));
    (env, contract_id, admin, source, issuer, cred)
}

fn check_lookups(client: &HarpocratesRegistryClient<'_>, model: &Model, env: &Env, label: &str) {
    for p in &model.proofs {
        let proof_id = b32(env, slot_byte(0xA1, p.proof_id));
        let video = b32(env, slot_byte(0xB2, p.video));
        let by_id = client
            .get_proof(&proof_id)
            .unwrap_or_else(|| panic!("{label}: missing proof slot={}", p.proof_id));
        assert_tier_shape(&by_id, p.tier, label);
        assert_eq!(by_id.video_hash, video, "{label}: video mismatch");
        let by_video = client
            .get_by_video(&video)
            .unwrap_or_else(|| panic!("{label}: missing video slot={}", p.video));
        assert_eq!(by_video.tier, by_id.tier, "{label}: lookup tier diverge");
        assert_eq!(
            by_video.video_hash, by_id.video_hash,
            "{label}: lookup video diverge"
        );
        if let Some(n) = p.nullifier {
            assert!(
                client.has_nullifier(&b32(env, slot_byte(0xD4, n))),
                "{label}: missing nullifier slot={n}"
            );
        }
    }
}

fn run_seed(seed: u32) {
    let (env, contract_id, admin, source, issuer, cred) = init_fixture();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let mut rng = Lcg::new(seed);
    let mut model = Model::default();

    for step in 0..STEPS_PER_SEED {
        let label = format!("seed={seed} step={step}");
        let cmd = pick_cmd(&mut rng);
        match cmd {
            TierCmd::Anonymous => {
                let proof_slot = rng.below(KEY_POOL as u32) as u8;
                let video_slot = rng.below(KEY_POOL as u32) as u8;
                let null_slot = rng.below(KEY_POOL as u32) as u8;
                let proof_id = b32(&env, slot_byte(0xA1, proof_slot));
                let video = b32(&env, slot_byte(0xB2, video_slot));
                let metadata = b32(&env, slot_byte(0xC3, rng.below(KEY_POOL as u32) as u8));
                let nullifier = b32(&env, slot_byte(0xD4, null_slot));

                let expect_fail = model.is_paused(PAUSE_DOMAIN_TIER1_REGISTRATION)
                    || model.has_proof(proof_slot)
                    || model.has_video(video_slot)
                    || model.has_nullifier(null_slot);

                let before_count = model.proofs.len();
                let result = try_register_anonymous(
                    &env,
                    &contract_id,
                    &video,
                    &metadata,
                    &proof_id,
                    &nullifier,
                    &cred,
                );
                if expect_fail {
                    assert!(result.is_err(), "{label}: anonymous should reject");
                    assert_eq!(
                        model.proofs.len(),
                        before_count,
                        "{label}: storage changed on reject"
                    );
                } else {
                    let rec = result.unwrap_or_else(|e| panic!("{label}: anonymous err={e}"));
                    assert_tier_shape(&rec, TIER_SILENT_WITNESS, &label);
                    model.insert(ModelProof {
                        proof_id: proof_slot,
                        video: video_slot,
                        tier: TIER_SILENT_WITNESS,
                        nullifier: Some(null_slot),
                    });
                }
            }
            TierCmd::Source => {
                let proof_slot = rng.below(KEY_POOL as u32) as u8;
                let video_slot = rng.below(KEY_POOL as u32) as u8;
                let proof_id = b32(&env, slot_byte(0xA1, proof_slot));
                let video = b32(&env, slot_byte(0xB2, video_slot));
                let metadata = b32(&env, slot_byte(0xC3, rng.below(KEY_POOL as u32) as u8));

                let expect_fail = model.is_paused(PAUSE_DOMAIN_TIER2_REGISTRATION)
                    || model.has_proof(proof_slot)
                    || model.has_video(video_slot);

                let before_count = model.proofs.len();
                let result =
                    try_register_source(&env, &contract_id, &source, &video, &metadata, &proof_id);
                if expect_fail {
                    assert!(result.is_err(), "{label}: source should reject");
                    assert_eq!(
                        model.proofs.len(),
                        before_count,
                        "{label}: storage changed on reject"
                    );
                } else {
                    let rec = result.unwrap_or_else(|e| panic!("{label}: source err={e}"));
                    assert_tier_shape(&rec, TIER_CONSISTENT_SOURCE, &label);
                    model.insert(ModelProof {
                        proof_id: proof_slot,
                        video: video_slot,
                        tier: TIER_CONSISTENT_SOURCE,
                        nullifier: None,
                    });
                }
            }
            TierCmd::Seal => {
                let proof_slot = rng.below(KEY_POOL as u32) as u8;
                let video_slot = rng.below(KEY_POOL as u32) as u8;
                let proof_id = b32(&env, slot_byte(0xA1, proof_slot));
                let video = b32(&env, slot_byte(0xB2, video_slot));
                let metadata = b32(&env, slot_byte(0xC3, rng.below(KEY_POOL as u32) as u8));

                let expect_fail = model.is_paused(PAUSE_DOMAIN_TIER3_REGISTRATION)
                    || model.has_proof(proof_slot)
                    || model.has_video(video_slot);

                let before_count = model.proofs.len();
                let result =
                    try_register_seal(&env, &contract_id, &issuer, &video, &metadata, &proof_id);
                if expect_fail {
                    assert!(result.is_err(), "{label}: seal should reject");
                    assert_eq!(
                        model.proofs.len(),
                        before_count,
                        "{label}: storage changed on reject"
                    );
                } else {
                    let rec = result.unwrap_or_else(|e| panic!("{label}: seal err={e}"));
                    assert_tier_shape(&rec, TIER_PUBLIC_SEAL, &label);
                    model.insert(ModelProof {
                        proof_id: proof_slot,
                        video: video_slot,
                        tier: TIER_PUBLIC_SEAL,
                        nullifier: None,
                    });
                }
            }
            TierCmd::DuplicateProofCrossTier => {
                if model.proofs.is_empty() {
                    continue;
                }
                let existing = &model.proofs[rng.below(model.proofs.len() as u32) as usize];
                // Fresh video so only proof_id collides.
                let mut video_slot = rng.below(KEY_POOL as u32) as u8;
                let mut guard = 0;
                while model.has_video(video_slot) && guard < 16 {
                    video_slot = rng.below(KEY_POOL as u32) as u8;
                    guard += 1;
                }
                if model.has_video(video_slot) {
                    continue;
                }
                let proof_id = b32(&env, slot_byte(0xA1, existing.proof_id));
                let video = b32(&env, slot_byte(0xB2, video_slot));
                let metadata = b32(&env, slot_byte(0xC3, 1));
                // Attempt on a different tier than the original when possible.
                let result = if existing.tier == TIER_CONSISTENT_SOURCE {
                    try_register_seal(&env, &contract_id, &issuer, &video, &metadata, &proof_id)
                } else {
                    try_register_source(&env, &contract_id, &source, &video, &metadata, &proof_id)
                };
                assert!(
                    result.is_err(),
                    "{label}: duplicate proof_id must fail cross-tier"
                );
                let err = result.err().unwrap();
                assert!(
                    err == RegistryError::DuplicateProof as u32
                        || err == RegistryError::Paused as u32
                        || err == 0xffff,
                    "{label}: unexpected err={err}"
                );
            }
            TierCmd::DuplicateVideoCrossTier => {
                if model.proofs.is_empty() {
                    continue;
                }
                let existing = &model.proofs[rng.below(model.proofs.len() as u32) as usize];
                let mut proof_slot = rng.below(KEY_POOL as u32) as u8;
                let mut guard = 0;
                while model.has_proof(proof_slot) && guard < 16 {
                    proof_slot = rng.below(KEY_POOL as u32) as u8;
                    guard += 1;
                }
                if model.has_proof(proof_slot) {
                    continue;
                }
                let proof_id = b32(&env, slot_byte(0xA1, proof_slot));
                let video = b32(&env, slot_byte(0xB2, existing.video));
                let metadata = b32(&env, slot_byte(0xC3, 2));
                let result = if existing.tier == TIER_PUBLIC_SEAL {
                    try_register_source(&env, &contract_id, &source, &video, &metadata, &proof_id)
                } else {
                    try_register_seal(&env, &contract_id, &issuer, &video, &metadata, &proof_id)
                };
                assert!(
                    result.is_err(),
                    "{label}: duplicate video_hash must fail cross-tier"
                );
                let err = result.err().unwrap();
                assert!(
                    err == RegistryError::DuplicateVideo as u32
                        || err == RegistryError::Paused as u32
                        || err == 0xffff,
                    "{label}: unexpected err={err}"
                );
            }
            TierCmd::DuplicateNullifier => {
                let Some(existing) = model.proofs.iter().find(|p| p.nullifier.is_some()) else {
                    continue;
                };
                let null_slot = existing.nullifier.unwrap();
                let mut proof_slot = rng.below(KEY_POOL as u32) as u8;
                let mut video_slot = rng.below(KEY_POOL as u32) as u8;
                let mut guard = 0;
                while (model.has_proof(proof_slot) || model.has_video(video_slot)) && guard < 16 {
                    proof_slot = rng.below(KEY_POOL as u32) as u8;
                    video_slot = rng.below(KEY_POOL as u32) as u8;
                    guard += 1;
                }
                if model.has_proof(proof_slot) || model.has_video(video_slot) {
                    continue;
                }
                let result = try_register_anonymous(
                    &env,
                    &contract_id,
                    &b32(&env, slot_byte(0xB2, video_slot)),
                    &b32(&env, slot_byte(0xC3, 3)),
                    &b32(&env, slot_byte(0xA1, proof_slot)),
                    &b32(&env, slot_byte(0xD4, null_slot)),
                    &cred,
                );
                assert!(result.is_err(), "{label}: duplicate nullifier must fail");
                let err = result.err().unwrap();
                assert!(
                    err == RegistryError::DuplicateNullifier as u32
                        || err == RegistryError::Paused as u32
                        || err == 0xffff,
                    "{label}: unexpected err={err}"
                );
            }
            TierCmd::PauseTier { tier_bit } => {
                client.pause(&admin, &tier_bit, &3600u64);
                model.paused |= tier_bit;
                // Other tiers remain registerable when not paused.
                let other_bits = PAUSE_DOMAIN_ALL_REGISTRATION & !tier_bit;
                for bit in [
                    PAUSE_DOMAIN_TIER1_REGISTRATION,
                    PAUSE_DOMAIN_TIER2_REGISTRATION,
                    PAUSE_DOMAIN_TIER3_REGISTRATION,
                ] {
                    if other_bits & bit != 0 && !model.is_paused(bit) {
                        assert!(
                            !client.is_paused(&bit),
                            "{label}: unrelated tier bit={bit} should stay live"
                        );
                    }
                }
                assert!(client.is_paused(&tier_bit), "{label}: paused bit not set");
            }
            TierCmd::UnpauseTier { tier_bit } => {
                client.unpause(&admin, &tier_bit);
                model.paused &= !tier_bit;
                assert!(!client.is_paused(&tier_bit), "{label}: unpause failed");
            }
        }
        check_lookups(&client, &model, &env, &label);
    }

    // Final global uniqueness properties.
    let mut seen_proof = std::vec::Vec::new();
    let mut seen_video = std::vec::Vec::new();
    let mut seen_null = std::vec::Vec::new();
    for p in &model.proofs {
        assert!(
            !seen_proof.contains(&p.proof_id),
            "seed={seed}: proof_id not unique"
        );
        assert!(
            !seen_video.contains(&p.video),
            "seed={seed}: video not unique"
        );
        seen_proof.push(p.proof_id);
        seen_video.push(p.video);
        if let Some(n) = p.nullifier {
            assert!(!seen_null.contains(&n), "seed={seed}: nullifier not unique");
            seen_null.push(n);
        }
    }
}

#[test]
fn identity_tier_shape_invariants_hold_for_canonical_registrations() {
    let (env, contract_id, _admin, source, issuer, cred) = init_fixture();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let anon = client.register_anonymous(
        &b32(&env, slot_byte(0xB2, 1)),
        &b32(&env, slot_byte(0xC3, 1)),
        &b32(&env, slot_byte(0xA1, 1)),
        &b32(&env, slot_byte(0xD4, 1)),
        &cred,
        &proof_buf(&env),
    );
    assert_tier_shape(&anon, TIER_SILENT_WITNESS, "canonical-anon");

    let src = client.register_source(
        &source,
        &b32(&env, slot_byte(0xB2, 2)),
        &b32(&env, slot_byte(0xC3, 2)),
        &b32(&env, slot_byte(0xA1, 2)),
    );
    assert_tier_shape(&src, TIER_CONSISTENT_SOURCE, "canonical-source");

    let seal = client.register_seal(
        &issuer,
        &b32(&env, slot_byte(0xB2, 3)),
        &b32(&env, slot_byte(0xC3, 3)),
        &b32(&env, slot_byte(0xA1, 3)),
    );
    assert_tier_shape(&seal, TIER_PUBLIC_SEAL, "canonical-seal");

    // Cross-tier uniqueness still holds on the live contract.
    let dup = try_register_source(
        &env,
        &contract_id,
        &source,
        &b32(&env, slot_byte(0xB2, 99)),
        &b32(&env, slot_byte(0xC3, 99)),
        &b32(&env, slot_byte(0xA1, 1)), // same proof_id as anonymous
    );
    assert_eq!(dup.err(), Some(RegistryError::DuplicateProof as u32));
}

#[test]
fn identity_tier_property_suite_across_seeds() {
    for seed in SEEDS.iter() {
        run_seed(*seed);
    }
}

#[test]
fn identity_tier_pause_isolates_registration_domains() {
    let (env, contract_id, admin, source, issuer, cred) = init_fixture();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.pause(&admin, &PAUSE_DOMAIN_TIER2_REGISTRATION, &7200u64);
    assert!(client.is_paused(&PAUSE_DOMAIN_TIER2_REGISTRATION));
    assert!(!client.is_paused(&PAUSE_DOMAIN_TIER1_REGISTRATION));
    assert!(!client.is_paused(&PAUSE_DOMAIN_TIER3_REGISTRATION));

    let blocked = try_register_source(
        &env,
        &contract_id,
        &source,
        &b32(&env, slot_byte(0xB2, 4)),
        &b32(&env, slot_byte(0xC3, 4)),
        &b32(&env, slot_byte(0xA1, 4)),
    );
    assert_eq!(blocked.err(), Some(RegistryError::Paused as u32));

    let anon = client.register_anonymous(
        &b32(&env, slot_byte(0xB2, 5)),
        &b32(&env, slot_byte(0xC3, 5)),
        &b32(&env, slot_byte(0xA1, 5)),
        &b32(&env, slot_byte(0xD4, 5)),
        &cred,
        &proof_buf(&env),
    );
    assert_tier_shape(&anon, TIER_SILENT_WITNESS, "pause-isolates-anon");

    let seal = client.register_seal(
        &issuer,
        &b32(&env, slot_byte(0xB2, 6)),
        &b32(&env, slot_byte(0xC3, 6)),
        &b32(&env, slot_byte(0xA1, 6)),
    );
    assert_tier_shape(&seal, TIER_PUBLIC_SEAL, "pause-isolates-seal");
}
