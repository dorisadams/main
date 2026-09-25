//! Structured fuzzing of the verifier-input boundary (contract layer).
//!
//! The contract is the last line of defence: a frame that reaches it has
//! already passed through a backend and a browser, both of which an attacker
//! may control. Rejection here must be deterministic, allocation-free, and
//! bounded — a mutant must never panic the host, never consume unbounded
//! budget, and never leave partial state behind.
//!
//! The PRNG, mutator set, and seeds are mirrored byte-for-byte by
//! `backend/test_verifier_fuzz.py` and
//! `frontend/src/verifierInputs.fuzz.test.ts`, so all three layers explore the
//! same space and a divergence is attributable to one layer.
//!
//! Both boundaries are fuzzed: the pure [`verifier_inputs`] codec and the real
//! on-chain `classify_public_inputs` entry point.
//!
//! See `docs/zk-fuzzing.md`.

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};
#[cfg(test)]
use std::vec::Vec;
#[cfg(test)]
use std::{format, vec};

/// Fixed, small, and shared with the other layers — the CI budget for this
/// file must not drift with CI mood.
#[cfg(test)]
const SEEDS: [u32; 4] = [1, 7, 1337, 20260727];

/// Mutants per seed against the pure codec.
#[cfg(test)]
const ITERATIONS_PER_SEED: usize = 400;

/// Mutants per seed against the on-chain entry point. Lower, because each one
/// is a real contract invocation with a real budget attached.
#[cfg(test)]
const ON_CHAIN_ITERATIONS_PER_SEED: usize = 64;

#[cfg(test)]
const MUTATOR_COUNT: u32 = 10;

#[cfg(test)]
const MODULUS_BE: [u8; 32] = verifier_inputs::BN254_SCALAR_FIELD_MODULUS_BE;

/// Numerical Recipes LCG — chosen for exact reproducibility across Python,
/// TypeScript, and Rust rather than for statistical quality.
#[cfg(test)]
struct Lcg {
    state: u32,
}

#[cfg(test)]
impl Lcg {
    fn new(seed: u32) -> Self {
        Lcg { state: seed }
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

/// Apply one structured mutation. Mutator indices match the ordering of the
/// `MUTATORS` tuple in the Python and TypeScript harnesses.
#[cfg(test)]
fn mutate(base: &[u8], mutator: u32, rng: &mut Lcg) -> Vec<u8> {
    let mut data: Vec<u8> = base.to_vec();
    let field_len = verifier_inputs::FIELD_LEN;
    // Field-level mutators must respect the actual frame length: the
    // revocation schema carries 4 field words (128 bytes) while the silent
    // witness carries 5 (160 bytes).
    let field_count = (data.len() / field_len) as u32;

    match mutator {
        // 0: truncate_tail
        0 => {
            let keep = rng.below(data.len() as u32 + 1) as usize;
            data.truncate(keep);
            data
        }
        // 1: extend_tail
        1 => {
            let extra = 1 + rng.below(64);
            for _ in 0..extra {
                data.push(rng.below(256) as u8);
            }
            data
        }
        // 2: bit_flip
        2 => {
            if data.is_empty() {
                return data;
            }
            let index = rng.below(data.len() as u32) as usize;
            data[index] ^= 1u8 << rng.below(8);
            data
        }
        // 3: byte_saturate
        3 => {
            if data.is_empty() {
                return data;
            }
            let index = rng.below(data.len() as u32) as usize;
            data[index] = if rng.below(2) == 1 { 0xff } else { 0x00 };
            data
        }
        // 4: field_zero
        4 => {
            let index = rng.below(field_count) as usize;
            for byte in data.iter_mut().skip(index * field_len).take(field_len) {
                *byte = 0x00;
            }
            data
        }
        // 5: field_saturate
        5 => {
            let index = rng.below(field_count) as usize;
            for byte in data.iter_mut().skip(index * field_len).take(field_len) {
                *byte = 0xff;
            }
            data
        }
        // 6: field_swap
        6 => {
            let left = rng.below(field_count) as usize * field_len;
            let right = rng.below(field_count) as usize * field_len;
            for offset in 0..field_len {
                data.swap(left + offset, right + offset);
            }
            data
        }
        // 7: frame_duplicate
        7 => {
            let copy = data.clone();
            data.extend_from_slice(&copy);
            data
        }
        // 8: frame_rotate
        8 => {
            if data.is_empty() {
                return data;
            }
            let offset = rng.below(data.len() as u32) as usize;
            data.rotate_left(offset);
            data
        }
        // 9: field_modulus
        _ => {
            let index = rng.below(field_count) as usize;
            data[index * field_len..(index + 1) * field_len].copy_from_slice(&MODULUS_BE);
            data
        }
    }
}

/// Canonical starting frame for a schema, lifted straight from the shared
/// conformance corpus so the fuzzers and the conformance runners agree on what
/// "well-formed" means.
#[cfg(test)]
fn positive_frame(schema: &str) -> Vec<u8> {
    let mut hi = vec![0u8; 16];
    hi.extend_from_slice(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ]);
    let mut lo = vec![0u8; 16];
    lo.extend_from_slice(&[
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ]);

    let credential_root = vec![0x01u8; 32];
    let nullifier = vec![0x02u8; 32];
    let revocation_root = vec![0x03u8; 32];

    let mut frame = Vec::with_capacity(PUBLIC_INPUTS_LEN);
    if schema == verifier_inputs::SCHEMA_SILENT_WITNESS {
        frame.extend_from_slice(&hi);
        frame.extend_from_slice(&lo);
        frame.extend_from_slice(&credential_root);
        frame.extend_from_slice(&nullifier);
        // Fifth field word: the canonical silent-witness domain tag.
        frame.extend_from_slice(&verifier_inputs::SILENT_WITNESS_DOMAIN_TAG_BE);
    } else {
        frame.extend_from_slice(&revocation_root);
        frame.extend_from_slice(&nullifier);
        frame.extend_from_slice(&REVOCATION_DOMAIN_SEPARATOR);
        frame.extend_from_slice(&credential_root);
    }
    frame
}

#[cfg(test)]
const SCHEMAS: [&str; 2] = [
    verifier_inputs::SCHEMA_SILENT_WITNESS,
    verifier_inputs::SCHEMA_REVOCATION_WITNESS,
];

#[cfg(test)]
fn schema_id_of(schema: &str) -> u32 {
    if schema == verifier_inputs::SCHEMA_SILENT_WITNESS {
        SCHEMA_ID_SILENT_WITNESS
    } else {
        SCHEMA_ID_REVOCATION_WITNESS
    }
}

#[cfg(test)]
fn declared(code: u32) -> bool {
    code <= 9
}

// ---------------------------------------------------------------------------
// 1. Totality — every mutant yields a declared verdict, never a panic
// ---------------------------------------------------------------------------

#[test]
fn codec_never_panics_and_always_yields_a_declared_verdict() {
    for schema in SCHEMAS.iter() {
        let base = positive_frame(schema);

        for seed in SEEDS.iter() {
            let mut rng = Lcg::new(*seed);

            for iteration in 0..ITERATIONS_PER_SEED {
                let mutator = rng.below(MUTATOR_COUNT);
                let mutant = mutate(&base, mutator, &mut rng);

                let verdict = match verifier_inputs::classify(
                    schema,
                    &mutant,
                    64,
                    &REVOCATION_DOMAIN_SEPARATOR,
                ) {
                    Ok(()) => verifier_inputs::ACCEPTED_CODE,
                    Err(code) => code.as_code(),
                };

                assert!(
                    declared(verdict),
                    "seed={} schema={} iteration={} mutator={} gave undeclared verdict {}",
                    seed,
                    schema,
                    iteration,
                    mutator,
                    verdict
                );
            }
        }
    }
}

#[test]
fn proof_length_sweep_is_bounded_and_declared() {
    let base = positive_frame(verifier_inputs::SCHEMA_SILENT_WITNESS);

    for seed in SEEDS.iter() {
        let mut rng = Lcg::new(*seed);
        for _ in 0..ITERATIONS_PER_SEED {
            // Sweep the whole u32 range of claimed proof lengths, including
            // values far past anything the host could ever materialise.
            let proof_len = rng.next_u32();
            let verdict = match verifier_inputs::classify(
                verifier_inputs::SCHEMA_SILENT_WITNESS,
                &base,
                proof_len,
                &REVOCATION_DOMAIN_SEPARATOR,
            ) {
                Ok(()) => verifier_inputs::ACCEPTED_CODE,
                Err(code) => code.as_code(),
            };
            assert!(
                declared(verdict),
                "proof_len={} gave {}",
                proof_len,
                verdict
            );
        }
    }
}

#[test]
fn proof_length_edges_are_exact() {
    let base = positive_frame(verifier_inputs::SCHEMA_SILENT_WITNESS);
    let cases: &[(u32, u32)] = &[
        (0, verifier_inputs::RejectCode::ProofUndersize.as_code()),
        (
            verifier_inputs::MIN_PROOF_BYTES - 1,
            verifier_inputs::RejectCode::ProofUndersize.as_code(),
        ),
        (
            verifier_inputs::MIN_PROOF_BYTES,
            verifier_inputs::ACCEPTED_CODE,
        ),
        (
            verifier_inputs::MAX_PROOF_BYTES,
            verifier_inputs::ACCEPTED_CODE,
        ),
        (
            verifier_inputs::MAX_PROOF_BYTES + 1,
            verifier_inputs::RejectCode::ProofOversize.as_code(),
        ),
        (
            u32::MAX,
            verifier_inputs::RejectCode::ProofOversize.as_code(),
        ),
    ];

    for &(proof_len, expected) in cases {
        let verdict = match verifier_inputs::classify(
            verifier_inputs::SCHEMA_SILENT_WITNESS,
            &base,
            proof_len,
            &verifier_inputs::SILENT_WITNESS_DOMAIN_TAG_BE,
        ) {
            Ok(()) => verifier_inputs::ACCEPTED_CODE,
            Err(code) => code.as_code(),
        };
        assert_eq!(
            verdict, expected,
            "proof_len={} expected {} got {}",
            proof_len, expected, verdict
        );
    }
}

#[test]
fn proof_length_boundary_neighbourhood_is_declared() {
    // Structured neighbourhood around the accepted window — complements the
    // full-u32 sweep with denser coverage of the off-by-one band.
    let base = positive_frame(verifier_inputs::SCHEMA_SILENT_WITNESS);
    let mut lengths: Vec<u32> = vec![];
    for delta in 0u32..32 {
        lengths.push(delta); // near zero / undersize
        lengths.push(verifier_inputs::MIN_PROOF_BYTES.saturating_sub(delta));
        lengths.push(verifier_inputs::MIN_PROOF_BYTES.saturating_add(delta));
        lengths.push(verifier_inputs::MAX_PROOF_BYTES.saturating_sub(delta));
        if let Some(over) = verifier_inputs::MAX_PROOF_BYTES.checked_add(delta) {
            lengths.push(over);
        }
    }
    lengths.push(u32::MAX);

    for proof_len in lengths {
        let verdict = match verifier_inputs::classify(
            verifier_inputs::SCHEMA_SILENT_WITNESS,
            &base,
            proof_len,
            &verifier_inputs::SILENT_WITNESS_DOMAIN_TAG_BE,
        ) {
            Ok(()) => verifier_inputs::ACCEPTED_CODE,
            Err(code) => code.as_code(),
        };
        assert!(
            declared(verdict),
            "proof_len={} gave undeclared {}",
            proof_len,
            verdict
        );
    }
}

// ---------------------------------------------------------------------------
// 2. The real on-chain boundary
// ---------------------------------------------------------------------------

#[test]
fn on_chain_classification_never_panics_on_a_mutant() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    for schema in SCHEMAS.iter() {
        let base = positive_frame(schema);
        let schema_id = schema_id_of(schema);

        for seed in SEEDS.iter() {
            let mut rng = Lcg::new(*seed);

            for iteration in 0..ON_CHAIN_ITERATIONS_PER_SEED {
                let mutator = rng.below(MUTATOR_COUNT);
                let mutant = mutate(&base, mutator, &mut rng);

                let bytes = Bytes::from_slice(&env, &mutant);
                let verdict = client.classify_public_inputs(&schema_id, &bytes, &64);

                assert!(
                    declared(verdict),
                    "on-chain seed={} iteration={} mutator={} gave {}",
                    seed,
                    iteration,
                    mutator,
                    verdict
                );

                // A rejected classification must leave no trace: the entry
                // point is read-only and must never consume a nullifier.
                assert!(!client.has_nullifier(&BytesN::from_array(&env, &[0x02u8; 32])));
            }
        }
    }
}

#[test]
fn on_chain_and_pure_codec_agree_on_every_mutant() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.init(&Address::generate(&env));

    let mut divergences: Vec<_> = vec![];

    for schema in SCHEMAS.iter() {
        let base = positive_frame(schema);
        let schema_id = schema_id_of(schema);
        let mut rng = Lcg::new(SEEDS[0]);

        for iteration in 0..ON_CHAIN_ITERATIONS_PER_SEED {
            let mutator = rng.below(MUTATOR_COUNT);
            let mutant = mutate(&base, mutator, &mut rng);

            let expected_domain: &[u8; verifier_inputs::FIELD_LEN] =
                if *schema == verifier_inputs::SCHEMA_SILENT_WITNESS {
                    &verifier_inputs::SILENT_WITNESS_DOMAIN_TAG_BE
                } else {
                    &REVOCATION_DOMAIN_SEPARATOR
                };
            let pure = match verifier_inputs::classify(schema, &mutant, 64, expected_domain) {
                Ok(()) => verifier_inputs::ACCEPTED_CODE,
                Err(code) => code.as_code(),
            };
            let on_chain =
                client.classify_public_inputs(&schema_id, &Bytes::from_slice(&env, &mutant), &64);

            if pure != on_chain {
                divergences.push(format!(
                    "{} iteration={} mutator={}: pure={} on_chain={}",
                    schema, iteration, mutator, pure, on_chain
                ));
            }
        }
    }

    assert!(divergences.is_empty(), "divergences: {:?}", divergences);
}

// ---------------------------------------------------------------------------
// 3. Determinism
// ---------------------------------------------------------------------------

#[test]
fn a_seed_replays_the_same_mutants_and_verdicts() {
    let base = positive_frame(verifier_inputs::SCHEMA_SILENT_WITNESS);

    let run = || {
        let mut rng = Lcg::new(SEEDS[2]);
        let mut trace: Vec<(u32, u32)> = vec![];
        for _ in 0..64 {
            let mutator = rng.below(MUTATOR_COUNT);
            let mutant = mutate(&base, mutator, &mut rng);
            let verdict = match verifier_inputs::classify(
                verifier_inputs::SCHEMA_SILENT_WITNESS,
                &mutant,
                64,
                &REVOCATION_DOMAIN_SEPARATOR,
            ) {
                Ok(()) => verifier_inputs::ACCEPTED_CODE,
                Err(code) => code.as_code(),
            };
            trace.push((mutator, verdict));
        }
        trace
    };

    assert_eq!(run(), run());
}

#[test]
fn distinct_seeds_explore_distinct_paths() {
    let trace = |seed: u32| {
        let mut rng = Lcg::new(seed);
        (0..64)
            .map(|_| rng.below(MUTATOR_COUNT))
            .collect::<Vec<_>>()
    };
    assert_ne!(trace(SEEDS[0]), trace(SEEDS[1]));
}

// ---------------------------------------------------------------------------
// 4. Minimized regression corpus
// ---------------------------------------------------------------------------

#[cfg(test)]
const REGRESSIONS: &str = include_str!("../../../../zk/vectors/fuzz_regressions_v1.json");

#[test]
fn regression_corpus_is_versioned_and_present() {
    assert!(REGRESSIONS.contains("\"format\": \"harpocrates.fuzz-regressions\""));
    assert!(REGRESSIONS.contains("\"version\": 1"));
    assert!(REGRESSIONS.contains("\"codec\": \"hpx-vi/1\""));
    // Every entry must name the code it pins, so a silently emptied corpus
    // cannot pass as a green run.
    assert!(REGRESSIONS.contains("\"expect_reject_code\""));
}
