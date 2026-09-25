//! Cross-layer verifier conformance (`hpx-vi/1`).
//!
//! Drives the shared corpus in `zk/vectors/verifier_conformance_v1.json`
//! through **both** contract-side boundaries:
//!
//! 1. the pure [`verifier_inputs`] codec, and
//! 2. the real on-chain `classify_public_inputs` entry point, invoked through
//!    the generated contract client.
//!
//! The Python (`backend/test_conformance_vectors.py`) and TypeScript
//! (`frontend/src/verifierInputs.conformance.test.ts`) runners drive the same
//! file. A divergence in any layer fails exactly one of the three suites and
//! names the offending case id, so mismatch diagnosis does not require
//! re-deriving which layer is wrong.
//!
//! The corpus is deliberately dependency-free: it is scanned with a small
//! line-oriented reader rather than a JSON crate, so conformance adds no
//! third-party code to a contract crate.

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};
#[cfg(test)]
use std::string::{String, ToString};
#[cfg(test)]
use std::vec::Vec;
#[cfg(test)]
use std::{format, vec};

#[cfg(test)]
const CORPUS: &str = include_str!("../../../../zk/vectors/verifier_conformance_v1.json");

#[cfg(test)]
#[derive(Debug)]
struct ConformanceCase {
    id: String,
    schema: String,
    public_inputs_hex: String,
    proof_hex: String,
    accept: bool,
    reject_code: Option<String>,
}

/// Extract the value of `"<key>": <value>` from a single corpus line.
#[cfg(test)]
fn field_value(line: &str, key: &str) -> Option<String> {
    let trimmed = line.trim();
    let prefix = format!("\"{}\":", key);
    let rest = trimmed.strip_prefix(prefix.as_str())?;
    let rest = rest.trim().trim_end_matches(',').trim();
    if rest == "null" {
        return Some("null".to_string());
    }
    Some(rest.trim_matches('"').to_string())
}

/// Line-oriented reader for the generated corpus.
///
/// The generator emits each case with a stable key order ending in
/// `reject_code`, which is what closes a case here. Any structural drift
/// (missing key, reordered keys) surfaces as a zero-case corpus, which the
/// `corpus_is_non_empty_and_versioned` test rejects.
#[cfg(test)]
fn parse_corpus() -> Vec<ConformanceCase> {
    let mut cases = Vec::new();
    let mut current: Option<(String, String, String, String, bool)> = None;

    for line in CORPUS.lines() {
        if let Some(id) = field_value(line, "id") {
            current = Some((id, String::new(), String::new(), String::new(), false));
            continue;
        }
        let Some(state) = current.as_mut() else {
            continue;
        };
        if let Some(schema) = field_value(line, "schema") {
            state.1 = schema;
        } else if let Some(public_inputs) = field_value(line, "public_inputs_hex") {
            state.2 = public_inputs;
        } else if let Some(proof) = field_value(line, "proof_hex") {
            state.3 = proof;
        } else if let Some(accept) = field_value(line, "accept") {
            state.4 = accept == "true";
        } else if let Some(reject_code) = field_value(line, "reject_code") {
            let (id, schema, public_inputs_hex, proof_hex, accept) = current.take().unwrap();
            cases.push(ConformanceCase {
                id,
                schema,
                public_inputs_hex,
                proof_hex,
                accept,
                reject_code: if reject_code == "null" {
                    None
                } else {
                    Some(reject_code)
                },
            });
        }
    }

    cases
}

#[cfg(test)]
fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0, "corpus hex must be even length");
    let raw = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in raw.chunks(2) {
        let high = (chunk[0] as char).to_digit(16).expect("corpus hex digit");
        let low = (chunk[1] as char).to_digit(16).expect("corpus hex digit");
        out.push((high * 16 + low) as u8);
    }
    out
}

#[cfg(test)]
fn schema_id(schema: &str) -> u32 {
    match schema {
        "silent_witness/v1" => SCHEMA_ID_SILENT_WITNESS,
        "revocation_witness/v1" => SCHEMA_ID_REVOCATION_WITNESS,
        other => panic!("corpus references unknown schema: {}", other),
    }
}

/// Expected numeric code for a case: 0 when accepted, otherwise the stable
/// [`RejectCode`] discriminant.
#[cfg(test)]
fn expected_code(case: &ConformanceCase) -> u32 {
    match (&case.reject_code, case.accept) {
        (None, true) => verifier_inputs::ACCEPTED_CODE,
        (Some(code), false) => RejectCode::from_wire(code)
            .unwrap_or_else(|| panic!("corpus uses unknown reject code: {}", code))
            .as_code(),
        _ => panic!("case {} has inconsistent accept/reject_code", case.id),
    }
}

// ---------------------------------------------------------------------------
// Corpus integrity
// ---------------------------------------------------------------------------

#[test]
fn corpus_is_non_empty_and_versioned() {
    assert!(
        CORPUS.contains("\"codec\": \"hpx-vi/1\""),
        "corpus codec id drifted from the contract implementation"
    );
    assert!(
        CORPUS.contains("\"version\": 1"),
        "corpus version drifted; bump the runners alongside the format"
    );

    let cases = parse_corpus();
    assert!(
        cases.len() >= 20,
        "expected a substantive corpus, parsed {} cases",
        cases.len()
    );
    assert!(
        cases.iter().any(|case| case.accept),
        "corpus must contain positive cases"
    );
    assert!(
        cases.iter().any(|case| !case.accept),
        "corpus must contain negative cases"
    );
}

#[test]
fn corpus_constants_match_contract_constants() {
    // The domain separator is the one value that must be byte-identical
    // between the corpus and the deployed contract, so it is asserted
    // directly rather than through a case.
    let mut hex = String::new();
    for byte in REVOCATION_DOMAIN_SEPARATOR.iter() {
        hex.push_str(&format!("{:02x}", byte));
    }
    assert!(
        CORPUS.contains(hex.as_str()),
        "corpus revocation domain separator does not match REVOCATION_DOMAIN_SEPARATOR"
    );
}

// ---------------------------------------------------------------------------
// Boundary 1: the pure codec
// ---------------------------------------------------------------------------

#[test]
fn codec_agrees_with_every_corpus_case() {
    let mut mismatches: Vec<String> = vec![];

    for case in parse_corpus() {
        let public_inputs = decode_hex(&case.public_inputs_hex);
        // Only the length of the proof blob is semantically relevant, so the
        // blob itself is never materialised — this keeps the oversize case
        // cheap and keeps proof material out of the test process.
        let proof_len = (case.proof_hex.len() / 2) as u32;

        let expected_domain = if case.schema == verifier_inputs::SCHEMA_SILENT_WITNESS {
            &verifier_inputs::SILENT_WITNESS_DOMAIN_TAG_BE
        } else {
            &REVOCATION_DOMAIN_SEPARATOR
        };

        let actual = match verifier_inputs::classify(
            &case.schema,
            &public_inputs,
            proof_len,
            expected_domain,
        ) {
            Ok(()) => verifier_inputs::ACCEPTED_CODE,
            Err(code) => code.as_code(),
        };
        let expected = expected_code(&case);

        if actual != expected {
            mismatches.push(format!(
                "{}: expected code {} ({:?}), got {}",
                case.id, expected, case.reject_code, actual
            ));
        }
    }

    assert!(mismatches.is_empty(), "codec mismatches: {:?}", mismatches);
}

// ---------------------------------------------------------------------------
// Boundary 2: the real on-chain entry point
// ---------------------------------------------------------------------------

#[test]
fn on_chain_entry_point_agrees_with_every_corpus_case() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.init(&Address::generate(&env));

    let mut mismatches: Vec<String> = vec![];

    for case in parse_corpus() {
        let public_inputs = Bytes::from_slice(&env, &decode_hex(&case.public_inputs_hex));
        let proof_len = (case.proof_hex.len() / 2) as u32;

        let actual =
            client.classify_public_inputs(&schema_id(&case.schema), &public_inputs, &proof_len);
        let expected = expected_code(&case);

        if actual != expected {
            mismatches.push(format!(
                "{}: expected code {} ({:?}), got {}",
                case.id, expected, case.reject_code, actual
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "on-chain mismatches: {:?}",
        mismatches
    );
}

#[test]
fn classification_is_idempotent_and_side_effect_free() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let case = parse_corpus()
        .into_iter()
        .find(|case| case.accept)
        .expect("corpus must contain a positive case");
    let public_inputs = Bytes::from_slice(&env, &decode_hex(&case.public_inputs_hex));
    let proof_len = (case.proof_hex.len() / 2) as u32;

    let first = client.classify_public_inputs(&schema_id(&case.schema), &public_inputs, &proof_len);
    let second =
        client.classify_public_inputs(&schema_id(&case.schema), &public_inputs, &proof_len);

    assert_eq!(first, verifier_inputs::ACCEPTED_CODE);
    assert_eq!(first, second, "classification must be deterministic");
    // Classification must not consume a nullifier or otherwise mutate state.
    assert_eq!(client.get_verifier(), None);
}

#[test]
fn unknown_schema_is_rejected_without_panicking() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.init(&Address::generate(&env));

    let frame = Bytes::from_array(&env, &[0u8; 128]);
    assert_eq!(
        client.classify_public_inputs(&9_999, &frame, &128),
        RejectCode::UnknownSchema.as_code()
    );
}
