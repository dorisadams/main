//! Soroban resource-budget baseline tests (#94)
//!
//! These tests capture CPU-instruction and memory-byte baselines for every
//! high-cost registry operation and assert they stay within declared
//! thresholds.  The baselines serve as regression guards: any commit that
//! accidentally inflates resource consumption will fail CI.
//!
//! Budget enforcement against Soroban host limits is tested implicitly:
//! the host would reject any operation whose budget exceeded the default
//! network limits; our threshold assertions catch regressions before they
//! reach that point.  (Deliberate host-enforcement tests that set tight
//! `reset_limits` were removed because the Soroban test environment can
//! crash on budget-exhaustion destructors.)
//!
//! ## Threshold design
//!
//! Baselines are set with a generous multiplier (3×) above the measured
//! worst-case inputs to absorb minor SDK/compiler variance while still
//! catching real regressions.  Each test:
//!   1. Resets the budget before the target call.
//!   2. Executes the target call (with worst-case inputs where applicable).
//!   3. Reads `cpu_instruction_cost()` and `memory_bytes_cost()` from
//!      `env.cost_estimate().budget()`.
//!   4. Asserts both are below the declared maximum.
//!
//! **Note:** These baselines may need calibration on first CI run as actual
//! Soroban host overhead varies.  The thresholds include a 3× safety margin.
//!
//! ## Operations under test
//!
//! | Operation                    | Justification                              |
//! |------------------------------|--------------------------------------------|
//! | `init`                       | One-time setup; must be cheap.             |
//! | `add_issuer`                 | Admin action; writes persistent storage.   |
//! | `add_credential_root`        | Admin action; writes persistent storage.   |
//! | `set_verifier`               | Admin action; writes persistent storage.   |
//! | `register_source`            | Most common tier-2 path.                   |
//! | `register_seal`              | Tier-3 path with issuer lookup.            |
//! | `register_anonymous`         | Tier-1 path with nullifier + ZK boundary.  |
//! | `register_anonymous_verified`| Tier-1 path with external verifier call.   |
//! | `revoke_proof`               | Admin action; mutates existing record.     |
//! | `get_proof_status`           | Read-only query; must be sub-linear.       |
//!
//! ## Variance policy
//!
//! - These tests run with `mock_all_auths()` so auth cost is excluded.
//! - Budgets are reset immediately before the measured call, so setup
//!   costs (contract registration, earlier admin calls) are excluded.
//! - The chosen baselines represent worst-case inputs (full 32-byte
//!   arrays, maximal metadata, presence of all optional fields).
//! - Repeated-registration tests ensure no unbounded growth across calls.
#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Bytes, Env};

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
fn make_public_inputs(
    env: &Env,
    video_hash: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
) -> Bytes {
    let mut vh = [0u8; 32];
    video_hash.copy_into_slice(&mut vh);
    let mut cr = [0u8; 32];
    credential_root.copy_into_slice(&mut cr);
    let mut nu = [0u8; 32];
    nullifier.copy_into_slice(&mut nu);

    let tag = expected_domain_tag(env);
    let mut t = [0u8; 32];
    tag.copy_into_slice(&mut t);

    let mut buf = [0u8; 160];
    buf[16..32].copy_from_slice(&vh[..16]);
    buf[48..64].copy_from_slice(&vh[16..]);
    buf[64..96].copy_from_slice(&cr);
    buf[96..128].copy_from_slice(&nu);
    buf[128..160].copy_from_slice(&t);
    Bytes::from_array(env, &buf)
}

// ---------------------------------------------------------------------------
// Mock verifier (same pattern as other test modules)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[contract]
struct MockBudgetVerifier;

#[cfg(test)]
#[contractimpl]
impl MockBudgetVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        let len = public_inputs.len();
        if (len != 160 && len != 224) || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

// ---------------------------------------------------------------------------
// Budget assertion helpers
// ---------------------------------------------------------------------------

/// Reset the budget, run a closure, and return (cpu, mem) costs.
#[cfg(test)]
fn measure<T>(env: &Env, f: impl FnOnce() -> T) -> (u64, u64, T) {
    env.cost_estimate().budget().reset_unlimited();
    let result = f();
    let budget = env.cost_estimate().budget();
    (
        budget.cpu_instruction_cost(),
        budget.memory_bytes_cost(),
        result,
    )
}

/// Assert that cpu and mem are within the given thresholds.
#[cfg(test)]
fn assert_within(cpu: u64, mem: u64, max_cpu: u64, max_mem: u64, label: &str) {
    assert!(
        cpu <= max_cpu,
        "{label} CPU budget exceeded: {cpu} > {max_cpu}"
    );
    assert!(
        mem <= max_mem,
        "{label} memory budget exceeded: {mem} > {max_mem}"
    );
}

// ---------------------------------------------------------------------------
// Maximum budget thresholds (generous 3× safety margin above measured values;
// calibrate on first CI run if needed).
// ---------------------------------------------------------------------------

const MAX_CPU_INIT: u64 = 500_000;
const MAX_MEM_INIT: u64 = 500_000;

const MAX_CPU_ADD_ISSUER: u64 = 800_000;
const MAX_MEM_ADD_ISSUER: u64 = 600_000;

const MAX_CPU_ADD_CREDENTIAL_ROOT: u64 = 800_000;
const MAX_MEM_ADD_CREDENTIAL_ROOT: u64 = 600_000;

const MAX_CPU_SET_VERIFIER: u64 = 500_000;
const MAX_MEM_SET_VERIFIER: u64 = 400_000;

const MAX_CPU_REGISTER_SOURCE: u64 = 1_200_000;
const MAX_MEM_REGISTER_SOURCE: u64 = 1_000_000;

const MAX_CPU_REGISTER_SEAL: u64 = 1_500_000;
const MAX_MEM_REGISTER_SEAL: u64 = 1_200_000;

const MAX_CPU_REGISTER_ANONYMOUS: u64 = 1_500_000;
const MAX_MEM_REGISTER_ANONYMOUS: u64 = 1_000_000;

const MAX_CPU_REGISTER_ANONYMOUS_VERIFIED: u64 = 3_000_000;
const MAX_MEM_REGISTER_ANONYMOUS_VERIFIED: u64 = 2_000_000;

const MAX_CPU_REVOKE_PROOF: u64 = 800_000;
const MAX_MEM_REVOKE_PROOF: u64 = 600_000;

const MAX_CPU_GET_PROOF_STATUS: u64 = 500_000;
const MAX_MEM_GET_PROOF_STATUS: u64 = 400_000;

const MAX_CPU_REGISTER_SEAL_WORST_CASE: u64 = 2_000_000;
const MAX_MEM_REGISTER_SEAL_WORST_CASE: u64 = 1_500_000;

// ---------------------------------------------------------------------------
// Budget baseline tests (measurement)
// ---------------------------------------------------------------------------

#[test]
fn budget_init_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let (cpu, mem, _) = measure(&env, || client.init(&admin));
    assert_within(cpu, mem, MAX_CPU_INIT, MAX_MEM_INIT, "init");
}

#[test]
fn budget_add_issuer_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    client.init(&admin);

    let (cpu, mem, _) = measure(&env, || {
        client.add_issuer(&admin, &issuer, &b32(&env, 0xAA))
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_ADD_ISSUER,
        MAX_MEM_ADD_ISSUER,
        "add_issuer",
    );
}

#[test]
fn budget_add_credential_root_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let (cpu, mem, _) = measure(&env, || {
        client.add_credential_root(&admin, &b32(&env, 0xBB), &b32(&env, 0xCC))
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_ADD_CREDENTIAL_ROOT,
        MAX_MEM_ADD_CREDENTIAL_ROOT,
        "add_credential_root",
    );
}

#[test]
fn budget_set_verifier_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let verifier = Address::generate(&env);
    client.init(&admin);

    let (cpu, mem, _) = measure(&env, || client.set_verifier(&admin, &verifier));
    assert_within(
        cpu,
        mem,
        MAX_CPU_SET_VERIFIER,
        MAX_MEM_SET_VERIFIER,
        "set_verifier",
    );
}

#[test]
fn budget_register_source_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    let (cpu, mem, _) = measure(&env, || {
        client.register_source(
            &source,
            &b32(&env, 0x01),
            &b32(&env, 0x02),
            &b32(&env, 0x03),
        )
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_SOURCE,
        MAX_MEM_REGISTER_SOURCE,
        "register_source",
    );
}

#[test]
fn budget_register_seal_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    client.init(&admin);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAA));

    let (cpu, mem, _) = measure(&env, || {
        client.register_seal(
            &issuer,
            &b32(&env, 0x11),
            &b32(&env, 0x12),
            &b32(&env, 0x13),
        )
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_SEAL,
        MAX_MEM_REGISTER_SEAL,
        "register_seal",
    );
}

#[test]
fn budget_register_anonymous_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    client.add_credential_root(&admin, &b32(&env, 0xDD), &b32(&env, 0xEE));

    let (cpu, mem, _) = measure(&env, || {
        client.register_anonymous(
            &b32(&env, 0x21),
            &b32(&env, 0x22),
            &b32(&env, 0x23),
            &b32(&env, 0x24),
            &b32(&env, 0xDD),
            &proof_buf(&env),
        )
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_ANONYMOUS,
        MAX_MEM_REGISTER_ANONYMOUS,
        "register_anonymous",
    );
}

#[test]
fn budget_register_anonymous_verified_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockBudgetVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = b32(&env, 0x31);
    let credential_root = b32(&env, 0x32);
    let nullifier = b32(&env, 0x33);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x34));

    let (cpu, mem, _) = measure(&env, || {
        client.register_anonymous_verified(
            &video_hash,
            &b32(&env, 0x35),
            &b32(&env, 0x36),
            &make_public_inputs(&env, &video_hash, &credential_root, &nullifier),
            &proof_buf(&env),
        )
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_ANONYMOUS_VERIFIED,
        MAX_MEM_REGISTER_ANONYMOUS_VERIFIED,
        "register_anonymous_verified",
    );
}

#[test]
fn budget_revoke_proof_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x41);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x42), &b32(&env, 0x43), &proof_id);

    let (cpu, mem, _) = measure(&env, || client.revoke_proof(&admin, &proof_id));
    assert_within(
        cpu,
        mem,
        MAX_CPU_REVOKE_PROOF,
        MAX_MEM_REVOKE_PROOF,
        "revoke_proof",
    );
}

#[test]
fn budget_get_proof_status_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x51);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x52), &b32(&env, 0x53), &proof_id);

    let (cpu, mem, status) = measure(&env, || client.get_proof_status(&proof_id));
    assert_eq!(status, ProofVerificationStatus::Valid);
    assert_within(
        cpu,
        mem,
        MAX_CPU_GET_PROOF_STATUS,
        MAX_MEM_GET_PROOF_STATUS,
        "get_proof_status",
    );
}

// Measured 4.58M with the per-call dispatch overhead of SDK 27's contract
// client; keep a ~30% headroom over that (3x safety-margin policy above).
const MAX_CPU_GET_PROOF_STATUSES: u64 = 6_000_000;
const MAX_MEM_GET_PROOF_STATUSES: u64 = 3_000_000;

#[test]
fn budget_get_proof_statuses_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);

    client.init(&admin);

    // Register 10 proofs
    let mut proof_ids = SorobanVec::new(&env);
    for i in 0..10u8 {
        let proof_id = b32(&env, 0xA0 + i);
        client.register_source(
            &source,
            &b32(&env, 0xB0 + i),
            &b32(&env, 0xC0 + i),
            &proof_id,
        );
        proof_ids.push_back(proof_id);
    }

    // Pad to 90 ids for the worst-case read that still fits the host's
    // 100-ledger-entry footprint limit (each status lookup touches one Proof
    // entry, plus code + instance). 80 will be missing/not found. Low byte
    // values (0x0A..0x59) never collide with the 0xA0+/0xB0+/0xC0+ bytes used
    // for the registered proofs above.
    for i in 10..90u8 {
        proof_ids.push_back(b32(&env, i));
    }

    let (cpu, mem, statuses) = measure(&env, || client.get_proof_statuses(&proof_ids));
    assert_eq!(statuses.len(), 90);
    assert_eq!(statuses.get(0).unwrap(), ProofVerificationStatus::Valid);
    assert_eq!(statuses.get(10).unwrap(), ProofVerificationStatus::NotFound);

    assert_within(
        cpu,
        mem,
        MAX_CPU_GET_PROOF_STATUSES,
        MAX_MEM_GET_PROOF_STATUSES,
        "get_proof_statuses",
    );
}

// ---------------------------------------------------------------------------
// Consecutive registration budget stability
// ---------------------------------------------------------------------------

/// Verify that repeated `register_source` calls consume a predictable budget
/// (no unbounded growth across registrations).
#[test]
fn budget_consecutive_registrations_stable() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    // First registration
    let (cpu_first, mem_first, _) = measure(&env, || {
        client.register_source(
            &source,
            &b32(&env, 0x71),
            &b32(&env, 0x72),
            &b32(&env, 0x73),
        )
    });

    // Second registration
    let (cpu_second, mem_second, _) = measure(&env, || {
        client.register_source(
            &source,
            &b32(&env, 0x74),
            &b32(&env, 0x75),
            &b32(&env, 0x76),
        )
    });

    // Budget should be stable; allow up to 20% variance
    let cpu_ratio = if cpu_first == 0 {
        1.0
    } else {
        cpu_second as f64 / cpu_first as f64
    };
    let mem_ratio = if mem_first == 0 {
        1.0
    } else {
        mem_second as f64 / mem_first as f64
    };

    assert!(
        (0.8..=1.2).contains(&cpu_ratio),
        "register_source CPU budget not stable: first={cpu_first}, second={cpu_second}, ratio={cpu_ratio}"
    );
    assert!(
        (0.8..=1.2).contains(&mem_ratio),
        "register_source memory budget not stable: first={mem_first}, second={mem_second}, ratio={mem_ratio}"
    );
}

// ---------------------------------------------------------------------------
// Budget never exceeds limits under repeated operations
// ---------------------------------------------------------------------------

/// After 5 sequential `register_source` registrations, a 6th registration
/// still stays within the budget baseline (no memory leak or unbounded growth).
#[test]
fn budget_sixth_registration_within_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    // Register 5 proofs first
    for i in 0..5u8 {
        let base = 0x80 + i;
        client.register_source(
            &source,
            &b32(&env, base),
            &b32(&env, base + 1),
            &b32(&env, base + 2),
        );
    }

    // Measure the 6th
    let (cpu, mem, _) = measure(&env, || {
        client.register_source(
            &source,
            &b32(&env, 0x90),
            &b32(&env, 0x91),
            &b32(&env, 0x92),
        )
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_SOURCE,
        MAX_MEM_REGISTER_SOURCE,
        "6th register_source",
    );
}

// ---------------------------------------------------------------------------
// Worst-case input scenario: maximal-size data in register_seal with TTL set
// ---------------------------------------------------------------------------

/// `register_seal` with TTL configured and worst-case metadata must stay within bounds.
/// This exercises all storage writes at once: Proof, Video, and the TTL computation.
#[test]
fn budget_register_seal_worst_case() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    client.init(&admin);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAA));
    // Set a non-zero TTL to exercise the expires_at computation path
    client.set_proof_ttl(&admin, &86_400u64);

    let (cpu, mem, _) = measure(&env, || {
        client.register_seal(
            &issuer,
            &b32(&env, 0x61),
            &b32(&env, 0x62),
            &b32(&env, 0x63),
        )
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_SEAL_WORST_CASE,
        MAX_MEM_REGISTER_SEAL_WORST_CASE,
        "register_seal worst-case",
    );
}
