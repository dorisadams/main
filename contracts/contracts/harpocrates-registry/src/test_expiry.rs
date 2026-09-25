//! Proof-expiration policy tests (#44)
//!
//! Policy rules under test:
//!
//! 1. `expires_at == 0` → proof never expires (default, backward-compat).
//! 2. `expires_at > 0 && now <= expires_at` → `get_proof_status` returns `Valid`.
//! 3. `expires_at > 0 && now  > expires_at` → `get_proof_status` returns `Expired`.
//! 4. `status == REVOKED`                   → `get_proof_status` returns `Revoked`
//!    regardless of `expires_at`.
//! 5. Non-existent proof_id                 → `get_proof_status` returns `NotFound`.
//! 6. `set_proof_ttl` only affects *new* registrations; existing records are
//!    unaffected.
//! 7. A TTL of `u64::MAX` is handled by saturating addition (no overflow).
//!
//! The test harness controls ledger time via `env.ledger().set_timestamp()`.
#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{testutils::Address as _, testutils::Ledger, Address, Bytes, Env};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

/// Set up a fresh registry and return (env, contract_id, admin).
/// Ledger timestamp starts at `start_ts`.
#[cfg(test)]
fn init_at(start_ts: u64) -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(start_ts);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, contract_id, admin)
}

// ---------------------------------------------------------------------------
// Default TTL = 0 (no expiration)
// ---------------------------------------------------------------------------

/// Without a TTL the record's expires_at is 0 and the proof is always Valid.
#[test]
fn expiry_default_ttl_zero_never_expires() {
    let (env, contract_id, _) = init_at(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x01);

    let rec = client.register_source(&source, &b32(&env, 0x02), &b32(&env, 0x03), &proof_id);
    assert_eq!(
        rec.expires_at, 0,
        "default TTL must produce expires_at == 0"
    );

    // Advance ledger far into the future
    env.ledger().set_timestamp(u64::MAX / 2);
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );
}

/// get_proof_ttl returns 0 before any admin sets a TTL.
#[test]
fn expiry_get_proof_ttl_default_is_zero() {
    let (env, contract_id, _) = init_at(0);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    assert_eq!(client.get_proof_ttl(), 0u64);
}

// ---------------------------------------------------------------------------
// Configuring a TTL
// ---------------------------------------------------------------------------

/// After set_proof_ttl, newly registered proofs carry expires_at = now + ttl.
#[test]
fn expiry_set_ttl_applies_to_new_proofs() {
    let ts: u64 = 10_000;
    let ttl: u64 = 3_600;
    let (env, contract_id, admin) = init_at(ts);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);

    client.set_proof_ttl(&admin, &ttl);
    let rec = client.register_source(
        &source,
        &b32(&env, 0x10),
        &b32(&env, 0x11),
        &b32(&env, 0x12),
    );
    assert_eq!(rec.expires_at, ts + ttl);
}

/// set_proof_ttl does NOT retroactively change already-registered proofs.
#[test]
fn expiry_set_ttl_does_not_affect_existing_proofs() {
    let ts: u64 = 10_000;
    let (env, contract_id, admin) = init_at(ts);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);

    // Register without TTL
    let proof_id = b32(&env, 0x20);
    let rec_before = client.register_source(&source, &b32(&env, 0x21), &b32(&env, 0x22), &proof_id);
    assert_eq!(rec_before.expires_at, 0);

    // Now set a TTL
    client.set_proof_ttl(&admin, &3_600u64);

    // The existing record is still unchanged
    let stored = client.get_proof(&proof_id).unwrap();
    assert_eq!(
        stored.expires_at, 0,
        "existing record must not be affected by TTL change"
    );
}

// ---------------------------------------------------------------------------
// get_proof_status boundary cases
// ---------------------------------------------------------------------------

/// Status is Valid at exactly the expiration second (not yet past).
#[test]
fn expiry_status_valid_at_expiry_second() {
    let ts: u64 = 5_000;
    let ttl: u64 = 500;
    let (env, contract_id, admin) = init_at(ts);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);

    client.set_proof_ttl(&admin, &ttl);
    let proof_id = b32(&env, 0x30);
    client.register_source(&source, &b32(&env, 0x31), &b32(&env, 0x32), &proof_id);

    // At exactly expires_at the proof is still valid (boundary: now == expires_at)
    env.ledger().set_timestamp(ts + ttl);
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );
}

/// Status is Expired one second past the deadline.
#[test]
fn expiry_status_expired_one_second_past() {
    let ts: u64 = 5_000;
    let ttl: u64 = 500;
    let (env, contract_id, admin) = init_at(ts);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);

    client.set_proof_ttl(&admin, &ttl);
    let proof_id = b32(&env, 0x40);
    client.register_source(&source, &b32(&env, 0x41), &b32(&env, 0x42), &proof_id);

    env.ledger().set_timestamp(ts + ttl + 1);
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Expired
    );
}

/// A revoked proof reports Revoked even if not yet expired.
#[test]
fn expiry_revoked_takes_priority_over_valid() {
    let ts: u64 = 1_000;
    let ttl: u64 = 86_400; // 1 day
    let (env, contract_id, admin) = init_at(ts);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);

    client.set_proof_ttl(&admin, &ttl);
    let proof_id = b32(&env, 0x50);
    client.register_source(&source, &b32(&env, 0x51), &b32(&env, 0x52), &proof_id);

    client.revoke_proof(&admin, &proof_id);
    // Time is still within the TTL window
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Revoked
    );
}

/// A revoked proof also reports Revoked after its TTL has passed.
#[test]
fn expiry_revoked_takes_priority_over_expired() {
    let ts: u64 = 1_000;
    let ttl: u64 = 100;
    let (env, contract_id, admin) = init_at(ts);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);

    client.set_proof_ttl(&admin, &ttl);
    let proof_id = b32(&env, 0x60);
    client.register_source(&source, &b32(&env, 0x61), &b32(&env, 0x62), &proof_id);
    client.revoke_proof(&admin, &proof_id);

    // Advance past expiry
    env.ledger().set_timestamp(ts + ttl + 999);
    // Revoked takes precedence
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Revoked
    );
}

/// get_proof_status returns NotFound for an unknown proof_id.
#[test]
fn expiry_status_not_found_for_unknown_id() {
    let (env, contract_id, _) = init_at(0);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    assert_eq!(
        client.get_proof_status(&b32(&env, 0xFF)),
        ProofVerificationStatus::NotFound
    );
}

// ---------------------------------------------------------------------------
// TTL overflow safety
// ---------------------------------------------------------------------------

/// Setting TTL to u64::MAX does not overflow; saturating_add is used.
#[test]
fn expiry_ttl_max_does_not_overflow() {
    let ts: u64 = 1_000;
    let (env, contract_id, admin) = init_at(ts);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);

    client.set_proof_ttl(&admin, &u64::MAX);
    let proof_id = b32(&env, 0x70);
    let rec = client.register_source(&source, &b32(&env, 0x71), &b32(&env, 0x72), &proof_id);
    // saturating_add(u64::MAX) from 1_000 == u64::MAX
    assert_eq!(rec.expires_at, u64::MAX);
    // Still valid since now (1_000) <= u64::MAX
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );
}

// ---------------------------------------------------------------------------
// Backward-compatibility: records without expires_at field
// ---------------------------------------------------------------------------

/// Proofs registered with the default TTL of 0 are treated as non-expiring
/// even when queried far in the future.  This covers the migration case where
/// the field was absent before this schema change.
#[test]
fn expiry_backward_compat_zero_expires_at_is_eternal() {
    let (env, contract_id, _) = init_at(0);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);

    // No TTL configured → expires_at == 0 in stored record
    let proof_id = b32(&env, 0x80);
    client.register_source(&source, &b32(&env, 0x81), &b32(&env, 0x82), &proof_id);

    // Simulate a very distant future query
    env.ledger().set_timestamp(9_999_999_999);
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid,
        "expires_at == 0 must always be Valid regardless of ledger time"
    );
}

// ---------------------------------------------------------------------------
// All three tiers respect the TTL
// ---------------------------------------------------------------------------

#[cfg(test)]
#[contract]
struct MockVerifier3;

#[cfg(test)]
#[contractimpl]
impl MockVerifier3 {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        let len = public_inputs.len();
        // Canonical frame shapes: 128 (revocation), 160 (silent witness),
        // 224 (scoped silent witness).
        if (len != 128 && len != 160 && len != 224) || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

#[cfg(test)]
fn make_pi(env: &Env, vh: &BytesN<32>, cr: &BytesN<32>, nu: &BytesN<32>) -> Bytes {
    let mut v = [0u8; 32];
    vh.copy_into_slice(&mut v);
    let mut c = [0u8; 32];
    cr.copy_into_slice(&mut c);
    let mut n = [0u8; 32];
    nu.copy_into_slice(&mut n);
    // Compute the expected domain tag (SHA-256 of the 3 domain field constants concatenated)
    let domain_tag = expected_domain_tag_for_test(env);
    let mut dt = [0u8; 32];
    domain_tag.copy_into_slice(&mut dt);
    // 5 public inputs × 32 bytes = 160 bytes
    let mut buf = [0u8; 160];
    buf[16..32].copy_from_slice(&v[..16]);
    buf[48..64].copy_from_slice(&v[16..]);
    buf[64..96].copy_from_slice(&c);
    buf[96..128].copy_from_slice(&n);
    buf[128..160].copy_from_slice(&dt);
    Bytes::from_array(env, &buf)
}

#[cfg(test)]
fn expected_domain_tag_for_test(env: &Env) -> BytesN<32> {
    let protocol: [u8; 32] = [
        0x26, 0x1e, 0x9f, 0x6e, 0x39, 0xe3, 0xc1, 0xae, 0x6a, 0xca, 0x9f, 0x29, 0xe8, 0x4c, 0x10,
        0xd5, 0x9c, 0x82, 0xd5, 0xf4, 0xb4, 0x0c, 0x21, 0xc1, 0xb7, 0xe3, 0xc0, 0x1a, 0xd5, 0x71,
        0xc2, 0x1,
    ];
    let version: [u8; 32] = [
        0x0c, 0x89, 0xef, 0xf4, 0xec, 0x8e, 0x39, 0xa0, 0x1e, 0x9f, 0x19, 0x54, 0x7a, 0x0c, 0xc9,
        0xdd, 0x7f, 0xd2, 0xa9, 0x7d, 0x79, 0xba, 0x4d, 0x94, 0xfd, 0x32, 0xe9, 0x7a, 0x1f, 0x5a,
        0xc6, 0x23,
    ];
    let network: [u8; 32] = [
        0x2a, 0x2c, 0x3f, 0x48, 0xce, 0x2e, 0x3c, 0x2f, 0x1e, 0x6c, 0x89, 0xb1, 0x8d, 0x64, 0xb5,
        0xf5, 0xc1, 0xf8, 0x8a, 0x59, 0xa0, 0xd9, 0xbc, 0x82, 0xcb, 0x61, 0xa1, 0xe8, 0xcb, 0x77,
        0xa5, 0xf,
    ];
    let mut preimage = Bytes::new(env);
    preimage.extend_from_array(&protocol);
    preimage.extend_from_array(&version);
    preimage.extend_from_array(&network);
    env.crypto().sha256(&preimage).into()
}

/// All three registration paths store expires_at correctly when TTL is set.
#[test]
fn expiry_all_tiers_store_expires_at() {
    let ts: u64 = 2_000;
    let ttl: u64 = 1_000;
    let (env, contract_id, admin) = init_at(ts);
    let verifier_id = env.register(MockVerifier3, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.set_proof_ttl(&admin, &ttl);
    client.set_verifier(&admin, &verifier_id);
    let issuer = Address::generate(&env);
    let source = Address::generate(&env);
    let credential_root = b32(&env, 0x90);
    client.add_issuer(&admin, &issuer, &b32(&env, 0x91));
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x92));

    // Tier 1 – anonymous_verified
    let vh1 = b32(&env, 0x93);
    let nu1 = b32(&env, 0x94);
    let pid1 = b32(&env, 0x95);
    let r1 = client.register_anonymous_verified(
        &vh1,
        &b32(&env, 0x96),
        &pid1,
        &make_pi(&env, &vh1, &credential_root, &nu1),
        &Bytes::from_array(&env, &[1, 2, 3, 4]),
    );
    assert_eq!(r1.expires_at, ts + ttl);

    // Tier 2 – source
    let r2 = client.register_source(
        &source,
        &b32(&env, 0x97),
        &b32(&env, 0x98),
        &b32(&env, 0x99),
    );
    assert_eq!(r2.expires_at, ts + ttl);

    // Tier 3 – seal
    let r3 = client.register_seal(
        &issuer,
        &b32(&env, 0x9A),
        &b32(&env, 0x9B),
        &b32(&env, 0x9C),
    );
    assert_eq!(r3.expires_at, ts + ttl);
}
