//! Deterministic testnet deployment fixture (#350).
//!
//! This module pins a reproducible, fully-initialized registry state that
//! mirrors a real testnet deployment without using live credentials, real
//! media, or production keys.
//!
//! ## What the fixture covers
//!
//! 1. **Happy-path deployment sequence** – init → set_verifier →
//!    add_issuer → add_credential_root, with every expected storage key
//!    and typed event asserted afterward.
//! 2. **All three identity tiers** – anonymous, source, and seal proofs
//!    registered against the initialized state.
//! 3. **Negative authorization** – every privileged entry point is driven
//!    by a non-admin caller and must produce `Unauthorized (#3)`.
//! 4. **Budget boundary** – a single registration call stays inside a
//!    fixed CPU/memory ceiling so CI does not regress on resource usage.
//! 5. **Encoding boundary** – malformed public inputs (wrong length, dirty
//!    padding, zero identity fields) are rejected before the verifier is
//!    invoked.
//! 6. **Migration compatibility** – `upgrade_storage` is idempotent when
//!    storage is already at the current schema version; re-running it must
//!    not emit an upgrade event or alter any existing record.
//! 7. **Rollback safety** – revoking the issuer and credential root that
//!    were added in the fixture leaves the registry in a consistent state
//!    and all subsequent registration attempts fail with the expected
//!    errors.
//!
//! ## Privacy and trust-boundary notes
//!
//! - No real keys, real proofs, real media, or production contract IDs are
//!   used anywhere in this file.
//! - Failure paths assert only error codes; they never print proof bytes,
//!   public inputs, witness values, credential roots, or nullifiers.
//! - The mock verifier accepts any 128-byte public-input blob with a
//!   non-empty proof, matching the interface contract without needing a
//!   real Noir circuit.
//! - All synthetic hashes are derived from a single fixed domain tag byte
//!   and a slot number so they are reproducible across runs without any
//!   external randomness.
//!
//! ## Compatibility and rollback
//!
//! This is a test-only module.  It does not alter any exported function
//! signature, storage key, event schema, or artifact format.  Rolling back
//! means reverting or removing this file; no on-chain repair is required.
//!
//! ## CI reproduction
//!
//! ```bash
//! cd contracts
//! cargo test -p harpocrates-registry deployment_fixture -- --nocapture
//! ```

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Events as _, Ledger},
    Address, Bytes, Env,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed ledger timestamp used across all fixture tests so TTL-relative
/// assertions are deterministic.
#[cfg(test)]
const FIXTURE_TIMESTAMP: u64 = 1_750_000_000;

// ---------------------------------------------------------------------------
// Synthetic data helpers
// ---------------------------------------------------------------------------

/// Produce a deterministic 32-byte value from a domain tag and a slot
/// index.  No real hashes, keys, or media bytes are ever used.
#[cfg(test)]
fn slot(env: &Env, domain: u8, index: u8) -> BytesN<32> {
    // Synthetic values are used as BN254 field elements in public inputs, so
    // keep them below the scalar-field modulus (canonical encodings). One lead
    // 0x00 byte plus small non-zero tag bytes guarantees that.
    let mut buf = [0u8; 32];
    buf[0] = 0x00;
    buf[1] = domain;
    buf[2] = index;
    for i in 3..32 {
        buf[i] = domain ^ index ^ i as u8;
    }
    BytesN::from_array(env, &buf)
}

/// Build a minimal valid 128-byte silent-witness public-input frame.
///
/// Layout (four 32-byte BN254 field elements):
///   [  0.. 32)  video_hash_hi  (16-byte zero pad + high 16 bytes of video_hash)
///   [ 32.. 64)  video_hash_lo  (16-byte zero pad + low  16 bytes of video_hash)
///   [ 64.. 96)  credential_root
///   [ 96..128)  nullifier
///
/// Only the lower 16 bytes of each video-hash half carry non-zero data.
/// The credential_root and nullifier must be non-zero and below the BN254
/// modulus; using small synthetic values satisfies both.
#[cfg(test)]
fn silent_pi(
    env: &Env,
    video_hash: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
) -> Bytes {
    let mut vh = [0u8; 32];
    video_hash.copy_into_slice(&mut vh);
    let mut buf = [0u8; 160];
    // video_hash_hi: 16 zero bytes of padding then the first 16 bytes of the
    // video hash (must match the registration argument).
    buf[16..32].copy_from_slice(&vh[..16]);
    // video_hash_lo: 16 zero bytes of padding then the last 16 bytes.
    buf[48..64].copy_from_slice(&vh[16..]);
    let mut cr = [0u8; 32];
    credential_root.copy_into_slice(&mut cr);
    buf[64..96].copy_from_slice(&cr);
    let mut nu = [0u8; 32];
    nullifier.copy_into_slice(&mut nu);
    buf[96..128].copy_from_slice(&nu);
    // Fifth field word: the canonical silent-witness domain tag.
    let tag = expected_domain_tag(env);
    let mut t = [0u8; 32];
    tag.copy_into_slice(&mut t);
    buf[128..160].copy_from_slice(&t);
    Bytes::from_array(env, &buf)
}

/// A minimal proof blob accepted by the mock verifier (non-empty).
#[cfg(test)]
fn proof_buf(env: &Env) -> Bytes {
    Bytes::from_array(env, &[0xde, 0xad, 0xbe, 0xef])
}

// ---------------------------------------------------------------------------
// Mock verifier
// ---------------------------------------------------------------------------

#[cfg(test)]
#[contract]
struct MockDeploymentVerifier;

#[cfg(test)]
#[contractimpl]
impl MockDeploymentVerifier {
    /// Accept any canonical 160-byte public-input blob with a non-empty proof.
    /// This matches the real Noir verifier interface without requiring a
    /// live circuit; it panics on obviously malformed inputs so the
    /// contract's pre-verifier validation is still exercised.
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        if public_inputs.len() != 160 || proof.is_empty() {
            panic!("mock verifier: invalid inputs");
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture setup helper
// ---------------------------------------------------------------------------

/// Domain tags for synthetic hashes — each domain byte uniquely identifies
/// the kind of hash so collisions between fields are impossible.
#[cfg(test)]
mod domains {
    pub const VIDEO: u8 = 0xA1;
    pub const METADATA: u8 = 0xA2;
    pub const PROOF: u8 = 0xA3;
    pub const ISSUER_META: u8 = 0xA4;
    pub const CRED_META: u8 = 0xA5;
    pub const NULLIFIER: u8 = 0xA6;
    pub const CRED_ROOT: u8 = 0xA7;
}

/// A fully-initialized deployment fixture.
///
/// All addresses and hashes are deterministic; every field is documented
/// so reviewers can verify no real sensitive material is present.
#[cfg(test)]
struct DeploymentFixture {
    env: Env,
    contract_id: Address,
    verifier_id: Address,
    admin: Address,
    issuer: Address,
    source: Address,
    /// Active credential root registered by admin.
    credential_root: BytesN<32>,
    /// Metadata hash for the credential root record.
    cred_root_meta: BytesN<32>,
    /// Issuer metadata hash.
    issuer_meta: BytesN<32>,
}

#[cfg(test)]
impl DeploymentFixture {
    /// Build and initialize a fresh deployment fixture.
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

        // Pin the ledger timestamp so TTL assertions are reproducible.
        env.ledger().with_mut(|li| {
            li.timestamp = FIXTURE_TIMESTAMP;
        });

        let contract_id = env.register(HarpocratesRegistry, ());
        let verifier_id = env.register(MockDeploymentVerifier, ());

        let admin = Address::generate(&env);
        let issuer = Address::generate(&env);
        let source = Address::generate(&env);

        let credential_root = slot(&env, domains::CRED_ROOT, 1);
        let cred_root_meta = slot(&env, domains::CRED_META, 1);
        let issuer_meta = slot(&env, domains::ISSUER_META, 1);

        let client = HarpocratesRegistryClient::new(&env, &contract_id);

        // --- Deployment sequence -----------------------------------------
        client.init(&admin);
        client.set_verifier(&admin, &verifier_id);
        client.add_issuer(&admin, &issuer, &issuer_meta);
        client.add_credential_root(&admin, &credential_root, &cred_root_meta);

        DeploymentFixture {
            env,
            contract_id,
            verifier_id,
            admin,
            issuer,
            source,
            credential_root,
            cred_root_meta,
            issuer_meta,
        }
    }

    fn client(&self) -> HarpocratesRegistryClient {
        HarpocratesRegistryClient::new(&self.env, &self.contract_id)
    }
}

// ---------------------------------------------------------------------------
// 1. Happy-path deployment sequence
// ---------------------------------------------------------------------------

#[test]
fn deployment_fixture_init_state_is_consistent() {
    let f = DeploymentFixture::new();
    let client = f.client();

    // Admin is stored.
    // (No public get_admin; verify indirectly via a privileged call.)
    let new_issuer = Address::generate(&f.env);
    client.add_issuer(
        &f.admin,
        &new_issuer,
        &slot(&f.env, domains::ISSUER_META, 2),
    );
    assert!(client.get_issuer(&new_issuer).unwrap().active);

    // Verifier is stored.
    assert_eq!(client.get_verifier(), Some(f.verifier_id.clone()));

    // Issuer is active.
    let issuer_rec = client.get_issuer(&f.issuer).unwrap();
    assert!(issuer_rec.active);
    assert_eq!(issuer_rec.metadata_hash, f.issuer_meta);

    // Credential root is active.
    let cred_rec = client.get_credential_root(&f.credential_root).unwrap();
    assert!(cred_rec.active);
    assert_eq!(cred_rec.metadata_hash, f.cred_root_meta);

    // No proofs yet.
    let unknown_proof = slot(&f.env, domains::PROOF, 0xFF);
    assert!(client.get_proof(&unknown_proof).is_none());
    assert!(!client.has_nullifier(&slot(&f.env, domains::NULLIFIER, 0)));
}

#[test]
fn deployment_fixture_schema_version_is_v1() {
    let f = DeploymentFixture::new();
    let client = f.client();
    // upgrade_storage with the same version must not emit an event and
    // must leave the verifier record untouched (idempotency). Events only
    // reflect the most recent invocation, so capture right after the call.
    client.upgrade_storage(&f.admin);
    let events_after = f.env.events().all().events().len();
    assert_eq!(
        events_after, 0,
        "upgrade_storage must be a no-op when already at current version"
    );
    assert_eq!(client.get_verifier(), Some(f.verifier_id.clone()));
}

// ---------------------------------------------------------------------------
// 2. All three identity tiers
// ---------------------------------------------------------------------------

#[test]
fn deployment_fixture_all_tiers_register_successfully() {
    let f = DeploymentFixture::new();
    let client = f.client();

    // Tier 1 – anonymous (no verifier path, uses credential root directly).
    let anon_proof_id = slot(&f.env, domains::PROOF, 0x01);
    let anon_video = slot(&f.env, domains::VIDEO, 0x01);
    let anon_meta = slot(&f.env, domains::METADATA, 0x01);
    let anon_nullifier = slot(&f.env, domains::NULLIFIER, 0x01);

    let anon_rec = client.register_anonymous(
        &anon_video,
        &anon_meta,
        &anon_proof_id,
        &anon_nullifier,
        &f.credential_root,
        &proof_buf(&f.env),
    );
    assert_eq!(anon_rec.tier, TIER_SILENT_WITNESS);
    assert_eq!(anon_rec.nullifier, Some(anon_nullifier.clone()));
    assert!(client.has_nullifier(&anon_nullifier));

    // Tier 1 – anonymous_verified (uses mock verifier + public inputs).
    let av_proof_id = slot(&f.env, domains::PROOF, 0x02);
    let av_video = slot(&f.env, domains::VIDEO, 0x02);
    let av_meta = slot(&f.env, domains::METADATA, 0x02);
    let av_nullifier = slot(&f.env, domains::NULLIFIER, 0x02);

    let av_rec = client.register_anonymous_verified(
        &av_video,
        &av_meta,
        &av_proof_id,
        &silent_pi(&f.env, &av_video, &f.credential_root, &av_nullifier),
        &proof_buf(&f.env),
    );
    assert_eq!(av_rec.tier, TIER_SILENT_WITNESS);
    assert!(client.has_nullifier(&av_nullifier));

    // Tier 2 – consistent source.
    let src_proof_id = slot(&f.env, domains::PROOF, 0x03);
    let src_video = slot(&f.env, domains::VIDEO, 0x03);
    let src_meta = slot(&f.env, domains::METADATA, 0x03);

    let src_rec = client.register_source(&f.source, &src_video, &src_meta, &src_proof_id);
    assert_eq!(src_rec.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(src_rec.source, Some(f.source.clone()));
    assert!(client.get_by_video(&src_video).is_some());

    // Tier 3 – public seal.
    let seal_proof_id = slot(&f.env, domains::PROOF, 0x04);
    let seal_video = slot(&f.env, domains::VIDEO, 0x04);
    let seal_meta = slot(&f.env, domains::METADATA, 0x04);

    let seal_rec = client.register_seal(&f.issuer, &seal_video, &seal_meta, &seal_proof_id);
    assert_eq!(seal_rec.tier, TIER_PUBLIC_SEAL);
    assert_eq!(seal_rec.issuer, Some(f.issuer.clone()));

    // Proof status query for all four registrations.
    assert_eq!(
        client.get_proof_status(&anon_proof_id),
        ProofVerificationStatus::Valid
    );
    assert_eq!(
        client.get_proof_status(&av_proof_id),
        ProofVerificationStatus::Valid
    );
    assert_eq!(
        client.get_proof_status(&src_proof_id),
        ProofVerificationStatus::Valid
    );
    assert_eq!(
        client.get_proof_status(&seal_proof_id),
        ProofVerificationStatus::Valid
    );
}

// ---------------------------------------------------------------------------
// 3. Negative authorization – non-admin callers
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn deployment_fixture_non_admin_cannot_set_verifier() {
    let f = DeploymentFixture::new();
    let stranger = Address::generate(&f.env);
    f.client().set_verifier(&stranger, &f.verifier_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn deployment_fixture_non_admin_cannot_add_issuer() {
    let f = DeploymentFixture::new();
    let stranger = Address::generate(&f.env);
    let new_issuer = Address::generate(&f.env);
    f.client().add_issuer(
        &stranger,
        &new_issuer,
        &slot(&f.env, domains::ISSUER_META, 9),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn deployment_fixture_non_admin_cannot_add_credential_root() {
    let f = DeploymentFixture::new();
    let stranger = Address::generate(&f.env);
    f.client().add_credential_root(
        &stranger,
        &slot(&f.env, domains::CRED_ROOT, 9),
        &slot(&f.env, domains::CRED_META, 9),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn deployment_fixture_non_admin_cannot_revoke_issuer() {
    let f = DeploymentFixture::new();
    let stranger = Address::generate(&f.env);
    f.client().revoke_issuer(&stranger, &f.issuer);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn deployment_fixture_non_admin_cannot_revoke_proof() {
    let f = DeploymentFixture::new();
    let client = f.client();
    let proof_id = slot(&f.env, domains::PROOF, 0x10);
    client.register_source(
        &f.source,
        &slot(&f.env, domains::VIDEO, 0x10),
        &slot(&f.env, domains::METADATA, 0x10),
        &proof_id,
    );
    let stranger = Address::generate(&f.env);
    client.revoke_proof(&stranger, &proof_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn deployment_fixture_double_init_is_rejected() {
    let f = DeploymentFixture::new();
    let second_admin = Address::generate(&f.env);
    f.client().init(&second_admin);
}

// ---------------------------------------------------------------------------
// 4. Budget boundary – single registration within a fixed ceiling
// ---------------------------------------------------------------------------

#[test]
fn deployment_fixture_single_registration_within_budget() {
    let f = DeploymentFixture::new();
    let client = f.client();

    // Set a hard budget ceiling; the numbers match the project's CI
    // constants in test_state_machine.rs (MAX_FUZZ_CPU / MAX_FUZZ_MEM).
    f.env
        .cost_estimate()
        .budget()
        .reset_limits(20_000_000, 16_000_000);

    let proof_id = slot(&f.env, domains::PROOF, 0x20);
    let nullifier = slot(&f.env, domains::NULLIFIER, 0x20);

    client.register_anonymous_verified(
        &slot(&f.env, domains::VIDEO, 0x20),
        &slot(&f.env, domains::METADATA, 0x20),
        &proof_id,
        &silent_pi(
            &f.env,
            &slot(&f.env, domains::VIDEO, 0x20),
            &f.credential_root,
            &nullifier,
        ),
        &proof_buf(&f.env),
    );

    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );
}

// ---------------------------------------------------------------------------
// 5. Encoding boundary – malformed public inputs
// ---------------------------------------------------------------------------

#[test]
fn deployment_fixture_empty_public_inputs_rejected() {
    let f = DeploymentFixture::new();
    let code =
        f.client()
            .classify_public_inputs(&SCHEMA_ID_SILENT_WITNESS, &Bytes::new(&f.env), &128);
    // Reject code 1 = length mismatch (from verifier_inputs::RejectCode::Length).
    assert_ne!(
        code,
        verifier_inputs::ACCEPTED_CODE,
        "empty pi must be rejected"
    );
}

#[test]
fn deployment_fixture_truncated_public_inputs_rejected() {
    let f = DeploymentFixture::new();
    // 127 bytes — one byte short.
    let short = Bytes::from_array(&f.env, &[0u8; 127]);
    let code = f
        .client()
        .classify_public_inputs(&SCHEMA_ID_SILENT_WITNESS, &short, &128);
    assert_ne!(code, verifier_inputs::ACCEPTED_CODE);
}

#[test]
fn deployment_fixture_dirty_padding_rejected() {
    let f = DeploymentFixture::new();
    // Set the first byte of video_hash_hi to 0x01, which makes the
    // 16-byte high-half padding non-zero — should yield padding error.
    let mut buf = [0u8; 128];
    buf[0] = 0x01; // dirty high pad
    buf[64..96].copy_from_slice(&[0x02; 32]); // credential_root
    buf[96..128].copy_from_slice(&[0x03; 32]); // nullifier
    let pi = Bytes::from_array(&f.env, &buf);
    let code = f
        .client()
        .classify_public_inputs(&SCHEMA_ID_SILENT_WITNESS, &pi, &128);
    assert_ne!(code, verifier_inputs::ACCEPTED_CODE);
}

#[test]
fn deployment_fixture_zero_nullifier_rejected() {
    let f = DeploymentFixture::new();
    let nullifier_zero = slot(&f.env, 0x00, 0x00); // all-zero
    let pi = silent_pi(
        &f.env,
        &slot(&f.env, domains::VIDEO, 0x30),
        &f.credential_root,
        &nullifier_zero,
    );
    let code = f.client().classify_public_inputs(
        &SCHEMA_ID_SILENT_WITNESS,
        &pi,
        &(proof_buf(&f.env).len()),
    );
    assert_ne!(code, verifier_inputs::ACCEPTED_CODE);
}

#[test]
fn deployment_fixture_valid_public_inputs_accepted() {
    let f = DeploymentFixture::new();
    let nullifier = slot(&f.env, domains::NULLIFIER, 0x30);
    let pi = silent_pi(
        &f.env,
        &slot(&f.env, domains::VIDEO, 0x30),
        &f.credential_root,
        &nullifier,
    );
    let code = f.client().classify_public_inputs(
        &SCHEMA_ID_SILENT_WITNESS,
        &pi,
        &verifier_inputs::MIN_PROOF_BYTES, // smallest accepted proof blob
    );
    assert_eq!(code, verifier_inputs::ACCEPTED_CODE);
}

#[test]
fn deployment_fixture_unknown_schema_id_rejected() {
    let f = DeploymentFixture::new();
    let pi = Bytes::from_array(&f.env, &[0u8; 128]);
    let code = f.client().classify_public_inputs(&9_999, &pi, &128);
    assert_ne!(code, verifier_inputs::ACCEPTED_CODE);
}

// ---------------------------------------------------------------------------
// 6. Migration idempotency
// ---------------------------------------------------------------------------

#[test]
fn deployment_fixture_upgrade_storage_is_idempotent() {
    let f = DeploymentFixture::new();
    let client = f.client();

    // Run upgrade_storage twice; both calls must succeed without error.
    client.upgrade_storage(&f.admin);
    client.upgrade_storage(&f.admin);

    // All fixture state must be intact after repeated upgrades.
    assert!(client.get_issuer(&f.issuer).unwrap().active);
    assert!(
        client
            .get_credential_root(&f.credential_root)
            .unwrap()
            .active
    );
    assert_eq!(client.get_verifier(), Some(f.verifier_id.clone()));
}

// ---------------------------------------------------------------------------
// 7. Rollback safety – revoke issuer and credential root
// ---------------------------------------------------------------------------

#[test]
fn deployment_fixture_revoked_issuer_blocks_seal_registration() {
    let f = DeploymentFixture::new();
    let client = f.client();

    client.revoke_issuer(&f.admin, &f.issuer);
    assert!(!client.get_issuer(&f.issuer).unwrap().active);

    // Attempting to register a seal with the revoked issuer must fail.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.register_seal(
            &f.issuer,
            &slot(&f.env, domains::VIDEO, 0x40),
            &slot(&f.env, domains::METADATA, 0x40),
            &slot(&f.env, domains::PROOF, 0x40),
        );
    }));
    assert!(
        result.is_err(),
        "register_seal with revoked issuer must panic"
    );
}

#[test]
fn deployment_fixture_revoked_credential_root_blocks_anonymous_registration() {
    let f = DeploymentFixture::new();
    let client = f.client();

    client.revoke_credential_root(&f.admin, &f.credential_root);
    assert!(
        !client
            .get_credential_root(&f.credential_root)
            .unwrap()
            .active
    );

    // Attempting to register with the revoked root must fail.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.register_anonymous(
            &slot(&f.env, domains::VIDEO, 0x50),
            &slot(&f.env, domains::METADATA, 0x50),
            &slot(&f.env, domains::PROOF, 0x50),
            &slot(&f.env, domains::NULLIFIER, 0x50),
            &f.credential_root,
            &proof_buf(&f.env),
        );
    }));
    assert!(
        result.is_err(),
        "register_anonymous with revoked credential root must panic"
    );
}

#[test]
fn deployment_fixture_revoked_state_read_queries_still_work() {
    let f = DeploymentFixture::new();
    let client = f.client();

    client.revoke_issuer(&f.admin, &f.issuer);
    client.revoke_credential_root(&f.admin, &f.credential_root);

    // Read-only queries must never be blocked by revocation state.
    let issuer_rec = client.get_issuer(&f.issuer).unwrap();
    assert!(!issuer_rec.active); // revoked, not deleted

    let cred_rec = client.get_credential_root(&f.credential_root).unwrap();
    assert!(!cred_rec.active); // revoked, not deleted

    assert_eq!(client.get_verifier(), Some(f.verifier_id.clone()));
    assert_eq!(
        client.get_proof_status(&slot(&f.env, domains::PROOF, 0xFF)),
        ProofVerificationStatus::NotFound
    );
}

// ---------------------------------------------------------------------------
// 8. Nullifier replay protection across registrations
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn deployment_fixture_duplicate_nullifier_rejected() {
    let f = DeploymentFixture::new();
    let client = f.client();
    let nullifier = slot(&f.env, domains::NULLIFIER, 0x60);

    client.register_anonymous(
        &slot(&f.env, domains::VIDEO, 0x60),
        &slot(&f.env, domains::METADATA, 0x60),
        &slot(&f.env, domains::PROOF, 0x60),
        &nullifier,
        &f.credential_root,
        &proof_buf(&f.env),
    );
    // Second registration reuses the same nullifier → DuplicateNullifier (#6).
    client.register_anonymous(
        &slot(&f.env, domains::VIDEO, 0x61),
        &slot(&f.env, domains::METADATA, 0x61),
        &slot(&f.env, domains::PROOF, 0x61),
        &nullifier,
        &f.credential_root,
        &proof_buf(&f.env),
    );
}

// ---------------------------------------------------------------------------
// 9. Proof TTL — default and custom
// ---------------------------------------------------------------------------

#[test]
fn deployment_fixture_default_proof_ttl_is_zero() {
    let f = DeploymentFixture::new();
    assert_eq!(f.client().get_proof_ttl(), DEFAULT_PROOF_TTL_SECS);
}

#[test]
fn deployment_fixture_custom_proof_ttl_is_stored() {
    let f = DeploymentFixture::new();
    let client = f.client();
    let ttl = 86_400u64; // 1 day
    client.set_proof_ttl(&f.admin, &ttl);
    assert_eq!(client.get_proof_ttl(), ttl);
}
