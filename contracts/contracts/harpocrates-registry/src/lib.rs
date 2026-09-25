#![no_std]

#[cfg(test)]
extern crate std;

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    Bytes, BytesN, Env, IntoVal, InvokeError, Symbol, Val, Vec, Vec as SorobanVec,
};

pub mod verifier_inputs;

use verifier_inputs::{RejectCode, PUBLIC_INPUTS_LEN};

/// Schema selectors accepted by [`HarpocratesRegistry::classify_public_inputs`].
pub const SCHEMA_ID_SILENT_WITNESS: u32 = 1;
pub const SCHEMA_ID_REVOCATION_WITNESS: u32 = 2;

/// Maximum Merkle depth for the `revocation_witness` circuit (#357).
/// Must match `MAX_REVOCATION_WITNESS_DEPTH` in the Noir circuit and host tooling.
/// Raising this value requires a new circuit version — do not change it silently.
pub const MAX_REVOCATION_WITNESS_DEPTH: u32 = 3;
/// Leaf capacity implied by [`MAX_REVOCATION_WITNESS_DEPTH`] (`2^depth` = 8).
pub const MAX_REVOCATION_LEAVES: u32 = 8;

const TIER_SILENT_WITNESS: u32 = 1;
const TIER_CONSISTENT_SOURCE: u32 = 2;
const TIER_PUBLIC_SEAL: u32 = 3;

const STATUS_REGISTERED: u32 = 1;
const STATUS_REVOKED: u32 = 2;
const STATUS_EXPIRED: u32 = 3;

pub const DEFAULT_PROOF_TTL_SECS: u64 = 0;

const STATUS_POLICY_ACTIVE: u32 = 1;
const STATUS_POLICY_CANCELLED: u32 = 2;

const MAX_SIGNERS: u32 = 16;
const DEFAULT_APPROVAL_TTL_SECS: u64 = 86_400;

const MAX_LINEAGE_DEPTH: u32 = 4;
const MAX_LINEAGE_FANOUT: u32 = 4;
const MAX_LINEAGE_PAYLOAD_BYTES: u32 = 4096;

// ---------------------------------------------------------------------------
// On-chain metadata envelope versioning (#317)
// ---------------------------------------------------------------------------
//
// Off-chain steganography payloads use versioned envelopes (`HRPSTG1` /
// `HRPSTG2` in `backend/envelope.py`). On-chain we store only the canonical
// metadata hash plus an explicit envelope version so verifiers can interpret
// the hash without a second protocol truth and without ever logging media,
// witnesses, or private keys.
//
// Legacy registrations that only supply `metadata_hash` are stamped as V1.
// V2 is additive; unsupported versions fail closed with a stable error.

/// Envelope version matching backend `HRPSTG1`.
pub const METADATA_ENVELOPE_V1: u32 = 1;
/// Envelope version matching backend `HRPSTG2`.
pub const METADATA_ENVELOPE_V2: u32 = 2;
/// Highest envelope version this wasm accepts.
pub const METADATA_ENVELOPE_VERSION_MAX: u32 = METADATA_ENVELOPE_V2;
/// Default for bare `metadata_hash` registrations (backward compatible).
pub const METADATA_ENVELOPE_VERSION_DEFAULT: u32 = METADATA_ENVELOPE_V1;


// ---------------------------------------------------------------------------
// Proof-history bounds (#90)
// ---------------------------------------------------------------------------
//
// Every proof carries an append-only history of lifecycle transitions.
// Each entry is bounded in size and the total number of entries per proof
// is capped to prevent storage exhaustion under hostile inputs.
//
// - MAX_HISTORY_ENTRIES_PER_PROOF limits total entries per proof.
// - MAX_HISTORY_LIMIT bounds the maximum number of entries returned by a
//   single query, protecting callers from unbounded iteration costs.
pub const MAX_HISTORY_ENTRIES_PER_PROOF: u32 = 256;
pub const MAX_HISTORY_LIMIT: u32 = 50;

// ---------------------------------------------------------------------------
// Scoped emergency pause controls (#87)
// ---------------------------------------------------------------------------
//
// Pauses are scoped per registration domain (one bit per identity tier) so a
// compromised path can be contained without freezing unaffected tiers or any
// read entry point. Reads (`get_proof`, `get_proof_status`, `get_by_video`,
// `has_nullifier`, `get_issuer`, `get_credential_root`, `get_verifier`,
// `is_paused`, `get_pause_state`) are never gated by pause state. Admin
// remediation entry points (`revoke_proof`, `revoke_issuer`,
// `revoke_credential_root`, `set_verifier`) also stay callable while paused,
// since incident response depends on them.
//
// Every pause is bounded: callers supply a `duration_secs` capped by
// `MAX_PAUSE_DURATION_SECS` (admin) or `MAX_GUARDIAN_PAUSE_DURATION_SECS`
// (guardian). A pause auto-expires once `ledger().timestamp() >=
// expires_at`, so a lost admin/guardian key cannot brick registration
// forever. `pause` is idempotent (re-pausing overwrites/extends the
// existing record); `unpause` on an already-unpaused domain is a no-op.
// Only the admin can lift a pause early — a compromised guardian key can
// raise the alarm but cannot stand it down before the bounded expiry.
//
// Migration: `Guardian` and `Pause(domain)` are new, additive storage keys.
// Existing deployments read as "no guardian set" / "nothing paused" until
// the admin opts in, so upgrading is backward compatible and requires no
// migration step. Rolling back to a pre-#87 wasm simply ignores these keys.
pub const PAUSE_DOMAIN_TIER1_REGISTRATION: u32 = 1 << 0;
pub const PAUSE_DOMAIN_TIER2_REGISTRATION: u32 = 1 << 1;
pub const PAUSE_DOMAIN_TIER3_REGISTRATION: u32 = 1 << 2;
/// Convenience alias that expands to all three registration domains at once.
pub const PAUSE_DOMAIN_ALL_REGISTRATION: u32 = PAUSE_DOMAIN_TIER1_REGISTRATION
    | PAUSE_DOMAIN_TIER2_REGISTRATION
    | PAUSE_DOMAIN_TIER3_REGISTRATION;

const PAUSE_DOMAIN_SINGLE_BITS: [u32; 3] = [
    PAUSE_DOMAIN_TIER1_REGISTRATION,
    PAUSE_DOMAIN_TIER2_REGISTRATION,
    PAUSE_DOMAIN_TIER3_REGISTRATION,
];

/// Maximum pause duration an admin may set in a single call (7 days).
pub const MAX_PAUSE_DURATION_SECS: u64 = 7 * 24 * 60 * 60;
/// Maximum pause duration a guardian may set in a single call (24 hours).
/// Kept shorter than the admin cap so a compromised guardian key cannot
/// freeze registration for longer than a day without admin involvement.
pub const MAX_GUARDIAN_PAUSE_DURATION_SECS: u64 = 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Constrained issuer and source delegation (#192)
// ---------------------------------------------------------------------------
//
// A source or issuer often needs an assistant, a scheduler, or a CI job to
// register on its behalf without handing over the key. A delegation grants
// exactly one capability, for a bounded time, and nothing else.
//
// What a delegation is NOT:
//
// - It is not issuer or source authority. A delegate cannot add or revoke
//   issuers, cannot add or revoke credential roots, cannot set the verifier,
//   pause a domain, or touch admin state. Those paths still require the
//   grantor's own key.
// - It is not transitive. `grant_delegation` requires the grantor's own
//   signature, and the delegated registration entry points are not grant entry
//   points, so there is no call path by which a delegate can re-delegate the
//   authority it received. A delegate that grants to a third party grants only
//   *its own* authority; the third party still cannot act for the original
//   grantor. This is enforced by construction, not by a runtime scan, so it
//   holds without bounding a delegation graph walk.
// - It is not attribution laundering. The registered `ProofRecord` still names
//   the grantor as source/issuer; the delegate appears only in the proof's
//   lifecycle history, so an auditor can see who actually acted.
//
// Bounds. `scope` must be a non-empty subset of the known scope bits.
// `duration_secs` must be non-zero and at most `MAX_DELEGATION_DURATION_SECS`.
// A grantor may hold at most `MAX_DELEGATIONS_PER_GRANTOR` distinct delegate
// addresses; re-granting to an existing delegate overwrites its record and does
// not consume another slot, so retries and renewals are idempotent in storage.
//
// Expiry. A delegation lapses on its own at `expires_at` — a forgotten grant
// cannot become permanent authority. An expired record still occupies its slot
// until `revoke_delegation` prunes it, which keeps the cap a simple, auditable
// count of distinct delegates rather than a time-dependent quantity.
//
// Migration. `Delegation` and `DelegationCount` are new, additive storage keys
// and the delegated entry points are new functions. Existing deployments read
// as "no delegations" until a grantor opts in; no migration step is required.
// Rolling back to a pre-#192 wasm ignores these keys, which fails closed: the
// delegated entry points disappear and only direct-key registration remains.

/// A delegate may call `register_source_delegated` for the grantor.
pub const DELEGATION_SCOPE_REGISTER_SOURCE: u32 = 1 << 0;
/// A delegate may call `register_seal_delegated` for the grantor.
pub const DELEGATION_SCOPE_REGISTER_SEAL: u32 = 1 << 1;
/// Every known scope bit. Used to reject unknown bits in `scope`.
pub const DELEGATION_SCOPE_ALL: u32 =
    DELEGATION_SCOPE_REGISTER_SOURCE | DELEGATION_SCOPE_REGISTER_SEAL;

/// Longest delegation a grantor may issue in a single call (30 days).
pub const MAX_DELEGATION_DURATION_SECS: u64 = 30 * 24 * 60 * 60;

/// Maximum number of distinct delegate addresses a single grantor may hold.
/// Bounds per-grantor storage growth under a hostile or buggy client.
pub const MAX_DELEGATIONS_PER_GRANTOR: u32 = 32;

// ---------------------------------------------------------------------------
// Verifier rotation state
// ---------------------------------------------------------------------------
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierState {
    pub active_verifier: Option<Address>,
    pub pending_verifier: Option<Address>,
    pub previous_verifier: Option<Address>,
    pub activation_ledger: u64,
    pub overlap_window: u64,
    pub rollback_window: u64,
    pub rollback_window_end: u64,
}

// ---------------------------------------------------------------------------
// Timelocked verifier and policy administration (#86)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ProposalAction {
    SetVerifier = 1,
    RevokeIssuer = 2,
    SetProofTtl = 3,
    RevokeCredentialRoot = 4,
}

pub const DEFAULT_SCOPE_EPOCH: u64 = 0;
pub const MAX_AGGREGATION_SIZE: u32 = 8;
pub const AGGREGATION_DOMAIN_SEPARATOR: [u8; 32] = [0u8; 32];

#[contractevent(topics = ["sealpolicy", "create"])]
pub struct SealPolicyCreated {
    #[topic]
    pub version: u32,
    pub required_approvals: u32,
    pub max_signers: u32,
}

#[contractevent(topics = ["sealpolicy", "cancel"])]
pub struct SealPolicyCancelled {
    #[topic]
    pub version: u32,
}

#[contractevent(topics = ["sealapproval", "record"])]
pub struct SealApprovalRecorded {
    #[topic]
    pub proof_id: BytesN<32>,
    pub signer: Address,
    pub policy_version: u32,
}

#[contractevent(topics = ["sealfinalize", "ok"])]
pub struct SealFinalized {
    #[topic]
    pub proof_id: BytesN<32>,
    pub approval_count: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealPolicy {
    pub version: u32,
    pub required_approvals: u32,
    pub max_signers: u32,
    pub approval_ttl: u64,
    pub expires_at: u64,
    pub status: u32,
}

/// Records a single issuer's approval for a proof under a specific policy
/// version. An approval is idempotent per (proof_id, signer) pair and expires
/// after `approved_at + policy.approval_ttl`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealApproval {
    pub proof_id: BytesN<32>,
    pub policy_version: u32,
    pub signer: Address,
    pub approved_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelockProposal {
    pub action: u32,
    pub proposer: Address,
    pub target: Address,
    pub payload: BytesN<32>,
    pub created_at: u64,
    pub min_execution_at: u64,
    pub executed: bool,
    pub cancelled: bool,
}

pub const DEFAULT_TIMELOCK_MIN_DELAY_SECS: u64 = 86_400;
pub const MAX_TIMELOCK_MIN_DELAY_SECS: u64 = 604_800;
pub const MAX_PENDING_TIMELOCK_PROPOSALS: u32 = 16;

/// A narrowly scoped, expiring authority to act for `grantor`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationRecord {
    pub grantor: Address,
    pub delegate: Address,
    /// Bitwise-OR of `DELEGATION_SCOPE_*`.
    pub scope: u32,
    pub granted_at: u64,
    /// Epoch seconds after which the delegation is inert. Never zero.
    pub expires_at: u64,
}

#[contractevent(topics = ["deleg", "grant"])]
pub struct DelegationGranted {
    #[topic]
    pub grantor: Address,
    #[topic]
    pub delegate: Address,
    pub scope: u32,
    pub granted_at: u64,
    pub expires_at: u64,
}

#[contractevent(topics = ["deleg", "revoke"])]
pub struct DelegationRevoked {
    #[topic]
    pub grantor: Address,
    #[topic]
    pub delegate: Address,
    pub revoked_by: Address,
    pub revoked_at: u64,
}

#[contractevent(topics = ["deleg", "used"])]
pub struct DelegationUsed {
    #[topic]
    pub grantor: Address,
    #[topic]
    pub delegate: Address,
    pub scope: u32,
    pub proof_id: BytesN<32>,
}

/// Threshold in ledgers below which we extend the TTL of records (approx 14 days)
pub const BUMP_THRESHOLD_LEDGERS: u32 = 241_920;

/// Target TTL in ledgers when extending the TTL of records (approx 30 days)
pub const BUMP_TARGET_LEDGERS: u32 = 518_400;

/// Verification status returned by `get_proof_status`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofVerificationStatus {
    Valid,
    Revoked,
    Expired,
    NotFound,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageRecord {
    /// SDK 27 requires `contracttype` structs to avoid generic fields, so the
    /// parent list is stored as a separate non-generic contracttype wrapper.
    pub parent_proof_ids: LineageChildren,
    pub manifest_digest: BytesN<32>,
    pub actor: Address,
    pub operation_type: Symbol,
    pub output_digest: BytesN<32>,
    pub depth: u32,
}

/// Wrapper so `LineageRecord` can store a list of parent proof IDs without a
/// generic field (unsupported in SDK 27 contract types).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageChildren {
    pub ids: Vec<BytesN<32>>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofRecord {
    pub video_hash: BytesN<32>,
    pub metadata_hash: BytesN<32>,
    pub tier: u32,
    pub status: u32,
    pub created_at: u64,
    pub expires_at: u64,
    pub source: Option<Address>,
    pub issuer: Option<Address>,
    pub nullifier: Option<BytesN<32>>,
    /// Optional batch size when this proof was registered as part of an
    /// aggregated batch (0 = not part of a batch).
    pub batch_size: u32,
}

/// Versioned on-chain metadata envelope binding (#317).
///
/// Stores only `(version, metadata_hash)` commitments — never raw envelope
/// bytes, media, witnesses, or secrets. Aligns with backend `envelope.py`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataEnvelope {
    /// Proof this envelope is bound to.
    pub proof_id: BytesN<32>,
    /// Envelope schema version (`METADATA_ENVELOPE_V1` / `V2`).
    pub version: u32,
    /// Canonical metadata hash (same value stored on `ProofRecord`).
    pub metadata_hash: BytesN<32>,
    /// Ledger timestamp when this envelope binding was written.
    pub bound_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRecord {
    pub metadata_hash: BytesN<32>,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRootRecord {
    pub metadata_hash: BytesN<32>,
    pub active: bool,
    pub issued_at: u64,
}

/// Pause record for a single registration domain bit. Presence of a record
/// does not by itself mean "paused" — see `domain_is_paused`, which also
/// checks `expires_at` against the current ledger time so pauses expire on
/// their own without requiring a follow-up transaction.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseRecord {
    pub paused_by: Address,
    pub paused_at: u64,
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ProofLifecycleAction {
    Registered = 1,
    Verified = 2,
    Revoked = 3,
    Expired = 4,
    Corrected = 5,
    TtlUpdated = 6,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofHistoryEntry {
    pub action: u32,
    pub timestamp: u64,
    pub actor: Option<Address>,
    pub reason_code: u32,
}

#[contractevent(topics = ["proof", "reg"])]
pub struct ProofRegistered {
    #[topic]
    pub proof_id: BytesN<32>,
    pub video_hash: BytesN<32>,
    pub tier: u32,
    pub status: u32,
    pub batch_size: u32,
}

// Metadata envelope events (#317) — version + hash only (privacy-safe).
// SDK 27 rejects 3-string topic lists here (attribute macro LengthExceedsMax),
// so the verb is folded into the second topic, matching the #336 drift fixes.
#[contractevent(topics = ["envelope", "metadatabound"])]
pub struct MetadataEnvelopeBound {
    #[topic]
    pub proof_id: BytesN<32>,
    pub version: u32,
    pub metadata_hash: BytesN<32>,
    pub bound_at: u64,
}

#[contractevent(topics = ["envelope", "metadataupgraded"])]
pub struct MetadataEnvelopeUpgraded {
    #[topic]
    pub proof_id: BytesN<32>,
    pub previous: u32,
    pub current: u32,
    pub metadata_hash: BytesN<32>,
}

// Soroban event topics are capped at 4 by the host; folded in #336 for
// compactness: ["proof", "batchreg"].
#[contractevent(topics = ["proof", "batchreg"])]
pub struct BatchProofRegistered {
    #[topic]
    pub batch_id: BytesN<32>,
    pub credential_root: BytesN<32>,
    pub count: u32,
    pub tier: u32,
    pub status: u32,
}

#[contractevent(topics = ["proof", "revoke"])]
pub struct ProofRevoked {
    #[topic]
    pub proof_id: BytesN<32>,
    pub status: u32,
}

#[contractevent(topics = ["issuer", "add"])]
pub struct IssuerAdded {
    #[topic]
    pub issuer: Address,
    pub metadata_hash: BytesN<32>,
}

#[contractevent(topics = ["issuer", "revoke"])]
pub struct IssuerRevoked {
    #[topic]
    pub issuer: Address,
}

#[contractevent(topics = ["verif", "set"])]
pub struct VerifierSet {
    #[topic]
    pub verifier: Address,
}

#[contractevent(topics = ["verif", "schedule"])]
pub struct VerifierRotationScheduled {
    #[topic]
    pub active_verifier: Address,
    pub pending_verifier: Address,
    pub activation_ledger: u64,
    pub overlap_window: u64,
    pub rollback_window: u64,
}

#[contractevent(topics = ["verif", "activate"])]
pub struct VerifierRotationActivated {
    #[topic]
    pub active_verifier: Address,
    pub previous_verifier: Address,
    pub rollback_window_end: u64,
}

#[contractevent(topics = ["verif", "rollback"])]
pub struct VerifierRotationRolledBack {
    #[topic]
    pub active_verifier: Address,
    pub previous_verifier: Address,
}

#[contractevent(topics = ["credroot", "add"])]
pub struct CredentialRootAdded {
    #[topic]
    pub credential_root: BytesN<32>,
    pub metadata_hash: BytesN<32>,
    pub issued_at: u64,
}

#[contractevent(topics = ["credroot", "revoke"])]
pub struct CredentialRootRevoked {
    #[topic]
    pub credential_root: BytesN<32>,
}

/// Domain-separated, privacy-safe proof lifecycle history event (#90).
///
/// Topics: `["proof", "history", proof_id]`. The payload carries only bounded
/// metadata (action, timestamp, actor, reason_code) — never media, proof bytes,
/// witnesses, nullifiers, or metadata hashes.
#[contractevent(topics = ["proof", "history"])]
pub struct ProofHistoryEvent {
    #[topic]
    pub proof_id: BytesN<32>,
    pub action: u32,
    pub timestamp: u64,
    pub actor: Option<Address>,
    pub reason_code: u32,
}

// ---------------------------------------------------------------------------
// Dispute / correction state machine (#dispute)
// ---------------------------------------------------------------------------
//
// A dispute is a bounded, auditable record that challenges a proof's accuracy
// without deleting or revoking the original proof. Disputes are separate from
// revocation: a disputed proof may still be `Valid` under `get_proof_status`.
//
// States
// ------
// Open        - dispute submitted, response pending.
// Responded   - issuer/source submitted a response commitment; admin decision pending.
// Resolved    - admin resolved the dispute (corrective action taken or noted).
// Dismissed   - admin dismissed the dispute (no corrective action).
// Superseded  - the disputed proof was superseded by a corrected proof.
//
// Valid transitions
// -----------------
// Open -> Responded  (by issuer/source of the proof, within respond_deadline)
// Open -> Dismissed  (by admin at any time)
// Open -> Superseded (by admin when a correcting proof is linked)
// Responded -> Resolved  (by admin, within resolve_deadline after response)
// Responded -> Dismissed (by admin at any time after response)
// Responded -> Superseded (by admin when a correcting proof is linked)
//
// Resolved, Dismissed, Superseded are terminal states.
//
// Spam / abuse controls
// ---------------------
// - MAX_OPEN_DISPUTES_PER_PROOF (4): cap on simultaneously Open disputes for
//   a single proof. Prevents resource exhaustion.
// - REPORTER_COOLDOWN_SECS (86400, 24 h): minimum interval between disputes
//   opened by the same reporter_hash for the same proof.
// - Deadlines stored in the record; callers / indexers can observe them.
//
// Privacy
// -------
// The reporter's identity is stored as a caller-supplied commitment
// (reporter_hash = H(reporter_address || proof_id)) rather than in the clear.
// This allows duplicate/spam detection without leaking the reporter address in
// contract storage that is world-readable on-chain.

/// Maximum number of simultaneously Open disputes allowed per proof.
pub const MAX_OPEN_DISPUTES_PER_PROOF: u32 = 4;
/// Minimum seconds between consecutive disputes by the same reporter on the
/// same proof (24 hours).
pub const REPORTER_COOLDOWN_SECS: u64 = 86_400;
/// Seconds from dispute open until the issuer/source must respond (7 days).
pub const RESPOND_DEADLINE_SECS: u64 = 604_800;
/// Seconds from response until the admin must resolve or dismiss (14 days).
pub const RESOLVE_DEADLINE_SECS: u64 = 1_209_600;

/// Dispute state transitions. Numeric values are stable on-chain identifiers;
/// do not renumber existing variants.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DisputeStatus {
    Open = 1,
    Responded = 2,
    Resolved = 3,
    Dismissed = 4,
    Superseded = 5,
}

/// Categorised dispute reasons. Numeric values are stable on-chain; do not
/// renumber.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DisputeReason {
    ContentError = 1,
    MetadataError = 2,
    TierMismatch = 3,
    CredentialLapsed = 4,
    PrivacyViolation = 5,
    Other = 6,
}

/// Immutable dispute record. Only `status`, `response_commitment`,
/// `resolve_deadline`, `resolved_at`, and `superseded_by` are mutated after
/// initial creation; the rest are set once at open time.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisputeRecord {
    /// Unique dispute identifier (caller-supplied, 32-byte opaque commitment).
    pub dispute_id: BytesN<32>,
    /// The proof this dispute challenges.
    pub proof_id: BytesN<32>,
    /// Categorised reason for the dispute.
    pub reason: DisputeReason,
    /// Privacy-safe commitment: H(reporter_address_bytes || proof_id_bytes).
    /// The reporter's actual address is never stored on-chain.
    pub reporter_hash: BytesN<32>,
    /// Off-chain commitment to the reporter's full evidence submission.
    pub commitment_hash: BytesN<32>,
    /// Current lifecycle state.
    pub status: DisputeStatus,
    /// Ledger timestamp when the dispute was opened.
    pub opened_at: u64,
    /// Ledger timestamp by which the issuer/source must respond.
    pub respond_deadline: u64,
    /// Ledger timestamp by which the admin must decide after a response.
    /// Set to 0 until a response is submitted.
    pub resolve_deadline: u64,
    /// Issuer/source commitment hash in response. None until Responded.
    pub response_commitment: Option<BytesN<32>>,
    /// Ledger timestamp of final resolution/dismissal. 0 while open.
    pub resolved_at: u64,
    /// Proof ID that supersedes the disputed proof, if Superseded.
    pub superseded_by: Option<BytesN<32>>,
}

// ---------------------------------------------------------------------------
// Dispute events (privacy-safe: commitments and timestamps only)
// ---------------------------------------------------------------------------

#[contractevent(topics = ["dispute", "open"])]
pub struct DisputeOpened {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub reason: DisputeReason,
    pub reporter_hash: BytesN<32>,
    pub commitment_hash: BytesN<32>,
    pub respond_deadline: u64,
}

#[contractevent(topics = ["dispute", "respond"])]
pub struct DisputeResponded {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub response_commitment: BytesN<32>,
    pub resolve_deadline: u64,
}

#[contractevent(topics = ["dispute", "resolve"])]
pub struct DisputeResolved {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub resolved_at: u64,
}

#[contractevent(topics = ["dispute", "dismiss"])]
pub struct DisputeDismissed {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub resolved_at: u64,
}

#[contractevent(topics = ["dispute", "supersede"])]
pub struct DisputeSuperseded {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub superseded_by: BytesN<32>,
    pub resolved_at: u64,
}

/// Schema record for issuer-certified attribute schemas.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaRecord {
    pub schema_hash: BytesN<32>,
    pub issuer_namespace: BytesN<32>,
    pub version: u32,
    pub active: bool,
    pub attribute_count: u32,
    pub created_at: u64,
}

#[contractevent(topics = ["schema", "add"])]
pub struct SchemaAdded {
    #[topic]
    pub schema_hash: BytesN<32>,
    pub issuer_namespace: BytesN<32>,
    pub version: u32,
    pub attribute_count: u32,
}

#[contractevent(topics = ["schema", "deprecate"])]
pub struct SchemaDeprecated {
    #[topic]
    pub schema_hash: BytesN<32>,
}

#[contractevent(topics = ["seldisc", "verify"])]
pub struct SelectiveDisclosureVerified {
    #[topic]
    pub schema_hash: BytesN<32>,
    pub credential_root: BytesN<32>,
    pub nullifier: BytesN<32>,
    pub evidence_digest: BytesN<32>,
}

/// Domain separator that binds non-revocation proofs to the Harpocrates
/// revocation witness circuit version.  Both the Noir circuit and this
/// contract use the same constant.  Changing the circuit requires updating
/// this value to prevent proof replay across protocol versions.
///
/// Format: 32-byte big-endian BN254 field element serialization of
///   `0x484152504f4352415445535f5245564f434154494f4e5f5631`
/// which represents the ASCII string "HARPOCRATES_REVOCATION_V1" as a
/// 192-bit integer.  The 8 leading zero bytes come from the BN254 field
/// serialisation (field elements are padded to 32 bytes).
///
/// Layout:
///   [ 0.. 8)  leading zeros (BN254 field padding)
///   [ 8..32)  "HARPOCRATES_REVOCATION_V1" (24 ASCII bytes)
const REVOCATION_DOMAIN_SEPARATOR: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 7 leading zeros (BN254 padding)
    0x48, 0x41, 0x52, 0x50, 0x4f, 0x43, 0x52, 0x41, // HARPOCRA
    0x54, 0x45, 0x53, 0x5f, 0x52, 0x45, 0x56, 0x4f, // TES_REVO
    0x43, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x56, // CATION_V
    0x31, // 1
];

/// Domain separator for the scoped nullifier v1 circuit.
/// "HARPOCRATES_SCOPED_NULLIFIER_V1" encoded as a 32-byte BN254 field element
/// (31 ASCII bytes with a leading 0x00 pad).
#[allow(dead_code)]
const SCOPED_NULLIFIER_V1_DOMAIN: [u8; 32] = [
    0x00, // leading zero (BN254 field padding)
    0x48, 0x41, 0x52, 0x50, 0x4f, 0x43, 0x52, 0x41, // HARPOCRA
    0x54, 0x45, 0x53, 0x5f, 0x53, 0x43, 0x4f, 0x50, // TES_SCOP
    0x45, 0x44, 0x5f, 0x4e, 0x55, 0x4c, 0x4c, 0x49, // ED_NULLI
    0x46, 0x49, 0x45, 0x52, 0x5f, 0x56, 0x31, // FIER_V1
];

/// Protocol domain constant ("harpocrates" SHA-256 field element).
pub const DOMAIN_PROTOCOL_FIELD: [u8; 32] = [
    0x26, 0x1e, 0x9f, 0x6e, 0x39, 0xe3, 0xc1, 0xae, 0x6a, 0xca, 0x9f, 0x29, 0xe8, 0x4c, 0x10, 0xd5,
    0x9c, 0x82, 0xd5, 0xf4, 0xb4, 0x0c, 0x21, 0xc1, 0xb7, 0xe3, 0xc0, 0x1a, 0xd5, 0x71, 0xc2, 0x01,
];

/// Circuit version domain constant ("1" SHA-256 field element).
pub const DOMAIN_VERSION_FIELD: [u8; 32] = [
    0x0c, 0x89, 0xef, 0xf4, 0xec, 0x8e, 0x39, 0xa0, 0x1e, 0x9f, 0x19, 0x54, 0x7a, 0x0c, 0xc9, 0xdd,
    0x7f, 0xd2, 0xa9, 0x7d, 0x79, 0xba, 0x4d, 0x94, 0xfd, 0x32, 0xe9, 0x7a, 0x1f, 0x5a, 0xc6, 0x23,
];

/// Target network domain constant ("testnet" SHA-256 field element).
pub const DOMAIN_NETWORK_FIELD: [u8; 32] = [
    0x2a, 0x2c, 0x3f, 0x48, 0xce, 0x2e, 0x3c, 0x2f, 0x1e, 0x6c, 0x89, 0xb1, 0x8d, 0x64, 0xb5, 0xf5,
    0xc1, 0xf8, 0x8a, 0x59, 0xa0, 0xd9, 0xbc, 0x82, 0xcb, 0x61, 0xa1, 0xe8, 0xcb, 0x77, 0xa5, 0x0f,
];

/// Expected length of v1 public inputs (5 × 32 = 160 bytes, including domain_tag).
const SILENT_WITNESS_V1_INPUT_LEN: u32 = 160;

/// Expected length of v2 scoped public inputs (7 × 32 = 224 bytes, including domain_tag).
const SILENT_WITNESS_V2_INPUT_LEN: u32 = 224;

#[contractevent(topics = ["revroot", "set"])]
pub struct RevocationRootSet {
    #[topic]
    pub revocation_root: BytesN<32>,
}

#[contractevent(topics = ["nonrev", "check"])]
pub struct NonRevocationChecked {
    #[topic]
    pub credential_root: BytesN<32>,
    pub nullifier: BytesN<32>,
    pub revocation_root: BytesN<32>,
}

#[contractevent(topics = ["pause", "set"])]
pub struct DomainPaused {
    #[topic]
    pub domain: u32,
    pub paused_by: Address,
    pub paused_at: u64,
    pub expires_at: u64,
}

#[contractevent(topics = ["pause", "clear"])]
pub struct DomainUnpaused {
    #[topic]
    pub domain: u32,
    pub unpaused_by: Address,
    pub unpaused_at: u64,
}

#[contractevent(topics = ["guardian", "set"])]
pub struct GuardianSet {
    #[topic]
    pub guardian: Address,
}

#[contractevent(topics = ["admin", "propose"])]
pub struct AdminProposed {
    #[topic]
    pub pending_admin: Address,
    pub current_admin: Address,
}

#[contractevent(topics = ["admin", "cancel"])]
pub struct AdminTransferCancelled {
    #[topic]
    pub pending_admin: Address,
    pub current_admin: Address,
}

#[contractevent(topics = ["admin", "accept"])]
pub struct AdminAccepted {
    #[topic]
    pub new_admin: Address,
    pub previous_admin: Address,
}

#[contractevent(topics = ["scope", "epoch"])]
pub struct ScopeEpochSet {
    #[topic]
    pub scope: BytesN<32>,
    pub epoch: u64,
}

// ---------------------------------------------------------------------------
// Timelock proposal events (#86)
// ---------------------------------------------------------------------------

#[contractevent(topics = ["timelock", "propose"])]
pub struct TimelockProposalCreated {
    #[topic]
    pub proposal_id: u32,
    pub action: u32,
    #[topic]
    pub proposer: Address,
    pub target: Address,
    pub created_at: u64,
    pub min_execution_at: u64,
}

#[contractevent(topics = ["timelock", "cancel"])]
pub struct TimelockProposalCancelled {
    #[topic]
    pub proposal_id: u32,
    pub action: u32,
    #[topic]
    pub cancelled_by: Address,
    pub cancelled_at: u64,
}

#[contractevent(topics = ["timelock", "exec"])]
pub struct TimelockProposalExecuted {
    #[topic]
    pub proposal_id: u32,
    pub action: u32,
    #[topic]
    pub executed_by: Address,
    pub executed_at: u64,
}

#[contractevent(topics = ["timelock", "emergency"])]
pub struct TimelockEmergencyExec {
    #[topic]
    pub proposal_id: u32,
    pub action: u32,
    #[topic]
    pub executed_by: Address,
    pub executed_at: u64,
}

// Soroban event topics allow at most 2 in SDK 27, so the third topic is
// folded into the second: ["timelock", "delayset"].
#[contractevent(topics = ["timelock", "delayset"])]
pub struct TimelockMinDelaySet {
    pub previous_delay: u64,
    pub new_delay: u64,
    #[topic]
    pub set_by: Address,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SchemaVersion {
    V1 = 1,
}

#[contractevent(topics = ["schema", "upgrade"])]
pub struct SchemaUpgraded {
    pub previous: u32,
    pub current: u32,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Proof(BytesN<32>),
    Video(BytesN<32>),
    Nullifier(BytesN<32>),
    CredentialRoot(BytesN<32>),
    Issuer(Address),
    Verifier,
    ProofTtl,
    /// Optional emergency-pause guardian, distinct from admin (#87).
    Guardian,
    /// Pause record for a single registration domain bit (#87).
    Pause(u32),
    PendingAdmin,
    /// Merkle root of the credential-revocation tree (set by admin).
    RevocationRoot,
    ProofHistorySeq(BytesN<32>),
    ProofHistoryEntry(BytesN<32>, u32),
    /// Scoped, expiring delegation from a grantor to a delegate (#192).
    Delegation(Address, Address),
    /// Count of distinct delegate addresses held by a grantor (#192).
    DelegationCount(Address),
    /// Verifier rotation state (schedule/activate/rollback).
    VerifierState,
    /// Storage schema version.
    SchemaVersion,
    /// Scope epoch for verifier-scope binding.
    ScopeEpoch(BytesN<32>),
    /// Sequential counter for timelock proposal IDs (#86).
    ProposalSeq,
    /// Timelock proposal by sequential ID (#86).
    Proposal(u32),
    /// Minimum timelock delay in seconds (#86).
    TimelockMinDelay,
    /// Schema definition by schema hash.
    Schema(BytesN<32>),
    /// Verifiable derivative lineage record keyed by output digest.
    Lineage(BytesN<32>),
    /// Versioned metadata envelope binding keyed by proof_id (#317).
    MetadataEnvelope(BytesN<32>),
    /// Stores the `DisputeRecord` for a given dispute_id (#dispute).
    Dispute(BytesN<32>),
    /// Counts open (non-terminal) disputes for a proof_id (#dispute).
    /// Used to enforce MAX_OPEN_DISPUTES_PER_PROOF.
    ProofOpenDisputeCount(BytesN<32>),
    /// Tracks the last-opened timestamp for a reporter_hash/proof pair.
    /// Key is the caller-supplied `reporter_hash` (a 32-byte commitment).
    ReporterCooldown(BytesN<32>),
    /// Current seal-policy version counter (set by admin) (#124).
    SealPolicyCount,
    /// Seal policy by version number (#124).
    SealPolicy(u32),
    /// Bounded signer set for a seal policy version (#124).
    SealPolicySigners(u32),
    /// Individual approval per (proof_id, signer) (#124).
    SealApproval(BytesN<32>, Address),
    /// Bounded signer set for a finalized threshold seal (#124).
    ThresholdSigners(BytesN<32>),
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RegistryError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    DuplicateProof = 4,
    DuplicateVideo = 5,
    DuplicateNullifier = 6,
    InvalidProof = 7,
    UnknownIssuer = 8,
    VerifierNotSet = 9,
    InvalidPublicInputs = 10,
    UnknownCredentialRoot = 11,
    RevokedCredentialRoot = 12,
    HistorySaturated = 13,
    InvalidHistoryAction = 14,
    InvalidReasonCode = 15,
    HistoryLimitExceeded = 16,
    AlreadyExpired = 17,
    NoCorrectionChange = 18,
    HistoryCorruption = 19,
    NoPendingAdmin = 20,
    /// The requested operation is blocked by an active domain pause (#87).
    Paused = 21,
    /// `domain` was zero or contained bits outside the known pause domains.
    InvalidPauseDomain = 22,
    /// `duration_secs` was zero or exceeded the caller's role cap.
    InvalidPauseDuration = 23,
    /// `scope` was zero or contained bits outside `DELEGATION_SCOPE_ALL` (#192).
    InvalidDelegationScope = 24,
    /// `duration_secs` was zero or above `MAX_DELEGATION_DURATION_SECS` (#192).
    InvalidDelegationDuration = 25,
    /// No delegation exists from the named grantor to the caller (#192).
    DelegationNotFound = 26,
    /// The delegation exists but its `expires_at` has passed (#192).
    DelegationExpired = 27,
    /// The delegation exists and is live, but does not carry the scope the
    /// attempted operation requires (#192).
    DelegationScopeExceeded = 28,
    /// The grantor already holds `MAX_DELEGATIONS_PER_GRANTOR` delegates (#192).
    DelegationsSaturated = 29,
    /// A grantor may not delegate to itself (#192).
    SelfDelegation = 30,
    /// The requested timelock proposal does not exist (#86).
    ProposalNotFound = 31,
    ProposalNotReady = 32,
    ProposalAlreadyExecuted = 33,
    ProposalCancelled = 34,
    InvalidProposalAction = 35,
    InvalidProposalPayload = 36,
    ProposalsSaturated = 37,
    InvalidTimelockDelay = 38,
    AlreadyCancelled = 39,
    RotationNotScheduled = 40,
    RotationNotReady = 41,
    RotationWindowClosed = 42,
    BatchTooLarge = 43,
    InvalidScopeEpoch = 44,
    DisputeNotFound = 45,
    DisputeAlreadyResolved = 46,
    SupersessionCycleDetected = 47,
    SupersessionNotFound = 48,
    DomainTagMismatch = 49,
    UnknownSchema = 50,
    InactiveSchema = 51,
    SchemaVersionMismatch = 52,
    // --- Restored feature errors (append-only; never renumber existing) ---
    /// A scoped-nullifier proof was generated for a stale scope epoch.
    StaleEpoch = 53,
    /// Batch aggregation was requested with zero or too many elements.
    BatchSizeExceeded = 54,
    /// Credential roots in a batch were not all identical.
    BatchCredentialRootMismatch = 55,
    /// The batch element count did not match the supplied video-hash list.
    BatchCountMismatch = 56,
    /// A lineage parent proof/lineage record was not found.
    InvalidLineage = 57,
    /// A lineage edge would introduce a cycle.
    LineageCycle = 58,
    /// The requested lineage depth exceeds `MAX_LINEAGE_DEPTH`.
    LineageTooDeep = 59,
    /// The requested lineage fan-out exceeds `MAX_LINEAGE_FANOUT`.
    LineageFanOutExceeded = 60,
    /// The proof already has `MAX_OPEN_DISPUTES_PER_PROOF` open disputes.
    TooManyOpenDisputes = 61,
    /// The respond/resolve deadline for this dispute transition has passed.
    DisputeWindowExpired = 62,
    /// The dispute is already in a terminal state.
    DisputeAlreadyClosed = 63,
    /// Supersession would create a cycle (direct or depth-1).
    DisputeCyclicSupersession = 64,
    /// The caller is not the proof's issuer/source (or admin for Tier 1).
    UnauthorizedResponder = 65,
    /// The reporter must wait out `REPORTER_COOLDOWN_SECS` before re-reporting.
    ReporterOnCooldown = 66,
    /// The dispute is not in the state this transition requires.
    InvalidDisputeTransition = 67,
    // --- Threshold seal policy (#124, restored; append-only) ---
    /// The referenced seal policy version does not exist.
    UnknownSealPolicy = 68,
    /// The seal policy exists but is cancelled, or its expiry has passed.
    InactiveSealPolicy = 69,
    /// The signer is not in the policy's signer set.
    UnknownPolicySigner = 70,
    /// The signer has already approved this proof (duplicate call).
    DuplicateApproval = 71,
    /// The caller attempted to finalize before the threshold was met.
    ThresholdNotMet = 72,
    /// `required_approvals` was zero or exceeded `max_signers`.
    InvalidThreshold = 73,
    /// The signer set (or configured bound) exceeds `MAX_SIGNERS`.
    SignerSetTooLarge = 74,
    /// The seal policy's absolute expiry has passed.
    PolicyExpired = 75,
    /// The proof already exists; threshold seals are single-finalization.
    AlreadyFinalized = 76,
    // --- Metadata envelope versioning (#317; appended after #124 to keep
    // previously shipped threshold codes unchanged) ---
    /// Metadata envelope version is zero or above `METADATA_ENVELOPE_VERSION_MAX` (#317).
    UnsupportedMetadataEnvelopeVersion = 77,
    /// Metadata envelope hash is zero / malformed (#317).
    InvalidMetadataEnvelope = 78,
    /// No metadata envelope (and no proof) for the requested id (#317).
    MetadataEnvelopeNotFound = 79,
    /// Bound envelope hash does not match the proof's `metadata_hash` (#317).
    MetadataEnvelopeHashMismatch = 80,
}

#[contract]
pub struct HarpocratesRegistry;

#[contractimpl]
impl HarpocratesRegistry {
    pub fn init(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic_with_error!(&env, RegistryError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::SchemaVersion, &(SchemaVersion::V1 as u32));
    }

    /// Return the persistent storage schema version.
    ///
    /// Missing keys (pre-#85 deployments) are treated as V1 so callers and
    /// the upgrade harness stay compatible without a forced rewrite.
    pub fn get_storage_schema_version(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::SchemaVersion)
            .unwrap_or(SchemaVersion::V1 as u32)
    }

    /// Apply sequential storage migrations up to the current target schema.
    ///
    /// - Admin-only; unauthorized callers fail with `Unauthorized`.
    /// - Idempotent at the current target (V1): repeated calls are no-ops and
    ///   do not emit `SchemaUpgraded`.
    /// - Legacy deployments without `DataKey::SchemaVersion` are stamped to V1
    ///   without emitting `SchemaUpgraded` (layout already matches V1).
    /// - Future V2+ migrations land in the `current < target` branch and MUST
    ///   preserve existing proof / video / nullifier records and never log
    ///   media, secrets, witnesses, or private keys.
    ///
    /// Rollback: redeploying a prior wasm that ignores unknown keys leaves
    /// stamped `SchemaVersion` intact; V1 readers treat it as authoritative.
    pub fn upgrade_storage(env: Env, admin: Address) {
        require_admin(&env, &admin);

        let had_version = env.storage().persistent().has(&DataKey::SchemaVersion);
        let current_version: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::SchemaVersion)
            .unwrap_or(SchemaVersion::V1 as u32);

        let target_version = SchemaVersion::V1 as u32;

        // Legacy pre-#85 registries: stamp V1 without a SchemaUpgraded event.
        if !had_version {
            env.storage()
                .persistent()
                .set(&DataKey::SchemaVersion, &target_version);
            return;
        }

        if current_version < target_version {
            // Migrations will be added here when moving to V2, V3, etc.

            env.storage()
                .persistent()
                .set(&DataKey::SchemaVersion, &target_version);

            SchemaUpgraded {
                previous: current_version,
                current: target_version,
            }
            .publish(&env);
        }
    }

    pub fn propose_admin(env: Env, admin: Address, pending_admin: Address) {
        require_admin(&env, &admin);

        env.storage()
            .persistent()
            .set(&DataKey::PendingAdmin, &pending_admin);
        AdminProposed {
            pending_admin,
            current_admin: admin,
        }
        .publish(&env);
    }

    pub fn cancel_admin_transfer(env: Env, admin: Address) {
        require_admin(&env, &admin);

        let pending_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdmin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NoPendingAdmin));
        env.storage().persistent().remove(&DataKey::PendingAdmin);
        AdminTransferCancelled {
            pending_admin,
            current_admin: admin,
        }
        .publish(&env);
    }

    pub fn accept_admin(env: Env, pending_admin: Address) {
        let proposed_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdmin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NoPendingAdmin));

        pending_admin.require_auth();
        if proposed_admin != pending_admin {
            panic_with_error!(&env, RegistryError::Unauthorized);
        }

        let previous_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));
        env.storage()
            .persistent()
            .set(&DataKey::Admin, &pending_admin);
        env.storage().persistent().remove(&DataKey::PendingAdmin);
        AdminAccepted {
            new_admin: pending_admin,
            previous_admin,
        }
        .publish(&env);
    }

    pub fn add_issuer(env: Env, admin: Address, issuer: Address, metadata_hash: BytesN<32>) {
        require_admin(&env, &admin);

        env.storage().persistent().set(
            &DataKey::Issuer(issuer.clone()),
            &IssuerRecord {
                metadata_hash: metadata_hash.clone(),
                active: true,
            },
        );
        IssuerAdded {
            issuer,
            metadata_hash,
        }
        .publish(&env);
    }

    pub fn set_verifier(env: Env, admin: Address, verifier: Address) {
        require_admin(&env, &admin);

        env.storage()
            .persistent()
            .set(&DataKey::Verifier, &verifier);
        env.storage().persistent().remove(&DataKey::VerifierState);
        VerifierSet { verifier }.publish(&env);
    }

    pub fn get_verifier(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Verifier)
    }

    pub fn schedule_verifier_rotation(
        env: Env,
        admin: Address,
        verifier: Address,
        activation_ledger: u64,
        overlap_window: u64,
        rollback_window: u64,
    ) {
        require_admin(&env, &admin);

        let active_verifier = get_active_verifier(&env);
        let state = VerifierState {
            active_verifier: Some(active_verifier.clone()),
            pending_verifier: Some(verifier.clone()),
            previous_verifier: Some(active_verifier.clone()),
            activation_ledger,
            overlap_window,
            rollback_window,
            rollback_window_end: activation_ledger.saturating_add(rollback_window),
        };
        env.storage()
            .persistent()
            .set(&DataKey::VerifierState, &state);
        VerifierRotationScheduled {
            active_verifier: active_verifier.clone(),
            pending_verifier: verifier.clone(),
            activation_ledger,
            overlap_window,
            rollback_window,
        }
        .publish(&env);
    }

    pub fn activate_verifier_rotation(env: Env, admin: Address) {
        require_admin(&env, &admin);

        let mut state = get_verifier_rotation_state(&env);
        let pending_verifier = state
            .pending_verifier
            .clone()
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::RotationNotScheduled));
        let active_verifier = state
            .active_verifier
            .clone()
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::RotationNotScheduled));
        let current_ledger = u64::from(env.ledger().sequence());
        if current_ledger < state.activation_ledger {
            panic_with_error!(&env, RegistryError::RotationNotReady);
        }

        state.active_verifier = Some(pending_verifier.clone());
        state.pending_verifier = None;
        state.rollback_window_end = current_ledger.saturating_add(state.rollback_window.max(0));
        env.storage()
            .persistent()
            .set(&DataKey::VerifierState, &state);
        env.storage()
            .persistent()
            .set(&DataKey::Verifier, &pending_verifier);
        VerifierRotationActivated {
            active_verifier: pending_verifier,
            previous_verifier: active_verifier,
            rollback_window_end: state.rollback_window_end,
        }
        .publish(&env);
    }

    pub fn rollback_verifier_rotation(env: Env, admin: Address) {
        require_admin(&env, &admin);

        let state = get_verifier_rotation_state(&env);
        let active_verifier = state
            .active_verifier
            .clone()
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::RotationNotScheduled));
        let previous_verifier = state
            .previous_verifier
            .clone()
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::RotationNotScheduled));
        let current_ledger = u64::from(env.ledger().sequence());
        if state.rollback_window_end == 0 || current_ledger > state.rollback_window_end {
            panic_with_error!(&env, RegistryError::RotationWindowClosed);
        }

        env.storage()
            .persistent()
            .set(&DataKey::Verifier, &previous_verifier);
        env.storage().persistent().remove(&DataKey::VerifierState);
        VerifierRotationRolledBack {
            active_verifier: previous_verifier.clone(),
            previous_verifier: active_verifier,
        }
        .publish(&env);
    }

    pub fn get_verifier_state(env: Env) -> VerifierState {
        get_verifier_rotation_state(&env)
    }

    pub fn add_credential_root(
        env: Env,
        admin: Address,
        credential_root: BytesN<32>,
        metadata_hash: BytesN<32>,
    ) {
        require_admin(&env, &admin);

        let issued_at = env.ledger().timestamp();
        env.storage().persistent().set(
            &DataKey::CredentialRoot(credential_root.clone()),
            &CredentialRootRecord {
                metadata_hash: metadata_hash.clone(),
                active: true,
                issued_at,
            },
        );
        CredentialRootAdded {
            credential_root,
            metadata_hash,
            issued_at,
        }
        .publish(&env);
    }

    pub fn revoke_credential_root(env: Env, admin: Address, credential_root: BytesN<32>) {
        require_admin(&env, &admin);

        let mut record = get_credential_root_record(&env, &credential_root);
        record.active = false;
        env.storage()
            .persistent()
            .set(&DataKey::CredentialRoot(credential_root.clone()), &record);
        CredentialRootRevoked { credential_root }.publish(&env);
    }

    pub fn get_credential_root(
        env: Env,
        credential_root: BytesN<32>,
    ) -> Option<CredentialRootRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::CredentialRoot(credential_root))
    }

    pub fn revoke_issuer(env: Env, admin: Address, issuer: Address) {
        require_admin(&env, &admin);

        let mut record = get_issuer_record(&env, &issuer);
        record.active = false;
        env.storage()
            .persistent()
            .set(&DataKey::Issuer(issuer.clone()), &record);
        IssuerRevoked { issuer }.publish(&env);
    }

    // -----------------------------------------------------------------------
    // Expiration policy (#44)
    // -----------------------------------------------------------------------

    pub fn set_proof_ttl(env: Env, admin: Address, ttl_secs: u64) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::ProofTtl, &ttl_secs);
    }

    pub fn get_proof_ttl(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::ProofTtl)
            .unwrap_or(DEFAULT_PROOF_TTL_SECS)
    }

    // -----------------------------------------------------------------------
    // Timelocked verifier and policy administration (#86)
    // -----------------------------------------------------------------------

    pub fn propose_timelocked_action(
        env: Env,
        admin: Address,
        action: u32,
        target: Address,
        payload: BytesN<32>,
    ) -> u32 {
        require_admin(&env, &admin);
        if action == 0 || action > 4 {
            panic_with_error!(&env, RegistryError::InvalidProposalAction);
        }
        let pending_count: u32 = count_pending_proposals(&env);
        if pending_count >= MAX_PENDING_TIMELOCK_PROPOSALS {
            panic_with_error!(&env, RegistryError::ProposalsSaturated);
        }
        let now = env.ledger().timestamp();
        let min_delay = get_timelock_min_delay(&env);
        let proposal_id = next_proposal_id(&env);
        let proposal = TimelockProposal {
            action,
            proposer: admin.clone(),
            target,
            payload,
            created_at: now,
            min_execution_at: now.saturating_add(min_delay),
            executed: false,
            cancelled: false,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        TimelockProposalCreated {
            proposal_id,
            action,
            proposer: admin,
            target: proposal.target,
            created_at: now,
            min_execution_at: proposal.min_execution_at,
        }
        .publish(&env);
        proposal_id
    }

    pub fn cancel_timelocked_proposal(env: Env, admin: Address, proposal_id: u32) {
        require_admin(&env, &admin);
        let mut proposal = get_timelock_proposal_or_panic(&env, proposal_id);
        if proposal.executed {
            panic_with_error!(&env, RegistryError::ProposalAlreadyExecuted);
        }
        if proposal.cancelled {
            panic_with_error!(&env, RegistryError::AlreadyCancelled);
        }
        proposal.cancelled = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        TimelockProposalCancelled {
            proposal_id,
            action: proposal.action,
            cancelled_by: admin,
            cancelled_at: env.ledger().timestamp(),
        }
        .publish(&env);
    }

    pub fn execute_timelocked_proposal(env: Env, caller: Address, proposal_id: u32) {
        let proposal = get_timelock_proposal_or_panic(&env, proposal_id);
        if proposal.executed {
            panic_with_error!(&env, RegistryError::ProposalAlreadyExecuted);
        }
        if proposal.cancelled {
            panic_with_error!(&env, RegistryError::ProposalCancelled);
        }
        let now = env.ledger().timestamp();
        if now < proposal.min_execution_at {
            panic_with_error!(&env, RegistryError::ProposalNotReady);
        }
        let mut mutable_proposal = proposal.clone();
        mutable_proposal.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &mutable_proposal);
        caller.require_auth();
        dispatch_timelocked_action(&env, &proposal);
        TimelockProposalExecuted {
            proposal_id,
            action: proposal.action,
            executed_by: caller,
            executed_at: now,
        }
        .publish(&env);
    }

    /// Emergency path to execute an approved timelocked action, bypassing the
    /// delay. Renamed from `emergency_execute_timelocked_proposal`, which
    /// exceeded Soroban's 32-character function-name limit.
    pub fn emergency_execute_proposal(env: Env, admin: Address, proposal_id: u32) {
        require_admin(&env, &admin);
        let proposal = get_timelock_proposal_or_panic(&env, proposal_id);
        if proposal.executed {
            panic_with_error!(&env, RegistryError::ProposalAlreadyExecuted);
        }
        if proposal.cancelled {
            panic_with_error!(&env, RegistryError::ProposalCancelled);
        }
        let mut mutable_proposal = proposal.clone();
        mutable_proposal.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &mutable_proposal);
        dispatch_timelocked_action(&env, &proposal);
        TimelockEmergencyExec {
            proposal_id,
            action: proposal.action,
            executed_by: admin,
            executed_at: env.ledger().timestamp(),
        }
        .publish(&env);
    }

    pub fn get_timelock_proposal(env: Env, proposal_id: u32) -> Option<TimelockProposal> {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
    }

    pub fn get_timelock_proposal_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ProposalSeq)
            .unwrap_or(0u32)
    }

    pub fn get_timelock_min_delay_secs(env: Env) -> u64 {
        get_timelock_min_delay(&env)
    }

    pub fn set_timelock_min_delay_secs(env: Env, admin: Address, delay_secs: u64) {
        require_admin(&env, &admin);
        if delay_secs == 0 || delay_secs > MAX_TIMELOCK_MIN_DELAY_SECS {
            panic_with_error!(&env, RegistryError::InvalidTimelockDelay);
        }
        let previous = get_timelock_min_delay(&env);
        env.storage()
            .persistent()
            .set(&DataKey::TimelockMinDelay, &delay_secs);
        TimelockMinDelaySet {
            previous_delay: previous,
            new_delay: delay_secs,
            set_by: admin,
        }
        .publish(&env);
    }

    pub fn get_proof_status(env: Env, proof_id: BytesN<32>) -> ProofVerificationStatus {
        let record: Option<ProofRecord> = env.storage().persistent().get(&DataKey::Proof(proof_id));
        match record {
            None => ProofVerificationStatus::NotFound,
            Some(r) => {
                if r.status == STATUS_REVOKED {
                    return ProofVerificationStatus::Revoked;
                }
                if r.status == STATUS_EXPIRED {
                    return ProofVerificationStatus::Expired;
                }
                if r.expires_at > 0 && env.ledger().timestamp() > r.expires_at {
                    return ProofVerificationStatus::Expired;
                }
                ProofVerificationStatus::Valid
            }
        }
    }

    /// Return the human-readable verification status of multiple proofs in a single
    /// batch query, efficiently retrieving them without exceeding Soroban read budgets.
    ///
    /// The maximum number of proof IDs in a single batch is bounded (e.g. 100) to
    /// ensure the query always completes within resource limits.
    pub fn get_proof_statuses(
        env: Env,
        proof_ids: Vec<BytesN<32>>,
    ) -> Vec<ProofVerificationStatus> {
        let max_batch_size = 100;
        if proof_ids.len() > max_batch_size {
            panic_with_error!(&env, RegistryError::BatchTooLarge);
        }

        let mut statuses = Vec::new(&env);
        for proof_id in proof_ids.iter() {
            statuses.push_back(Self::get_proof_status(env.clone(), proof_id));
        }
        statuses
    }

    // -----------------------------------------------------------------------
    // Scope epoch management (scoped nullifier v1)
    // -----------------------------------------------------------------------

    /// Set the current epoch for a given scope identifier.
    ///
    /// When the admin advances the epoch for a scope, all proofs generated
    /// under the previous epoch for that scope will have stale epoch values
    /// and will be rejected by `register_anonymous_verified`.
    ///
    /// The scope is a 32-byte identifier derived from the scope string
    /// (e.g., SHA-256 hash mod BN254 field).  An empty (zero) scope
    /// represents the global/unscoped context.
    ///
    /// Only the registry admin may call this.
    pub fn set_scope_epoch(env: Env, admin: Address, scope: BytesN<32>, epoch: u64) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::ScopeEpoch(scope.clone()), &epoch);
        ScopeEpochSet { scope, epoch }.publish(&env);
    }

    /// Get the current epoch for a given scope.
    /// Returns `DEFAULT_SCOPE_EPOCH` (0) if no epoch has been set.
    pub fn get_scope_epoch(env: Env, scope: BytesN<32>) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::ScopeEpoch(scope))
            .unwrap_or(DEFAULT_SCOPE_EPOCH)
    }

    // -----------------------------------------------------------------------
    // Registration entry points
    // -----------------------------------------------------------------------

    pub fn register_anonymous(
        env: Env,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
        nullifier: BytesN<32>,
        credential_root: BytesN<32>,
        proof: Bytes,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER1_REGISTRATION);
        require_unique(&env, &proof_id, &video_hash);

        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateNullifier);
        }

        if !verify_demo_zk_boundary(&proof, &credential_root) {
            panic_with_error!(&env, RegistryError::InvalidProof);
        }
        require_active_credential_root(&env, &credential_root);

        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(nullifier.clone()), &true);

        let expires_at = compute_expires_at(&env);
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_SILENT_WITNESS,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: None,
            issuer: None,
            nullifier: Some(nullifier),
            batch_size: 0,
        };
        save_record(&env, &proof_id, record.clone(), None);
        record
    }

    pub fn register_anonymous_verified(
        env: Env,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
        public_inputs: Bytes,
        proof: Bytes,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER1_REGISTRATION);
        require_unique(&env, &proof_id, &video_hash);

        let input_len = public_inputs.len();

        let record = if input_len == SILENT_WITNESS_V2_INPUT_LEN {
            // v2 scoped nullifier path
            let parsed = parse_scoped_silent_witness_public_inputs(&env, &public_inputs);
            if parsed.video_hash != video_hash {
                panic_with_error!(&env, RegistryError::InvalidPublicInputs);
            }
            if parsed.domain_tag != expected_domain_tag(&env) {
                panic_with_error!(&env, RegistryError::DomainTagMismatch);
            }
            require_active_credential_root(&env, &parsed.credential_root);

            // Epoch validation: the proof's epoch must match the current epoch for its scope.
            let current_epoch = get_scope_epoch_raw(&env, &parsed.verifier_scope);
            if parsed.epoch != current_epoch {
                panic_with_error!(&env, RegistryError::StaleEpoch);
            }

            if env
                .storage()
                .persistent()
                .has(&DataKey::Nullifier(parsed.nullifier.clone()))
            {
                panic_with_error!(&env, RegistryError::DuplicateNullifier);
            }

            let verifier: Address = env
                .storage()
                .persistent()
                .get(&DataKey::Verifier)
                .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierNotSet));
            verify_external_proof(&env, &verifier, public_inputs, proof);

            env.storage()
                .persistent()
                .set(&DataKey::Nullifier(parsed.nullifier.clone()), &true);

            let expires_at = compute_expires_at(&env);
            save_record(
                &env,
                &proof_id,
                ProofRecord {
                    video_hash,
                    metadata_hash,
                    tier: TIER_SILENT_WITNESS,
                    status: STATUS_REGISTERED,
                    created_at: env.ledger().timestamp(),
                    expires_at,
                    source: None,
                    issuer: None,
                    nullifier: Some(parsed.nullifier),
                    batch_size: 0,
                },
                None,
            )
        } else if input_len == SILENT_WITNESS_V1_INPUT_LEN {
            // v1 legacy path (backward compatible)
            let parsed = parse_silent_witness_public_inputs(&env, &public_inputs);
            if parsed.video_hash != video_hash {
                panic_with_error!(&env, RegistryError::InvalidPublicInputs);
            }
            if parsed.domain_tag != expected_domain_tag(&env) {
                panic_with_error!(&env, RegistryError::DomainTagMismatch);
            }
            require_active_credential_root(&env, &parsed.credential_root);

            if env
                .storage()
                .persistent()
                .has(&DataKey::Nullifier(parsed.nullifier.clone()))
            {
                panic_with_error!(&env, RegistryError::DuplicateNullifier);
            }

            let verifier: Address = env
                .storage()
                .persistent()
                .get(&DataKey::Verifier)
                .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierNotSet));
            verify_external_proof(&env, &verifier, public_inputs, proof);

            env.storage()
                .persistent()
                .set(&DataKey::Nullifier(parsed.nullifier.clone()), &true);

            let expires_at = compute_expires_at(&env);
            save_record(
                &env,
                &proof_id,
                ProofRecord {
                    video_hash,
                    metadata_hash,
                    tier: TIER_SILENT_WITNESS,
                    status: STATUS_REGISTERED,
                    created_at: env.ledger().timestamp(),
                    expires_at,
                    source: None,
                    issuer: None,
                    nullifier: Some(parsed.nullifier),
                    batch_size: 0,
                },
                None,
            )
        } else {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        };

        record
    }

    // -----------------------------------------------------------------------
    // Batch aggregation registration
    // -----------------------------------------------------------------------

    /// Register multiple video hashes under the same credential using a
    /// single aggregated UltraHonk proof produced by the Silent Witness
    /// Aggregator circuit.
    ///
    /// # Arguments
    ///
    /// * `env` – Soroban environment
    /// * `batch_id` – Unique batch identifier (serves as the batch proof_id)
    /// * `metadata_hash` – Shared metadata hash for all elements in the batch
    /// * `public_inputs` – Aggregated public inputs (1 domain separator +
    ///   MAX_AGGREGATION_SIZE × 4 field elements; see AGGREGATED_PUBLIC_INPUT_SIZE)
    /// * `proof` – Aggregated UltraHonk proof bytes
    /// * `video_hashes` – Ordered list of video hashes in the batch (must
    ///   match the order in public_inputs)
    ///
    /// # Panics
    ///
    /// - `BatchSizeExceeded` if `video_hashes.len() > MAX_AGGREGATION_SIZE`
    /// - `BatchCountMismatch` if the number of video hashes doesn't match
    ///   the parsed batch count from public inputs
    /// - `InvalidPublicInputs` if the domain separator or public input layout
    ///   is wrong
    /// - `UnknownCredentialRoot` if the credential root is not registered
    /// - `RevokedCredentialRoot` if the credential root has been revoked
    /// - `DuplicateNullifier` if any nullifier in the batch was already consumed
    /// - `DuplicateProof` if the batch_id was already used
    /// - `DuplicateVideo` if any video hash was already registered
    /// - `VerifierNotSet` if no verifier contract is configured
    /// - `InvalidProof` if the external UltraHonk verifier rejects the proof
    pub fn register_batch_verified(
        env: Env,
        batch_id: BytesN<32>,
        metadata_hash: BytesN<32>,
        public_inputs: Bytes,
        proof: Bytes,
        video_hashes: Vec<BytesN<32>>,
    ) -> Vec<ProofRecord> {
        let batch_size = video_hashes.len();

        if batch_size == 0 || batch_size > MAX_AGGREGATION_SIZE {
            panic_with_error!(&env, RegistryError::BatchSizeExceeded);
        }

        // Parse the aggregated public inputs to extract domain separator and
        // element public inputs.
        let parsed = parse_aggregated_public_inputs(&env, &public_inputs, batch_size);

        // 1. Domain binding — must match the expected aggregation version tag.
        let expected_domain = BytesN::from_array(&env, &AGGREGATION_DOMAIN_SEPARATOR);
        if parsed.domain_separator != expected_domain {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        // 2. Verify the aggregated UltraHonk proof through the configured
        //    verifier contract.
        let verifier: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Verifier)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierNotSet));
        verify_external_proof(&env, &verifier, public_inputs, proof);

        // 3. Credential root must be registered and active.
        let shared_root = &parsed.elements[0].credential_root;
        require_active_credential_root(&env, shared_root);

        // 4. Verify batch integrity: credential roots must match and the
        //    video hashes must match the parsed public inputs.
        let expires_at = compute_expires_at(&env);
        let now = env.ledger().timestamp();
        let mut results: SorobanVec<ProofRecord> = SorobanVec::new(&env);
        // Track nullifiers and videos already seen inside this batch: storage
        // writes happen only after every check passes, so without this a
        // batch carrying the same nullifier twice would slip through.
        let mut seen_nullifiers: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
        let mut seen_videos: SorobanVec<BytesN<32>> = SorobanVec::new(&env);

        for i in 0..batch_size {
            let element = &parsed.elements[i as usize];

            // All credential roots in the batch must be identical.
            if element.credential_root != *shared_root {
                panic_with_error!(&env, RegistryError::BatchCredentialRootMismatch);
            }

            // Match video hash from the caller's input.
            let video_hash = video_hashes.get(i).unwrap_or_else(|| {
                panic_with_error!(&env, RegistryError::BatchCountMismatch);
            });
            if element.video_hash != video_hash {
                panic_with_error!(&env, RegistryError::InvalidPublicInputs);
            }

            // Derive a deterministic sub-proof_id for each element.
            let element_proof_id = derive_element_proof_id(&env, &batch_id, i);

            // Check proof_id uniqueness within the batch scope.
            if env
                .storage()
                .persistent()
                .has(&DataKey::Proof(element_proof_id.clone()))
            {
                panic_with_error!(&env, RegistryError::DuplicateProof);
            }

            // Check video hash uniqueness.
            if env
                .storage()
                .persistent()
                .has(&DataKey::Video(video_hash.clone()))
            {
                panic_with_error!(&env, RegistryError::DuplicateVideo);
            }

            // Check nullifier uniqueness, both against storage and against
            // the elements earlier in this same batch.
            if env
                .storage()
                .persistent()
                .has(&DataKey::Nullifier(element.nullifier.clone()))
            {
                panic_with_error!(&env, RegistryError::DuplicateNullifier);
            }
            for j in 0..seen_nullifiers.len() {
                if seen_nullifiers.get_unchecked(j) == element.nullifier {
                    panic_with_error!(&env, RegistryError::DuplicateNullifier);
                }
            }
            seen_nullifiers.push_back(element.nullifier.clone());
            seen_videos.push_back(video_hash.clone());
        }

        // All checks passed — persist every element.
        for i in 0..batch_size {
            let element = &parsed.elements[i as usize];
            let video_hash = video_hashes.get(i).unwrap();
            let element_proof_id = derive_element_proof_id(&env, &batch_id, i);

            // Consume the nullifier.
            env.storage()
                .persistent()
                .set(&DataKey::Nullifier(element.nullifier.clone()), &true);

            let record = save_record(
                &env,
                &element_proof_id,
                ProofRecord {
                    video_hash: video_hash.clone(),
                    metadata_hash: metadata_hash.clone(),
                    tier: TIER_SILENT_WITNESS,
                    status: STATUS_REGISTERED,
                    created_at: now,
                    expires_at,
                    source: None,
                    issuer: None,
                    nullifier: Some(element.nullifier.clone()),
                    batch_size,
                },
                None,
            );

            results.push_back(record);
        }

        // Emit a top-level batch event.
        BatchProofRegistered {
            batch_id,
            credential_root: shared_root.clone(),
            count: batch_size,
            tier: TIER_SILENT_WITNESS,
            status: STATUS_REGISTERED,
        }
        .publish(&env);

        results
    }

    pub fn register_source(
        env: Env,
        source: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER2_REGISTRATION);
        source.require_auth();
        require_unique(&env, &proof_id, &video_hash);

        let expires_at = compute_expires_at(&env);
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_CONSISTENT_SOURCE,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: Some(source.clone()),
            issuer: None,
            nullifier: None,
            batch_size: 0,
        };
        save_record(&env, &proof_id, record.clone(), Some(source.clone()));
        record
    }

    pub fn register_seal(
        env: Env,
        issuer: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER3_REGISTRATION);
        issuer.require_auth();
        require_unique(&env, &proof_id, &video_hash);

        let issuer_record = get_issuer_record(&env, &issuer);
        if !issuer_record.active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }

        let expires_at = compute_expires_at(&env);
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_PUBLIC_SEAL,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: None,
            issuer: Some(issuer.clone()),
            nullifier: None,
            batch_size: 0,
        };
        save_record(&env, &proof_id, record.clone(), Some(issuer.clone()));
        record
    }

    // -----------------------------------------------------------------------
    // Constrained issuer and source delegation (#192)
    // -----------------------------------------------------------------------

    /// Grant `delegate` a narrowly scoped, expiring authority to register on
    /// the caller's behalf.
    ///
    /// Requires the grantor's own signature — a delegate can never create or
    /// extend a delegation, which is what makes the mechanism non-transitive.
    ///
    /// `scope` is a non-empty subset of `DELEGATION_SCOPE_ALL`.
    /// `duration_secs` is non-zero and at most `MAX_DELEGATION_DURATION_SECS`.
    ///
    /// Idempotent: re-granting to an existing delegate overwrites that
    /// delegate's record — narrowing or widening scope, extending or shortening
    /// expiry — and does not consume another storage slot. Returns the epoch
    /// second at which the delegation lapses on its own.
    ///
    /// # Reverts
    ///
    /// - `SelfDelegation`              if `grantor == delegate`
    /// - `InvalidDelegationScope`      if `scope` is zero or has unknown bits
    /// - `InvalidDelegationDuration`   if `duration_secs` is zero or over the cap
    /// - `DelegationsSaturated`        if the grantor already holds the maximum
    pub fn grant_delegation(
        env: Env,
        grantor: Address,
        delegate: Address,
        scope: u32,
        duration_secs: u64,
    ) -> u64 {
        grantor.require_auth();

        if grantor == delegate {
            panic_with_error!(&env, RegistryError::SelfDelegation);
        }
        validate_delegation_scope(&env, scope);
        if duration_secs == 0 || duration_secs > MAX_DELEGATION_DURATION_SECS {
            panic_with_error!(&env, RegistryError::InvalidDelegationDuration);
        }

        let key = DataKey::Delegation(grantor.clone(), delegate.clone());
        let is_new = !env.storage().persistent().has(&key);

        if is_new {
            let count = delegation_count(&env, &grantor);
            if count >= MAX_DELEGATIONS_PER_GRANTOR {
                panic_with_error!(&env, RegistryError::DelegationsSaturated);
            }
            env.storage()
                .persistent()
                .set(&DataKey::DelegationCount(grantor.clone()), &(count + 1));
        }

        let granted_at = env.ledger().timestamp();
        let expires_at = granted_at.saturating_add(duration_secs);

        env.storage().persistent().set(
            &key,
            &DelegationRecord {
                grantor: grantor.clone(),
                delegate: delegate.clone(),
                scope,
                granted_at,
                expires_at,
            },
        );

        DelegationGranted {
            grantor,
            delegate,
            scope,
            granted_at,
            expires_at,
        }
        .publish(&env);

        expires_at
    }

    /// Revoke a delegation ahead of its expiry.
    ///
    /// Callable by the grantor (withdrawing authority it issued) or by the
    /// admin (incident response against a compromised delegate). Revoking a
    /// delegation that does not exist is a no-op rather than an error, so
    /// retries and concurrent revocations converge.
    pub fn revoke_delegation(env: Env, revoker: Address, grantor: Address, delegate: Address) {
        revoker.require_auth();

        if revoker != grantor {
            let admin: Address = env
                .storage()
                .persistent()
                .get(&DataKey::Admin)
                .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));
            if revoker != admin {
                panic_with_error!(&env, RegistryError::Unauthorized);
            }
        }

        let key = DataKey::Delegation(grantor.clone(), delegate.clone());
        if !env.storage().persistent().has(&key) {
            return;
        }

        env.storage().persistent().remove(&key);

        // Free the slot so the grantor can delegate to someone else. Saturating
        // so a corrupted counter can never underflow into a huge allowance.
        let count = delegation_count(&env, &grantor);
        env.storage().persistent().set(
            &DataKey::DelegationCount(grantor.clone()),
            &count.saturating_sub(1),
        );

        DelegationRevoked {
            grantor,
            delegate,
            revoked_by: revoker,
            revoked_at: env.ledger().timestamp(),
        }
        .publish(&env);
    }

    /// Read-only: the raw delegation record, if one is stored. A record past
    /// its `expires_at` is still returned so operators can see and prune it;
    /// use `is_delegation_active` to ask whether it currently grants anything.
    pub fn get_delegation(
        env: Env,
        grantor: Address,
        delegate: Address,
    ) -> Option<DelegationRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::Delegation(grantor, delegate))
    }

    /// Read-only: does a live delegation from `grantor` to `delegate` carry
    /// every bit of `scope`? Returns `false` for unknown, expired, or
    /// insufficiently scoped delegations rather than erroring, so callers can
    /// pre-flight without a trial transaction.
    pub fn is_delegation_active(env: Env, grantor: Address, delegate: Address, scope: u32) -> bool {
        if scope == 0 || scope & !DELEGATION_SCOPE_ALL != 0 {
            return false;
        }
        let record: Option<DelegationRecord> = env
            .storage()
            .persistent()
            .get(&DataKey::Delegation(grantor, delegate));
        match record {
            Some(record) => {
                env.ledger().timestamp() < record.expires_at && record.scope & scope == scope
            }
            None => false,
        }
    }

    /// Read-only: how many distinct delegates a grantor currently holds,
    /// against `MAX_DELEGATIONS_PER_GRANTOR`.
    pub fn get_delegation_count(env: Env, grantor: Address) -> u32 {
        delegation_count(&env, &grantor)
    }

    /// Register a Tier 2 consistent-source proof on `source`'s behalf.
    ///
    /// Authorizes the *delegate*, not the source: the source's key is never
    /// required at call time. The stored `ProofRecord` still names `source`,
    /// while the delegate is recorded in the proof's lifecycle history, so the
    /// audit trail distinguishes authority from actor.
    ///
    /// Subject to the same Tier 2 pause domain and uniqueness rules as
    /// `register_source`.
    pub fn register_source_delegated(
        env: Env,
        delegate: Address,
        source: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER2_REGISTRATION);
        delegate.require_auth();
        require_delegation(&env, &source, &delegate, DELEGATION_SCOPE_REGISTER_SOURCE);
        require_unique(&env, &proof_id, &video_hash);

        let expires_at = compute_expires_at(&env);
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_CONSISTENT_SOURCE,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: Some(source.clone()),
            issuer: None,
            nullifier: None,
            batch_size: 0,
        };
        save_record(&env, &proof_id, record.clone(), Some(delegate.clone()));
        DelegationUsed {
            grantor: source,
            delegate,
            scope: DELEGATION_SCOPE_REGISTER_SOURCE,
            proof_id,
        }
        .publish(&env);
        record
    }

    /// Register a Tier 3 public-seal proof on `issuer`'s behalf.
    ///
    /// The issuer must still be a registered, active issuer — a delegation
    /// never substitutes for issuer standing, it only lets someone else
    /// exercise it. Subject to the same Tier 3 pause domain and uniqueness
    /// rules as `register_seal`.
    pub fn register_seal_delegated(
        env: Env,
        delegate: Address,
        issuer: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER3_REGISTRATION);
        delegate.require_auth();
        require_delegation(&env, &issuer, &delegate, DELEGATION_SCOPE_REGISTER_SEAL);
        require_unique(&env, &proof_id, &video_hash);

        let issuer_record = get_issuer_record(&env, &issuer);
        if !issuer_record.active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }

        let expires_at = compute_expires_at(&env);
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_PUBLIC_SEAL,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: None,
            issuer: Some(issuer.clone()),
            nullifier: None,
            batch_size: 0,
        };
        save_record(&env, &proof_id, record.clone(), Some(delegate.clone()));
        DelegationUsed {
            grantor: issuer,
            delegate,
            scope: DELEGATION_SCOPE_REGISTER_SEAL,
            proof_id,
        }
        .publish(&env);
        record
    }

    pub fn revoke_proof(env: Env, admin: Address, proof_id: BytesN<32>) {
        require_admin(&env, &admin);

        let mut record = get_proof_record(&env, &proof_id);
        record.status = STATUS_REVOKED;
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &record);
        ProofRevoked {
            proof_id: proof_id.clone(),
            status: STATUS_REVOKED,
        }
        .publish(&env);
        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Revoked as u32,
            Some(admin),
            1,
        );
    }

    // -----------------------------------------------------------------------
    // Lifecycle history (#90)
    // -----------------------------------------------------------------------

    pub fn verify_proof(env: Env, actor: Address, proof_id: BytesN<32>, reason_code: u32) {
        require_admin(&env, &actor);

        let _record = get_proof_record(&env, &proof_id);

        if reason_code > 255 {
            panic_with_error!(&env, RegistryError::InvalidReasonCode);
        }

        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Verified as u32,
            Some(actor),
            reason_code,
        );
    }

    pub fn expire_proof(env: Env, admin: Address, proof_id: BytesN<32>, reason_code: u32) {
        require_admin(&env, &admin);

        let mut record = get_proof_record(&env, &proof_id);
        if record.status == STATUS_REVOKED {
            panic_with_error!(&env, RegistryError::Unauthorized);
        }
        if record.status == STATUS_EXPIRED {
            panic_with_error!(&env, RegistryError::AlreadyExpired);
        }

        record.status = STATUS_EXPIRED;
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &record);

        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Expired as u32,
            Some(admin),
            reason_code,
        );
    }

    pub fn correct_proof(
        env: Env,
        admin: Address,
        proof_id: BytesN<32>,
        new_metadata_hash: BytesN<32>,
        reason_code: u32,
    ) {
        require_admin(&env, &admin);

        let mut record = get_proof_record(&env, &proof_id);
        if record.metadata_hash == new_metadata_hash {
            panic_with_error!(&env, RegistryError::NoCorrectionChange);
        }

        record.metadata_hash = new_metadata_hash.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &record);

        // Keep the versioned envelope hash in sync when present (#317).
        let envelope_key = DataKey::MetadataEnvelope(proof_id.clone());
        if let Some(mut envelope) = env
            .storage()
            .persistent()
            .get::<DataKey, MetadataEnvelope>(&envelope_key)
        {
            envelope.metadata_hash = new_metadata_hash;
            envelope.bound_at = env.ledger().timestamp();
            env.storage().persistent().set(&envelope_key, &envelope);
        }

        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Corrected as u32,
            Some(admin),
            reason_code,
        );
    }

    pub fn get_proof_history_at(
        env: Env,
        proof_id: BytesN<32>,
        seq: u32,
    ) -> Option<ProofHistoryEntry> {
        let total: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProofHistorySeq(proof_id.clone()))
            .unwrap_or(0);

        if seq == 0 || seq > total {
            return None;
        }

        env.storage()
            .persistent()
            .get(&DataKey::ProofHistoryEntry(proof_id, seq))
    }

    pub fn get_proof_history_count(env: Env, proof_id: BytesN<32>) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ProofHistorySeq(proof_id))
            .unwrap_or(0)
    }


    // -----------------------------------------------------------------------
    // On-chain metadata envelope versioning (#317)
    // -----------------------------------------------------------------------

    /// Bind or upgrade a versioned metadata envelope for an existing proof.
    ///
    /// Compatible callers that only use `register_*` with a bare
    /// `metadata_hash` continue to work: `save_record` stamps V1 automatically.
    /// This entry point is for explicit V2 (or future) bindings and upgrades.
    ///
    /// Rules:
    /// - `version` must be in `1..=METADATA_ENVELOPE_VERSION_MAX`
    /// - `metadata_hash` must be non-zero and match the proof's stored hash
    /// - first bind may set any supported version
    /// - re-bind may only upgrade version (never downgrade)
    ///
    /// Auth: admin, or the proof's source/issuer when present.
    pub fn bind_metadata_envelope(
        env: Env,
        actor: Address,
        proof_id: BytesN<32>,
        version: u32,
        metadata_hash: BytesN<32>,
    ) -> MetadataEnvelope {
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Proof(proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::MetadataEnvelopeNotFound);
        }

        let proof = get_proof_record(&env, &proof_id);
        require_metadata_envelope_actor(&env, &actor, &proof);
        require_supported_metadata_envelope_version(&env, version);

        let zero = BytesN::from_array(&env, &[0u8; 32]);
        if metadata_hash == zero {
            panic_with_error!(&env, RegistryError::InvalidMetadataEnvelope);
        }
        if metadata_hash != proof.metadata_hash {
            panic_with_error!(&env, RegistryError::MetadataEnvelopeHashMismatch);
        }

        let key = DataKey::MetadataEnvelope(proof_id.clone());
        let previous: Option<MetadataEnvelope> = env.storage().persistent().get(&key);
        if let Some(ref prev) = previous {
            if version < prev.version {
                panic_with_error!(&env, RegistryError::UnsupportedMetadataEnvelopeVersion);
            }
            if version == prev.version && metadata_hash == prev.metadata_hash {
                // Idempotent no-op return.
                return prev.clone();
            }
            if version == prev.version && metadata_hash != prev.metadata_hash {
                // Same-version hash changes go through `correct_proof`.
                panic_with_error!(&env, RegistryError::MetadataEnvelopeHashMismatch);
            }
        }

        let bound_at = env.ledger().timestamp();
        let envelope = MetadataEnvelope {
            proof_id: proof_id.clone(),
            version,
            metadata_hash: metadata_hash.clone(),
            bound_at,
        };
        env.storage().persistent().set(&key, &envelope);

        if let Some(prev) = previous {
            if version > prev.version {
                MetadataEnvelopeUpgraded {
                    proof_id: proof_id.clone(),
                    previous: prev.version,
                    current: version,
                    metadata_hash: metadata_hash.clone(),
                }
                .publish(&env);
            }
        } else {
            MetadataEnvelopeBound {
                proof_id: proof_id.clone(),
                version,
                metadata_hash: metadata_hash.clone(),
                bound_at,
            }
            .publish(&env);
        }

        envelope
    }

    /// Return the versioned metadata envelope for `proof_id`, if stored.
    pub fn get_metadata_envelope(env: Env, proof_id: BytesN<32>) -> Option<MetadataEnvelope> {
        env.storage()
            .persistent()
            .get(&DataKey::MetadataEnvelope(proof_id))
    }

    /// Resolve the envelope version for a proof.
    ///
    /// Returns the stored envelope version when present; otherwise
    /// `METADATA_ENVELOPE_VERSION_DEFAULT` for proofs that exist without an
    /// explicit envelope row (pre-#317 / stamped callers). Returns `0` when
    /// the proof is unknown (callers must treat 0 as not-found).
    ///
    /// Name is capped at 32 chars by the SDK (`resolve_envelope_version`).
    pub fn resolve_envelope_version(env: Env, proof_id: BytesN<32>) -> u32 {
        if let Some(envelope) = env
            .storage()
            .persistent()
            .get::<DataKey, MetadataEnvelope>(&DataKey::MetadataEnvelope(proof_id.clone()))
        {
            return envelope.version;
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::Proof(proof_id))
        {
            return METADATA_ENVELOPE_VERSION_DEFAULT;
        }
        0
    }

    /// Whether `version` is accepted by this wasm build.
    ///
    /// Name is capped at 32 chars by the SDK.
    pub fn is_supported_envelope_version(_env: Env, version: u32) -> bool {
        version >= METADATA_ENVELOPE_V1 && version <= METADATA_ENVELOPE_VERSION_MAX
    }


    pub fn get_proof(env: Env, proof_id: BytesN<32>) -> Option<ProofRecord> {
        env.storage().persistent().get(&DataKey::Proof(proof_id))
    }

    pub fn get_by_video(env: Env, video_hash: BytesN<32>) -> Option<ProofRecord> {
        let proof_id: Option<BytesN<32>> =
            env.storage().persistent().get(&DataKey::Video(video_hash));
        proof_id.and_then(|id| env.storage().persistent().get(&DataKey::Proof(id)))
    }

    pub fn has_nullifier(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier))
    }

    pub fn get_issuer(env: Env, issuer: Address) -> Option<IssuerRecord> {
        env.storage().persistent().get(&DataKey::Issuer(issuer))
    }

    pub fn register_lineage(
        env: Env,
        actor: Address,
        parent_proof_ids: Vec<BytesN<32>>,
        manifest_digest: BytesN<32>,
        operation_type: Symbol,
        output_digest: BytesN<32>,
        depth: u32,
    ) -> LineageRecord {
        actor.require_auth();
        validate_lineage(&env, &parent_proof_ids, &output_digest, depth);

        let record = LineageRecord {
            parent_proof_ids: LineageChildren {
                ids: parent_proof_ids.clone(),
            },
            manifest_digest: manifest_digest.clone(),
            actor: actor.clone(),
            operation_type: operation_type.clone(),
            output_digest: output_digest.clone(),
            depth,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Lineage(output_digest.clone()), &record);
        record
    }

    pub fn get_lineage(env: Env, output_digest: BytesN<32>) -> Option<LineageRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::Lineage(output_digest))
    }

    // -----------------------------------------------------------------------
    // Revocation-witness root management (#98)
    // -----------------------------------------------------------------------

    pub fn set_revocation_root(env: Env, admin: Address, revocation_root: BytesN<32>) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::RevocationRoot, &revocation_root);
        RevocationRootSet { revocation_root }.publish(&env);
    }

    pub fn get_revocation_root(env: Env) -> Option<BytesN<32>> {
        env.storage().persistent().get(&DataKey::RevocationRoot)
    }

    /// Verify a non-revocation proof produced by the `revocation_witness`
    /// Noir circuit.
    ///
    /// The proof demonstrates that `credential_root` is **not** a member of
    /// the currently-published revocation tree (`revocation_root`) without
    /// revealing which revoked credentials exist or which identity is acting.
    ///
    /// # Public input layout (128 bytes, 4 x BN254 field elements)
    ///
    /// ```text
    /// [  0.. 32)  revocation_root   - must match the on-chain stored root
    /// [ 32.. 64)  nullifier         - one-use replay guard
    /// [ 64.. 96)  domain_separator  - must match REVOCATION_DOMAIN_SEPARATOR
    /// [ 96..128)  credential_root   - must be registered & active on-chain
    /// ```
    ///
    /// # Reverts
    ///
    /// - `NotInitialized`      if no revocation root has been published yet
    /// - `VerifierNotSet`       if no external verifier contract is configured
    /// - `InvalidPublicInputs`  if the domain separator or layout is wrong
    /// - `UnknownCredentialRoot` if the credential has not been registered
    /// - `RevokedCredentialRoot` if the credential root has been revoked
    /// - `DuplicateNullifier`   if this nullifier was already consumed
    /// - `InvalidProof`         if the external verifier rejects the proof
    pub fn check_non_revocation(env: Env, public_inputs: Bytes, proof: Bytes) {
        let parsed = parse_revocation_public_inputs(&env, &public_inputs);

        // 1. Domain binding - must match the expected version tag.
        let expected_domain = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);
        if parsed.domain_separator != expected_domain {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        // 2. Revocation root - must match the currently published root.
        let stored_root: BytesN<32> = env
            .storage()
            .persistent()
            .get(&DataKey::RevocationRoot)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));
        if parsed.revocation_root != stored_root {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        require_active_credential_root(&env, &parsed.credential_root);

        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(parsed.nullifier.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateNullifier);
        }

        let verifier: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Verifier)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierNotSet));
        verify_external_proof(&env, &verifier, public_inputs, proof);

        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(parsed.nullifier.clone()), &true);

        NonRevocationChecked {
            credential_root: parsed.credential_root,
            nullifier: parsed.nullifier,
            revocation_root: parsed.revocation_root,
        }
        .publish(&env);
    }

    // -----------------------------------------------------------------------
    // Scoped emergency pause controls (#87)
    // -----------------------------------------------------------------------

    /// Assign the address permitted to trigger emergency pauses without
    /// holding the admin key. Admin-only. Pass the admin's own address to
    /// revoke the guardian role.
    pub fn set_guardian(env: Env, admin: Address, guardian: Address) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::Guardian, &guardian);
        GuardianSet { guardian }.publish(&env);
    }

    /// The currently configured guardian, if any.
    pub fn get_guardian(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Guardian)
    }

    /// Pause one or more registration domains (`PAUSE_DOMAIN_*`, or their
    /// bitwise-OR combination) for `duration_secs`. Callable by the admin or
    /// the guardian; the admin is capped at `MAX_PAUSE_DURATION_SECS`, the
    /// guardian at `MAX_GUARDIAN_PAUSE_DURATION_SECS`. Re-pausing an
    /// already-paused domain extends (overwrites) its expiry rather than
    /// erroring, so retries are idempotent. Reads and non-registration admin
    /// entry points are never affected. Returns the epoch-second timestamp
    /// at which the pause auto-expires.
    pub fn pause(env: Env, caller: Address, domain: u32, duration_secs: u64) -> u64 {
        validate_domain(&env, domain);
        let is_admin = require_pauser(&env, &caller);
        let max_duration = if is_admin {
            MAX_PAUSE_DURATION_SECS
        } else {
            MAX_GUARDIAN_PAUSE_DURATION_SECS
        };
        if duration_secs == 0 || duration_secs > max_duration {
            panic_with_error!(&env, RegistryError::InvalidPauseDuration);
        }

        let paused_at = env.ledger().timestamp();
        let expires_at = paused_at.saturating_add(duration_secs);

        for bit in domain_bits(domain) {
            env.storage().persistent().set(
                &DataKey::Pause(bit),
                &PauseRecord {
                    paused_by: caller.clone(),
                    paused_at,
                    expires_at,
                },
            );
        }

        DomainPaused {
            domain,
            paused_by: caller,
            paused_at,
            expires_at,
        }
        .publish(&env);

        expires_at
    }

    /// Lift a pause early. Admin-only — a guardian can raise the alarm but
    /// only the admin can stand it down before the bounded expiry. Unpausing
    /// a domain that is not currently stored as paused is a no-op.
    pub fn unpause(env: Env, admin: Address, domain: u32) {
        validate_domain(&env, domain);
        require_admin(&env, &admin);

        let unpaused_at = env.ledger().timestamp();
        let mut changed = false;
        for bit in domain_bits(domain) {
            if env.storage().persistent().has(&DataKey::Pause(bit)) {
                env.storage().persistent().remove(&DataKey::Pause(bit));
                changed = true;
            }
        }

        if changed {
            DomainUnpaused {
                domain,
                unpaused_by: admin,
                unpaused_at,
            }
            .publish(&env);
        }
    }

    /// Read-only: is any bit of `domain` currently paused (i.e. has an
    /// unexpired pause record)? A domain past its `expires_at` is treated as
    /// unpaused even if a stale record has not yet been cleared.
    pub fn is_paused(env: Env, domain: u32) -> bool {
        validate_domain(&env, domain);
        let now = env.ledger().timestamp();
        domain_bits(domain).any(|bit| domain_is_paused(&env, bit, now))
    }

    /// Read-only: the raw pause record for a single domain bit, if one is
    /// currently stored (including a stale record past its `expires_at`
    /// that has not yet been cleared by `unpause`).
    pub fn get_pause_state(env: Env, domain: u32) -> Option<PauseRecord> {
        validate_single_domain(&env, domain);
        env.storage().persistent().get(&DataKey::Pause(domain))
    }

    // -----------------------------------------------------------------------
    // Cross-layer verifier-input conformance
    // -----------------------------------------------------------------------

    /// Classify verifier material against the canonical `hpx-vi/1` codec.
    ///
    /// Read-only, side-effect free, and bounded: the work is O(1) in the frame
    /// size and no storage is touched, so it is safe to expose publicly and
    /// safe to call while any domain is paused.
    ///
    /// `schema_id` is [`SCHEMA_ID_SILENT_WITNESS`] or
    /// [`SCHEMA_ID_REVOCATION_WITNESS`]. `proof_len` is the length of the proof
    /// blob the caller intends to submit — passed as a length rather than the
    /// blob itself so classification never transports proof material.
    ///
    /// Returns [`verifier_inputs::ACCEPTED_CODE`] (`0`) when the material is
    /// canonical, otherwise the stable [`RejectCode::as_code`] value. This is
    /// the on-chain half of the cross-layer conformance corpus in
    /// `zk/vectors/verifier_conformance_v1.json`.
    ///
    /// Compatibility: this entry point is purely additive. The registration
    /// paths still apply the v1-lenient rules described in
    /// `docs/zk-conformance-vectors.md`; promoting the codec to enforcement is
    /// a separate, versioned migration.
    pub fn classify_public_inputs(
        env: Env,
        schema_id: u32,
        public_inputs: Bytes,
        proof_len: u32,
    ) -> u32 {
        // Schema dispatch precedes the length check, matching the Python and
        // TypeScript layers: an unrecognised schema is reported as such even
        // when the frame is also the wrong length.
        if schema_id != SCHEMA_ID_SILENT_WITNESS && schema_id != SCHEMA_ID_REVOCATION_WITNESS {
            return RejectCode::UnknownSchema.as_code();
        }

        // Each schema has its own canonical frame length: silent witness is
        // 160 bytes (5 field words), revocation witness is 128 bytes (4).
        let expected_len = if schema_id == SCHEMA_ID_SILENT_WITNESS {
            verifier_inputs::SILENT_WITNESS_PUBLIC_INPUTS_LEN
        } else {
            verifier_inputs::REVOCATION_PUBLIC_INPUTS_LEN
        };
        if public_inputs.len() as usize != expected_len {
            return RejectCode::Length.as_code();
        }

        let mut frame = [0u8; PUBLIC_INPUTS_LEN];
        // copy_into_slice requires an exactly-sized destination, so slice the
        // input to its canonical length and copy into a matching subslice.
        let head = public_inputs.slice(0..(expected_len as u32));
        head.copy_into_slice(&mut frame[..expected_len]);

        let parsed = if schema_id == SCHEMA_ID_SILENT_WITNESS {
            verifier_inputs::parse_silent_witness(
                &frame,
                &verifier_inputs::SILENT_WITNESS_DOMAIN_TAG_BE,
            )
            .map(|_| ())
        } else {
            // The revocation frame occupies the first 128 bytes of `frame`.
            let rev_frame: &[u8; verifier_inputs::REVOCATION_PUBLIC_INPUTS_LEN] = frame
                [..verifier_inputs::REVOCATION_PUBLIC_INPUTS_LEN]
                .try_into()
                .expect("128-byte revocation frame");
            verifier_inputs::parse_revocation_witness(rev_frame, &REVOCATION_DOMAIN_SEPARATOR)
                .map(|_| ())
        };

        if let Err(code) = parsed {
            return code.as_code();
        }

        match verifier_inputs::check_proof_bounds(proof_len) {
            Ok(()) => verifier_inputs::ACCEPTED_CODE,
            Err(code) => code.as_code(),
        }
    }

    // -----------------------------------------------------------------------
    // Schema management (issuer-certified attribute schemas)
    // -----------------------------------------------------------------------

    pub fn add_schema(
        env: Env,
        admin: Address,
        schema_hash: BytesN<32>,
        issuer_namespace: BytesN<32>,
        version: u32,
        attribute_count: u32,
    ) {
        require_admin(&env, &admin);

        if env
            .storage()
            .persistent()
            .has(&DataKey::Schema(schema_hash.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateProof);
        }

        if attribute_count == 0 || attribute_count > 16 {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        let created_at = env.ledger().timestamp();
        env.storage().persistent().set(
            &DataKey::Schema(schema_hash.clone()),
            &SchemaRecord {
                schema_hash: schema_hash.clone(),
                issuer_namespace: issuer_namespace.clone(),
                version,
                active: true,
                attribute_count,
                created_at,
            },
        );
        SchemaAdded {
            schema_hash,
            issuer_namespace,
            version,
            attribute_count,
        }
        .publish(&env);
    }

    pub fn deprecate_schema(env: Env, admin: Address, schema_hash: BytesN<32>) {
        require_admin(&env, &admin);

        let mut record = get_schema_record(&env, &schema_hash);
        record.active = false;
        env.storage()
            .persistent()
            .set(&DataKey::Schema(schema_hash.clone()), &record);
        SchemaDeprecated { schema_hash }.publish(&env);
    }

    pub fn get_schema(env: Env, schema_hash: BytesN<32>) -> Option<SchemaRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::Schema(schema_hash))
    }

    // -----------------------------------------------------------------------
    // Selective disclosure verification
    // -----------------------------------------------------------------------

    pub fn verify_selective_disclosure(env: Env, public_inputs: Bytes, proof: Bytes) {
        let parsed = parse_selective_disclosure_inputs(&env, &public_inputs);

        if parsed.circuit_version != CURRENT_SELECTIVE_DISCLOSURE_VERSION as u32 {
            panic_with_error!(&env, RegistryError::SchemaVersionMismatch);
        }

        let schema = get_schema_record(&env, &parsed.schema_hash);
        if !schema.active {
            panic_with_error!(&env, RegistryError::InactiveSchema);
        }

        if schema.version != parsed.schema_version {
            panic_with_error!(&env, RegistryError::SchemaVersionMismatch);
        }

        if schema.issuer_namespace != parsed.issuer_namespace {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        require_active_credential_root(&env, &parsed.credential_root);

        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(parsed.nullifier.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateNullifier);
        }

        let verifier: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Verifier)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierNotSet));
        verify_external_proof(&env, &verifier, public_inputs, proof);

        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(parsed.nullifier.clone()), &true);

        SelectiveDisclosureVerified {
            schema_hash: parsed.schema_hash,
            credential_root: parsed.credential_root,
            nullifier: parsed.nullifier,
            evidence_digest: parsed.evidence_digest,
        }
        .publish(&env);
    }

    // -----------------------------------------------------------------------
    // Dispute / correction state machine (#dispute)
    // -----------------------------------------------------------------------

    /// Open a new dispute against a registered proof.
    ///
    /// # Parameters
    /// - `reporter`:        The reporter's address (requires auth; proves liveness).
    /// - `reporter_hash`:   Privacy-safe commitment H(reporter_address || proof_id),
    ///   computed off-chain by the reporter. The raw reporter address is never
    ///   stored in contract state or events.
    /// - `dispute_id`:      Caller-chosen 32-byte unique identifier.
    /// - `proof_id`:        The proof being challenged.
    /// - `reason`:          Categorised dispute reason.
    /// - `commitment_hash`: Off-chain commitment to the reporter's submission.
    ///
    /// # Guards
    /// - Proof must exist.
    /// - `dispute_id` must not already be used.
    /// - Proof must have fewer than `MAX_OPEN_DISPUTES_PER_PROOF` open disputes.
    /// - Reporter must not be on cooldown for this proof.
    pub fn open_dispute(
        env: Env,
        reporter: Address,
        reporter_hash: BytesN<32>,
        dispute_id: BytesN<32>,
        proof_id: BytesN<32>,
        reason: DisputeReason,
        commitment_hash: BytesN<32>,
    ) -> DisputeRecord {
        reporter.require_auth();

        // 1. Proof must exist.
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Proof(proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::DisputeNotFound);
        }

        // 2. dispute_id must be fresh.
        if env
            .storage()
            .persistent()
            .has(&DataKey::Dispute(dispute_id.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateProof);
        }

        // 3. Cap open disputes per proof.
        let open_count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProofOpenDisputeCount(proof_id.clone()))
            .unwrap_or(0u32);
        if open_count >= MAX_OPEN_DISPUTES_PER_PROOF {
            panic_with_error!(&env, RegistryError::TooManyOpenDisputes);
        }

        // 4. Reporter cooldown (keyed by the privacy-safe reporter_hash).
        let cooldown_key = DataKey::ReporterCooldown(reporter_hash.clone());
        let last_open: u64 = env
            .storage()
            .persistent()
            .get(&cooldown_key)
            .unwrap_or(0u64);
        let now = env.ledger().timestamp();
        if last_open > 0 && now.saturating_sub(last_open) < REPORTER_COOLDOWN_SECS {
            panic_with_error!(&env, RegistryError::ReporterOnCooldown);
        }

        // 5. Persist cooldown timestamp.
        env.storage().persistent().set(&cooldown_key, &now);

        // 6. Compute deadlines.
        let respond_deadline = now.saturating_add(RESPOND_DEADLINE_SECS);

        // 7. Build and store the dispute record.
        let record = DisputeRecord {
            dispute_id: dispute_id.clone(),
            proof_id: proof_id.clone(),
            reason,
            reporter_hash: reporter_hash.clone(),
            commitment_hash: commitment_hash.clone(),
            status: DisputeStatus::Open,
            opened_at: now,
            respond_deadline,
            resolve_deadline: 0,
            response_commitment: None,
            resolved_at: 0,
            superseded_by: None,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Dispute(dispute_id.clone()), &record);

        // 8. Increment open-dispute counter.
        env.storage().persistent().set(
            &DataKey::ProofOpenDisputeCount(proof_id.clone()),
            &(open_count + 1),
        );

        // 9. Emit event.
        DisputeOpened {
            dispute_id,
            proof_id,
            reason,
            reporter_hash,
            commitment_hash,
            respond_deadline,
        }
        .publish(&env);

        record
    }

    /// Submit a response commitment to an open dispute.
    ///
    /// Only the issuer (Tier 3) or source (Tier 2) of the disputed proof may
    /// respond. Tier 1 (Silent Witness) proofs have no on-chain identity, so
    /// the admin acts as the sole responder for anonymous proofs.
    ///
    /// # Guards
    /// - Dispute must be in `Open` state.
    /// - Must be within `respond_deadline`.
    /// - Caller must be the issuer, source, or (for anonymous proofs) admin.
    pub fn respond_dispute(
        env: Env,
        responder: Address,
        dispute_id: BytesN<32>,
        response_commitment: BytesN<32>,
    ) -> DisputeRecord {
        responder.require_auth();

        let mut record = get_dispute_record(&env, &dispute_id);

        // Must be Open.
        if record.status != DisputeStatus::Open {
            panic_with_error!(&env, RegistryError::InvalidDisputeTransition);
        }

        let now = env.ledger().timestamp();

        // Must be within respond_deadline.
        if now > record.respond_deadline {
            panic_with_error!(&env, RegistryError::DisputeWindowExpired);
        }

        // Authorise: issuer, source, or admin.
        let proof: ProofRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Proof(record.proof_id.clone()))
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::DisputeNotFound));

        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));

        let is_authorised = match (proof.issuer.as_ref(), proof.source.as_ref()) {
            (Some(issuer), _) => &responder == issuer || &responder == &admin,
            (_, Some(source)) => &responder == source || &responder == &admin,
            _ => &responder == &admin, // Tier 1: admin only
        };

        if !is_authorised {
            panic_with_error!(&env, RegistryError::UnauthorizedResponder);
        }

        // Transition -> Responded.
        record.status = DisputeStatus::Responded;
        record.response_commitment = Some(response_commitment.clone());
        record.resolve_deadline = now.saturating_add(RESOLVE_DEADLINE_SECS);

        env.storage()
            .persistent()
            .set(&DataKey::Dispute(dispute_id.clone()), &record);

        DisputeResponded {
            dispute_id,
            proof_id: record.proof_id.clone(),
            response_commitment,
            resolve_deadline: record.resolve_deadline,
        }
        .publish(&env);

        record
    }

    /// Resolve a responded dispute (admin only).
    ///
    /// Resolution indicates that the admin has reviewed both the dispute and
    /// the response commitments and has taken (or noted) any appropriate
    /// corrective action. The original proof record is **not** modified.
    ///
    /// # Guards
    /// - Dispute must be in `Responded` state.
    /// - Must be within `resolve_deadline`.
    pub fn resolve_dispute(env: Env, admin: Address, dispute_id: BytesN<32>) -> DisputeRecord {
        require_admin(&env, &admin);

        let mut record = get_dispute_record(&env, &dispute_id);

        // Must be Responded.
        if record.status != DisputeStatus::Responded {
            panic_with_error!(&env, RegistryError::InvalidDisputeTransition);
        }

        let now = env.ledger().timestamp();

        if now > record.resolve_deadline {
            panic_with_error!(&env, RegistryError::DisputeWindowExpired);
        }

        // Transition -> Resolved.
        record.status = DisputeStatus::Resolved;
        record.resolved_at = now;

        env.storage()
            .persistent()
            .set(&DataKey::Dispute(dispute_id.clone()), &record);

        // Decrement open-dispute counter.
        decrement_open_dispute_count(&env, &record.proof_id);

        DisputeResolved {
            dispute_id,
            proof_id: record.proof_id.clone(),
            resolved_at: now,
        }
        .publish(&env);

        record
    }

    /// Dismiss a dispute (admin only).
    ///
    /// Dismissal is valid from both `Open` and `Responded` states. A dismissed
    /// dispute is permanently closed with no corrective action.
    pub fn dismiss_dispute(env: Env, admin: Address, dispute_id: BytesN<32>) -> DisputeRecord {
        require_admin(&env, &admin);

        let mut record = get_dispute_record(&env, &dispute_id);

        // Must be non-terminal.
        match record.status {
            DisputeStatus::Open | DisputeStatus::Responded => {}
            _ => panic_with_error!(&env, RegistryError::DisputeAlreadyClosed),
        }

        let now = env.ledger().timestamp();

        // Transition -> Dismissed.
        record.status = DisputeStatus::Dismissed;
        record.resolved_at = now;

        env.storage()
            .persistent()
            .set(&DataKey::Dispute(dispute_id.clone()), &record);

        // Decrement open-dispute counter.
        decrement_open_dispute_count(&env, &record.proof_id);

        DisputeDismissed {
            dispute_id,
            proof_id: record.proof_id.clone(),
            resolved_at: now,
        }
        .publish(&env);

        record
    }

    /// Supersede a disputed proof by linking a corrected proof (admin only).
    ///
    /// This marks the dispute as `Superseded` and records the correcting proof
    /// ID. The original disputed proof is **not** revoked - callers should use
    /// `revoke_proof` separately if revocation is also desired.
    ///
    /// # Guards
    /// - Dispute must be in `Open` or `Responded` state.
    /// - `superseding_proof_id` must exist in the registry.
    /// - It must not equal the disputed `proof_id` (trivial cycle).
    /// - It must not already point back to the disputed proof (depth-1 cycle).
    pub fn supersede_dispute(
        env: Env,
        admin: Address,
        dispute_id: BytesN<32>,
        superseding_proof_id: BytesN<32>,
    ) -> DisputeRecord {
        require_admin(&env, &admin);

        let mut record = get_dispute_record(&env, &dispute_id);

        // Must be non-terminal.
        match record.status {
            DisputeStatus::Open | DisputeStatus::Responded => {}
            _ => panic_with_error!(&env, RegistryError::DisputeAlreadyClosed),
        }

        // Superseding proof must exist.
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Proof(superseding_proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::DisputeNotFound);
        }

        // Trivial self-cycle.
        if superseding_proof_id == record.proof_id {
            panic_with_error!(&env, RegistryError::DisputeCyclicSupersession);
        }

        // Depth-1 cycle guard via the compact reverse index.
        if check_supersession_cycle(&env, &record.proof_id, &superseding_proof_id) {
            panic_with_error!(&env, RegistryError::DisputeCyclicSupersession);
        }

        let now = env.ledger().timestamp();

        // Transition -> Superseded.
        record.status = DisputeStatus::Superseded;
        record.superseded_by = Some(superseding_proof_id.clone());
        record.resolved_at = now;

        env.storage()
            .persistent()
            .set(&DataKey::Dispute(dispute_id.clone()), &record);

        // Record the reverse supersession direction for cycle detection.
        record_supersession_direction(&env, &record.proof_id, &superseding_proof_id);

        // Decrement open-dispute counter.
        decrement_open_dispute_count(&env, &record.proof_id);

        DisputeSuperseded {
            dispute_id,
            proof_id: record.proof_id.clone(),
            superseded_by: superseding_proof_id,
            resolved_at: now,
        }
        .publish(&env);

        record
    }

    /// Retrieve a dispute record by its dispute_id.
    pub fn get_dispute(env: Env, dispute_id: BytesN<32>) -> Option<DisputeRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::Dispute(dispute_id))
    }

    /// Return the number of currently Open disputes for a given proof.
    pub fn get_open_dispute_count(env: Env, proof_id: BytesN<32>) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ProofOpenDisputeCount(proof_id))
            .unwrap_or(0u32)
    }

    // -----------------------------------------------------------------------
    // Threshold Seal Policy (#124, restored) — authorization surface
    // -----------------------------------------------------------------------
    //
    // Trust boundary: policy administration is admin-only; approval authority
    // is strictly the policy signer set ∩ active issuers; explicit
    // finalization carries no special authority but cannot exceed what the
    // recorded approvals prove.

    /// Create a versioned m-of-n threshold seal policy.
    ///
    /// `required_approvals` (m) must be > 0 and ≤ `max_signers` (n).
    /// `max_signers` must be ≤ `MAX_SIGNERS` (16).
    /// `approval_ttl` is per-approval TTL in seconds; `0` uses the default.
    /// `policy_expiry` is an absolute epoch-second deadline; `0` means no expiry.
    ///
    /// Cancels any previously-active policy by incrementing the version
    /// counter. Only the registry admin may call this.
    pub fn create_seal_policy(
        env: Env,
        admin: Address,
        required_approvals: u32,
        max_signers: u32,
        approval_ttl: u64,
        policy_expiry: u64,
    ) -> u32 {
        require_admin(&env, &admin);

        if required_approvals == 0 || required_approvals > max_signers {
            panic_with_error!(&env, RegistryError::InvalidThreshold);
        }
        if max_signers > MAX_SIGNERS {
            panic_with_error!(&env, RegistryError::SignerSetTooLarge);
        }

        let version: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::SealPolicyCount)
            .unwrap_or(0u32)
            + 1;
        env.storage()
            .persistent()
            .set(&DataKey::SealPolicyCount, &version);

        let effective_ttl = if approval_ttl == 0 {
            DEFAULT_APPROVAL_TTL_SECS
        } else {
            approval_ttl
        };

        env.storage().persistent().set(
            &DataKey::SealPolicy(version),
            &SealPolicy {
                version,
                required_approvals,
                max_signers,
                approval_ttl: effective_ttl,
                expires_at: policy_expiry,
                status: STATUS_POLICY_ACTIVE,
            },
        );

        // Cancel any previously active policy
        if version > 1 {
            let prev_version = version - 1;
            let mut prev_policy = get_seal_policy(&env, &prev_version);
            if prev_policy.status == STATUS_POLICY_ACTIVE {
                prev_policy.status = STATUS_POLICY_CANCELLED;
                env.storage()
                    .persistent()
                    .set(&DataKey::SealPolicy(prev_version), &prev_policy);
                SealPolicyCancelled {
                    version: prev_version,
                }
                .publish(&env);
            }
        }

        env.storage().persistent().set(
            &DataKey::SealPolicySigners(version),
            &SorobanVec::<Address>::new(&env),
        );

        SealPolicyCreated {
            version,
            required_approvals,
            max_signers,
        }
        .publish(&env);

        version
    }

    /// Add an issuer address to a seal policy's signer set.
    ///
    /// The signer must be an active issuer in the registry. The policy must be
    /// active and its signer set must not exceed `max_signers`. Adding a
    /// signer that is already present is a no-op. Only the registry admin may
    /// call this.
    pub fn add_seal_policy_signer(env: Env, admin: Address, policy_version: u32, signer: Address) {
        require_admin(&env, &admin);

        let policy = get_seal_policy_active(&env, &policy_version);

        if !env
            .storage()
            .persistent()
            .has(&DataKey::Issuer(signer.clone()))
        {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }
        if !get_issuer_record(&env, &signer).active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }

        let signers: SorobanVec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::SealPolicySigners(policy_version))
            .unwrap_or_else(|| SorobanVec::new(&env));

        // Idempotent: adding an existing signer is a no-op, so re-adding a
        // member never trips the capacity bound.
        for i in 0..signers.len() {
            let s: Address = signers.get_unchecked(i);
            if s == signer {
                return;
            }
        }

        if signers.len() >= policy.max_signers {
            panic_with_error!(&env, RegistryError::SignerSetTooLarge);
        }

        let mut signers = signers;
        signers.push_back(signer);
        env.storage()
            .persistent()
            .set(&DataKey::SealPolicySigners(policy_version), &signers);
    }

    /// Remove an issuer from a seal policy's signer set.
    ///
    /// Removing a signer that is not present is a no-op. Only the registry
    /// admin may call this.
    pub fn remove_seal_policy_signer(
        env: Env,
        admin: Address,
        policy_version: u32,
        signer: Address,
    ) {
        require_admin(&env, &admin);

        let _policy = get_seal_policy_active(&env, &policy_version);

        let signers: SorobanVec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::SealPolicySigners(policy_version))
            .unwrap_or_else(|| SorobanVec::new(&env));

        let mut new_signers = SorobanVec::<Address>::new(&env);
        for i in 0..signers.len() {
            let s: Address = signers.get_unchecked(i);
            if s != signer {
                new_signers.push_back(s);
            }
        }

        env.storage()
            .persistent()
            .set(&DataKey::SealPolicySigners(policy_version), &new_signers);
    }

    /// Cancel an active seal policy. Only the registry admin may call this.
    pub fn cancel_seal_policy(env: Env, admin: Address, policy_version: u32) {
        require_admin(&env, &admin);

        let mut policy = get_seal_policy_active(&env, &policy_version);
        policy.status = STATUS_POLICY_CANCELLED;
        env.storage()
            .persistent()
            .set(&DataKey::SealPolicy(policy_version), &policy);

        SealPolicyCancelled {
            version: policy_version,
        }
        .publish(&env);
    }

    /// Record a signer's approval for a proof under the active seal policy.
    ///
    /// - The signer must be an active issuer and a member of the active
    ///   policy's signer set.
    /// - The approval is idempotent per (proof_id, signer): a repeat approval
    ///   returns `false` and changes nothing.
    /// - The proof must not already be registered.
    /// - The approval expires after `policy.approval_ttl` seconds.
    ///
    /// If this approval causes the threshold to be met, the proof is
    /// finalized atomically in the same transaction and `true` is returned.
    pub fn approve_seal(
        env: Env,
        signer: Address,
        proof_id: BytesN<32>,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
    ) -> bool {
        signer.require_auth();

        let policy_version = get_active_policy_version(&env);
        let policy = get_seal_policy_active(&env, &policy_version);

        // Authorization order matters: signer-set membership is the primary
        // authorization boundary (an address outside the set is rejected as
        // `UnknownPolicySigner`), then issuer liveness (a revoked signer is
        // rejected as `UnknownIssuer`).
        require_policy_signer(&env, policy_version, &signer);

        let record = get_issuer_record(&env, &signer);
        if !record.active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }

        // Idempotent before the finalized check so a duplicate approval from
        // the same signer stays idempotent even after finalization, and a
        // distinct signer learns the proof is sealed via `AlreadyFinalized`.
        if env
            .storage()
            .persistent()
            .has(&DataKey::SealApproval(proof_id.clone(), signer.clone()))
        {
            return false;
        }

        if env
            .storage()
            .persistent()
            .has(&DataKey::Proof(proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::AlreadyFinalized);
        }

        let now = env.ledger().timestamp();
        env.storage().persistent().set(
            &DataKey::SealApproval(proof_id.clone(), signer.clone()),
            &SealApproval {
                proof_id: proof_id.clone(),
                policy_version,
                signer: signer.clone(),
                approved_at: now,
            },
        );

        SealApprovalRecorded {
            proof_id: proof_id.clone(),
            signer,
            policy_version,
        }
        .publish(&env);

        // Finalize atomically when the threshold is met.
        let approvals = count_active_approvals(&env, &proof_id, &policy);
        if approvals >= policy.required_approvals {
            finalize_threshold_seal(&env, &proof_id, &video_hash, &metadata_hash, &policy);
            return true;
        }

        false
    }

    /// Atomically finalize a threshold seal when enough approvals exist.
    ///
    /// This can be called explicitly by any caller after sufficient approvals
    /// are collected, or is called automatically by `approve_seal`. It carries
    /// no special authority: it cannot finalize beyond what the recorded,
    /// unexpired approvals from active issuers prove.
    pub fn finalize_seal(
        env: Env,
        proof_id: BytesN<32>,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
    ) -> ProofRecord {
        let policy_version = get_active_policy_version(&env);
        let policy = get_seal_policy_active(&env, &policy_version);

        if env
            .storage()
            .persistent()
            .has(&DataKey::Proof(proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::AlreadyFinalized);
        }

        let approvals = count_active_approvals(&env, &proof_id, &policy);
        if approvals < policy.required_approvals {
            panic_with_error!(&env, RegistryError::ThresholdNotMet);
        }

        finalize_threshold_seal(&env, &proof_id, &video_hash, &metadata_hash, &policy)
    }

    /// Return the current active seal-policy version, if any.
    pub fn get_active_seal_policy(env: Env) -> Option<SealPolicy> {
        let version: Option<u32> = env.storage().persistent().get(&DataKey::SealPolicyCount);
        let version = version?;
        let policy: Option<SealPolicy> = env
            .storage()
            .persistent()
            .get(&DataKey::SealPolicy(version));
        let policy = policy?;
        if policy.status != STATUS_POLICY_ACTIVE {
            return None;
        }
        if policy.expires_at > 0 && env.ledger().timestamp() > policy.expires_at {
            return None;
        }
        Some(policy)
    }

    /// Return a specific seal policy by version, regardless of status.
    pub fn get_seal_policy_by_version(env: Env, version: u32) -> Option<SealPolicy> {
        env.storage()
            .persistent()
            .get(&DataKey::SealPolicy(version))
    }

    /// Return the number of approvals currently recorded for a proof under
    /// the active seal policy. Only counts approvals from active issuers
    /// whose approvals have not expired.
    pub fn get_seal_approval_count(env: Env, proof_id: BytesN<32>) -> u32 {
        let policy_version = match get_active_policy_version_opt(&env) {
            Some(v) => v,
            None => return 0,
        };
        let policy = match get_seal_policy_opt(&env, &policy_version) {
            Some(p) => p,
            None => return 0,
        };
        if policy.status != STATUS_POLICY_ACTIVE {
            return 0;
        }
        if policy.expires_at > 0 && env.ledger().timestamp() > policy.expires_at {
            return 0;
        }
        count_active_approvals(&env, &proof_id, &policy)
    }

    /// Return the approval record for a (proof_id, signer) pair, if any.
    pub fn get_seal_approval(
        env: Env,
        proof_id: BytesN<32>,
        signer: Address,
    ) -> Option<SealApproval> {
        env.storage()
            .persistent()
            .get(&DataKey::SealApproval(proof_id, signer))
    }
}

fn require_admin(env: &Env, candidate: &Address) {
    let admin: Option<Address> = env.storage().persistent().get(&DataKey::Admin);
    let admin = admin.unwrap_or_else(|| panic_with_error!(env, RegistryError::NotInitialized));

    candidate.require_auth();
    if &admin != candidate {
        panic_with_error!(env, RegistryError::Unauthorized);
    }
}

// ---------------------------------------------------------------------------
// Threshold seal policy helpers (#124, restored)
// ---------------------------------------------------------------------------

fn get_seal_policy(env: &Env, version: &u32) -> SealPolicy {
    env.storage()
        .persistent()
        .get(&DataKey::SealPolicy(*version))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownSealPolicy))
}

fn get_seal_policy_opt(env: &Env, version: &u32) -> Option<SealPolicy> {
    env.storage()
        .persistent()
        .get(&DataKey::SealPolicy(*version))
}

/// Load a policy and require it to be active (status and absolute expiry).
fn get_seal_policy_active(env: &Env, version: &u32) -> SealPolicy {
    let policy = get_seal_policy(env, version);
    if policy.status != STATUS_POLICY_ACTIVE {
        panic_with_error!(env, RegistryError::InactiveSealPolicy);
    }
    if policy.expires_at > 0 && env.ledger().timestamp() > policy.expires_at {
        panic_with_error!(env, RegistryError::PolicyExpired);
    }
    policy
}

fn get_active_policy_version(env: &Env) -> u32 {
    get_active_policy_version_opt(env)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownSealPolicy))
}

fn get_active_policy_version_opt(env: &Env) -> Option<u32> {
    let version: Option<u32> = env.storage().persistent().get(&DataKey::SealPolicyCount);
    version.filter(|v| *v > 0)
}

/// Require that `signer` is a member of the policy's signer set.
fn require_policy_signer(env: &Env, policy_version: u32, signer: &Address) {
    let signers: SorobanVec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::SealPolicySigners(policy_version))
        .unwrap_or_else(|| SorobanVec::new(env));

    for i in 0..signers.len() {
        let s: Address = signers.get_unchecked(i);
        if s == *signer {
            return;
        }
    }
    panic_with_error!(env, RegistryError::UnknownPolicySigner);
}

/// Count approvals for `proof_id` that still carry authority: the approver is
/// an active issuer and the approval has not passed `policy.approval_ttl`.
fn count_active_approvals(env: &Env, proof_id: &BytesN<32>, policy: &SealPolicy) -> u32 {
    let now = env.ledger().timestamp();
    let mut count = 0u32;

    let signers: SorobanVec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::SealPolicySigners(policy.version))
        .unwrap_or_else(|| SorobanVec::new(env));

    for i in 0..signers.len() {
        let s: Address = signers.get_unchecked(i);

        // Skip signers who are no longer active issuers.
        match env
            .storage()
            .persistent()
            .get::<_, IssuerRecord>(&DataKey::Issuer(s.clone()))
        {
            Some(record) if record.active => {}
            _ => continue,
        }

        let approval_key = DataKey::SealApproval(proof_id.clone(), s);
        let approval: Option<SealApproval> = env.storage().persistent().get(&approval_key);
        if let Some(a) = approval {
            if policy.approval_ttl > 0 {
                let expires = a.approved_at.saturating_add(policy.approval_ttl);
                if now > expires {
                    continue;
                }
            }
            count += 1;
        }
    }

    count
}

/// Write the finalized Tier-3 proof record and emit `SealFinalized`.
///
/// Privacy: the stored record and event carry only hashes, counts, addresses,
/// and timestamps — never proof bytes, witnesses, or media.
fn finalize_threshold_seal(
    env: &Env,
    proof_id: &BytesN<32>,
    video_hash: &BytesN<32>,
    metadata_hash: &BytesN<32>,
    policy: &SealPolicy,
) -> ProofRecord {
    let mut signers_vec = SorobanVec::<Address>::new(env);

    let policy_signers: SorobanVec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::SealPolicySigners(policy.version))
        .unwrap_or_else(|| SorobanVec::new(env));

    for i in 0..policy_signers.len() {
        let s: Address = policy_signers.get_unchecked(i);

        // Only include signers who have an active (non-expired) approval.
        match env
            .storage()
            .persistent()
            .get::<_, IssuerRecord>(&DataKey::Issuer(s.clone()))
        {
            Some(record) if record.active => {}
            _ => continue,
        }

        let approval_key = DataKey::SealApproval(proof_id.clone(), s.clone());
        let approval: Option<SealApproval> = env.storage().persistent().get(&approval_key);
        if let Some(a) = approval {
            if policy.approval_ttl > 0 {
                let expires = a.approved_at.saturating_add(policy.approval_ttl);
                if env.ledger().timestamp() > expires {
                    continue;
                }
            }
            signers_vec.push_back(s);
        }
    }

    let approval_count = signers_vec.len();

    // Use the first signer as the primary issuer (for backward compatibility).
    let primary_issuer: Option<Address> = if signers_vec.len() > 0 {
        Some(signers_vec.get_unchecked(0))
    } else {
        None
    };
    let history_actor = primary_issuer.clone();

    let expires_at = compute_expires_at(env);

    env.storage()
        .persistent()
        .set(&DataKey::ThresholdSigners(proof_id.clone()), &signers_vec);

    save_record(
        env,
        proof_id,
        ProofRecord {
            video_hash: video_hash.clone(),
            metadata_hash: metadata_hash.clone(),
            tier: TIER_PUBLIC_SEAL,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: None,
            issuer: primary_issuer,
            nullifier: None,
            batch_size: 0,
        },
        history_actor,
    );

    let record = get_proof_record(env, proof_id);

    SealFinalized {
        proof_id: proof_id.clone(),
        approval_count,
    }
    .publish(env);

    record
}

/// Require that `caller` is either the admin or the configured guardian, and
/// authorize the call. Returns `true` when the caller is the admin, so
/// callers can apply role-specific limits (e.g. pause duration caps).
fn require_pauser(env: &Env, caller: &Address) -> bool {
    let admin: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::NotInitialized));

    caller.require_auth();

    if caller == &admin {
        return true;
    }

    let guardian: Option<Address> = env.storage().persistent().get(&DataKey::Guardian);
    match guardian {
        Some(g) if &g == caller => false,
        _ => panic_with_error!(env, RegistryError::Unauthorized),
    }
}

/// Reject `scope` unless it is nonzero and composed only of known
/// `DELEGATION_SCOPE_*` bits.
fn validate_delegation_scope(env: &Env, scope: u32) {
    if scope == 0 || scope & !DELEGATION_SCOPE_ALL != 0 {
        panic_with_error!(env, RegistryError::InvalidDelegationScope);
    }
}

fn delegation_count(env: &Env, grantor: &Address) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::DelegationCount(grantor.clone()))
        .unwrap_or(0)
}

/// Require a live delegation from `grantor` to `delegate` carrying every bit of
/// `scope`, and authorize the call.
///
/// The three failure modes are kept distinct — absent, expired, and
/// insufficiently scoped — because an operator responding to a failed
/// registration needs to know which one happened, and none of the three
/// discloses anything about the media or the proof.
fn require_delegation(env: &Env, grantor: &Address, delegate: &Address, scope: u32) {
    validate_delegation_scope(env, scope);

    let record: DelegationRecord = env
        .storage()
        .persistent()
        .get(&DataKey::Delegation(grantor.clone(), delegate.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::DelegationNotFound));

    if env.ledger().timestamp() >= record.expires_at {
        panic_with_error!(env, RegistryError::DelegationExpired);
    }

    if record.scope & scope != scope {
        panic_with_error!(env, RegistryError::DelegationScopeExceeded);
    }
}

/// Reject `domain` unless it is nonzero and composed only of known
/// `PAUSE_DOMAIN_*` bits. Accepts single domains and their bitwise-OR
/// combination (e.g. `PAUSE_DOMAIN_ALL_REGISTRATION`).
fn validate_domain(env: &Env, domain: u32) {
    if domain == 0 || domain & !PAUSE_DOMAIN_ALL_REGISTRATION != 0 {
        panic_with_error!(env, RegistryError::InvalidPauseDomain);
    }
}

/// Reject `domain` unless it is exactly one known `PAUSE_DOMAIN_*` bit.
fn validate_single_domain(env: &Env, domain: u32) {
    if !PAUSE_DOMAIN_SINGLE_BITS.contains(&domain) {
        panic_with_error!(env, RegistryError::InvalidPauseDomain);
    }
}

/// Iterate the single-bit domains present in `domain` (already validated by
/// `validate_domain`/`validate_single_domain`).
fn domain_bits(domain: u32) -> impl Iterator<Item = u32> {
    PAUSE_DOMAIN_SINGLE_BITS
        .into_iter()
        .filter(move |bit| domain & bit != 0)
}

fn domain_is_paused(env: &Env, domain_bit: u32, now: u64) -> bool {
    let record: Option<PauseRecord> = env.storage().persistent().get(&DataKey::Pause(domain_bit));
    match record {
        Some(r) => now < r.expires_at,
        None => false,
    }
}

fn require_domain_unpaused(env: &Env, domain_bit: u32) {
    let now = env.ledger().timestamp();
    if domain_is_paused(env, domain_bit, now) {
        panic_with_error!(env, RegistryError::Paused);
    }
}

/// Compute the `expires_at` value for a freshly registered proof.
///
/// Returns `created_at + ttl` when a non-zero TTL is configured, or `0`
/// (no expiration) otherwise.  Uses saturating addition to avoid overflow on
/// extreme inputs.
fn compute_expires_at(env: &Env) -> u64 {
    let ttl: u64 = env
        .storage()
        .persistent()
        .get(&DataKey::ProofTtl)
        .unwrap_or(DEFAULT_PROOF_TTL_SECS);
    if ttl == 0 {
        0
    } else {
        env.ledger().timestamp().saturating_add(ttl)
    }
}

fn require_unique(env: &Env, proof_id: &BytesN<32>, video_hash: &BytesN<32>) {
    if env
        .storage()
        .persistent()
        .has(&DataKey::Proof(proof_id.clone()))
    {
        panic_with_error!(env, RegistryError::DuplicateProof);
    }

    if env
        .storage()
        .persistent()
        .has(&DataKey::Video(video_hash.clone()))
    {
        panic_with_error!(env, RegistryError::DuplicateVideo);
    }
}

fn get_proof_record(env: &Env, proof_id: &BytesN<32>) -> ProofRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Proof(proof_id.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::DuplicateProof))
}

fn get_issuer_record(env: &Env, issuer: &Address) -> IssuerRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Issuer(issuer.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownIssuer))
}

fn get_credential_root_record(env: &Env, credential_root: &BytesN<32>) -> CredentialRootRecord {
    env.storage()
        .persistent()
        .get(&DataKey::CredentialRoot(credential_root.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownCredentialRoot))
}

fn get_active_verifier(env: &Env) -> Address {
    env.storage()
        .persistent()
        .get(&DataKey::Verifier)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::VerifierNotSet))
}

fn get_verifier_rotation_state(env: &Env) -> VerifierState {
    env.storage()
        .persistent()
        .get(&DataKey::VerifierState)
        .unwrap_or(VerifierState {
            active_verifier: env.storage().persistent().get(&DataKey::Verifier),
            pending_verifier: None,
            previous_verifier: None,
            activation_ledger: 0,
            overlap_window: 0,
            rollback_window: 0,
            rollback_window_end: 0,
        })
}

fn require_active_credential_root(env: &Env, credential_root: &BytesN<32>) {
    let record = get_credential_root_record(env, credential_root);
    if !record.active {
        panic_with_error!(env, RegistryError::RevokedCredentialRoot);
    }
}

fn save_record(
    env: &Env,
    proof_id: &BytesN<32>,
    record: ProofRecord,
    actor: Option<Address>,
) -> ProofRecord {
    env.storage()
        .persistent()
        .set(&DataKey::Proof(proof_id.clone()), &record);
    env.storage()
        .persistent()
        .set(&DataKey::Video(record.video_hash.clone()), proof_id);
    ProofRegistered {
        proof_id: proof_id.clone(),
        video_hash: record.video_hash.clone(),
        tier: record.tier,
        status: record.status,
        batch_size: record.batch_size,
    }
    .publish(env);
    // Registration has one canonical observable order: the domain event is
    // emitted first, followed by the append-only lifecycle history event.
    // Keeping both emissions here also covers aggregated registrations and
    // prevents a new registration path from silently omitting history.
    record_proof_history(
        env,
        proof_id,
        ProofLifecycleAction::Registered as u32,
        actor,
        record.tier,
    );
    // Stamp a V1 metadata envelope for bare-hash registrations (#317).
    // Explicit V2+ bindings use `bind_metadata_envelope` after register.
    stamp_default_metadata_envelope(env, proof_id, &record.metadata_hash);
    record
}

/// Append a bounded, privacy-safe lifecycle entry to a proof's history (#90).
///
/// Enforces `MAX_HISTORY_ENTRIES_PER_PROOF`, rejects unknown actions and
/// out-of-range reason codes, and emits only the `ProofHistoryEvent`
/// (`["proof", "history", proof_id]`). No media, proof bytes, witnesses,
/// nullifiers, or metadata hashes are written or emitted here.
fn record_proof_history(
    env: &Env,
    proof_id: &BytesN<32>,
    action: u32,
    actor: Option<Address>,
    reason_code: u32,
) {
    if !(1..=6).contains(&action) {
        panic_with_error!(env, RegistryError::InvalidHistoryAction);
    }
    if reason_code > 255 {
        panic_with_error!(env, RegistryError::InvalidReasonCode);
    }

    let seq_key = DataKey::ProofHistorySeq(proof_id.clone());
    let seq: u32 = env.storage().persistent().get(&seq_key).unwrap_or(0);

    if seq >= MAX_HISTORY_ENTRIES_PER_PROOF {
        panic_with_error!(env, RegistryError::HistorySaturated);
    }

    let next_seq = seq + 1;
    let now = env.ledger().timestamp();
    env.storage().persistent().set(
        &DataKey::ProofHistoryEntry(proof_id.clone(), next_seq),
        &ProofHistoryEntry {
            action,
            timestamp: now,
            actor: actor.clone(),
            reason_code,
        },
    );
    env.storage().persistent().set(&seq_key, &next_seq);

    ProofHistoryEvent {
        proof_id: proof_id.clone(),
        action,
        timestamp: now,
        actor,
        reason_code,
    }
    .publish(env);
}

/// Validate a lineage edge set: bounded fan-out and depth, no self-reference,
/// and every parent must already be a known proof or lineage record.

fn require_supported_metadata_envelope_version(env: &Env, version: u32) {
    if version < METADATA_ENVELOPE_V1 || version > METADATA_ENVELOPE_VERSION_MAX {
        panic_with_error!(env, RegistryError::UnsupportedMetadataEnvelopeVersion);
    }
}

fn require_metadata_envelope_actor(env: &Env, actor: &Address, proof: &ProofRecord) {
    actor.require_auth();

    let admin: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::NotInitialized));
    if *actor == admin {
        return;
    }
    if let Some(ref source) = proof.source {
        if *actor == *source {
            return;
        }
    }
    if let Some(ref issuer) = proof.issuer {
        if *actor == *issuer {
            return;
        }
    }
    panic_with_error!(env, RegistryError::Unauthorized);
}

/// Idempotently stamp a V1 envelope for newly registered proofs.
fn stamp_default_metadata_envelope(env: &Env, proof_id: &BytesN<32>, metadata_hash: &BytesN<32>) {
    let key = DataKey::MetadataEnvelope(proof_id.clone());
    if env.storage().persistent().has(&key) {
        return;
    }
    let zero = BytesN::from_array(env, &[0u8; 32]);
    // Zero hash still gets a version stamp so resolve_* stays consistent;
    // bind_metadata_envelope rejects zero for explicit upgrades.
    let bound_at = env.ledger().timestamp();
    let envelope = MetadataEnvelope {
        proof_id: proof_id.clone(),
        version: METADATA_ENVELOPE_VERSION_DEFAULT,
        metadata_hash: if *metadata_hash == zero {
            zero
        } else {
            metadata_hash.clone()
        },
        bound_at,
    };
    env.storage().persistent().set(&key, &envelope);
    MetadataEnvelopeBound {
        proof_id: proof_id.clone(),
        version: METADATA_ENVELOPE_VERSION_DEFAULT,
        metadata_hash: envelope.metadata_hash.clone(),
        bound_at,
    }
    .publish(env);
}

fn validate_lineage(
    env: &Env,
    parent_proof_ids: &SorobanVec<BytesN<32>>,
    output_digest: &BytesN<32>,
    depth: u32,
) {
    if parent_proof_ids.len() > MAX_LINEAGE_FANOUT as u32 {
        panic_with_error!(env, RegistryError::LineageFanOutExceeded);
    }
    if depth > MAX_LINEAGE_DEPTH {
        panic_with_error!(env, RegistryError::LineageTooDeep);
    }

    for parent in parent_proof_ids.iter() {
        if parent == *output_digest {
            panic_with_error!(env, RegistryError::LineageCycle);
        }
        let is_known_parent = env
            .storage()
            .persistent()
            .has(&DataKey::Proof(parent.clone()))
            || env
                .storage()
                .persistent()
                .has(&DataKey::Lineage(parent.clone()));
        if !is_known_parent {
            panic_with_error!(env, RegistryError::InvalidLineage);
        }
    }
}

/// Derive the deterministic sub-proof_id for batch element `index`.
///
/// Uses a full 32-byte XOR spread of the batch id so sibling elements never
/// collide while remaining reproducible from `(batch_id, index)` alone.
fn derive_element_proof_id(env: &Env, batch_id: &BytesN<32>, index: u32) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    batch_id.copy_into_slice(&mut bytes);

    let index_byte = (index & 0xFF) as u8;
    for j in 0..32 {
        bytes[j] ^= index_byte.wrapping_mul((j as u8).wrapping_add(1));
    }

    BytesN::from_array(env, &bytes)
}

// ---------------------------------------------------------------------------
// Silent Witness v1 public input parsing (backward compatible)
// ---------------------------------------------------------------------------

struct SilentWitnessInputs {
    video_hash: BytesN<32>,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
    domain_tag: BytesN<32>,
}

/// Compute the expected domain tag for this contract deployment.
///
/// The tag is BN254 Pedersen([DOMAIN_PROTOCOL_FIELD, DOMAIN_VERSION_FIELD, DOMAIN_NETWORK_FIELD]).
/// Because Soroban does not expose a Pedersen precompile we use SHA-256 as a
/// structurally equivalent binding: SHA-256(protocol_bytes || version_bytes || network_bytes).
/// The circuit constants (DOMAIN_*_FIELD) are derived from the same SHA-256 inputs so the
/// contract check mirrors the circuit constraint.
///
/// Concretely, the contract checks:
///   SHA-256(DOMAIN_PROTOCOL_FIELD || DOMAIN_VERSION_FIELD || DOMAIN_NETWORK_FIELD) == domain_tag
///
/// The off-chain prover populates domain_tag from the Noir helper circuit which uses
/// Pedersen; the two approaches diverge in algorithm but both bind to the same constants,
/// ensuring cross-version and cross-network rejection.
pub(crate) fn expected_domain_tag(env: &Env) -> BytesN<32> {
    let mut preimage = Bytes::new(env);
    preimage.extend_from_array(&DOMAIN_PROTOCOL_FIELD);
    preimage.extend_from_array(&DOMAIN_VERSION_FIELD);
    preimage.extend_from_array(&DOMAIN_NETWORK_FIELD);
    env.crypto().sha256(&preimage).into()
}

/// Read a 128-byte public-input frame out of `Bytes`, rejecting any other
/// length before allocating.
fn read_public_input_frame(env: &Env, public_inputs: &Bytes) -> [u8; PUBLIC_INPUTS_LEN] {
    if public_inputs.len() as usize != PUBLIC_INPUTS_LEN {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }
    let mut frame = [0u8; PUBLIC_INPUTS_LEN];
    public_inputs.copy_into_slice(&mut frame);
    frame
}

/// Parse the legacy (v1-lenient) silent-witness layout.
///
/// Behaviour is unchanged from the pre-codec implementation: only the frame
/// length is enforced. Field-level canonicity, half padding, and zero-field
/// rules are defined by [`verifier_inputs`] and surfaced through
/// [`HarpocratesRegistry::classify_public_inputs`]; see
/// `docs/zk-conformance-vectors.md` for the migration that promotes them to
/// enforcement on this path.
fn parse_silent_witness_public_inputs(env: &Env, public_inputs: &Bytes) -> SilentWitnessInputs {
    if public_inputs.len() != SILENT_WITNESS_V1_INPUT_LEN {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }
    let mut frame = [0u8; 160];
    public_inputs.copy_into_slice(&mut frame);

    let mut video_hash = [0u8; 32];
    video_hash[..16].copy_from_slice(&frame[16..32]);
    video_hash[16..].copy_from_slice(&frame[48..64]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&frame[64..96]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&frame[96..128]);

    let mut domain_tag = [0u8; 32];
    domain_tag.copy_from_slice(&frame[128..160]);

    SilentWitnessInputs {
        video_hash: BytesN::from_array(env, &video_hash),
        credential_root: BytesN::from_array(env, &credential_root),
        nullifier: BytesN::from_array(env, &nullifier),
        domain_tag: BytesN::from_array(env, &domain_tag),
    }
}

// ---------------------------------------------------------------------------
// Silent Witness v2 (scoped) public input parsing
// ---------------------------------------------------------------------------

struct ScopedSilentWitnessInputs {
    video_hash: BytesN<32>,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
    verifier_scope: BytesN<32>,
    epoch: u64,
    domain_tag: BytesN<32>,
}

/// Parse the 224-byte public-input blob produced by the v2 scoped
/// silent_witness Noir circuit.
///
/// Layout (7 x BN254 field elements, 32 bytes each):
///   [  0.. 32)  video_hash_hi + video_hash_lo (packed)
///   [ 32.. 64)  video_hash_lo continued
///   [ 64.. 96)  credential_root
///   [ 96..128)  nullifier
///   [128..160)  verifier_scope
///   [160..192)  epoch
///   [192..224)  domain_tag
fn parse_scoped_silent_witness_public_inputs(
    env: &Env,
    public_inputs: &Bytes,
) -> ScopedSilentWitnessInputs {
    if public_inputs.len() != SILENT_WITNESS_V2_INPUT_LEN {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }

    let mut bytes = [0u8; 224];
    public_inputs.copy_into_slice(&mut bytes);

    // Reassemble video_hash: hi occupies bytes 16..32 of the first field word,
    // lo occupies bytes 48..64 of the second field word (UltraHonk packs 128-bit
    // values in the low half of a 256-bit field element).
    let mut video_hash = [0u8; 32];
    video_hash[..16].copy_from_slice(&bytes[16..32]);
    video_hash[16..].copy_from_slice(&bytes[48..64]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&bytes[64..96]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&bytes[96..128]);

    let mut verifier_scope = [0u8; 32];
    verifier_scope.copy_from_slice(&bytes[128..160]);

    let mut epoch_bytes = [0u8; 32];
    epoch_bytes.copy_from_slice(&bytes[160..192]);
    let epoch = bytes_to_u64_be(&epoch_bytes);

    let mut domain_tag = [0u8; 32];
    domain_tag.copy_from_slice(&bytes[192..224]);

    ScopedSilentWitnessInputs {
        video_hash: BytesN::from_array(env, &video_hash),
        credential_root: BytesN::from_array(env, &credential_root),
        nullifier: BytesN::from_array(env, &nullifier),
        verifier_scope: BytesN::from_array(env, &verifier_scope),
        epoch,
        domain_tag: BytesN::from_array(env, &domain_tag),
    }
}

/// Convert a 32-byte big-endian value to a u64.
/// Only the last 8 bytes are used; upper bytes must be zero for valid epochs.
fn bytes_to_u64_be(bytes: &[u8; 32]) -> u64 {
    // Check that upper bytes are zero (epoch must fit in u64)
    for b in &bytes[..24] {
        if *b != 0 {
            // Epoch value overflows u64 — treat as invalid (max)
            return u64::MAX;
        }
    }
    let mut val: u64 = 0;
    for b in &bytes[24..32] {
        val = (val << 8) | (*b as u64);
    }
    val
}

/// Get the raw scope epoch value for a scope field element.
fn get_scope_epoch_raw(env: &Env, scope: &BytesN<32>) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::ScopeEpoch(scope.clone()))
        .unwrap_or(DEFAULT_SCOPE_EPOCH)
}

fn verify_external_proof(env: &Env, verifier: &Address, public_inputs: Bytes, proof: Bytes) {
    let build_args = |env: &Env| {
        let mut args: SorobanVec<Val> = SorobanVec::new(env);
        args.push_back(public_inputs.clone().into_val(env));
        args.push_back(proof.clone().into_val(env));
        args
    };

    // The verifier contract returns `()` on success and reverts with its own
    // error on any verification failure. A rejected verification is mapped to
    // the registry's own `InvalidProof` code so callers see a stable,
    // privacy-safe error rather than the verifier's internals.
    let result = env.try_invoke_contract::<(), InvokeError>(
        verifier,
        &Symbol::new(env, "verify_proof"),
        build_args(env),
    );
    if matches!(result, Ok(Ok(()))) {
        return;
    }

    // Staged-verifier overlap: while the rollback window is open, a proof
    // that the newly-activated verifier rejects is retried against the
    // previous verifier, so in-flight evidence is not invalidated by a
    // misbehaving cutover. Outside the window the failure is final.
    let state = get_verifier_rotation_state(env);
    if let Some(previous) = &state.previous_verifier {
        let current_ledger = u64::from(env.ledger().sequence());
        if previous != verifier
            && state.rollback_window_end > 0
            && current_ledger <= state.rollback_window_end
        {
            let retry = env.try_invoke_contract::<(), InvokeError>(
                previous,
                &Symbol::new(env, "verify_proof"),
                build_args(env),
            );
            if matches!(retry, Ok(Ok(()))) {
                return;
            }
        }
    }

    panic_with_error!(env, RegistryError::InvalidProof);
}

struct RevocationPublicInputs {
    revocation_root: BytesN<32>,
    nullifier: BytesN<32>,
    domain_separator: BytesN<32>,
    credential_root: BytesN<32>,
}

/// Parse the 128-byte public-input blob produced by the revocation_witness
/// Noir circuit.
///
/// Layout (4 x BN254 field elements, 32 bytes each):
///   [  0.. 32)  revocation_root
///   [ 32.. 64)  nullifier
///   [ 64.. 96)  domain_separator
///   [ 96..128)  credential_root
fn parse_revocation_public_inputs(env: &Env, public_inputs: &Bytes) -> RevocationPublicInputs {
    if public_inputs.len() as usize != verifier_inputs::REVOCATION_PUBLIC_INPUTS_LEN {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }
    let mut frame = [0u8; verifier_inputs::REVOCATION_PUBLIC_INPUTS_LEN];
    public_inputs.copy_into_slice(&mut frame);

    let mut revocation_root = [0u8; 32];
    revocation_root.copy_from_slice(&frame[0..32]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&frame[32..64]);

    let mut domain_separator = [0u8; 32];
    domain_separator.copy_from_slice(&frame[64..96]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&frame[96..128]);

    RevocationPublicInputs {
        revocation_root: BytesN::from_array(env, &revocation_root),
        nullifier: BytesN::from_array(env, &nullifier),
        domain_separator: BytesN::from_array(env, &domain_separator),
        credential_root: BytesN::from_array(env, &credential_root),
    }
}

/// Parsed element of an aggregated batch proof.
///
/// NOTE: `BytesN<32>` is not `Copy` in SDK 27, so the parsing function seeds
/// its fixed-size element array with `core::array::from_fn` instead of the
/// `[value; N]` initialization syntax.
#[derive(Clone)]
struct AggregatedBatchElement {
    video_hash: BytesN<32>,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
}

/// Parsed aggregated batch public inputs.
struct AggregatedPublicInputs {
    domain_separator: BytesN<32>,
    elements: [AggregatedBatchElement; MAX_AGGREGATION_SIZE as usize],
}

/// Parse aggregated batch public inputs.
///
/// Avoids large stack allocations by parsing elements directly from the
/// `Bytes` reference element-by-element, using a small 128-byte temp buffer.
///
/// Layout:
///   [   0..  32)  domain_separator      – 32 bytes
///   [  32.. 160)  element_0             – 128 bytes (4 × 32 byte fields)
///   [ 160.. 288)  element_1
///   ...
///   [ 928..1056)  element_7
///
/// Each element is 128 bytes with the same layout as `single_witness`:
///   [  0.. 32)  video_hash_hi     → reconstructed into video_hash (hi 16 bytes → [0..16], lo 16 bytes → [16..32])
///   [ 32.. 64)  video_hash_lo
///   [ 64.. 96)  credential_root
///   [ 96..128)  nullifier
fn parse_aggregated_public_inputs(
    env: &Env,
    public_inputs: &Bytes,
    batch_size: u32,
) -> AggregatedPublicInputs {
    let expected_len = 32 + (batch_size * 128);
    if public_inputs.len() != expected_len {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }

    // Parse domain separator from the first 32 bytes (small stack buffer).
    // NOTE: We must slice first because Bytes.copy_into_slice expects the
    // destination to match the full Bytes length.
    let domain_slice = public_inputs.slice(0..32);
    let mut domain_bytes = [0u8; 32];
    domain_slice.copy_into_slice(&mut domain_bytes);
    let domain_separator = BytesN::from_array(env, &domain_bytes);

    // Initialize default elements. `AggregatedBatchElement` is not `Copy`, so
    // seed the fixed-size array with a closure instead of `[value; N]` syntax.
    let mut elements: [AggregatedBatchElement; MAX_AGGREGATION_SIZE as usize] =
        core::array::from_fn(|_| AggregatedBatchElement {
            video_hash: BytesN::from_array(env, &[0u8; 32]),
            credential_root: BytesN::from_array(env, &[0u8; 32]),
            nullifier: BytesN::from_array(env, &[0u8; 32]),
        });

    // Parse each batch element using a small 128-byte temp buffer.
    // We slice the Bytes at the element offset to avoid allocating a full
    // buffer for the entire public input blob.
    let mut element_bytes = [0u8; 128];
    for i in 0..batch_size {
        let element_start = 32 + (i * 128);
        let element_slice = public_inputs.slice(element_start..element_start + 128);
        element_slice.copy_into_slice(&mut element_bytes);

        // Reconstruct video hash from the two limbs (same as silent witness parsing).
        let mut video_hash = [0u8; 32];
        video_hash[..16].copy_from_slice(&element_bytes[16..32]);
        video_hash[16..].copy_from_slice(&element_bytes[48..64]);

        let mut credential_root = [0u8; 32];
        credential_root.copy_from_slice(&element_bytes[64..96]);

        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&element_bytes[96..128]);

        elements[i as usize] = AggregatedBatchElement {
            video_hash: BytesN::from_array(env, &video_hash),
            credential_root: BytesN::from_array(env, &credential_root),
            nullifier: BytesN::from_array(env, &nullifier),
        };
    }

    AggregatedPublicInputs {
        domain_separator,
        elements,
    }
}

fn verify_demo_zk_boundary(proof: &Bytes, credential_root: &BytesN<32>) -> bool {
    !proof.is_empty() && credential_root.len() == 32
}

// ---------------------------------------------------------------------------
// Dispute helper functions
// ---------------------------------------------------------------------------

/// Retrieve a dispute record, panicking with `DisputeNotFound` if absent.
fn get_dispute_record(env: &Env, dispute_id: &BytesN<32>) -> DisputeRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Dispute(dispute_id.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::DisputeNotFound))
}

/// Decrement the open-dispute counter for a proof.  Saturates at 0 to avoid
/// underflow on double-close (which should never happen under correct logic
/// but is defended against for safety).
fn decrement_open_dispute_count(env: &Env, proof_id: &BytesN<32>) {
    let key = DataKey::ProofOpenDisputeCount(proof_id.clone());
    let count: u32 = env.storage().persistent().get(&key).unwrap_or(0u32);
    let new_count = count.saturating_sub(1);
    if new_count == 0 {
        env.storage().persistent().remove(&key);
    } else {
        env.storage().persistent().set(&key, &new_count);
    }
}

/// Depth-1 cycle guard for supersession.
///
/// Returns `true` if allowing `superseding_proof_id` to supersede
/// `disputed_proof_id` would create a cycle. Two conditions are rejected:
///
/// 1. **Duplicate edge** - an arrow `disputed_proof_id -> superseding_proof_id`
///    already exists, so re-recording it is a no-op that could mask corruption.
/// 2. **Reverse edge (2-cycle)** - an arrow `superseding_proof_id ->
///    disputed_proof_id` already exists, so the proposed edge would close a
///    length-2 cycle.
///
/// The reverse index maps a superseding proof to the proof it corrected:
///   DataKey::Dispute(SHA-256("harp_sup_rev" ‖ superseding_proof_id)) -> disputed_proof_id
fn check_supersession_cycle(
    env: &Env,
    disputed_proof_id: &BytesN<32>,
    superseding_proof_id: &BytesN<32>,
) -> bool {
    // 1. Duplicate edge: reverse[superseding] == disputed.
    let forward_rev = supersession_reverse_key(env, superseding_proof_id);
    if let Some(recorded_original) = env
        .storage()
        .persistent()
        .get::<DataKey, BytesN<32>>(&DataKey::Dispute(forward_rev))
    {
        if recorded_original == *disputed_proof_id {
            return true;
        }
    }

    // 2. Reverse edge: reverse[disputed] == superseding.
    let reverse_rev = supersession_reverse_key(env, disputed_proof_id);
    if let Some(recorded_superseder) = env
        .storage()
        .persistent()
        .get::<DataKey, BytesN<32>>(&DataKey::Dispute(reverse_rev))
    {
        if recorded_superseder == *superseding_proof_id {
            return true;
        }
    }

    false
}

/// Record the supersession direction in the reverse index.
/// Called from `supersede_dispute` after all guards pass.
fn record_supersession_direction(
    env: &Env,
    disputed_proof_id: &BytesN<32>,
    superseding_proof_id: &BytesN<32>,
) {
    let rev_key_hash = supersession_reverse_key(env, superseding_proof_id);
    env.storage()
        .persistent()
        .set(&DataKey::Dispute(rev_key_hash), disputed_proof_id);
}

/// Compute the reverse-index key for a supersession:
///   SHA-256("harp_sup_rev" ‖ superseding_proof_id_bytes)
///
/// "harp_sup_rev" is a 12-byte domain prefix that avoids key collisions with
/// legitimate dispute_id keys.  The 12-byte prefix + 32-byte suffix = 44
/// bytes of pre-image, hashed to a 32-byte key.
fn supersession_reverse_key(env: &Env, superseding_proof_id: &BytesN<32>) -> BytesN<32> {
    // domain prefix: ASCII "harp_sup_rev" = 12 bytes
    const PREFIX: [u8; 12] = *b"harp_sup_rev";

    // Build a 44-byte pre-image: [PREFIX (12)] ‖ [superseding_proof_id (32)]
    let mut pre_image = [0u8; 44];
    pre_image[..12].copy_from_slice(&PREFIX);
    let mut tail: [u8; 32] = pre_image[12..44].try_into().expect("32-byte tail");
    superseding_proof_id.copy_into_slice(&mut tail);

    let pre_image_bytes = Bytes::from_array(env, &pre_image);
    BytesN::from(env.crypto().sha256(&pre_image_bytes))
}

// ---------------------------------------------------------------------------
// Timelock proposal helpers (#86)
// ---------------------------------------------------------------------------

fn get_timelock_min_delay(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::TimelockMinDelay)
        .unwrap_or(DEFAULT_TIMELOCK_MIN_DELAY_SECS)
}

fn get_timelock_proposal_or_panic(env: &Env, proposal_id: u32) -> TimelockProposal {
    env.storage()
        .persistent()
        .get(&DataKey::Proposal(proposal_id))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::ProposalNotFound))
}

fn next_proposal_id(env: &Env) -> u32 {
    let current: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::ProposalSeq)
        .unwrap_or(0u32);
    let next = current.saturating_add(1);
    env.storage().persistent().set(&DataKey::ProposalSeq, &next);
    next
}

fn count_pending_proposals(env: &Env) -> u32 {
    let count: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::ProposalSeq)
        .unwrap_or(0u32);
    if count == 0 {
        return 0;
    }
    let mut pending = 0u32;
    for pid in 1..=count {
        if let Some(proposal) = env
            .storage()
            .persistent()
            .get::<DataKey, TimelockProposal>(&DataKey::Proposal(pid))
        {
            if !proposal.executed && !proposal.cancelled {
                pending += 1;
            }
        }
    }
    pending
}

fn dispatch_timelocked_action(env: &Env, proposal: &TimelockProposal) {
    match proposal.action {
        1 => {
            env.storage()
                .persistent()
                .set(&DataKey::Verifier, &proposal.target);
            env.storage().persistent().remove(&DataKey::VerifierState);
            VerifierSet {
                verifier: proposal.target.clone(),
            }
            .publish(env);
        }
        2 => {
            let mut record = get_issuer_record(env, &proposal.target);
            record.active = false;
            env.storage()
                .persistent()
                .set(&DataKey::Issuer(proposal.target.clone()), &record);
            IssuerRevoked {
                issuer: proposal.target.clone(),
            }
            .publish(env);
        }
        3 => {
            let payload = proposal.payload.to_array();
            let mut ttl_bytes = [0u8; 8];
            ttl_bytes.copy_from_slice(&payload[..8]);
            let ttl_secs = u64::from_be_bytes(ttl_bytes);
            env.storage()
                .persistent()
                .set(&DataKey::ProofTtl, &ttl_secs);
        }
        4 => {
            let mut record = get_credential_root_record(env, &proposal.payload);
            record.active = false;
            env.storage()
                .persistent()
                .set(&DataKey::CredentialRoot(proposal.payload.clone()), &record);
            CredentialRootRevoked {
                credential_root: proposal.payload.clone(),
            }
            .publish(env);
        }
        _ => panic_with_error!(env, RegistryError::InvalidProposalAction),
    }
}

// ---------------------------------------------------------------------------
// Selective disclosure helpers
// ---------------------------------------------------------------------------

/// Current version of the selective disclosure circuit.
const CURRENT_SELECTIVE_DISCLOSURE_VERSION: u32 = 1;

fn get_schema_record(env: &Env, schema_hash: &BytesN<32>) -> SchemaRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Schema(schema_hash.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownSchema))
}

struct SelectiveDisclosureInputs {
    schema_hash: BytesN<32>,
    issuer_namespace: BytesN<32>,
    schema_version: u32,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
    video_hash_hi: BytesN<32>,
    video_hash_lo: BytesN<32>,
    verifier_digest: BytesN<32>,
    circuit_version: u32,
    evidence_digest: BytesN<32>,
    predicate_commitment: BytesN<32>,
}

fn parse_selective_disclosure_inputs(
    env: &Env,
    public_inputs: &Bytes,
) -> SelectiveDisclosureInputs {
    if public_inputs.len() != 352 {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }

    let mut bytes = [0u8; 352];
    public_inputs.copy_into_slice(&mut bytes);

    let schema_hash = BytesN::from_array(env, &read_32(&bytes[0..32]));
    let issuer_namespace = BytesN::from_array(env, &read_32(&bytes[32..64]));
    let schema_version = u32_from_be_bytes(&read_32(&bytes[64..96]));
    let credential_root = BytesN::from_array(env, &read_32(&bytes[96..128]));
    let nullifier = BytesN::from_array(env, &read_32(&bytes[128..160]));
    let video_hash_hi = BytesN::from_array(env, &read_32(&bytes[160..192]));
    let video_hash_lo = BytesN::from_array(env, &read_32(&bytes[192..224]));
    let verifier_digest = BytesN::from_array(env, &read_32(&bytes[224..256]));
    let circuit_version = u32_from_be_bytes(&read_32(&bytes[256..288]));
    let evidence_digest = BytesN::from_array(env, &read_32(&bytes[288..320]));
    let predicate_commitment = BytesN::from_array(env, &read_32(&bytes[320..352]));

    SelectiveDisclosureInputs {
        schema_hash,
        issuer_namespace,
        schema_version,
        credential_root,
        nullifier,
        video_hash_hi,
        video_hash_lo,
        verifier_digest,
        circuit_version,
        evidence_digest,
        predicate_commitment,
    }
}

fn array_from_slice<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut arr = [0u8; N];
    arr.copy_from_slice(slice);
    arr
}

fn read_32(slice: &[u8]) -> [u8; 32] {
    array_from_slice(slice)
}

fn u32_from_be_bytes(bytes: &[u8; 32]) -> u32 {
    u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]])
}

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_aggregation;
#[cfg(test)]
mod test_auth;
#[cfg(test)]
mod test_budget;
#[cfg(test)]
mod test_conformance;
#[cfg(test)]
mod test_delegation;
#[cfg(test)]
mod test_deployment_fixture;
#[cfg(test)]
mod test_dispute;
#[cfg(test)]
mod test_expiry;
#[cfg(test)]
mod test_fuzz;
#[cfg(test)]
mod test_identity_tier_properties;
#[cfg(test)]
mod test_invariants;
#[cfg(test)]
mod test_lifecycle;
#[cfg(test)]
mod test_lineage;
#[cfg(test)]
mod test_pause;
#[cfg(test)]
mod test_registration_replay;
#[cfg(test)]
mod test_revocation;
#[cfg(test)]
mod test_schema;
#[cfg(test)]
mod test_scoped_nullifier;
#[cfg(test)]
mod test_selective_disclosure;
#[cfg(test)]
mod test_state_machine;
#[cfg(test)]
mod test_threshold_seal;
#[cfg(test)]
pub mod test_timelock;
#[cfg(test)]
mod test_upgrade_compat;
#[cfg(test)]
mod test_metadata_envelope;
