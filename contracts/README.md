# Harpocrates Soroban Contracts

This workspace contains the Stellar Soroban contracts for Harpocrates.

## Contracts

```text
contracts/harpocrates-registry
```

`HarpocratesRegistry` stores evidence records for all identity tiers:

- Tier 1 Silent Witness: anonymous Noir proof with nullifier protection.
- Tier 2 Consistent Source: Stellar account signed source.
- Tier 3 Public Seal: approved institutional issuer.

## Build

```powershell
cargo test
stellar contract build
```

## Threshold Seal Policy (#124, restored for #336)

Tier-3 Public Seals optionally require m-of-n institutional approvals instead
of a single issuer. The policy boundary and its authorization invariants are
covered by `contracts/harpocrates-registry/src/test_threshold_seal.rs`.

Run focused:

```bash
cd contracts
cargo test -p harpocrates-registry test_threshold_seal -- --nocapture
```

### Authorization surface

- `create_seal_policy`, `add_seal_policy_signer`, `remove_seal_policy_signer`,
  and `cancel_seal_policy` are admin-only (`Unauthorized` otherwise).
- `approve_seal` requires the signer's own auth. Authorization is checked in
  a fixed order: the policy must exist and be active (`UnknownSealPolicy`,
  `InactiveSealPolicy`, `PolicyExpired`), the signer must be a member of the
  policy's signer set (`UnknownPolicySigner`), and the signer must be an
  active issuer (`UnknownIssuer`). Membership of the signer set is the primary
  authorization boundary.
- Approvals are idempotent per (proof_id, signer): a duplicate approval from
  the same signer returns `false` and changes nothing, including after
  finalization. A distinct signer approving an already-finalized proof gets
  `AlreadyFinalized`.
- `finalize_seal` carries no special authority: it can only finalize what the
  recorded, unexpired approvals from active issuers already prove
  (`ThresholdNotMet` otherwise).

### Trust-boundary invariants under test

- Expired approvals (`approval_ttl`) and revoked issuers stop counting before
  finalization; a seal already finalized is not invalidated by later issuer
  revocation.
- Finalization is atomic: threshold met in `approve_seal` writes the proof in
  the same invocation, emits `SealFinalized`, and can never be re-finalized.
- No active/expired/cancelled policy blocks approval entirely.
- Signer sets are bounded (`MAX_SIGNERS`, `max_signers`), duplicates are
  no-ops, and adding a signer never bypasses issuer liveness checks.
- Events (`SealPolicyCreated`, `SealPolicyCancelled`, `SealApprovalRecorded`,
  `SealFinalized`) carry only hashes, counts, addresses, and timestamps —
  never proof bytes, witnesses, or media.

### Migration and rollback

`SealPolicyCount`, `SealPolicy(v)`, `SealPolicySigners(v)`,
`SealApproval(proof_id, signer)`, and `ThresholdSigners(proof_id)` are additive
storage keys; upgrading an initialized contract starts with no policy and all
existing records untouched. The threshold error codes are appended at the end
of `RegistryError` (#68–#76, append-only) so existing codes are unchanged; the
later #317 metadata-envelope errors are appended after them (#77–#80).
Rollback is a plain wasm redeploy; older readers ignore the new keys.

## Identity-Tier Property Tests

Issue #345 adds focused property tests for identity-tier invariants in
`contracts/harpocrates-registry/src/test_identity_tier_properties.rs`.

The harness uses a deterministic LCG over reproducible seeds to generate
registration sequences across Silent Witness (tier 1), Consistent Source
(tier 2), and Public Seal (tier 3). After every step it checks:

- tier-shaped privacy fields (no source/issuer on tier 1; nullifier only on tier 1)
- global uniqueness of `proof_id` and `video_hash` across tiers
- nullifier uniqueness for Silent Witness registrations
- pause-domain isolation (pausing one tier never blocks the others)
- lookup consistency (`get_proof` / `get_by_video`)
- rejected duplicates leave prior storage unchanged

Failure messages report only seeds, tier tags, slot indices, and error codes —
never proof bytes, public inputs, witnesses, or media.

Run focused:

```
cargo test -p harpocrates-registry identity_tier -- --nocapture
```

This change is test-only. It does not alter exported contract entry points,
storage keys, or on-chain migration behavior.

## Registry State-Machine Fuzzing

Issue #93 adds deterministic state-machine fuzzing for the registry contract in
`contracts/harpocrates-registry/src/test_state_machine.rs`. The harness drives
the real Soroban contract boundary with bounded authorized and adversarial
command streams, including duplicate proof/video/nullifier attempts, wrong
admins, revoked and unknown issuers, invalid and oversized public inputs,
missing verifier/revocation-root cases, replayed non-revocation nullifiers,
admin-transfer replacement/cancellation, TTL expiry, and client-side cancelled,
timed-out, or partial operations that must not reach contract storage.

The oracle is an explicit model of registry storage and status semantics. After
every generated command it checks:

- `Proof`, `Video`, `Nullifier`, `Issuer`, `CredentialRoot`, `Verifier`,
  `ProofTtl`, and `RevocationRoot` query results match the model.
- `get_proof_status` returns `Valid`, `Expired`, `Revoked`, or `NotFound`
  according to the modeled timestamp, TTL, and revocation state.
- rejected transitions return the expected `RegistryError`, emit no contract
  event, and leave storage unchanged.
- successful transitions emit only the existing typed lifecycle events, except
  `set_proof_ttl`, which intentionally has no event.
- each command remains inside a fixed fuzz budget ceiling so hostile inputs stay
  bounded in CI.

The CI corpus is the combination of curated adversarial sequences and fixed
generated seeds in `REGRESSION_SEEDS`; it runs as part of normal
`cargo test --workspace`, so no workflow or dependency upgrade is required.
Local expansion is opt-in:

```bash
cd contracts
HARPOCRATES_REGISTRY_FUZZ_RUNS=128 \
HARPOCRATES_REGISTRY_FUZZ_SEED=0x9300000000000001 \
cargo test -p harpocrates-registry registry_state_machine -- --nocapture
```

When a case fails, the runner shrinks the command stream by deletion and command
simplification, then prints the original seed, the failing step, the shrunk
command list, and the expected/actual error code. It never prints proof bytes,
public input bytes, witnesses, media, credentials, signatures, or raw metadata.
The model uses deterministic slot numbers and synthetic hashes only.

## Upgrade Compatibility Harness

Issue #347 adds a focused upgrade compatibility harness in
`contracts/harpocrates-registry/src/test_upgrade_compat.rs`. It drives the
real `upgrade_storage` / `get_storage_schema_version` boundary with:

- positive V1 init + idempotent upgrade calls
- negative unauthorized upgrade attempts
- legacy registries missing `DataKey::SchemaVersion` (stamp without event)
- regression that Tier-2 source proofs and the verifier pointer survive upgrade

```bash
cd contracts
cargo test -p harpocrates-registry upgrade_compat -- --nocapture
```

### Compatibility, Migration, And Rollback

`upgrade_storage` is the only admin path that advances `DataKey::SchemaVersion`.
At V1 the call is a no-op when the key is already present. Pre-#85 deployments
that lack the key are stamped to V1 without emitting `SchemaUpgraded` because
the on-disk layout is already V1-compatible. Future V2+ migrations must land
in the sequential branch inside `upgrade_storage`, preserve existing proof /
video / nullifier records, and must never log media, secrets, witnesses, or
private keys.

Rollback is redeploying a prior wasm: additive `SchemaVersion` keys are
ignored by older readers, and no proof rewrite is required for the V1 stamp.
Operators should call `get_storage_schema_version` after upgrade to confirm
the stamped version before rotating verifiers.

### Threat Assumptions

The harness assumes Soroban auth + persistent storage semantics. It does not
exercise live mainnet wasm replace, cryptographic verifier soundness, or real
evidence payloads. Failure modes under test are deterministic `RegistryError`
codes (`Unauthorized`) and privacy-safe absence of `SchemaUpgraded` on no-ops.

### Compatibility And Rollout

This fuzzing change is test-only. It does not alter exported contract
functions, storage keys, event schemas, proof/public-input formats, verifier
domains, script arguments, or deployed artifact compatibility. There is no
migration. Rollout is enabling the new tests in CI through the existing
contracts workflow. Rollback is removal or revert of the test module and this
documentation; no on-chain repair is needed.

### Signals And Privacy

Production observers continue to rely on existing typed events:

```text
["proof", "reg", proof_id]        => video_hash, tier, status
["proof", "revoke", proof_id]     => status
["issuer", "add", issuer]         => metadata_hash
["issuer", "revoke", issuer]      => {}
["verif", "set", verifier]        => {}
["credroot", "add", root]         => metadata_hash, issued_at
["credroot", "revoke", root]      => {}
["admin", "propose", pending]     => current_admin
["admin", "cancel", pending]      => current_admin
["admin", "accept", new_admin]    => previous_admin
["revroot", "set", root]          => {}
["nonrev", "check", root]         => nullifier, revocation_root
```

Failures are observable as deterministic transaction reverts with typed
`RegistryError` codes, not as extra events. The fuzz runner treats failed,
cancelled, timed-out, and partial operations as privacy-sensitive and asserts
that they do not emit success signals or write registry records.

### Threat Assumptions And Limits

The harness assumes Soroban ledger execution is atomic and serializes
concurrent submissions. Concurrent behavior is modeled as interleaved retries
and collisions against the same global `Proof`, `Video`, and `Nullifier` keys.
Client-side timeouts/cancellations are modeled as commands that never submit a
transaction; submitted partial failures are modeled through contract calls that
fail after parsing or authorization gates. Real user evidence, production
secrets, live mainnet behavior, and cryptographic verifier soundness are out of
scope for this test module. Cryptographic vectors remain owned by the Noir and
verifier conformance fixtures.

### Troubleshooting

Use the printed seed and shrunk commands to reproduce a failure with
`HARPOCRATES_REGISTRY_FUZZ_SEED`. If the failure is a budget ceiling only,
compare against `src/test_budget.rs` before raising the fuzz ceiling. If a
contract error changes intentionally, update the model order to match the
contract's exact validation order and keep the fixed seed in the corpus.

The current registry exports:

```text
init
get_storage_schema_version
upgrade_storage
propose_admin
cancel_admin_transfer
accept_admin
add_credential_root
revoke_credential_root
get_credential_root
add_issuer
revoke_issuer
set_verifier
get_verifier
set_proof_ttl
get_proof_ttl
register_anonymous
register_anonymous_verified
register_source
register_seal
revoke_proof
get_proof
get_by_video
has_nullifier
get_issuer
set_revocation_root
get_revocation_root
check_non_revocation
get_proof_status
get_proof_history
get_proof_history_at
get_proof_history_count
open_dispute
respond_dispute
resolve_dispute
dismiss_dispute
supersede_dispute
get_dispute
get_open_dispute_count
verify_proof
expire_proof
correct_proof
set_guardian
get_guardian
pause
unpause
is_paused
get_pause_state
```

## Staged verifier rotation

The registry now supports a staged verifier transition so a new verifier can be introduced without an unsafe instant cutover:

1. The admin schedules a pending verifier with an activation ledger and rollback window.
2. Once the ledger reaches the activation threshold, the admin activates the pending verifier.
3. During the rollback window, the admin can revert to the previous verifier if the new verifier misbehaves or fails validation.

The rotation state is persisted and can be inspected via `get_verifier_state`.

### Operational flow

```powershell
./scripts/schedule-verifier-rotation.ps1 -ContractId YOUR_REGISTRY -Admin harpocrates-admin -Verifier YOUR_NEW_VERIFIER -ActivationLedger 1000 -OverlapWindow 100 -RollbackWindow 200
./scripts/activate-verifier-rotation.ps1 -ContractId YOUR_REGISTRY -Admin harpocrates-admin
./scripts/rollback-verifier-rotation.ps1 -ContractId YOUR_REGISTRY -Admin harpocrates-admin
```

### Rollback and troubleshooting

- Activation is rejected before the configured activation ledger.
- Rollback is rejected once the rollback window closes.
- If the pending verifier fails validation or causes operational issues, revert to the previous verifier within the rollback window.
- If you need to reconfigure the verifier after the rotation completes, call `set_verifier` again to reset the rotation state and install a fresh verifier.

## Admin Transfer

Admin control uses a two-step transfer:

1. The current admin calls `propose_admin`, which creates or replaces the pending
   admin proposal.
2. The pending admin calls `accept_admin` to complete the transfer.

The current admin may call `cancel_admin_transfer` before acceptance. Proposals,
cancellations, and acceptances emit `["admin", "propose"]`,
`["admin", "cancel"]`, and `["admin", "accept"]` lifecycle events.

### Storage compatibility

The existing `DataKey::Admin` value and all existing record layouts are
unchanged. `DataKey::PendingAdmin` is appended as a new, independent persistent
storage key, so upgrading an initialized contract preserves its current admin
and all existing registry data. An upgraded contract starts with no pending
admin proposal.

## Emergency Pause

Registration can be paused per identity tier without affecting reads or
unaffected tiers. See `EMERGENCY_PAUSE.md` for the domain model, authorization
matrix, event schema, migration/rollback notes, and troubleshooting.

## Tier 1 Verifier

`register_anonymous` is the development/demo boundary.

`register_anonymous_verified` is the real Tier 1 entrypoint. It checks public
inputs, requires an active credential root, prevents nullifier reuse, then calls
the configured verifier contract:

```text
verify_proof(public_inputs, proof)
```

See `VERIFIER_INTEGRATION.md` for the UltraHonk verifier deployment plan.

Current Testnet verifier:

```text
CCP2EQPKT5XAYTOARX3LGHNMJ37A6W2WY3H54MRIHEZVTVAZZPUSGZQJ
```

## Events

The registry emits typed Soroban events with `#[contractevent]`:

```text
["proof", "reg", proof_id]        => video_hash, tier, status
["proof", "revoke", proof_id]     => status
["issuer", "add", issuer]         => metadata_hash
["issuer", "revoke", issuer]      => {}
["verif", "set", verifier]        => {}
["credroot", "add", root]         => metadata_hash, issued_at
["credroot", "revoke", root]      => {}
["proof", "history", proof_id]    => action, timestamp, actor, reason_code
["admin", "propose", pending]     => current_admin
["admin", "cancel", pending]      => current_admin
["admin", "accept", new_admin]    => previous_admin
["revroot", "set", root]          => {}
["nonrev", "check", root]         => nullifier, revocation_root
["pause", "set", domain]          => paused_by, paused_at, expires_at
["pause", "clear", domain]        => unpaused_by, unpaused_at
["guardian", "set", guardian]     => {}
["dispute", "open", dispute_id]   => proof_id, reason, reporter_hash, commitment_hash, respond_deadline
["dispute", "respond", dispute_id] => proof_id, response_commitment, resolve_deadline
["dispute", "resolve", dispute_id] => proof_id, resolved_at
["dispute", "dismiss", dispute_id] => proof_id, resolved_at
["dispute", "supersede", dispute_id] => proof_id, superseded_by, resolved_at
["verif", "schedule"]             => active_verifier, pending_verifier, activation_ledger, overlap_window, rollback_window
["verif", "activate"]             => active_verifier, previous_verifier, rollback_window_end
["verif", "rollback"]             => active_verifier, previous_verifier
```

For every successful proof registration, `proof/reg` is emitted before the
corresponding `proof/history` event. Batch registration emits that same pair
for each derived proof in input order. Rejected registrations emit neither
event, so indexers can treat the ordered pair as the registration boundary.

## Lifecycle History (#90)

Every proof carries an append-only history of lifecycle transitions. History
entries are privacy-safe: they contain only `proof_id`, `action`, `timestamp`,
`actor`, and `reason_code`. No `video_hash`, `metadata_hash`, `nullifier`, or
proof bytes are ever stored in history or emitted in history events.

### Actions

```text
Registered  = 1
Verified    = 2
Revoked     = 3
Expired     = 4
Corrected   = 5
TtlUpdated  = 6
```

### Bounds

- `MAX_HISTORY_ENTRIES_PER_PROOF = 256` caps total entries per proof.
- `MAX_HISTORY_LIMIT = 50` caps the maximum number of entries returned by a
  single `get_proof_history` call.

### Query

```text
get_proof_history(proof_id, offset, limit) -> Vec<ProofHistoryEntry>
get_proof_history_count(proof_id) -> u32
```

`offset` is zero-based. `limit` must be `<= MAX_HISTORY_LIMIT`. Entries are
returned in chronological order.

### State Transitions

| Function | Authorization | Effect |
|----------|---------------|--------|
| `verify_proof` | Admin | Records a verification event in history. |
| `expire_proof` | Admin | Sets `status = STATUS_EXPIRED` and records history. Rejects if already expired. |
| `correct_proof` | Admin | Updates `metadata_hash` and records history. Rejects if metadata is unchanged. |

All registration functions and `revoke_proof` automatically record history.

### Privacy Properties

- History entries contain no sensitive proof material.
- Reason codes are bounded `u32` values (`0..=255`); free-text reasons are not accepted.
- The `actor` field records the address that authorized the transition, or `None` for anonymous registrations.
- On-chain history events use the topic `["proof", "history", proof_id]` so indexers can filter without reading contract storage.

### Backward Compatibility

Proofs registered before this feature have zero history entries. `get_proof_history`
returns an empty vector for such proofs. The existing `ProofRecord` schema is unchanged.

## Dispute And Supersession

`open_dispute`, `respond_dispute`, `resolve_dispute`, `dismiss_dispute`,
`supersede_dispute`, `get_dispute`, and `get_open_dispute_count` add a bounded,
auditable dispute/correction state machine. Disputes never modify or delete the
disputed proof and are independent of revocation - a disputed proof can still
report `Valid` from `get_proof_status`. Reporter identity is stored only as a
caller-supplied `reporter_hash` commitment, and events carry commitment hashes
and timestamps only.

Bounds: `MAX_OPEN_DISPUTES_PER_PROOF = 4`, `REPORTER_COOLDOWN_SECS = 86400`,
`RESPOND_DEADLINE_SECS = 604800`, `RESOLVE_DEADLINE_SECS = 1209600`. All new
storage keys (`Dispute`, `ProofOpenDisputeCount`, `ReporterCooldown`) are
additive, so upgrading requires no migration and rollback is a plain wasm
redeploy.

See [DISPUTE.md](DISPUTE.md) for the state machine, error codes, threat notes,
and migration/rollback details.

## Scripts

PowerShell helpers live in `scripts/`:

```text
add-issuer.ps1
add-credential-root.ps1
register-anonymous-verified.ps1
register-source.ps1
register-seal.ps1
revoke-credential-root.ps1
set-verifier.ps1
schedule-verifier-rotation.ps1
activate-verifier-rotation.ps1
rollback-verifier-rotation.ps1
```
