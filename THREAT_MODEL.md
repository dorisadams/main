# Harpocrates Protocol Threat Model

**Version:** 1.2  
**Date:** 2026-09-24  
**Status:** Active  
**Review cadence:** Every major protocol change or at minimum every six months.  
**Maintainer:** See `CODEOWNERS`.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Assets](#2-assets)
3. [Actors and Trust Levels](#3-actors-and-trust-levels)
4. [Deployment Assumptions](#4-deployment-assumptions)
5. [Trust Boundaries](#5-trust-boundaries)
6. [Threat Scenarios](#6-threat-scenarios)
   - [T1 Metadata Spoofing](#t1-metadata-spoofing)
   - [T2 Replay Attacks](#t2-replay-attacks)
   - [T3 Malicious or Compromised Issuers](#t3-malicious-or-compromised-issuers)
   - [T4 Compromised Client / Browser](#t4-compromised-client--browser)
   - [T5 Privacy Leakage](#t5-privacy-leakage)
   - [T6 Backend API Abuse](#t6-backend-api-abuse)
   - [T7 Steganographic Integrity Loss](#t7-steganographic-integrity-loss)
   - [T8 ZK Circuit and Proof Integrity](#t8-zk-circuit-and-proof-integrity)
   - [T9 Admin Key Compromise](#t9-admin-key-compromise)
   - [T10 NeonDB Persistence Integrity](#t10-neondb-persistence-integrity)
   - [T11 Local Credential Vault Compromise](#t11-local-credential-vault-compromise)
7. [Mitigations by Component](#7-mitigations-by-component)
8. [Open Risks and Follow-up Issues](#8-open-risks-and-follow-up-issues)
9. [Non-Goals](#9-non-goals)
10. [Review and Update Cadence](#10-review-and-update-cadence)

---

## 1. Overview

Harpocrates is a Stellar Testnet evidence protocol that registers video integrity
and portable proof metadata under one of three identity tiers:

| Tier | Name | Identity model |
|------|------|----------------|
| 1 | Silent Witness | Anonymous ZK credential — Noir UltraHonk on BN254 |
| 2 | Consistent Source | Pseudonymous Stellar wallet address |
| 3 | Public Seal | Verified institutional issuer address |

The system consists of four cooperating components:

- **harpocrates-registry** — Soroban smart contract on Stellar Testnet that is the
  authoritative, tamper-evident store of all proof records.
- **Flask backend** — HTTP service for video steganography (embed/extract) and
  NeonDB proof-event persistence.
- **React frontend** — Evidence Studio (registration) and Verification Portal
  (lookup), runs entirely in the browser.
- **Noir ZK circuit** (`silent_witness`) — UltraHonk circuit that proves knowledge
  of credential and nullifier secrets without revealing them; proving runs
  client-side in the browser.

The threat model covers the Testnet deployment. A mainnet deployment would
inherit all the same attack surfaces and would additionally require re-evaluation
of every open risk listed in Section 8.

---

## 2. Assets

| ID | Asset | Confidentiality | Integrity | Availability |
|----|-------|-----------------|-----------|--------------|
| A1 | Credential secret (`credential_secret`) | Critical — must never leave the browser | High | Medium |
| A2 | Nullifier secret (`nullifier_secret`) | Critical — must never leave the browser | High | Medium |
| A3 | Video content (evidence file) | High — source may be sensitive | High — hash binds identity | Medium |
| A4 | Embedded video hash (registered on-chain) | Low — public after registration | Critical — chain of custody | High |
| A5 | Proof record on Soroban (ProofRecord) | Low — public | Critical | High (Stellar liveness) |
| A6 | NeonDB proof-event log | Low — semi-public API | Medium | Medium |
| A7 | Steganographic metadata payload | Low — extractable from video | High — integrity verified by hash | Medium |
| A8 | Registry admin keypair | Critical | Critical | High |
| A9 | Issuer keypair (Tier 3) | High | Critical | High |
| A10 | Noir circuit artifacts (`silent_witness.json`) | Low — public | High — circuit upgrade path | Medium |
| A11 | Credential root set (allowlist) | Low | High — gates all Tier 1 proofs | High |
| A12 | Backend `DATABASE_URL` / `METRICS_TOKEN` | Critical | High | Medium |

---

## 3. Actors and Trust Levels

| Actor | Trust level | Description |
|-------|-------------|-------------|
| **Silent Witness** | Untrusted input, ZK-verified identity | Anonymous user who proves credential membership without revealing identity. Secrets stay in the browser. |
| **Consistent Source** | Partially trusted | Any Stellar wallet holder. Identity is pseudonymous; Freighter signs the XDR. |
| **Public Seal Issuer** | Admin-delegated trust | Institutional address explicitly allow-listed by the registry admin. |
| **Registry Admin** | Highest trusted | Holds the Soroban admin key. Controls issuer list, credential roots, verifier contract, proof revocation, and TTL. |
| **Backend operator** | Infrastructure trust | Controls Flask config, `DATABASE_URL`, CORS origins, and `METRICS_TOKEN`. |
| **Verifier / Relying party** | Untrusted consumer | Reads on-chain proof records or calls the Verification Portal. Must not be trusted to supply correct hashes without independent recomputation. |
| **Attacker** | Zero trust | Any actor attempting to forge proofs, replay registrations, spoof metadata, or extract secrets. |

---

## 4. Deployment Assumptions

The following conditions are assumed to be true for the current Testnet deployment.
Each assumption is a potential attack surface if violated.

| ID | Assumption | Risk if violated |
|----|------------|-----------------|
| D1 | The Soroban contract WASM deployed matches `RegistryWasmHash` in README. | Backdoored contract accepts forged proofs. |
| D2 | The `SilentWitnessUltraHonkVerifier` contract address is correct and unmodified. | `register_anonymous_verified` calls the wrong verifier; ZK proofs are not actually checked. |
| D3 | The admin key (`GDVRSXIO4SK2...`) is held by a single trusted operator. | Any admin key leak allows unrestricted contract control. |
| D4 | The Flask backend runs behind TLS in any non-localhost deployment. | Credential secrets sent to `/api/noir/silent-witness` (dev-only path) or metadata hashes in transit can be intercepted. |
| D5 | `CORS_ORIGINS` is set to the exact frontend origin; wildcard is never used without `ALLOW_WILDCARD_CORS=true`. | CORS bypass from arbitrary origins. |
| D6 | `DATABASE_URL` points to a private NeonDB instance not reachable from the public internet without authentication. | Any caller can read the full proof-event log. |
| D7 | Circuit artifacts in `frontend/public/noir/` match the circuit used to generate `RegistryWasmHash`-era verifier keys. | Browser-generated proofs fail on-chain verification or (worse) a stale verifier accepts proofs from a replaced circuit. |
| D8 | Stellar Testnet ledger timestamps are monotonically increasing and not manipulable by a single validator. | Proof TTL enforcement can be bypassed. |
| D9 | ffmpeg/ffprobe binaries on the backend host are from a trusted, unmodified distribution. | Malicious ffmpeg could exfiltrate video frames or corrupt steganographic output. |


---

## 5. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser (user device)                                          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  React frontend                                          │   │
│  │  • credential_secret / nullifier_secret (A1, A2)        │   │
│  │  • seedVault (in-memory only, never serialised)         │   │
│  │  • Noir prover (bb.js + noir_js, runs in WASM)          │   │
│  │  • Freighter extension (XDR signing)                    │   │
│  └──────────┬──────────────────────┬───────────────────────┘   │
│             │ HTTPS (stego API)    │ Stellar RPC / Freighter    │
└─────────────┼──────────────────────┼───────────────────────────┘
              │  TB-1                │  TB-2
  ┌───────────▼──────────┐  ┌───────▼───────────────────────┐
  │  Flask backend       │  │  Stellar Testnet              │
  │  • stego embed/      │  │  • HarpocratesRegistry        │
  │    extract           │  │    (Soroban contract)         │
  │  • NeonDB events     │  │  • UltraHonk verifier         │
  │  • /api/proofs/*     │  │    contract                   │
  └───────────┬──────────┘  └───────────────────────────────┘
              │  TB-3
  ┌───────────▼──────────┐
  │  NeonDB (PostgreSQL) │
  │  proof_events table  │
  └──────────────────────┘
```

**TB-1 Browser → Backend:** The browser sends video bytes and metadata JSON over
HTTPS. Secrets (`credential_secret`, `nullifier_secret`) are **never** included
in any backend call during normal operation. The `/api/noir/silent-witness`
dev-only endpoint accepts secrets but is disabled in production
(`NOIR_WORKER_ENABLED` defaults to `false` when `APP_ENV=production`).

**TB-2 Browser → Stellar:** The Freighter wallet extension signs the XDR
transaction. The browser constructs the transaction but does not hold the
Stellar private key. All on-chain operations are validated by the Soroban VM.

**TB-3 Backend → NeonDB:** The backend writes proof events using parameterized
queries via `psycopg`. `DATABASE_URL` is read from the environment and never
logged. The NeonDB row schema does not store ZK secrets.

**TB-4 Offline local verification (client → nothing):** When the Verification
Portal runs "Offline local check", the browser performs the hash, stego
extraction, structural validation, and file→metadata binding with zero network
calls and no storage or log writes. This boundary produces **no trust
decision**: a verifier must still consult the registry (TB-2) and event feed
(TB-3) to confirm revocation, expiry, or nullifier replay, so offline success
is reported only as a local check with chain/registry status "not checked".
Envelopes carrying secret-shaped keys are rejected before any field is read,
and output copy never carries file names, hashes, or secret material.

---

## 6. Threat Scenarios

Each scenario lists: description, attack vector, affected assets, existing
mitigations (with code references), residual risk, and severity.

---

### T1 Metadata Spoofing

**Description:** An attacker submits a `POST /api/stego/embed` request with a
crafted metadata payload that claims a false tier, a false `sourceHash`, or a
false `proofId` in order to register fraudulent evidence.

**Attack vector:** Unauthenticated HTTP request to the Flask backend.

**Affected assets:** A4, A5, A7.

**Existing mitigations:**

| Mitigation | Location |
|------------|----------|
| Required field check (`protocol`, `version`, `tier`, `sourceHash`, `proofId`, `timestamp`) | `app.py` → `validate_embed_metadata` |
| Tier allowlist (`silent`, `source`, `seal`) | `app.py` → `ALLOWED_TIERS` |
| `sourceHash` and `proofId` must be valid 32-byte hex | `app.py` → `is_hex_32` |
| `protocol` field must equal `"harpocrates"` | `app.py` → `validate_embed_metadata` |
| Canonical metadata hash is computed server-side and returned in `X-Harpocrates-Metadata-Hash` | `stego.py` → `canonical_metadata_hash` |
| On-chain: `register_source` requires caller to `require_auth()` their own Stellar address | `lib.rs` → `register_source` |
| On-chain: `register_seal` requires the issuer to be in the active allowlist | `lib.rs` → `register_seal`, `get_issuer_record` |

**Residual risk:** The backend does not authenticate callers. Any process that
can reach the Flask API can submit embed requests with arbitrary metadata values
that pass field-format validation. The on-chain registration step then enforces
identity — but the steganographic artifact itself (and the NeonDB record) can
be created with spoofed metadata by anyone. This means NeonDB records and
embedded metadata are less trustworthy than on-chain records.

**Severity:** Medium (backend), Low (on-chain after Stellar auth).

---

### T2 Replay Attacks

**Description:** An attacker attempts to re-register the same proof, video hash,
or nullifier to inflate the apparent evidence corpus, suppress legitimate
registrations by pre-occupying unique keys, or link multiple registrations to
the same identity.

**Attack vector:** Direct Soroban contract invocation with a previously seen
`proof_id`, `video_hash`, or `nullifier`.

**Affected assets:** A4, A5.

**Existing mitigations:**

| Mitigation | Location |
|------------|----------|
| `require_unique` panics with `DuplicateProof` if `proof_id` already stored | `lib.rs` → `require_unique` |
| `require_unique` panics with `DuplicateVideo` if `video_hash` already stored | `lib.rs` → `require_unique` |
| Nullifier stored on first use; second use panics with `DuplicateNullifier` | `lib.rs` → `register_anonymous`, `register_anonymous_verified` |
| Nullifier is bound to `(credential_secret, nullifier_secret, video_hash_hi, video_hash_lo)` in circuit | `silent_witness/src/main.nr` → `derived_nullifier` |
| Proof TTL: admin can set a global `ProofTtl`; expired proofs return `ProofVerificationStatus::Expired` | `lib.rs` → `set_proof_ttl`, `get_proof_status` |

**Residual risk:** Nullifier binding is only enforced for Tier 1
(`register_anonymous_verified`). Tier 2 (`register_source`) and Tier 3
(`register_seal`) are replay-protected only by `video_hash` uniqueness — a
different `proof_id` for the same content would currently be rejected by the
`DuplicateVideo` check, but a different video encoding of the same content
would produce a different hash and pass. There is no content-level deduplication.

**Severity:** Low (on-chain uniqueness checks are enforced at the VM level).

---

### T3 Malicious or Compromised Issuers

**Description:** A Tier 3 issuer (Public Seal) that is compromised or turns
malicious signs fraudulent video registrations, lending institutional credibility
to fabricated evidence.

**Attack vector:** Issuer invokes `register_seal` with a fabricated `video_hash`
and `metadata_hash` for content they did not actually review.

**Affected assets:** A5, A9.

**Existing mitigations:**

| Mitigation | Location |
|------------|----------|
| Issuer must be in the active allowlist (`add_issuer`) before any seal registration | `lib.rs` → `get_issuer_record` |
| Admin can revoke a compromised issuer at any time (`revoke_issuer`) | `lib.rs` → `revoke_issuer` |
| `IssuerRevoked` event is emitted on chain | `lib.rs` → `IssuerRevoked` struct |
| `register_seal` requires `issuer.require_auth()` — the issuer's Stellar keypair must sign | `lib.rs` → `register_seal` |
| Typed `IssuerAdded` / `IssuerRevoked` events enable off-chain monitoring | `lib.rs` → event structs |

**Control (#357):** The `revocation_witness` Merkle tree is protocol-bounded at
`MAX_REVOCATION_WITNESS_DEPTH = 3` (`MAX_REVOCATION_LEAVES = 8`). The Noir
circuit is fixed at this depth; host tooling (`zk/tools/revocation_depth.py`,
verifier codec) rejects oversized depth before proving so hostile trees cannot
inflate witness size or proving cost at this boundary. Depth changes require a
new circuit version.

**Residual risk:** Revocation is reactive, not proactive. Records registered
before revocation remain `STATUS_REGISTERED` on-chain. The admin must manually
call `revoke_proof` for each fraudulent record — there is no bulk revocation.
The `metadata_hash` stored in the issuer's `IssuerRecord` is not verified by
the contract to match the `metadata_hash` in the proof registration; an issuer
can register a proof with a `metadata_hash` that differs from their declared
issuer metadata.

**Severity:** Medium.

---

### T4 Compromised Client / Browser

**Description:** An attacker gains code-execution access to the user's browser
(via XSS, malicious extension, or supply-chain compromise of the frontend bundle)
and attempts to exfiltrate `credential_secret` or `nullifier_secret`, or to
substitute a different transaction for the user to sign in Freighter.

**Attack vector:** XSS in the React app, malicious browser extension,
compromised CDN / npm package.

**Affected assets:** A1, A2, A3.

**Existing mitigations:**

| Mitigation | Location |
|------------|----------|
| Secrets held only in React state (never written to `localStorage`, `sessionStorage`, or cookies) | `frontend/src/seedVault.ts` → `createClearSeeds` |
| Secrets are cleared from state after proof generation completes | `frontend/src/seedVault.ts` → `createClearSeeds` |
| Credential and nullifier secrets are reduced modulo BN254 field order before use, preventing trivially large-value probing | `frontend/src/seedVault.ts` → `fieldSecret` |
| Network passphrase guard blocks signing on wrong network | `frontend/src/networkGuard.ts` → `checkNetworkMatch` |
| Content-Security-Policy is not set by the Flask backend (frontend is served separately via nginx per Dockerfile) | `frontend/nginx.conf` |
| The Noir prover runs entirely in the browser — secrets are never sent to the backend in production | `frontend/src/noirClient.ts` → `generateSilentWitnessProof` |

**Residual risk:** The application does not set a `Content-Security-Policy` header
that would mitigate XSS. If XSS is achieved, in-memory secrets can be read by
injected scripts before they are cleared. Freighter signs whatever XDR the page
presents; a compromised page can substitute a different transaction (e.g., a
different `video_hash`). Users must trust the Freighter extension itself. The
npm dependency surface (Aztec `bb.js`, `@noir-lang/*`, `@stellar/stellar-sdk`,
`@stellar/freighter-api`) is large and represents a significant supply-chain
attack surface.

**Severity:** High (if browser is compromised — inherent to client-side proving
model). Medium (for CSP omission alone).

---

### T5 Privacy Leakage

**Description:** An observer links a Silent Witness registration to a real-world
identity by correlating on-chain data, NeonDB records, network metadata, or the
structure of the steganographic payload.

**Attack vector:** Passive on-chain observation, NeonDB API enumeration,
network traffic analysis.

**Affected assets:** A1, A2, A3.

**Existing mitigations:**

| Mitigation | Location |
|------------|----------|
| Nullifier is a Pedersen hash of `(credential_secret, nullifier_secret, video_hash_hi, video_hash_lo)` — does not reveal the secret | `silent_witness/src/main.nr` |
| `credential_root` is a Pedersen hash of `credential_secret` alone — different roots are unlinkable without the secret | `silent_witness/src/main.nr` |
| No `source` address stored for Tier 1 registrations | `lib.rs` → `register_anonymous_verified` (source: None) |
| Sensitive keys (`credentialSecret`, `nullifierSecret`, `proof`, `publicInputs`, `authorization`) are redacted from backend logs | `logging_utils.py` → `SENSITIVE_KEYS` |
| `/api/noir/silent-witness` disabled in production (`NOIR_WORKER_ENABLED=false`) | `config.py` → `noir_worker_enabled` |

**Residual risk:** The `credential_root` value is stored on-chain and in NeonDB.
If the same `credential_root` appears in multiple registrations across different
video hashes, an observer can link them to the same credential (the same
`credential_secret`). This is by design for consistent pseudonymity, but it means
a Silent Witness who reuses their credential across many registrations becomes
progressively more identifiable via on-chain graph analysis.

NeonDB stores the IP-level origin of embed/extract requests implicitly through
PostgreSQL connection logs and any upstream reverse-proxy access logs. These
are outside the application's control.

The steganographic payload is embedded in plaintext (zlib-compressed JSON) —
anyone with the video can extract the full metadata including `proofId`,
`tier`, and `timestamp`. This is intentional (verifiers must be able to extract
it), but it means evidence submitted for a Silent Witness registration still
carries a readable metadata trail in the video file itself.

**Severity:** Medium.


---

### T6 Backend API Abuse

**Description:** An attacker floods the Flask backend with large video uploads,
rapid embed/extract requests, or crafted payloads to exhaust CPU/memory, corrupt
the NeonDB event log, or inject malicious data into the proof record.

**Attack vector:** Unauthenticated HTTP POST to `/api/stego/embed`,
`/api/stego/extract`, or `/api/proofs/register`.

**Affected assets:** A6, A3.

**Existing mitigations:**

| Mitigation | Location |
|------------|----------|
| `MAX_CONTENT_LENGTH` enforced at Flask layer (300 MB default); `RequestEntityTooLarge` returns 413 | `app.py` → `create_app`, `config.py` |
| Video size independently capped at 250 MB (`MAX_VIDEO_BYTES`) | `app.py` → `_enforce_video_size` |
| Metadata JSON capped at 16 KB (`MAX_METADATA_BYTES`) | `app.py` → embed route |
| Generic JSON payloads capped at 1 MB (`MAX_JSON_BYTES`) | `app.py` → `_enforce_json_size` |
| Video `content_type` must start with `video/` or be `application/octet-stream` | `app.py` → `validate_video_upload` |
| `secure_filename` (Werkzeug) prevents path traversal via `fileName` | `app.py` → `safe_filename` |
| `field_decimal` bounds check prevents out-of-range BN254 field values reaching the Noir worker | `app.py` → `is_field_decimal` |
| Parameterized SQL via `psycopg` prevents SQL injection in all DB writes | `db.py` → `insert_proof_event` |
| `limit` parameter on `GET /api/proofs` is clamped to [1, 100] | `db.py` → `list_proof_events` |
| Metrics endpoint is token-gated (`METRICS_TOKEN`) | `app.py` → `metrics` route |
| Request IDs (`X-Request-ID`) enable per-request tracing | `app.py` → `start_request_context` |
| Per-client rate limits on embed/extract/register/noir and upload-session create/chunk/commit, keyed on the real client IP | `app.py` → `@limiter.limit`, `config.py` |
| `Retry-After` + `X-RateLimit-*` hints and a JSON `RATE_LIMITED` envelope carrying `request_id` | `app.py` → `rate_limit_exceeded` |

**Residual risk:** Per-client rate limits are enforced per endpoint, but the
default in-process store (`memory://`) is not shared across workers, so counters
must be backed by a shared store in multi-worker or multi-replica deployments.
`TRUSTED_PROXIES` must be configured behind a reverse proxy, otherwise every
request keys on the proxy address. Video processing (ffmpeg frame pipeline) is
still CPU and memory intensive; a few concurrent large-video requests can
saturate a single worker.
`POST /api/proofs/register` has no authentication at all — any caller can insert
arbitrary (but format-validated) rows into `proof_events`. This means NeonDB
cannot be used as a trusted audit log for on-chain activity.

**Severity:** High (no rate limiting). Medium (unauthenticated register endpoint).

---

### T7 Steganographic Integrity Loss

**Description:** The embedded metadata in a video is destroyed or altered by
transcoding, re-encoding, platform compression, or deliberate pixel manipulation,
making the video unverifiable even though the on-chain record remains valid.

**Attack vector:** Any video processing pipeline (social media upload, format
conversion, lossy re-encode) applied to the embedded video after it leaves the
Evidence Studio.

**Affected assets:** A3, A7.

**Existing mitigations:**

| Mitigation | Location |
|------------|----------|
| Dual-channel embedding: border-block channel (more robust) with LSB fallback | `stego.py` → `embed_metadata`, `extract_metadata` |
| MAGIC header (`HRPSTG1`) gates payload parsing — corrupt/partial data returns `None` | `stego.py` → `_unpack_payload` |
| SHA-256 checksum over the compressed payload body; checksum mismatch returns `None` | `stego.py` → `_pack_payload`, `_unpack_payload` |
| zlib compression reduces payload size, increasing headroom before capacity limit | `stego.py` → `_pack_payload` |
| `X-Harpocrates-Embedded-Hash` is the hash of the post-embed file; verifiers hash their received copy and look that up on-chain | `app.py` → embed route response headers |

**Residual risk:** Both LSB and border-block channels are fragile against any
lossy re-encoding (H.264 at lower CRF, VP9, HEVC) or platform thumbnail/preview
re-encode. The on-chain `video_hash` is the hash of the exact embedded file
returned by the backend. If the video is transcoded, neither channel will
survive and extraction will return `None`. The on-chain record remains valid —
the problem is that the verifier cannot confirm the received video matches the
registered hash without the original embedded file.

There is no out-of-band integrity proof (e.g., a Merkle root of the raw frames)
that would survive transcoding. This is a known limitation of steganographic
approaches.

**Severity:** Medium (inherent to the steganographic approach; documented
limitation).

---

### T8 ZK Circuit and Proof Integrity

**Description:** An attacker submits a forged or trivially-satisfied ZK proof to
`register_anonymous_verified`, bypasses the verifier, or exploits the
`register_anonymous` stub path that does not call the real verifier contract.

**Attack vector:** Direct Soroban contract invocation with crafted `proof` and
`public_inputs` bytes; or use of `register_anonymous` instead of
`register_anonymous_verified`.

**Affected assets:** A5, A10, A11.

**Existing mitigations:**

| Mitigation | Location |
|------------|----------|
| `register_anonymous_verified` calls the external `SilentWitnessUltraHonkVerifier` contract via `verify_external_proof` | `lib.rs` → `verify_external_proof` |
| Public inputs are parsed and validated to be exactly 128 bytes (4 × 32-byte fields) | `lib.rs` → `parse_silent_witness_public_inputs` |
| `video_hash` extracted from public inputs is compared to the caller-supplied `video_hash` parameter | `lib.rs` → `register_anonymous_verified` |
| `credential_root` extracted from public inputs must be in the active allowlist | `lib.rs` → `require_active_credential_root` |
| Nullifier from public inputs is stored and replay-checked | `lib.rs` → `DuplicateNullifier` |
| Circuit enforces `derived_root == credential_root` and `derived_nullifier == nullifier` | `silent_witness/src/main.nr` |
| Circuit tests cover tampered public inputs, swapped fields, wrong video hash, and nullifier from different video | `silent_witness/src/main.nr` → test corpus |
| `credential_root` metadata is stored per-root so admin can audit which roots are active | `lib.rs` → `CredentialRootRecord` |

**Residual risk:**

1. **`register_anonymous` uses a stub verifier.** The function `verify_demo_zk_boundary`
   only checks that the proof bytes are non-empty and the credential root is 32 bytes.
   It does not call the real verifier contract. Any caller with an active
   `credential_root` and a non-empty `proof` byte string can register as a Silent
   Witness via this path without a valid ZK proof. This is a **critical open risk**
   for any context where Tier 1 anonymity guarantees matter.
   See [Open Risk OR-1](#or-1-register_anonymous-stub-verifier).

2. The `credential_root` stored in `CredentialRootRecord.metadata_hash` is an
   admin-supplied label, not a hash verified by the circuit. An admin could add
   a misleading `metadata_hash` for a credential root without on-chain enforcement.

3. Circuit artifact versioning: the compiled `silent_witness.json` in
   `frontend/public/noir/` must match the verifier contract's proving key. There
   is no on-chain mechanism to detect or enforce this alignment.

**Severity:** Critical (OR-1 stub path). Low (verified path via `register_anonymous_verified`).

---

### T9 Admin Key Compromise

**Description:** The registry admin's Stellar keypair is leaked or stolen,
giving an attacker full control over the Soroban registry: they can add/revoke
issuers and credential roots, set the verifier to a malicious contract, revoke
legitimate proofs, or transfer admin to themselves.

**Attack vector:** Keypair exfiltration from developer workstation, leaked
`.env` / shell history, or compromised CI/CD secrets.

**Affected assets:** A8, A5, A11.

**Existing mitigations:**

| Mitigation | Location |
|------------|----------|
| Two-step admin transfer: `propose_admin` + `accept_admin` — new admin must actively sign | `lib.rs` → `propose_admin`, `accept_admin` |
| `cancel_admin_transfer` allows the current admin to abort a pending transfer | `lib.rs` → `cancel_admin_transfer` |
| All admin operations emit typed on-chain events (`AdminProposed`, `AdminAccepted`, etc.) | `lib.rs` → event structs |
| `require_admin` validates both that the stored admin matches and that the caller has signed | `lib.rs` → `require_admin` |

**Residual risk:** The admin is a single Stellar keypair with no multisig or
threshold signing. Any single-point compromise gives an attacker complete control.
There is no time-lock or cooldown on admin operations — a compromised admin can
immediately revoke all credential roots, replacing them with attacker-controlled
roots, and set a malicious verifier contract.

On-chain events provide an audit trail but there is no off-chain alerting that
would detect suspicious admin operations in real time.

**Severity:** High.

---

### T10 NeonDB Persistence Integrity

**Description:** An attacker inserts fraudulent rows into `proof_events` by
calling `POST /api/proofs/register` without authentication, making the NeonDB
log appear to show more registrations than actually occurred on-chain, or
associating a fraudulent `txHash` with a legitimate video hash.

**Attack vector:** Unauthenticated `POST /api/proofs/register` from any
network-reachable host.

**Affected assets:** A6.

**Existing mitigations:**

| Mitigation | Location |
|------------|----------|
| `videoHash`, `metadataHash`, `proofId` validated as 32-byte hex strings | `app.py` → `register_proof_event` |
| `tier` not validated against allowlist on this path (informational only) | — |
| Payload size capped at 1 MB | `app.py` → `_enforce_json_size` |
| `safe_filename` prevents path traversal via `fileName` | `app.py` → `safe_filename` |
| Parameterized SQL prevents injection | `db.py` → `insert_proof_event` |

**Residual risk:** The endpoint has no authentication, HMAC, or bearer token.
Any caller that can reach the Flask API can write arbitrary rows. The
`txHash` and `txStatus` fields are stored as-is without verifying them against
the Stellar network. NeonDB records therefore cannot serve as a trusted
secondary source of truth — they are best treated as a convenience cache that
must be reconciled against on-chain data for any security-sensitive decision.

**Severity:** Medium (NeonDB is secondary; Soroban is authoritative).


---

### T11 Local Credential Vault Compromise

**Description:** An attacker with local access to the user's device attempts to extract credential or nullifier seeds from `localStorage` or memory, potentially decrypting them to spoof the identity.

**Attack vector:** Malicious browser extension, cross-site scripting (XSS), or physical device access.

**Affected assets:** A1, A2.

**Existing mitigations:**

| Mitigation | Location |
|------------|----------|
| Seeds are encrypted in `localStorage` via AES-GCM and PBKDF2 | `credentialVault.ts` → `setup` |
| Vault automatically locks after 15 minutes of inactivity | `credentialVault.ts` → `resetTimeout` |
| Explicit zeroization when locking or destroying the vault | `credentialVault.ts` → `lock`, `destroy` |
| Only the encrypted envelope is persisted, not plaintext seeds | `safeStorage.ts` |

**Residual risk:** Memory scraping by highly privileged malware or malicious browser extensions could potentially read the derived `CryptoKey` or decrypted seeds while the vault is temporarily unlocked. XSS could invoke the vault's unlock method if the password was somehow intercepted (e.g. keylogger).

**Severity:** Low (relies on broader device/browser compromise which is out of scope).

---

## 7. Mitigations by Component

### 7.1 Soroban Contract (`harpocrates-registry`)

| Mitigation | Threats addressed | Code reference |
|------------|------------------|----------------|
| `require_admin` — admin address check + `require_auth()` on every privileged call | T9 | `lib.rs` → `require_admin` |
| Two-step admin transfer (`propose_admin` / `accept_admin` / `cancel_admin_transfer`) | T9 | `lib.rs` → `propose_admin`, `accept_admin` |
| `require_unique` — `DuplicateProof` and `DuplicateVideo` errors | T2 | `lib.rs` → `require_unique` |
| Nullifier set on first use, `DuplicateNullifier` on replay | T2 | `lib.rs` → `DataKey::Nullifier` |
| Credential root allowlist with active/revoked status | T1, T8 | `lib.rs` → `add_credential_root`, `revoke_credential_root` |
| Issuer allowlist with active/revoked status | T3 | `lib.rs` → `add_issuer`, `revoke_issuer` |
| External verifier contract hook (`verify_external_proof`) | T8 | `lib.rs` → `verify_external_proof` |
| Public input parsing with exact-length enforcement (128 bytes) | T8 | `lib.rs` → `parse_silent_witness_public_inputs` |
| `video_hash` cross-check between public inputs and call argument | T8 | `lib.rs` → `register_anonymous_verified` |
| Proof TTL / expiration (`set_proof_ttl`, `get_proof_status`) | T2 | `lib.rs` → `compute_expires_at`, `get_proof_status` |
| Admin proof revocation (`revoke_proof`) | T3 | `lib.rs` → `revoke_proof` |
| Typed contract events for all lifecycle operations | T3, T9 | `lib.rs` → event structs |

### 7.2 Flask Backend

| Mitigation | Threats addressed | Code reference |
|------------|------------------|----------------|
| CORS origin allowlist; wildcard blocked without explicit env flag | T6 | `config.py` → `load_config`, `app.py` → `CORS` |
| Security response headers (`X-Content-Type-Options`, `Referrer-Policy`, `CORP`, `Cache-Control`) | T4, T6 | `app.py` → `process_response` |
| `MAX_CONTENT_LENGTH` + `MAX_VIDEO_BYTES` + `MAX_METADATA_BYTES` + `MAX_JSON_BYTES` | T6 | `config.py`, `app.py` |
| Video content-type validation | T6 | `app.py` → `validate_video_upload` |
| Embed metadata field validation (required keys, tier allowlist, hex32 format) | T1 | `app.py` → `validate_embed_metadata` |
| `secure_filename` (Werkzeug) for `fileName` | T6 | `app.py` → `safe_filename` |
| BN254 field bounds check on `credentialSecret` / `nullifierSecret` | T6 | `app.py` → `is_field_decimal` |
| Parameterized SQL (psycopg) for all DB writes | T6, T10 | `db.py` → `insert_proof_event` |
| Sensitive key redaction in structured logs | T5 | `logging_utils.py` → `SENSITIVE_KEYS` |
| Noir worker disabled in production (`NOIR_WORKER_ENABLED=false`) | T4, T5 | `config.py` → `noir_worker_enabled` |
| Metrics endpoint token-gated | T6 | `app.py` → `metrics` |
| Request IDs for tracing | T6 | `app.py` → `start_request_context` |
| Steganographic MAGIC header + SHA-256 checksum on payload | T7 | `stego.py` → `_pack_payload`, `_unpack_payload` |
| Dual-channel embedding (border + LSB) | T7 | `stego.py` → `embed_metadata` |
| Quarantine directory and signature scanning (magic bytes) | T6 | `quarantine.py` → `isolate_upload`, `SignatureScanner` |
| Sandboxed ffmpeg execution (resource profiles, timeouts, and sanitized errors) | T6 | `stego.py` → `_start_decode`, `_start_encode`, `_kill_after_timeout` |
| AST-based API Schema generation prevents DB injections and application state side-effects during build/CI | T6, T10 | `devx/generate_api_schema.py` |


### 7.3 React Frontend

| Mitigation | Threats addressed | Code reference |
|------------|------------------|----------------|
| Seeds held only in React state or encrypted Vault; plaintext never written to persistent storage | T4, T5, T11 | `seedVault.ts`, `credentialVault.ts` |
| Seeds cleared after proof generation or vault inactivity | T4, T5, T11 | `seedVault.ts`, `credentialVault.ts` |
| BN254 field modulus reduction on credential/nullifier secrets | T4 | `seedVault.ts` → `fieldSecret` |
| Browser-side Noir proving — secrets never sent to server in production | T4, T5 | `noirClient.ts` → `generateSilentWitnessProof` |
| **Worker-isolated proving** — Noir proving runs in a dedicated Web Worker which is explicitly terminated upon success, failure, timeout, or cancellation. This guarantees the browser reclaims the memory hardware-isolate and drops all secrets reliably, rather than depending on GC. | T4, T5 | `proveWorker.ts`, `noirClient.ts` |
| Network passphrase guard (blocks wrong Stellar network) | T1 | `networkGuard.ts` → `checkNetworkMatch` |
| Offline local verification — zero network calls, no storage/log writes, and never a confirmed trust decision; envelope extraction reuses the existing single stego loader (no second protocol truth) and secret-shaped envelopes are rejected up-front | T4, T5 | `offlineVerification.ts`, `useVerification.ts` |
| Hex normalization and validation on all hash inputs | T1, T8 | `stellarEncoding.ts` → `asHex32`, `asHexBytes` |
| `CONTRACT_NETWORK_PASSPHRASE` exported constant used by guard | T1 | `harpocratesRegistry.ts` |

### 7.4 Noir ZK Circuit (`silent_witness`)

| Mitigation | Threats addressed | Code reference |
|------------|------------------|----------------|
| `assert(derived_root == credential_root)` — proves knowledge of `credential_secret` | T8 | `silent_witness/src/main.nr` |
| `assert(derived_nullifier == nullifier)` — binds nullifier to secrets + video hash | T2, T8 | `silent_witness/src/main.nr` |
| Nullifier commits to `(credential_secret, nullifier_secret, video_hash_hi, video_hash_lo)` | T2, T5 | `silent_witness/src/main.nr` |
| Test corpus: tampered public inputs, wrong video hash, swapped fields, cross-video nullifier | T2, T8 | `silent_witness/src/main.nr` → test functions |


---

## 8. Open Risks and Follow-up Issues

The items below are confirmed gaps between the current implementation and the
security properties the protocol claims. Each is labelled with a severity and
a suggested remediation. They should be tracked as issues in the project issue
tracker and linked back here when resolved.

---

### OR-1 `register_anonymous` Stub Verifier

**Severity:** Critical  
**Component:** Soroban contract  
**Description:** `register_anonymous` calls `verify_demo_zk_boundary`, which
only checks that `proof.len() > 0` and `credential_root.len() == 32`. It does
not invoke the `SilentWitnessUltraHonkVerifier` contract. Any caller with an
active credential root can register as a Silent Witness with a fake proof.  
**Code reference:** `lib.rs` → `verify_demo_zk_boundary`  
**Remediation:** Either remove `register_anonymous` entirely (routing all Tier 1
registrations through `register_anonymous_verified`) or gate it behind a
dedicated feature flag that is disabled by default. Add a contract test that
confirms a zero-length or trivially-constructed proof is rejected.

---

### OR-2 Backend API Rate Limiting

**Severity:** Low (residual)  
**Component:** Flask backend  
**Description:** Per-client rate limits now guard the upload and proof endpoints
via `flask-limiter`, keyed on the real client IP. The remaining risk is
deployment shape: the default `memory://` store is per-process, so limits must
be backed by a shared store (`RATELIMIT_STORAGE_URI`) when running more than one
worker or replica.  
**Remediation:** Configure `RATELIMIT_STORAGE_URI` (e.g. Redis) and
`TRUSTED_PROXIES` for multi-worker deployments; consider a signed request token
for embed operations.

---

### OR-3 Unauthenticated `POST /api/proofs/register`

**Severity:** Medium  
**Component:** Flask backend / NeonDB  
**Description:** The `/api/proofs/register` endpoint writes rows to `proof_events`
with no authentication. Any caller can insert a row claiming any `txHash` for
any `videoHash`. NeonDB records cannot be used as a trusted secondary source.  
**Remediation:** Require a bearer token (e.g., `REGISTER_TOKEN` env var) or
HMAC-signed payload on this endpoint. Alternatively, remove it and have the
frontend write directly to a separate authenticated events service.

---

### OR-4 Steganography Not Tamper-Evident Against Transcoding

**Severity:** Medium  
**Component:** Steganography (stego.py / frontend)  
**Description:** Both the border-block and LSB embedding channels are destroyed
by any lossy re-encode. Once the embedded metadata is lost, the video cannot be
linked to its on-chain record without the original file.  
**Remediation:** Document this limitation prominently in the user-facing UI
(warn users to preserve the original embedded file). As a future enhancement,
consider embedding a Merkle root of raw frame hashes into a sidecar file or
using a watermarking technique that is more robust to re-encoding.

---

### OR-5 Circuit Artifact Version Alignment

**Severity:** Medium  
**Component:** Frontend / Soroban verifier contract  
**Description:** The compiled circuit artifacts in `frontend/public/noir/`
(`silent_witness.json`, `silent_witness_helper.json`) must match the proving
key embedded in the `SilentWitnessUltraHonkVerifier` contract. There is no
on-chain or build-time check that enforces this alignment. A circuit upgrade
that replaces the verifier contract without updating the frontend artifacts (or
vice versa) will silently break all Tier 1 registrations.  
**Remediation:** Add a build-time check (CI step) that computes a hash of
`silent_witness.json` and compares it to a value stored alongside the verifier
contract's WASM hash. Document the circuit upgrade procedure in
`contracts/VERIFIER_INTEGRATION.md`.

---

### OR-6 Admin Key Single Point of Failure

**Severity:** High  
**Component:** Soroban contract  
**Description:** The registry admin is a single Stellar keypair. Compromise or
loss of this key gives an attacker (or leaves the protocol with) permanent
control over the registry. The two-step transfer mechanism protects against
accidental transfers but not against key exfiltration.  
**Remediation:** Migrate the admin to a Stellar multisig account (M-of-N
signers) before any mainnet or high-value deployment. Until then, keep the
admin key in a hardware wallet or HSM and rotate it immediately on any suspected
compromise.

---

### OR-7 No Content-Security-Policy Header

**Severity:** Medium  
**Component:** React frontend (nginx)  
**Description:** The nginx config (`frontend/nginx.conf`) does not set a
`Content-Security-Policy` header. A successful XSS attack has an unrestricted
execution context and can read in-memory secrets before they are cleared.  
**Remediation:** Add a strict CSP that restricts script sources to `'self'` and
the specific CDN hashes required by the Noir WASM bundle. Set
`X-Frame-Options: DENY` and `X-XSS-Protection: 0`.

---

### OR-8 `credential_root` `metadata_hash` Not Circuit-Verified

**Severity:** Low  
**Component:** Soroban contract  
**Description:** The `CredentialRootRecord.metadata_hash` is an admin-supplied
label stored alongside the credential root. The Noir circuit does not verify any
relationship between the credential root and this hash. An admin can associate
a misleading label without on-chain enforcement.  
**Remediation:** Document that `metadata_hash` is an advisory label only. If
stronger binding is needed, extend the circuit to commit to a metadata hash as
an additional public input and verify it in `register_anonymous_verified`.

---

### OR-9 No Audit Log for Admin Operations Beyond Events

**Severity:** Low  
**Component:** Soroban contract  
**Description:** Admin operations (add/revoke issuer, add/revoke credential root,
set verifier, transfer admin) emit typed contract events, but there is no
off-chain alerting or monitoring infrastructure that watches for these events
in real time.  
**Remediation:** Set up a Stellar event stream monitor (e.g., via
`soroban events` CLI or a webhook) that alerts the admin team whenever a
privileged contract event is emitted.

---

### OR-11 Unbounded External Evidence Fetch

**Severity:** Medium — **Resolved** in #287  
**Component:** Flask backend (`tx_verification.py`, `webhook.py`)  
**Description:** The backend makes outbound HTTP calls to two external systems:

1. **Stellar Horizon** — `tx_verification_loop` polls
   `/transactions/{tx_hash}` on `horizon-testnet.stellar.org` to resolve
   pending transaction statuses.
2. **Webhook subscribers** — `dispatch_webhook` `POST`s evidence events to
   operator-configured subscriber URLs.

Prior to this fix both calls used `urllib.request.urlopen(req, timeout=10)`.
A single `timeout=` value covers only the *read* phase in Python's
implementation; the TCP+TLS connect phase was unlimited. Additionally, the full
response body was buffered without a size cap, allowing a malicious or
misbehaving remote host to stall the worker indefinitely or exhaust heap memory
with an arbitrarily large response.

Privacy implication: pre-fix log lines included the raw transaction hash and
the subscriber URL in WARNING-level messages, which could leak correlation data
into log aggregation systems.

**Mitigations implemented** (`backend/fetch_external.py` + callers):

| Property | Mechanism | Default |
|----------|-----------|---------|
| Connect timeout | `socket_timeout = max(connect, read)` passed to `urlopen` | 5 s |
| Read timeout | Same `socket_timeout` covers each `recv` call | 10 s |
| Response-size cap | Chunked read with hard limit; raises `ResponseTooLargeError` | 64 KiB |
| Privacy-safe logging | URLs and tx-hashes logged at DEBUG only; WARNING messages log `host` only | — |
| Config-driven | Three new `AppConfig` fields (`EXTERNAL_FETCH_CONNECT_TIMEOUT_SECONDS`, `EXTERNAL_FETCH_READ_TIMEOUT_SECONDS`, `EXTERNAL_FETCH_MAX_RESPONSE_BYTES`) override defaults via env vars | — |

**Compatibility:** Existing callers pass no new arguments; all three parameters
default to the values that were previously hard-coded. No API or protocol
surface change.

**Rollback:** Remove `fetch_external.py`, revert `tx_verification.py` and
`webhook.py` to direct `urlopen` calls, and remove the three new config fields.
No database migration required.

---

### OR-12 Threshold Seal Policy Governance

**Severity:** Medium  
**Component:** Soroban contract  
**Description:** The m-of-n threshold seal policy introduces a governance layer
where multiple independent institutional issuers must approve a proof before
finalization. Risks include:
- A compromised admin key can create a policy with `required_approvals = 1`,
  bypassing the threshold requirement entirely.
- Approval TTL expiry windows may allow stale approvals to be counted if not
  properly validated.
- Issuer revocation between approval and finalization must be handled atomically
  to prevent partial-threshold seals.
**Mitigations implemented:**
- Policies are admin-only (inherits OR-6 admin trust assumption).
- Approvals from revoked issuers are excluded from the active count.
- Expired approvals are excluded by timestamp comparison.
- Finalization is atomic: threshold check and proof registration occur in a
  single Soroban transaction.
- `MAX_SIGNERS = 16` bounds storage consumption per policy.
- `DEFAULT_APPROVAL_TTL_SECS = 86_400` (1 day) provides a safe default.
- Backward compatibility: existing single-issuer `register_seal` is preserved.

---

## 9. Non-Goals

The following are explicitly outside the scope of this threat model:

- **Stellar network-level attacks** — validator collusion, eclipse attacks,
  or consensus-layer manipulation of the Testnet. The protocol inherits Stellar's
  security assumptions.
- **Physical access attacks** — an attacker with physical access to the user's
  device can extract browser memory or private keys regardless of application
  controls.
- **Legal and operational coercion** — compelled disclosure of credentials or
  admin keys by law enforcement or other authorities.
- **NeonDB infrastructure security** — the NeonDB platform's own access controls,
  encryption at rest, and SLA are out of scope. The application assumes the
  managed database provider's security posture is adequate.
- **Freighter extension security** — vulnerabilities in the Freighter browser
  extension itself are out of scope. Users must trust the extension they install.
- **Video content authenticity** — the protocol records the integrity of a given
  video file (the hash matches) but makes no claim about the content of the
  video (it could still be deepfaked or edited before hashing).
- **Mainnet deployment** — this model covers the Testnet deployment only. A
  mainnet deployment requires re-evaluation of every open risk, particularly
  OR-1 (stub verifier), OR-6 (admin key), and OR-2 (rate limiting).
- **Dependency vulnerability management** — routine CVE scanning and patching
  of npm and Python dependencies is a continuous operations concern, not
  addressed here.
- **Validating Silent Witness proof bytes offline** — offline local verification
  checks hash, envelope structure, and file binding only. Proof-byte validation
  requires the UltraHonk verifier (contract or WASM with the matching circuit
  artifact) and is intentionally not performed in offline mode; it is also not
  embedded into the canonical metadata, so no second protocol truth is created.

---


---

## 9.1 Privacy-Safe Backend Trace Fields

**Artifact:** `backend/trace_fields.py` (`harpocrates-trace-v1`)

Backend request logs and `/health`/`/ready` responses may carry opaque
correlation identifiers (`request_id`, `trace_id`, `span_id`,
`correlation_id`) plus a sanitized `endpoint_pattern`.

| Property | Guarantee |
|----------|-----------|
| Trust boundary | Public HTTP edge and structured logs only |
| Allowed | Opaque IDs, W3C `traceparent` (v00), sanitized routes, versioned ID tags |
| Forbidden | Media bytes, proofs, witness values, private keys, secrets, raw IPs, raw User-Agent |
| Malformed / oversized headers | Ignored; generated opaque IDs substituted |
| Cross-origin propagation | `http_security.CORS_ALLOW_HEADERS` accepts the trace headers; `CORS_EXPOSE_HEADERS` lets browser clients read the echoed IDs |
| Migration | Additive; existing `request_id` header/log field retained |
| Rollback | Stop emitting extended fields; callers keep `request_id` |

## 9.2 Per-Client Upload Rate Limits

**Artifact:** `backend/app.py`, `backend/config.py` (flask-limiter)

Per-client rate limits are enforced at the Flask request boundary for the
upload and proof endpoints.

| Property | Guarantee |
|----------|-----------|
| Trust boundary | Public HTTP edge; key is the real client IP, never raw forwarded headers |
| Default windows | embed/extract/register 30/min, silent-witness 20/min, upload-session 60/min, chunk 240/min |
| Failure response | Stable JSON `RATE_LIMITED` envelope with `request_id`; `Retry-After` + `X-RateLimit-*` headers |
| Privacy | Counters and logs never include media bytes, witness values, secrets, or raw forwarded headers |
| Malformed input | Oversized/unknown paths still counted per client; spoofed `X-Forwarded-For` ignored unless the peer is a trusted proxy |
| Migration | Additive; `RATELIMIT_ENABLED=false` disables the layer without changing routes |
| Rollback | Remove `@limiter.limit` decorators; endpoints behave as before |

## 10. Review and Update Cadence

| Trigger | Action |
|---------|--------|
| Any change to the Soroban contract interface or WASM | Re-review Sections 6 and 7.1; update D1/D2 assumptions. |
| Any change to the Noir circuit (`silent_witness`) | Re-review T8, OR-5; update D7 assumption. |
| Circuit artifact update in `frontend/public/noir/` | Verify alignment with deployed verifier contract; update OR-5 status. |
| New backend endpoint or authentication change | Re-review T1, T6, T10. |
| Admin key rotation | Update D3; verify two-step transfer completed cleanly. |
| Any new npm or Python dependency with network access | Assess supply-chain risk (T4). |
| Scheduled review | Every six months from the date of last update, regardless of changes. |

When updating this document, increment the version number, update the date, and
add a one-line change summary below:

| Version | Date | Summary |
|---------|------|---------|
| 1.0 | 2026-07-24 | Initial threat model. Covers all four components. Nine open risks identified. |
| 1.1 | 2026-07-26 | Add OR-10: Threshold seal policy governance (m-of-n Public Seal). |
| 1.2 | 2026-09-24 | Add OR-11: Unbounded external evidence fetch — resolved in #287. Connect timeout, response-size cap, and privacy-safe logging enforced via fetch_external.safe_urlopen. |
