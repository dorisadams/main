# Reproducible ZK Circuit and Verifier Artifacts

Generated ACIR bundles, verification keys, and WASM artifacts must be a
deterministic function of the source tree and the pinned toolchain. If they are
not, "the verifier on chain matches the circuit in git" is an unverifiable
claim, and a compromised or merely inconsistent build host can silently
substitute a different circuit.

This document covers the pinning, the hermetic build, the digest manifest, the
double-build check, and how to operate and roll back the pipeline.

## Components

| Path | Role |
| --- | --- |
| `zk/toolchain.lock.json` | Pinned toolchain versions, hermetic environment, normalization policy, declared artifacts, resource limits |
| `zk/tools/artifact_manifest.py` | Normalizes, digests, writes, verifies, and diffs manifests |
| `zk/tools/test_artifact_manifest.py` | Unit tests for normalization, the state machine, drift detection, and the privacy properties |
| `zk/noir/scripts/reproducible-build.sh` | Hermetic double-build driver |
| `zk/artifacts.manifest.json` | Committed manifest (written by a build; absent until first published) |
| `zk/browser.artifacts.manifest.json` | Committed digests for published browser ACIR under `frontend/public/noir/` |
| `.github/workflows/zk-ci.yml` | CI enforcement |

## Threat assumptions

The pipeline defends against:

- **Toolchain drift.** A build host running a different `nargo` or `bb` than the
  one pinned produces different artifacts. The build script refuses to run.
- **Host metadata leakage.** ACIR JSON embeds absolute source paths and debug
  symbols; WASM embeds `producers` and `name` sections. These differ per host
  and would otherwise make every build look non-reproducible, hiding real
  drift in the noise. Normalization removes exactly these.
- **Silent artifact substitution.** A manifest binds artifact digests to source
  digests and toolchain versions, so a substituted artifact fails `verify`.
- **Partial builds.** A build that fails halfway must not leave a manifest that
  a later step trusts.

It does **not** defend against a compromised `nargo`/`bb` binary that produces
consistently malicious output on every host. That is a supply-chain concern
addressed by the pinned installer commands in the lock file, not by digesting.

## Normalization

Digests are taken over a *normalized* form, defined entirely by
`zk/toolchain.lock.json` so the policy is auditable and versioned:

- **JSON** — parsed, volatile keys removed recursively (`debug_symbols`,
  `file_map`, `names`, `brillig_names`, `warnings`), re-emitted with sorted keys
  and no incidental whitespace.
- **WASM** — a bounded forward walk over sections; custom sections named in
  `strip_custom_sections` are dropped, everything else is preserved byte-for-byte
  and in order.
- **Binary** (verification keys, proofs) — byte-for-byte, no normalization.

Normalization can only remove fields the lock file names. A change to circuit
semantics always changes the bytecode, and therefore always changes the digest.
`test_artifact_manifest.py::test_json_normalization_still_detects_a_semantic_change`
pins that property.

Every manifest records `normalization_policy_sha256`, so comparing two manifests
produced under different policies is reported as drift rather than silently
succeeding.

## State machine

Each declared artifact reaches exactly one terminal state per run:

```
DECLARED ──not on disk──▶ MISSING     (fatal when `required`, else SKIPPED)
         ──over limit───▶ OVERSIZE    (fatal)
         ──unreadable───▶ UNREADABLE  (fatal)
         ──normalized───▶ DIGESTED    (success)
```

`verify` and `compare` add one transition on a `DIGESTED` artifact: `MATCHED` or
`DRIFTED`.

There is no partial success. If any artifact ends in a fatal state the run exits
non-zero and **no manifest is written**, so a half-built tree can never be
promoted. Cancellation (SIGINT) is handled the same way: the double-build driver
cleans its work directory on `EXIT INT TERM`, and the manifest is only written
after every artifact has resolved.

## Local verification

Install the pinned toolchain (inside WSL on Windows — see `zk/noir/README.md`):

```bash
noirup --version 1.0.0-beta.9
bbup   --version 0.87.0
```

Then:

```bash
# Full double build: build twice from clean, compare, write the manifest.
zk/noir/scripts/reproducible-build.sh

# One build, write a manifest.
zk/noir/scripts/reproducible-build.sh --single

# One build, compare against the committed manifest.
zk/noir/scripts/reproducible-build.sh --verify

# Tooling only — no toolchain required.
python -m pytest zk/tools -q
python zk/tools/artifact_manifest.py verify
python zk/tools/artifact_manifest.py verify-browser
```

## Configuration

The hermetic environment is declared in `zk/toolchain.lock.json` and exported by
the build script:

| Variable | Value | Why |
| --- | --- | --- |
| `SOURCE_DATE_EPOCH` | `0` | Removes build timestamps from artifacts |
| `TZ` | `UTC` | Removes local-time formatting differences |
| `LC_ALL` / `LANG` | `C` | Removes locale-dependent sorting and formatting |
| `RUST_BACKTRACE` | `0` | Keeps failure output free of host paths |
| `PYTHONHASHSEED` | `0` | Makes the tooling's own iteration order stable |

Resource limits (`limits` in the lock file) bound the walk so a corrupted or
hostile working directory cannot turn a build check into a denial of service:
`max_artifact_bytes` (256 MiB), `max_artifacts` (64), `max_provenance_files`
(512). Exceeding any of them is a fatal, typed failure — never a hang.

## Signals

Both the script and the tool emit single-line JSON on **stderr**:

| Event | Fields | Meaning |
| --- | --- | --- |
| `toolchain.pinned` | `detail` | Versions matched the lock |
| `build.start` / `build.done` | `detail` | Build pass boundaries |
| `circuit.compiled` / `circuit.skipped` | `detail` | Per-circuit progress |
| `artifact.state` | `path`, `state`, `bytes`, `normalized_bytes`, `digest` | State-machine transition |
| `manifest.written` | `path`, `artifacts`, `skipped`, `sources` | Success |
| `drift.finding` | `detail` | One drift finding |
| `verify.ok` / `verify.failed` | `artifacts` / `findings` | Verdict |
| `compare.ok` / `compare.failed` | `artifacts` / `findings` | Double-build verdict |
| `run.fatal` / `run.error` / `run.cancelled` | `path`, `state`, `reason` | Terminal failure |

**Privacy.** Signals carry only repo-relative paths, byte counts, digests, and
state names. Artifact contents are never logged, never echoed on failure, and
never embedded in a manifest. A digest mismatch is reported as two truncated
digests, never as a content diff — dumping proving-system bytes into a CI log is
the leak this pipeline exists to prevent. This is pinned by
`test_drift_findings_never_contain_artifact_content` and
`test_manifest_never_embeds_artifact_bytes`.

## Exit codes

| Code | Meaning | Operator action |
| --- | --- | --- |
| `0` | Reproducible | None |
| `1` | Drift detected | Read the `drift.finding` signals; a source digest change is expected after a circuit edit, an artifact-only change is not |
| `2` | Usage error | Fix the command line |
| `3` | Fatal | Toolchain mismatch, missing required artifact, or unreadable tree |

## Deployment impact and rollout

The pipeline is **inert until a manifest is committed**. The CI drift check
prints a notice and passes when `zk/artifacts.manifest.json` is absent, so
adding this pipeline does not block any existing branch.

To turn it on:

1. Run `zk/noir/scripts/reproducible-build.sh` on the pinned toolchain.
2. Commit the resulting `zk/artifacts.manifest.json`.
3. From that commit on, CI fails any PR whose artifacts or circuit sources
   disagree with the manifest.

## Rollback

Nothing here mutates tracked source. To roll back:

- **Disable enforcement:** delete `zk/artifacts.manifest.json`. The CI step
  becomes inert again on the next run.
- **Undo a build:** delete `zk/noir/*/target`. The build script only ever writes
  under those directories and the manifest path passed to it.
- **Undo a toolchain bump:** revert `zk/toolchain.lock.json` and re-run
  `--single` to regenerate the manifest under the previous pin.

No undocumented repair step is required in any of these cases.

## Artifact update workflow

When circuit sources change (e.g., editing `src/main.nr` or `Nargo.toml`), the
artifacts must be regenerated and the manifest updated in the same commit. The
workflow is:

1. **Edit circuit sources.** Make changes in `zk/noir/*/src/main.nr` or other
   tracked source files.

2. **Install the pinned toolchain** on a host with `nargo` and `bb`:
   ```bash
   noirup --version 1.0.0-beta.9
   bbup   --version 0.87.0
   ```

3. **Rebuild and write the manifest:**
   ```bash
   zk/noir/scripts/reproducible-build.sh --single
   ```
   This compiles all circuits from clean target directories, generates
   verification keys, and writes `zk/artifacts.manifest.json`.

4. **Publish browser artifacts** by copying the compiled ACIR files to the
   frontend's public directory, then refresh the browser manifest:
   ```bash
   cp zk/noir/silent_witness/target/silent_witness.json frontend/public/noir/
   cp zk/noir/silent_witness_helper/target/silent_witness_helper.json frontend/public/noir/
   cp zk/noir/silent_witness_aggregator/target/silent_witness_aggregator.json frontend/public/noir/
   cp zk/noir/silent_witness_aggregator_helper/target/silent_witness_aggregator_helper.json frontend/public/noir/
   python zk/tools/artifact_manifest.py write-browser
   python zk/tools/artifact_manifest.py verify-browser
   ```

5. **Run the full double-build** to confirm reproducibility:
   ```bash
   zk/noir/scripts/reproducible-build.sh
   ```

6. **Commit everything together** — circuit sources, the regenerated manifest,
   and the updated browser artifacts — in a single commit. CI will then
   rebuild and verify that the committed artifacts match.

### CI enforcement

When a pull request touches `zk/**`, the `circuit-build` job in CI:
1. Installs the pinned `nargo` and `bb` versions from `zk/toolchain.lock.json`.
2. Runs `zk/noir/scripts/reproducible-build.sh --verify`, which builds all
   circuits from clean targets and compares the normalized digests against
   the committed `zk/artifacts.manifest.json`.
3. Fails with `EXIT_DRIFT` (code 1) if any artifact disagrees with the
   manifest, preventing stale artifacts from merging.

To run the same check locally:
```bash
zk/noir/scripts/reproducible-build.sh --verify
```

### Adding a new circuit

1. Create the new Noir package under `zk/noir/<circuit-name>/`.
2. Add its expected artifact paths to `zk/toolchain.lock.json`.
3. Add the circuit name to `CIRCUITS` in `zk/noir/scripts/reproducible-build.sh`.
4. Run `zk/noir/scripts/reproducible-build.sh --single` to generate artifacts.
5. Copy any published ACIR to `frontend/public/noir/`.
6. Run the double-build and commit the manifest.

## Troubleshooting

**`nargo version drift` / `bb version drift`** — the installed toolchain does
not match the pin. Install the pinned version, or, if the bump is intentional,
update `zk/toolchain.lock.json` and regenerate the manifest in the same commit.

**Drift reported as `raw bytes differ but normalize to the same digest`** — this
is *not* a failure of reproducibility in the semantic sense; the artifacts agree
after host metadata is removed. It appears as a finding so you can decide
whether the metadata difference matters for your distribution.

**`4 artifact(s) in a fatal state; manifest not written`** — the declared
artifacts are not on disk. Generated artifacts are gitignored, so this is the
expected result of running the tool without building first. Run the build script
rather than the tool directly.

**Drift in `provenance` only** — a circuit source changed but the artifacts did
not. Either the artifacts are stale (rebuild) or the source change was
comment-only (rebuild and re-commit the manifest).


## Browser artifact manifest

Published ACIR under `frontend/public/noir/` is the browser trust boundary: the
Evidence Studio loads these bundles to prove in-browser. They must remain a
publish of the compiled circuit, not a second protocol truth.

| Command | Effect |
| --- | --- |
| `python zk/tools/artifact_manifest.py write-browser` | Digest every lock-declared `published_acir` file and write `zk/browser.artifacts.manifest.json` |
| `python zk/tools/artifact_manifest.py verify-browser` | Re-digest the published tree and fail on drift from that manifest; when a matching `zk/noir/<name>/target/<name>.json` is also on disk, require an identical normalized digest |

**Threat model.** A substituted or stale browser bundle could make the browser
prove a different circuit than the on-chain verifier expects. `verify-browser`
binds published digests to the pinned toolchain and normalization policy. When
build targets are present (local or CI after `nargo compile`), it also proves
the publish step did not rewrite bytecode.

**Privacy.** Signals and findings name repo-relative paths and truncated digests
only. ACIR bytes, witnesses, and private keys are never logged.

**Migration.** Committing `zk/browser.artifacts.manifest.json` turns the CI
check on. Existing callers are unchanged; this is an additive gate.

**Rollback.** Delete `zk/browser.artifacts.manifest.json` to make the CI step
inert again, or revert the publish under `frontend/public/noir/` and regenerate
with `write-browser`.

## Known divergence: silent_witness source vs published artifacts (do not
republish blindly)

As of the #336 branch, `zk/noir/silent_witness/src/main.nr` and
`zk/noir/silent_witness_helper/src/main.nr` carry the scoped-nullifier v1
extension (`verifier_scope`, `epoch`, and — main only — `domain_tag` as extra
inputs), while the committed browser artifacts under
`frontend/public/noir/silent_witness{,_helper}.json` and the deployed
verifier boundary (`contracts/.../src/verifier_inputs.rs` and
`backend/verifier_inputs.py`, both pinning a 160-byte / 5-public-input frame
for `silent_witness/v1`) still implement the pre-scoping ABI.

Consequences:

- The committed artifacts match the deployed verifiers; end-to-end proof
  generation against the current on-chain/backend boundary works.
- Republishing artifacts compiled from the current sources would produce
  ACIR for a circuit emitting a 7-public-input (224-byte) frame, which
  **neither** deployed verifier accepts — silently breaking
  verification for every browser client.
- The frontend `noirClient.ts` sends scope/epoch inputs that the committed
  artifacts ignore; harmless today (extra keys are dropped by the ABI), but
  it must be revisited in the same coordinated change that ships the new
  frame.

Closing this divergence is a coordinated zk release: compile the scoped
circuits, extend `verifier_inputs` in the contract, backend, and TypeScript
verifier layers in the same change, regenerate the conformance vectors, and
only then republish under `frontend/public/noir/` and refresh
`zk/browser.artifacts.manifest.json`. Do not run the artifact-update workflow
below for `silent_witness{,_helper}` until that lands.

## Limitations

- The double-build check runs twice on the *same* host. It catches
  non-determinism within a host (timestamps, iteration order, temporary paths)
  but not cross-host differences. Running the same check on a second CI runner
  architecture would close that gap and is not currently done.
- Proof artifacts are not in the manifest: a proof is a function of a witness,
  and witnesses are private material that must never enter a manifest or a CI
  log. Only the circuit, the verification key, and the published ACIR are pinned.
- The lock file pins versions, not binary digests, of `nargo` and `bb`. Pinning
  installer digests would require an upstream distribution channel that
  publishes them.
