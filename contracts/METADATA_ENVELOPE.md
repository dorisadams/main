# On-chain Metadata Envelope Versioning

**Issue:** #317  
**Status:** Active  
**Aligns with:** `backend/envelope.py` (`HRPSTG1` / `HRPSTG2`)

## Goal

Record an explicit **envelope version** next to each proof's canonical
`metadata_hash` so Harpocrates stays privacy-preserving and interoperable at
its public contract boundary — without inventing a second protocol truth.

## What is stored on-chain

| Field | Meaning |
| --- | --- |
| `version` | `1` (`METADATA_ENVELOPE_V1`) or `2` (`METADATA_ENVELOPE_V2`) |
| `metadata_hash` | Same 32-byte canonical hash already on `ProofRecord` |
| `bound_at` | Ledger timestamp of the bind/upgrade |
| `proof_id` | Binding key |

Raw envelope bytes, media, witnesses, nullifiers, and private keys are **never**
stored or logged. Typed events emit only `(proof_id, version, metadata_hash, bound_at)`.

## Compatibility

- Existing `register_*` entry points that take a bare `metadata_hash` keep working.
  `save_record` stamps a **V1** envelope automatically.
- Callers that understand V2 call `bind_metadata_envelope` after registration
  (admin, source, or issuer) to upgrade.
- `resolve_envelope_version` returns the stored version, or `1` when a
  proof exists without a row (legacy), or `0` when the proof is unknown.
- Downgrades and unsupported versions (`0` or `> METADATA_ENVELOPE_VERSION_MAX`)
  fail closed with `UnsupportedMetadataEnvelopeVersion` (error `#77`).

## Migration & rollback

| Direction | Behavior |
| --- | --- |
| Forward | Additive `DataKey::MetadataEnvelope(proof_id)`. No `SchemaVersion` bump required. |
| Existing proofs | First read via `resolve_*` treats missing rows as V1; next `correct_proof` or `bind_*` materializes a row. New registrations stamp V1 immediately. |
| Rollback | Pre-#317 wasm ignores the new key. Re-deploying an older wasm leaves orphan envelope rows that newer builds can still read. |

## Threat model notes

- **Confidentiality:** only hashes and version integers cross the trust boundary.
- **Integrity:** bind requires the hash to match `ProofRecord.metadata_hash`;
  same-version hash edits go through `correct_proof` (admin) so history stays authoritative.
- **Availability / DoS:** fixed-size types; no unbounded decoding of off-chain envelopes.
- **Replay / confusion:** version is explicit on-chain so V1 and V2 digests cannot be silently reinterpreted.

## API surface

- `bind_metadata_envelope(actor, proof_id, version, metadata_hash)`
- `get_metadata_envelope(proof_id)`
- `resolve_envelope_version(proof_id)`
- `is_supported_envelope_version(version)`

## Verification

```bash
cd contracts
cargo test -p harpocrates-registry test_metadata_envelope -- --nocapture
```
