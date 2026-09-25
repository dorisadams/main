# C2PA Manifest Fixtures

These fixtures provide synthetic, non-sensitive C2PA manifest test vectors for validating bounded manifest parsing in Harpocrates (`devx/c2pa_parser.py` and `devx/validate_c2pa_manifests.py`).

## Security & Privacy Notice
* All fixtures contain ONLY synthetic test values and placeholders.
* Real user media, production credentials, private keys, seeds, witness values, and nullifiers are strictly forbidden in fixtures.

## Fixture Index

* `valid-c2pa-manifest.json`: Well-formed C2PA manifest containing an embedded Harpocrates metadata assertion.
* `malformed-manifest.json`: Invalid JSON / structural schema mismatch.
* `oversized-manifest.json`: Manifest exceeding maximum byte size or assertion collection limits.
* `unsupported-version.json`: Manifest declaring an unsupported C2PA spec version.
* `expired-manifest.json`: Manifest with an expired claim timestamp or status.
* `revoked-manifest.json`: Manifest with a revoked assertion status.
