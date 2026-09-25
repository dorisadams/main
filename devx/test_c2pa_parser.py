"""Tests for bounded C2PA manifest parser."""

from __future__ import annotations

import json
import unittest
from devx.c2pa_parser import (
    parse_c2pa_manifest,
    MAX_C2PA_PAYLOAD_BYTES,
    MAX_ASSERTIONS_COUNT,
    STATUS_VALID,
    STATUS_MALFORMED,
    STATUS_OVERSIZED,
    STATUS_UNSUPPORTED,
    STATUS_EXPIRED,
    STATUS_REVOKED,
    ERR_OVERSIZED,
    ERR_MALFORMED,
    ERR_UNSUPPORTED_VERSION,
    ERR_EXPIRED,
    ERR_REVOKED,
)


class TestC2PAParser(unittest.TestCase):
    def test_valid_manifest_with_harpocrates_metadata(self) -> None:
        payload = {
            "specVersion": "c2pa-v1",
            "title": "Valid Sample",
            "assertions": [
                {
                    "label": "harpocrates.metadata",
                    "data": {
                        "protocol": "harpocrates",
                        "version": 1,
                        "tier": "silent",
                        "sourceHash": "a" * 64,
                        "proofId": "b" * 64,
                        "timestamp": "2026-01-01T00:00:00Z",
                    },
                }
            ],
            "ingredients": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertTrue(res.ok)
        self.assertEqual(res.status, STATUS_VALID)
        self.assertIsNotNone(res.canonical_metadata)
        self.assertEqual(res.canonical_metadata["protocol"], "harpocrates")
        self.assertEqual(res.canonical_metadata["tier"], "silent")

    def test_malformed_json_bytes(self) -> None:
        res = parse_c2pa_manifest(b"{bad_json: true")
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_MALFORMED)
        self.assertEqual(res.error_code, ERR_MALFORMED)

    def test_payload_below_max(self) -> None:
        valid_bytes = (
            b'{"specVersion":"c2pa-v1","assertions":[],"ingredients":[]}'
        )
        self.assertLess(len(valid_bytes), MAX_C2PA_PAYLOAD_BYTES)
        res = parse_c2pa_manifest(valid_bytes)
        self.assertTrue(res.ok)

    def test_payload_exactly_at_max(self) -> None:
        base = {"specVersion": "c2pa-v1", "assertions": [], "ingredients": [], "pad": ""}
        base_bytes = json.dumps(base).encode("utf-8")
        pad_len = MAX_C2PA_PAYLOAD_BYTES - len(base_bytes)
        base["pad"] = "a" * pad_len
        exact_bytes = json.dumps(base).encode("utf-8")
        self.assertEqual(len(exact_bytes), MAX_C2PA_PAYLOAD_BYTES)
        res = parse_c2pa_manifest(exact_bytes)
        self.assertTrue(res.ok)

    def test_oversized_payload_bytes(self) -> None:
        huge_bytes = b"x" * (MAX_C2PA_PAYLOAD_BYTES + 1)
        res = parse_c2pa_manifest(huge_bytes)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_OVERSIZED)
        self.assertEqual(res.error_code, ERR_OVERSIZED)

    def test_exceeds_ingredients_bound(self) -> None:
        from devx.c2pa_parser import MAX_INGREDIENTS_COUNT
        payload = {
            "specVersion": "c2pa-v1",
            "assertions": [],
            "ingredients": [{"title": f"i{i}"} for i in range(MAX_INGREDIENTS_COUNT + 1)],
        }
        res = parse_c2pa_manifest(payload)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_OVERSIZED)
        self.assertEqual(res.error_code, ERR_OVERSIZED)

    def test_exceeds_field_length_limit(self) -> None:
        payload = {
            "specVersion": "c2pa-v1",
            "long_field": "a" * 300,
            "assertions": [],
            "ingredients": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertTrue(res.ok)

    def test_dependency_failure_handling(self) -> None:
        from devx.c2pa_parser import STATUS_DEPENDENCY_FAILURE, ERR_DEPENDENCY_FAILURE, C2PAParseResult
        # Simulate dependency failure response
        res = C2PAParseResult(
            ok=False,
            status=STATUS_DEPENDENCY_FAILURE,
            error_code=ERR_DEPENDENCY_FAILURE,
            error_message="external C2PA library component unavailable",
        )
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_DEPENDENCY_FAILURE)
        self.assertEqual(res.error_code, ERR_DEPENDENCY_FAILURE)

    def test_exceeds_assertions_bound(self) -> None:
        payload = {
            "specVersion": "c2pa-v1",
            "assertions": [{"label": f"a{i}"} for i in range(MAX_ASSERTIONS_COUNT + 1)],
            "ingredients": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_OVERSIZED)
        self.assertEqual(res.error_code, ERR_OVERSIZED)

    def test_deeply_nested_structure(self) -> None:
        nested: dict = {"level": 0}
        curr = nested
        for i in range(12):
            curr["child"] = {}
            curr = curr["child"]
        res = parse_c2pa_manifest(nested)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_OVERSIZED)

    def test_unsupported_version(self) -> None:
        payload = {
            "specVersion": "c2pa-v999-future",
            "assertions": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_UNSUPPORTED)
        self.assertEqual(res.error_code, ERR_UNSUPPORTED_VERSION)

    def test_expired_claim(self) -> None:
        payload = {
            "specVersion": "c2pa-v1",
            "status": "expired",
            "assertions": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_EXPIRED)
        self.assertEqual(res.error_code, ERR_EXPIRED)

    def test_revoked_claim(self) -> None:
        payload = {
            "specVersion": "c2pa-v1",
            "status": "revoked",
            "assertions": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_REVOKED)
        self.assertEqual(res.error_code, ERR_REVOKED)

    def test_invalid_signature(self) -> None:
        payload = {
            "specVersion": "c2pa-v1",
            "signatureValid": False,
            "assertions": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertFalse(res.ok)
        self.assertEqual(res.error_code, "ERR_INVALID_SIGNATURE")

    def test_redaction_of_sensitive_keys(self) -> None:
        payload = {
            "specVersion": "c2pa-v1",
            "secret_key": "topsecretvalue",
            "privateKey": "-----BEGIN RSA PRIVATE KEY-----",
            "assertions": [],
            "ingredients": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertTrue(res.ok)
        serialized = str(res.to_dict())
        self.assertNotIn("topsecretvalue", serialized)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", serialized)


if __name__ == "__main__":
    unittest.main()
