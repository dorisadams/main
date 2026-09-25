"""Canonical metadata error taxonomy tests – issue #262.

Covers the taxonomy contract added in ``metadata_errors.py``:

  - every failure class (malformed, missing field, invalid field, unsupported
    version, oversized, expired, revoked, dependency failure) maps to a stable
    code + HTTP status,
  - the envelope serializer is consistent and privacy-safe (field *names* may
    appear; field *values*, secrets, and raw exception text never do),
  - ``MetadataError`` stays a ``ValueError`` so existing call sites and the
    app-level handler keep working (regression),
  - the steganographic envelope raises the canonical codes, and
  - ``POST /api/stego/embed`` returns the canonical envelope end to end.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import unittest

from flask import Flask, g

import app as app_module
from envelope import (
    MAX_PAYLOAD_BYTES,
    MetadataError,
    pack_envelope,
    validate_v1,
    validate_v2,
)
from errors import init_request_id
from metadata_errors import (
    METADATA_DEPENDENCY_FAILURE,
    METADATA_EXPIRED,
    METADATA_INVALID_FIELD,
    METADATA_MALFORMED,
    METADATA_MISSING_FIELD,
    METADATA_OVERSIZED,
    METADATA_REVOKED,
    METADATA_UNSUPPORTED_VERSION,
    TAXONOMY_VERSION,
    MetadataError as TaxonomyError,
    classify_validation_error,
    error_status,
    is_known_code,
    metadata_error_response,
    taxonomy,
)

_SECRET = "s3cr3t-witness-value-should-never-appear"

_NOW_UTC = "2026-06-18T00:00:00.000Z"

_VALID_METADATA: dict = {
    "protocol": "harpocrates",
    "version": 1,
    "tier": "silent",
    "sourceHash": "11" * 32,
    "proofId": "22" * 32,
    "timestamp": _NOW_UTC,
}


def _video_upload() -> tuple:
    return (io.BytesIO(b"video bytes"), "evidence.mp4", "video/mp4")


@contextlib.contextmanager
def _app_env(extra: dict[str, str], clear: list[str] | None = None):
    """Spin up a fresh Flask app with the given environment (as test_app does)."""
    clear = clear or []
    saved = {k: os.environ.get(k) for k in list(extra) + clear}
    for key in clear:
        os.environ.pop(key, None)
    os.environ.update(extra)
    try:
        yield app_module.create_app().test_client()
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


# ---------------------------------------------------------------------------
# 1. Taxonomy contract
# ---------------------------------------------------------------------------

class TestTaxonomyContract(unittest.TestCase):
    EXPECTED = {
        METADATA_MALFORMED: 400,
        METADATA_MISSING_FIELD: 400,
        METADATA_INVALID_FIELD: 400,
        METADATA_UNSUPPORTED_VERSION: 400,
        METADATA_OVERSIZED: 413,
        METADATA_EXPIRED: 400,
        METADATA_REVOKED: 403,
        METADATA_DEPENDENCY_FAILURE: 503,
    }

    def test_versioned(self):
        self.assertEqual(TAXONOMY_VERSION, "harpocrates-metadata-errors-v1")

    def test_every_code_has_a_stable_status(self):
        for code, status in self.EXPECTED.items():
            with self.subTest(code=code):
                self.assertTrue(is_known_code(code))
                self.assertEqual(error_status(code), status)

    def test_taxonomy_lists_every_code_without_duplicates(self):
        codes = [entry["code"] for entry in taxonomy()]
        self.assertEqual(sorted(codes), sorted(self.EXPECTED))
        self.assertEqual(len(codes), len(set(codes)))
        for entry in taxonomy():
            self.assertTrue(entry["message"])

    def test_unknown_code_is_rejected(self):
        self.assertFalse(is_known_code("NOT_A_METADATA_CODE"))
        with self.assertRaises(ValueError):
            error_status("NOT_A_METADATA_CODE")
        with self.assertRaises(ValueError):
            TaxonomyError("NOT_A_METADATA_CODE")


# ---------------------------------------------------------------------------
# 2. MetadataError compatibility + classifier
# ---------------------------------------------------------------------------

class TestMetadataErrorCompat(unittest.TestCase):
    def test_metadata_error_is_a_value_error_regression(self):
        # Existing ``except ValueError`` call sites must keep catching it.
        self.assertTrue(issubclass(TaxonomyError, ValueError))
        with self.assertRaises(ValueError):
            raise TaxonomyError(METADATA_MISSING_FIELD)

    def test_envelope_metadata_error_is_value_error(self):
        self.assertTrue(issubclass(MetadataError, ValueError))

    def test_as_metadata_error_is_idempotent(self):
        from metadata_errors import as_metadata_error

        original = TaxonomyError(METADATA_INVALID_FIELD, field="tier")
        self.assertIs(as_metadata_error(original), original)
        self.assertIsInstance(as_metadata_error(ValueError("boom")), TaxonomyError)

    def test_classifier_maps_each_class(self):
        cases = {
            "metadata missing required field: proofId": METADATA_MISSING_FIELD,
            "metadata payload exceeds the 64 KiB steganography limit": METADATA_OVERSIZED,
            "unsupported metadata version 99": METADATA_UNSUPPORTED_VERSION,
            "metadata must be a JSON object": METADATA_MALFORMED,
            "attestation has expired": METADATA_EXPIRED,
            "issuer key was revoked": METADATA_REVOKED,
            "metadata dependency unavailable": METADATA_DEPENDENCY_FAILURE,
            "metadata tier is invalid": METADATA_INVALID_FIELD,
        }
        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(classify_validation_error(ValueError(message)).code, expected)

    def test_classifier_never_echoes_raw_exception_text(self):
        error = classify_validation_error(ValueError(f"leaked {_SECRET}"))
        self.assertNotIn(_SECRET, error.message)
        self.assertNotIn(_SECRET, json.dumps(error.as_payload()))


# ---------------------------------------------------------------------------
# 3. Serialization consistency
# ---------------------------------------------------------------------------

class TestMetadataErrorSerialization(unittest.TestCase):
    def setUp(self):
        self.app = Flask("metadata-error-taxonomy-test")
        init_request_id(self.app)

    def _serialize(self, error):
        with self.app.test_request_context("/"):
            g.request_id = "req-taxonomy-1"
            response, status = metadata_error_response(error)
            return status, json.loads(response.get_data(as_text=True))

    def test_envelope_shape_and_status(self):
        status, body = self._serialize(TaxonomyError(METADATA_OVERSIZED))
        self.assertEqual(status, 413)
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"]["code"], METADATA_OVERSIZED)
        self.assertEqual(body["error"]["request_id"], "req-taxonomy-1")
        self.assertTrue(body["error"]["message"])

    def test_field_name_is_exposed_but_never_values(self):
        error = TaxonomyError(
            METADATA_INVALID_FIELD,
            "metadata sourceHash must be a 32-byte hex string",
            field="sourceHash",
        )
        status, body = self._serialize(error)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["field"], "sourceHash")
        self.assertNotIn(_SECRET, json.dumps(body))

    def test_legacy_value_error_is_serialized_without_new_fields(self):
        status, body = self._serialize(ValueError("metadata tier is invalid"))
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], METADATA_INVALID_FIELD)
        self.assertNotIn("field", body["error"])


# ---------------------------------------------------------------------------
# 4. Envelope codec raises the canonical codes
# ---------------------------------------------------------------------------

class TestEnvelopeUsesTaxonomy(unittest.TestCase):
    def test_missing_field_code_and_field_name(self):
        metadata = {k: v for k, v in _VALID_METADATA.items() if k != "proofId"}
        with self.assertRaises(MetadataError) as ctx:
            validate_v1(metadata)
        self.assertEqual(ctx.exception.code, METADATA_MISSING_FIELD)
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.field, "proofId")

    def test_invalid_hash_field(self):
        bad = dict(_VALID_METADATA, sourceHash="not-hex")
        with self.assertRaises(MetadataError) as ctx:
            validate_v1(bad)
        self.assertEqual(ctx.exception.code, METADATA_INVALID_FIELD)
        self.assertEqual(ctx.exception.field, "sourceHash")

    def test_malformed_non_object(self):
        with self.assertRaises(MetadataError) as ctx:
            validate_v2("not-a-dict")  # type: ignore[arg-type]
        self.assertEqual(ctx.exception.code, METADATA_MALFORMED)

    def test_unsupported_version(self):
        with self.assertRaises(MetadataError) as ctx:
            pack_envelope(dict(_VALID_METADATA), version=99)
        self.assertEqual(ctx.exception.code, METADATA_UNSUPPORTED_VERSION)

    def test_oversized_payload(self):
        with self.assertRaises(MetadataError) as ctx:
            pack_envelope(dict(_VALID_METADATA, big="x" * (MAX_PAYLOAD_BYTES + 1)), version=2)
        self.assertEqual(ctx.exception.code, METADATA_OVERSIZED)
        self.assertEqual(ctx.exception.status, 413)

    def test_errors_remain_value_errors_regression(self):
        with self.assertRaises(ValueError):
            validate_v1({})


# ---------------------------------------------------------------------------
# 5. HTTP boundary: POST /api/stego/embed
# ---------------------------------------------------------------------------

class TestEmbedMetadataErrorBoundary(unittest.TestCase):
    @contextlib.contextmanager
    def _client(self):
        with _app_env({}, clear=["REGISTER_API_KEY", "REGISTER_API_KEY_EXPIRES"]) as client:
            yield client

    def _post(self, client, metadata):
        return client.post(
            "/api/stego/embed",
            data={"metadata": metadata, "video": _video_upload()},
            content_type="multipart/form-data",
        )

    def test_malformed_json_is_canonical(self):
        with self._client() as client:
            response = self._post(client, "{not-json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"]["code"], METADATA_MALFORMED)
        self.assertIn("request_id", response.json["error"])

    def test_missing_field_is_canonical_with_field_name(self):
        with self._client() as client:
            response = self._post(client, json.dumps({"protocol": "harpocrates"}))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"]["code"], METADATA_MISSING_FIELD)
        self.assertEqual(response.json["error"]["field"], "proofId")
        self.assertIn("metadata missing required field", response.json["error"]["message"])

    def test_invalid_timestamp_message_survives(self):
        with self._client() as client:
            response = self._post(
                client, json.dumps({**_VALID_METADATA, "timestamp": "not-a-timestamp"})
            )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"]["code"], METADATA_INVALID_FIELD)
        self.assertIn("ISO-8601", response.json["error"]["message"])

    def test_oversized_metadata_is_canonical_413(self):
        with self._client() as client:
            response = self._post(client, "x" * 20_000)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json["error"]["code"], METADATA_OVERSIZED)

    def test_error_body_never_echoes_metadata_values(self):
        payload = dict(_VALID_METADATA, sourceHash="bad", witness=_SECRET)
        with self._client() as client:
            response = self._post(client, json.dumps(payload))
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(_SECRET, response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
