"""API contract conformance tests for the Harpocrates backend (issue #293).

These tests pin the *runtime* HTTP contract of ``backend/app.py`` to the two
artifacts that describe it: the OpenAPI document produced by
``devx/generate_api_schema.py`` and the response envelopes the service
promises callers (``errors.error_response`` / ``errors.ok_response`` plus the
request-id propagation hook).

They are deliberately scoped to non-destructive boundaries: every assertion is
made through the Flask test client with synthetic, non-sensitive payloads, and
the targeted requests fail *before* persistence, media pipelines, or proof
generation are reached. A failure therefore points at a contract drift rather
than at the environment.

Conformance surface:
* the live ``url_map`` must match the routes declared in ``app.py`` (the AST
  the OpenAPI generator reads), with a single documented dynamic exception;
* every error body must be one of exactly two documented shapes — the
  standardized envelope or the legacy flat body — and nothing else;
* standardized envelope codes must map to their declared HTTP status;
* request IDs must propagate to JSON object bodies and the ``X-Request-ID``
  header, and never leak untrusted/secret material;
* success bodies must keep their documented top-level field contracts.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import unittest
from pathlib import Path

from errors import (
    INTERNAL_ERROR,
    NOT_FOUND,
    PAYLOAD_TOO_LARGE,
    RATE_LIMITED,
    UNSUPPORTED_MEDIA_TYPE,
    VALIDATION_ERROR,
)

BACKEND_DIR = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_DIR.parent

# The OpenAPI generator reads the same AST contract this suite pins against.
if str(REPO_ROOT / "devx") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "devx"))

import generate_api_schema  # noqa: E402  (path is set above)

import app as app_module  # noqa: E402

# ---------------------------------------------------------------------------
# Contract constants
# ---------------------------------------------------------------------------

HEX_32 = "aa" * 32
HEX_32_B = "bb" * 32
HEX_32_C = "cc" * 32

# Routes whose path is computed at import time (``config.metrics_path``) are
# invisible to the AST-based OpenAPI generator. The gap is declared here so a
# new dynamic route makes this suite fail instead of silently drifting.
DECLARED_OPENAPI_GAP = {"/metrics": {"GET"}}

# Standardized envelope shape produced by ``errors.error_response``.
ENVELOPE_TOP_LEVEL_KEYS = {"ok", "error", "request_id"}
ENVELOPE_ERROR_KEYS = {"code", "message", "request_id"}

# Legacy flat error shape used by handlers that predate the envelope.
FLAT_ERROR_KEYS = {"error", "request_id"}

# Every standardized code must keep a stable HTTP status.
ERROR_CODE_STATUS = {
    VALIDATION_ERROR: 400,
    UNSUPPORTED_MEDIA_TYPE: 400,
    NOT_FOUND: 404,
    PAYLOAD_TOO_LARGE: 413,
    RATE_LIMITED: 429,
    INTERNAL_ERROR: 500,
}

# Distinctive values that must never be echoed back in any response body.
SENSITIVE_SENTINEL = "S3NT1NEL-private-key-material-9f3a7c2e-do-not-echo"

CLEAR_ENV = ["REGISTER_API_KEY", "REGISTER_API_KEY_EXPIRES"]
BASE_ENV = {
    "APP_ENV": "testing",
    "DATABASE_URL": "",
    "NOIR_WORKER_ENABLED": "false",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _app_env(extra: dict[str, str], clear: list[str] | None = None):
    """Build a fresh Flask test client with controlled environment variables.

    Mirrors the fixture convention used by ``backend/test_app.py`` so the
    conformance suite exercises the same application factory path as the rest
    of the backend tests.
    """
    clear = list(clear or [])
    saved = {k: os.environ.get(k) for k in list(extra) + clear}

    for key in clear:
        os.environ.pop(key, None)
    for key, value in {**BASE_ENV, **extra}.items():
        os.environ[key] = value

    try:
        yield app_module.create_app().test_client()
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _get_json(response) -> dict:
    body = response.get_json(silent=True)
    assert isinstance(body, dict), f"expected a JSON object body, got {response.data[:200]!r}"
    return body


def _classify_error_body(body: dict) -> str:
    """Return ``"envelope"``, ``"flat"``, or ``"other"`` for an error body."""
    keys = set(body)
    if (
        keys == ENVELOPE_TOP_LEVEL_KEYS
        and body.get("ok") is False
        and isinstance(body.get("error"), dict)
        and set(body["error"]) == ENVELOPE_ERROR_KEYS
    ):
        return "envelope"
    if keys == FLAT_ERROR_KEYS and isinstance(body.get("error"), str):
        return "flat"
    return "other"


def _empty_multipart(client, path: str, method: str = "post"):
    return getattr(client, method)(path, data={}, content_type="multipart/form-data")


def _error_probes(client) -> list[tuple[str, object, str]]:
    """Return ``(name, response, expected_shape)`` for every error boundary.

    Each request is deterministic and short-circuits before persistence, media
    processing, or proof generation.
    """
    probes: list[tuple[str, object, str]] = [
        # --- standardized envelope (errors.error_response) --------------
        (
            "register_missing_json_body",
            client.post(
                "/api/proofs/register", data="not json", content_type="text/plain"
            ),
            "envelope",
        ),
        (
            "register_non_object_json_body",
            client.post("/api/proofs/register", json=["not", "an", "object"]),
            "envelope",
        ),
        (
            "register_invalid_video_hash",
            client.post(
                "/api/proofs/register",
                json={
                    "videoHash": SENSITIVE_SENTINEL,
                    "metadataHash": HEX_32_B,
                    "proofId": HEX_32_C,
                    "tier": "source",
                },
            ),
            "envelope",
        ),
        (
            "register_unsupported_tier",
            client.post(
                "/api/proofs/register",
                json={
                    "videoHash": HEX_32,
                    "metadataHash": HEX_32_B,
                    "proofId": HEX_32_C,
                    "tier": "unsupported-tier",
                },
            ),
            "envelope",
        ),
        (
            "proof_by_video_invalid_hash",
            client.get("/api/proofs/by-video/not-a-hash"),
            "envelope",
        ),
        (
            "proofs_limit_not_integer",
            client.get("/api/proofs", query_string={"limit": "abc"}),
            "envelope",
        ),
        (
            "silent_witness_disabled_capability",
            client.post("/api/noir/silent-witness", json={"credentialSecret": SENSITIVE_SENTINEL}),
            "envelope",
        ),
        # --- legacy flat body ------------------------------------------
        (
            "embed_missing_fields",
            _empty_multipart(client, "/api/stego/embed"),
            "flat",
        ),
        (
            "embed_metadata_not_json",
            client.post(
                "/api/stego/embed",
                data={
                    "video": (io.BytesIO(b"\x00\x00\x00\x18ftypmp42"), "evidence.mp4"),
                    "metadata": SENSITIVE_SENTINEL,
                },
                content_type="multipart/form-data",
            ),
            "envelope",
        ),
        (
            "extract_missing_video",
            _empty_multipart(client, "/api/stego/extract"),
            "flat",
        ),
        (
            "upload_chunk_unknown_session",
            _empty_multipart(client, "/api/stego/upload-session/missing/chunk/0", method="put"),
            "flat",
        ),
        (
            "commit_unknown_session",
            _empty_multipart(client, "/api/stego/upload-session/missing/commit"),
            "flat",
        ),
        (
            "proofs_invalid_cursor",
            client.get("/api/proofs", query_string={"cursor": "@@@"}),
            "flat",
        ),
        (
            "lineage_missing_output_digest",
            client.post("/api/proofs/lineage", json={}),
            "flat",
        ),
        (
            "lineage_actor_limit_not_integer",
            client.get("/api/lineage/by-actor/unknown", query_string={"limit": "abc"}),
            "flat",
        ),
        (
            "proof_history_invalid_id",
            client.get("/api/proofs/history/not-a-hash"),
            "flat",
        ),
        (
            "time_attestation_create_missing_digest",
            client.post("/api/time-attestation/create", json={}),
            "flat",
        ),
        (
            "time_attestation_validate_missing_digest",
            client.post("/api/time-attestation/validate", json={}),
            "flat",
        ),
        (
            "time_attestation_anchor_malformed",
            client.post("/api/time-attestation/anchor", json={}),
            "flat",
        ),
        (
            "schema_unknown_hash",
            client.get(f"/api/schemas/{'ff' * 32}"),
            "flat",
        ),
        (
            "schema_invalid_hash",
            client.get("/api/schemas/not-a-hash"),
            "flat",
        ),
        (
            "selective_disclosure_missing_proof",
            client.post("/api/verify/selective-disclosure", json={}),
            "flat",
        ),
        (
            "job_unknown_id",
            client.get("/api/jobs/987654321"),
            "flat",
        ),
        (
            "job_download_unknown_id",
            client.get("/api/jobs/987654321/download"),
            "flat",
        ),
        (
            "job_cancel_unknown_id",
            client.post("/api/jobs/987654321/cancel"),
            "flat",
        ),
    ]
    return probes


def _live_routes(app) -> dict[str, set[str]]:
    """Return ``{rule: {methods}}`` for the application's HTTP surface."""
    routes: dict[str, set[str]] = {}
    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static" or rule.rule.startswith("/__test_"):
            continue
        # A single path may be registered once per HTTP verb; union the verbs
        # so ``/api/proofs/lineage`` reports {GET, POST} rather than whichever
        # rule Flask happened to iterate last.
        routes.setdefault(rule.rule, set()).update(
            set(rule.methods) - {"HEAD", "OPTIONS"}
        )
    return routes


def _declared_routes(app_py: Path) -> dict[str, set[str]]:
    declared: dict[str, set[str]] = {}
    for path, method, _endpoint in generate_api_schema.extract_routes_from_ast(app_py):
        declared.setdefault(path, set()).add(method.upper())
    return declared


# ---------------------------------------------------------------------------
# Route table ↔ source ↔ OpenAPI document conformance
# ---------------------------------------------------------------------------


class ApiRouteConformanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = app_module.app
        self.app_py = BACKEND_DIR / "app.py"

    def test_live_route_table_matches_source_declarations(self) -> None:
        live = _live_routes(self.app)
        declared = _declared_routes(self.app_py)

        # Every source-declared route must be served by the running app...
        self.assertEqual(
            set(declared) - set(live),
            set(),
            "routes declared in app.py are not registered on the running app",
        )
        # ...and the only served route absent from the AST contract is the
        # documented dynamic-path exception.
        self.assertEqual(
            set(live) - set(declared),
            set(DECLARED_OPENAPI_GAP),
            "the runtime registered an undocumented route",
        )
        for path, methods in declared.items():
            self.assertEqual(
                methods,
                live[path],
                f"method set drift for {path}",
            )

    def test_dynamic_route_exception_is_still_served(self) -> None:
        live = _live_routes(self.app)
        for path, methods in DECLARED_OPENAPI_GAP.items():
            self.assertIn(path, live, "declared dynamic route is no longer served")
            self.assertEqual(methods, live[path])

    def test_openapi_document_covers_every_live_route(self) -> None:
        schema = generate_api_schema.generate_schema(
            self.app_py, BACKEND_DIR / "schemas"
        )
        self.assertEqual(schema["openapi"], "3.1.0")
        self.assertEqual(schema["info"]["title"], "Harpocrates API")

        documented = {path: set(methods) for path, methods in schema["paths"].items()}
        live = _live_routes(self.app)

        # The document must describe exactly the routes the AST can see.
        self.assertEqual(set(documented), set(live) - set(DECLARED_OPENAPI_GAP))
        for path, methods_live in live.items():
            if path in DECLARED_OPENAPI_GAP:
                continue
            methods_doc = {
                method.lower() for method in documented.get(path, set())
            }
            self.assertEqual(
                methods_doc,
                {m.lower() for m in methods_live},
                f"OpenAPI document misses methods for {path}",
            )
            for method in methods_doc:
                spec = schema["paths"][path][method]
                self.assertIn("operationId", spec, f"{method.upper()} {path} lacks operationId")

    def test_openapi_document_has_no_phantom_paths(self) -> None:
        schema = generate_api_schema.generate_schema(
            self.app_py, BACKEND_DIR / "schemas"
        )
        live = _live_routes(self.app)
        for path in schema["paths"]:
            self.assertIn(
                path,
                live,
                f"OpenAPI document advertises unserved path {path}",
            )


# ---------------------------------------------------------------------------
# Error envelope conformance
# ---------------------------------------------------------------------------


class ErrorEnvelopeConformanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._env = _app_env({}, clear=CLEAR_ENV)
        self.client = self._env.__enter__()
        self.addCleanup(lambda: self._env.__exit__(None, None, None))

    def _assert_envelope(self, response, *, code: str) -> dict:
        body = _get_json(response)
        self.assertEqual(
            _classify_error_body(body),
            "envelope",
            f"body is not the standardized envelope: {body!r}",
        )
        self.assertEqual(response.status_code, ERROR_CODE_STATUS[code])
        self.assertEqual(body["error"]["code"], code)
        self.assertIsInstance(body["error"]["message"], str)
        self.assertTrue(body["error"]["message"])
        # The request id is exposed three ways and all three must agree.
        header_id = response.headers["X-Request-ID"]
        self.assertTrue(header_id)
        self.assertEqual(body["request_id"], header_id)
        self.assertEqual(body["error"]["request_id"], header_id)
        return body

    def _assert_flat(self, response, *, status: int) -> dict:
        body = _get_json(response)
        self.assertEqual(
            _classify_error_body(body),
            "flat",
            f"body is not the legacy flat error shape: {body!r}",
        )
        self.assertEqual(response.status_code, status)
        self.assertTrue(body["error"])
        self.assertEqual(body["request_id"], response.headers["X-Request-ID"])
        return body

    # -- positive / negative / boundary assertions ----------------------

    def test_validation_errors_use_standardized_envelope(self) -> None:
        self._assert_envelope(
            self.client.post("/api/proofs/register", json=["not", "an", "object"]),
            code=VALIDATION_ERROR,
        )
        self._assert_envelope(
            self.client.post(
                "/api/proofs/register",
                json={
                    "videoHash": "zz",
                    "metadataHash": HEX_32_B,
                    "proofId": HEX_32_C,
                    "tier": "source",
                },
            ),
            code=VALIDATION_ERROR,
        )
        self._assert_envelope(
            self.client.get("/api/proofs/by-video/not-a-hash"),
            code=VALIDATION_ERROR,
        )
        self._assert_envelope(
            self.client.get("/api/proofs", query_string={"limit": "abc"}),
            code=VALIDATION_ERROR,
        )

    def test_validation_messages_name_the_offending_field(self) -> None:
        body = self._assert_envelope(
            self.client.post(
                "/api/proofs/register",
                json={"videoHash": "zz", "metadataHash": HEX_32_B, "proofId": HEX_32_C},
            ),
            code=VALIDATION_ERROR,
        )
        self.assertEqual(
            body["error"]["message"], "videoHash must be a 32-byte hex string"
        )

        body = self._assert_envelope(
            self.client.post(
                "/api/proofs/register",
                json={
                    "videoHash": HEX_32,
                    "metadataHash": "nope",
                    "proofId": HEX_32_C,
                },
            ),
            code=VALIDATION_ERROR,
        )
        self.assertEqual(
            body["error"]["message"], "metadataHash must be a 32-byte hex string"
        )

        body = self._assert_envelope(
            self.client.post(
                "/api/proofs/register",
                json={"videoHash": HEX_32, "metadataHash": HEX_32_B, "proofId": "nope"},
            ),
            code=VALIDATION_ERROR,
        )
        self.assertEqual(
            body["error"]["message"], "proofId must be a 32-byte hex string"
        )

    def test_unsupported_tier_contract_lists_allowed_values(self) -> None:
        body = self._assert_envelope(
            self.client.post(
                "/api/proofs/register",
                json={
                    "videoHash": HEX_32,
                    "metadataHash": HEX_32_B,
                    "proofId": HEX_32_C,
                    "tier": "unsupported-tier",
                },
            ),
            code=VALIDATION_ERROR,
        )
        message = body["error"]["message"]
        for tier in ("silent", "source", "seal"):
            self.assertIn(tier, message, "tier contract list drifted")

    def test_disabled_capability_is_not_found_envelope(self) -> None:
        body = self._assert_envelope(
            self.client.post("/api/noir/silent-witness", json={}),
            code=NOT_FOUND,
        )
        self.assertEqual(body["error"]["message"], "local Noir worker is disabled")

    def test_oversized_request_body_is_payload_too_large_envelope(self) -> None:
        with _app_env({"MAX_CONTENT_LENGTH": "64"}, clear=CLEAR_ENV) as client:
            response = client.post(
                "/api/proofs/register",
                data="x" * 500,
                content_type="application/json",
            )
        self._assert_envelope(response, code=PAYLOAD_TOO_LARGE)

    def test_declared_error_codes_keep_stable_statuses(self) -> None:
        self.assertEqual(ERROR_CODE_STATUS[VALIDATION_ERROR], 400)
        self.assertEqual(ERROR_CODE_STATUS[NOT_FOUND], 404)
        self.assertEqual(ERROR_CODE_STATUS[PAYLOAD_TOO_LARGE], 413)
        self.assertEqual(ERROR_CODE_STATUS[UNSUPPORTED_MEDIA_TYPE], 400)
        self.assertEqual(ERROR_CODE_STATUS[RATE_LIMITED], 429)
        self.assertEqual(ERROR_CODE_STATUS[INTERNAL_ERROR], 500)

    def test_legacy_flat_errors_keep_their_shape(self) -> None:
        self._assert_flat(_empty_multipart(self.client, "/api/stego/embed"), status=400)
        self._assert_flat(_empty_multipart(self.client, "/api/stego/extract"), status=400)
        self._assert_flat(
            self.client.post("/api/time-attestation/create", json={}), status=400
        )
        self._assert_flat(self.client.get("/api/jobs/987654321"), status=404)
        self._assert_flat(self.client.get(f"/api/schemas/{'ff' * 32}"), status=404)
        self._assert_flat(
            self.client.get("/api/proofs", query_string={"cursor": "@@@"}), status=400
        )

    def test_every_error_probe_matches_a_documented_shape(self) -> None:
        for name, response, expected_shape in _error_probes(self.client):
            with self.subTest(probe=name):
                self.assertGreaterEqual(response.status_code, 400, name)
                body = _get_json(response)
                self.assertEqual(
                    _classify_error_body(body),
                    expected_shape,
                    f"{name} produced an undocumented error body: {body!r}",
                )
                self.assertEqual(
                    body["request_id"],
                    response.headers["X-Request-ID"],
                    f"{name} request id is not propagated consistently",
                )

    def test_error_envelope_never_leaks_submitted_material(self) -> None:
        for name, response, _shape in _error_probes(self.client):
            with self.subTest(probe=name):
                raw = response.get_data(as_text=True)
                self.assertNotIn(SENSITIVE_SENTINEL, raw, f"{name} echoed the sentinel")
                self.assertNotIn("privateKey", raw, f"{name} echoed a key name")


# ---------------------------------------------------------------------------
# Success envelope conformance
# ---------------------------------------------------------------------------


class SuccessEnvelopeConformanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._env = _app_env({}, clear=CLEAR_ENV)
        self.client = self._env.__enter__()
        self.addCleanup(lambda: self._env.__exit__(None, None, None))

    def test_health_contract(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        body = _get_json(response)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["service"], "harpocrates-stego")
        self.assertEqual(body["release_id"], "harpocrates-1.0.0")
        self.assertIn(body["network"], {"local", "testnet", "mainnet"})
        self.assertEqual(body["request_id"], response.headers["X-Request-ID"])

    def test_ready_contract_reports_dependency_and_aggregation_bounds(self) -> None:
        response = self.client.get("/ready")
        self.assertIn(response.status_code, {200, 503})
        body = _get_json(response)
        self.assertIsInstance(body["ok"], bool)
        self.assertEqual(
            body["ok"], response.status_code == 200, "ok must mirror the status code"
        )
        for field in ("database", "video_tools", "noir_worker", "aggregation"):
            self.assertIn(field, body)
        # The advertised bound must match the implementation constant that the
        # Noir circuit and Soroban contract are pinned to.
        self.assertEqual(body["max_aggregation_size"], app_module.MAX_AGGREGATION_SIZE)
        self.assertEqual(app_module.MAX_AGGREGATION_SIZE, 8)

    def test_schema_listing_contract(self) -> None:
        response = self.client.get("/api/schemas")
        self.assertEqual(response.status_code, 200)
        body = _get_json(response)
        self.assertIs(body["ok"], True)
        self.assertIsInstance(body["schemas"], list)
        self.assertTrue(body["schemas"], "canonical schemas must be discoverable")
        for schema in body["schemas"]:
            self.assertIn("schemaHash", schema)
            self.assertIn("version", schema)
            self.assertIn("attributes", schema)

    def test_proof_listing_contract(self) -> None:
        response = self.client.get("/api/proofs")
        self.assertEqual(response.status_code, 200)
        body = _get_json(response)
        self.assertIs(body["ok"], True)
        self.assertIsInstance(body["events"], list)
        self.assertIn("nextCursor", body)
        self.assertTrue(body["nextCursor"] is None or isinstance(body["nextCursor"], str))

    def test_upload_session_contract(self) -> None:
        response = self.client.post("/api/stego/upload-session")
        self.assertEqual(response.status_code, 200)
        body = _get_json(response)
        self.assertIsInstance(body["sessionId"], str)
        self.assertTrue(body["sessionId"])
        self.assertEqual(body["request_id"], response.headers["X-Request-ID"])

    def test_request_id_propagates_to_every_json_object_body(self) -> None:
        for method, path in (
            ("get", "/health"),
            ("get", "/ready"),
            ("get", "/api/schemas"),
            ("get", "/api/proofs"),
            ("get", "/api/proofs/lineage"),
        ):
            with self.subTest(path=path):
                response = getattr(self.client, method)(path)
                body = _get_json(response)
                self.assertIn("request_id", body)
                self.assertEqual(body["request_id"], response.headers["X-Request-ID"])

    def test_binary_and_text_responses_are_left_untouched(self) -> None:
        # Prometheus metrics are a documented exemption: not JSON, and must not
        # be rewritten by request-id propagation.
        response = self.client.get("/metrics")
        if response.status_code == 404:
            self.skipTest("metrics endpoint disabled in this configuration")
        self.assertTrue(response.mimetype.startswith("text/plain"))
        self.assertNotIn(b"request_id", response.data)


if __name__ == "__main__":
    unittest.main()
