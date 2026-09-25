from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import app as app_module
import stego
from config import load_config
from http_security import (
    CORS_ALLOW_HEADERS,
    CORS_EXPOSE_HEADERS,
    CORS_METHODS,
    SECURITY_HEADERS,
    apply_security_headers,
    cors_kwargs,
    is_cors_method_allowed,
    is_cors_request_header_allowed,
    is_origin_allowed,
)
from db import ConflictError, make_idempotency_key
from logging_utils import REDACTED_VALUE, redact_sensitive
from metrics import collector as metrics_collector


REAL_TEMPORARY_DIRECTORY = tempfile.TemporaryDirectory


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_VIDEO_HASH = "aa" * 32
VALID_METADATA_HASH = "bb" * 32
VALID_PROOF_ID = "cc" * 32

VALID_REGISTER_PAYLOAD: dict[str, object] = {
    "fileName": "evidence.mp4",
    "videoHash": VALID_VIDEO_HASH,
    "metadataHash": VALID_METADATA_HASH,
    "proofId": VALID_PROOF_ID,
    "tier": "source",
    "txHash": "deadbeef",
    "txStatus": "PENDING",
    "sourceAddress": "GCCHDCX2JTLB6FDKHGIAAQPS6JHBDETFXTCQRETJUP5BWBVT6G4LQKOQ",
    "contractId": "CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ",
}

TEST_API_KEY = "test-secret-key-for-registration"


# ---------------------------------------------------------------------------
# Context manager: spin up a fresh Flask app with specific env vars
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _app_env(extra: dict[str, str], clear: list[str] | None = None):
    """Temporarily set *extra* env vars, optionally clearing *clear* keys,
    then create a fresh Flask test client.  Restores the environment on exit.
    """
    clear = clear or []
    saved = {k: os.environ.get(k) for k in list(extra) + clear}

    for k in clear:
        os.environ.pop(k, None)
    os.environ.update(extra)

    try:
        fresh = app_module.create_app()
        yield fresh.test_client()
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _client_no_key():
    """Fresh test client with no REGISTER_API_KEY configured."""
    return _app_env({}, clear=["REGISTER_API_KEY", "REGISTER_API_KEY_EXPIRES"])


def _client_with_key(key: str, expires: str | None = None):
    """Fresh test client with the given API key (and optional expiry)."""
    extra: dict[str, str] = {"REGISTER_API_KEY": key}
    if expires:
        extra["REGISTER_API_KEY_EXPIRES"] = expires
    clear = [] if expires else ["REGISTER_API_KEY_EXPIRES"]
    return _app_env(extra, clear=clear)


# ---------------------------------------------------------------------------
# Helper: POST /api/proofs/register
# ---------------------------------------------------------------------------

def _post_register(
    client,
    *,
    token: str | None = None,
    auth_header: str | None = None,
    payload: dict | None = None,
):
    headers = {"Content-Type": "application/json"}
    if auth_header is not None:
        headers["Authorization"] = auth_header
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return client.post(
        "/api/proofs/register",
        data=json.dumps(payload or VALID_REGISTER_PAYLOAD),
        headers=headers,
    )


# ---------------------------------------------------------------------------
# General hardening tests (pre-existing)
# ---------------------------------------------------------------------------

class AppHardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        metrics_collector.reset()
        self.client = app_module.app.test_client()

    def tearDown(self) -> None:
        # Clean up any test routes registered on the shared app instance.
        for rule in list(self.client.application.url_map.iter_rules()):
            if rule.rule.startswith("/__test_"):
                self.client.application.url_map._rules.remove(rule)

    # ------------------------------------------------------------------
    # Health / Ready
    # ------------------------------------------------------------------

    def test_health_sets_security_headers(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["Cross-Origin-Resource-Policy"], "same-site")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Harpocrates-Release"], "harpocrates-1.0.0")
        self.assertEqual(response.headers["X-Harpocrates-Network"], "testnet")

    def test_request_log_includes_correlation_fields(self) -> None:
        with self.assertLogs("harpocrates.requests", level="INFO") as logs:
            response = self.client.get("/health", headers={"X-Request-ID": "req-test-1"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Request-ID"], "req-test-1")
        event = json.loads(logs.output[0].split(":", 2)[2])
        self.assertEqual(event["event"], "request")
        self.assertEqual(event["request_id"], "req-test-1")
        self.assertEqual(event["route"], "/health")
        self.assertEqual(event["status"], 200)
        self.assertIn("duration_ms", event)

    def test_error_log_includes_correlation_fields(self) -> None:
        with self.assertLogs("harpocrates.requests", level="INFO") as logs:
            response = self.client.post(
                "/api/stego/embed",
                data={
                    "metadata": json.dumps(valid_metadata()),
                    "video": (io.BytesIO(b"not a video"), "note.txt"),
                },
                content_type="multipart/form-data",
                headers={"X-Request-ID": "req-error-1"},
            )

        self.assertEqual(response.status_code, 400)
        events = [json.loads(item.split(":", 2)[2]) for item in logs.output]
        error_event = next(item for item in events if item["event"] == "error")
        request_event = next(item for item in events if item["event"] == "request")
        self.assertEqual(error_event["request_id"], "req-error-1")
        self.assertEqual(error_event["route"], "/api/stego/embed")
        self.assertEqual(error_event["status"], 400)
        self.assertEqual(request_event["request_id"], "req-error-1")
        self.assertEqual(request_event["status"], 400)

    def test_health_returns_request_id(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertIn("X-Request-Id", response.headers)
        self.assertTrue(response.headers["X-Request-Id"])

    def test_health_returns_standard_envelope(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["ok"], True)
        self.assertIn("request_id", response.json)
        self.assertEqual(response.json["service"], "harpocrates-stego")

    def test_ready_endpoint_reports_service_dependencies(self) -> None:
        response = self.client.get("/ready")

        self.assertIn(response.status_code, {200, 503})
        self.assertIn("video_tools", response.json)
        self.assertIn("database", response.json)
        self.assertIn("request_id", response.json)

    # ------------------------------------------------------------------
    # Error envelope shape
    # ------------------------------------------------------------------

    def test_error_response_includes_code_message_and_request_id(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["ok"], False)
        self.assertIn("error", response.json)
        self.assertIn("code", response.json["error"])
        self.assertIn("message", response.json["error"])
        self.assertIn("request_id", response.json["error"])
        self.assertEqual(response.json["error"]["code"], "VALIDATION_ERROR")
        self.assertEqual(
            response.json["error"]["message"], "video and metadata are required"
        )

    def test_error_response_request_id_header_matches_body(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        header_id = response.headers.get("X-Request-Id")
        body_id = response.json["error"]["request_id"]
        self.assertEqual(header_id, body_id)

    def test_forwarded_x_request_id_is_preserved(self) -> None:
        response = self.client.get(
            "/health",
            headers={"X-Request-Id": "caller-supplied-uuid"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Request-Id"], "caller-supplied-uuid")
        self.assertEqual(response.json["request_id"], "caller-supplied-uuid")

    # ------------------------------------------------------------------
    # Embed validation errors
    # ------------------------------------------------------------------

    def test_embed_rejects_non_video_upload(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps(valid_metadata()),
                "video": (io.BytesIO(b"not a video"), "note.txt"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["ok"], False)
        self.assertEqual(response.json["error"]["code"], "VALIDATION_ERROR")
        self.assertEqual(
            response.json["error"]["message"],
            "video upload must use a video content type",
        )

    def test_embed_rejects_invalid_video_signature_before_ffmpeg(self) -> None:
        with patch.object(app_module, "embed_metadata") as embed:
            response = self.client.post(
                "/api/stego/embed",
                data={
                    "metadata": json.dumps(valid_metadata()),
                    "video": (io.BytesIO(b"not really an mp4"), "evidence.mp4", "video/mp4"),
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 400)
        embed.assert_not_called()

    def test_extract_rejects_invalid_video_signature_before_ffmpeg(self) -> None:
        with patch.object(app_module, "extract_metadata") as extract:
            response = self.client.post(
                "/api/stego/extract",
                data={
                    "video": (io.BytesIO(b"not really an mp4"), "evidence.mp4", "video/mp4"),
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 400)
        extract.assert_not_called()
        self.assertEqual(
            response.json["error"],
            "uploaded file failed signature scan; invalid or unsupported video format",
        )

    def test_embed_rejects_missing_metadata_fields(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps({"protocol": "harpocrates"}),
                "video": (io.BytesIO(b"video bytes"), "evidence.mp4", "video/mp4"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["ok"], False)
        self.assertEqual(response.json["error"]["code"], "METADATA_MISSING_FIELD")
        self.assertEqual(response.json["error"]["field"], "proofId")
        self.assertIn(
            "metadata missing required field",
            response.json["error"]["message"],
        )

    # ------------------------------------------------------------------
    # Success envelope shape
    # ------------------------------------------------------------------

    def test_proofs_endpoint_returns_standard_envelope(self) -> None:
        response = self.client.get("/api/proofs")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["ok"], True)
        self.assertIn("request_id", response.json)
        self.assertIn("events", response.json)

    def test_proofs_by_video_rejects_invalid_hash_with_envelope(self) -> None:
        response = self.client.get("/api/proofs/by-video/not-hex")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["ok"], False)
        self.assertEqual(response.json["error"]["code"], "VALIDATION_ERROR")
        self.assertIn("request_id", response.json["error"])

    # ------------------------------------------------------------------
    # Internal errors do not leak details
    # ------------------------------------------------------------------

    def test_internal_error_does_not_leak_stack_trace(self) -> None:
        """The generic RuntimeError handler must never expose raw exception text."""
        from unittest.mock import patch

        def _raise_runtime():
            raise RuntimeError("secret credentials should not leak")

        with patch.dict(
            self.client.application.view_functions,
            {"health": _raise_runtime},
        ):
            response = self.client.get("/health")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["ok"], False)
        self.assertEqual(response.json["error"]["code"], "INTERNAL_ERROR")
        self.assertEqual(response.json["error"]["message"], "internal server error")
        self.assertNotIn("secret", response.json["error"]["message"])
        self.assertNotIn("credentials", response.json["error"]["message"])

    # ------------------------------------------------------------------
    # Payload too large
    # ------------------------------------------------------------------

    def test_request_too_large_returns_payload_too_large_code(self) -> None:
        """Verify the 413 envelope carries the PAYLOAD_TOO_LARGE error code."""
        original_max = self.client.application.config.get("MAX_CONTENT_LENGTH")
        try:
            self.client.application.config["MAX_CONTENT_LENGTH"] = 16
            response = self.client.post(
                "/api/proofs/register",
                data="x" * 128,
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 413)
            self.assertEqual(response.json["ok"], False)
            self.assertEqual(response.json["error"]["code"], "PAYLOAD_TOO_LARGE")
            self.assertIn("request_id", response.json["error"])
        finally:
            self.client.application.config["MAX_CONTENT_LENGTH"] = original_max

    def test_embed_success_removes_temp_directory(self) -> None:
        def fake_embed(source_path: str, output_path: str, _metadata: dict[str, object]) -> None:
            import urllib.request
            try:
                urllib.request.urlopen(source_path).read()
            except Exception:
                raise RuntimeError("source upload was not saved")
            req = urllib.request.Request(output_path, data=b"embedded video bytes", method="PUT")
            urllib.request.urlopen(req)

        response = self.post_with_tracked_tempdirs(
            "/api/stego/embed",
            {
                "metadata": json.dumps(valid_metadata()),
                "video": video_upload(),
            },
            patch.object(app_module, "embed_metadata", side_effect=fake_embed),
            patch.object(app_module, "insert_proof_event", return_value={"id": 1}),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"embedded video bytes")

    def test_embed_ffmpeg_failure_removes_temp_directory(self) -> None:
        def require_video_tool(binary: str) -> str:
            if binary == "ffmpeg":
                raise RuntimeError("ffmpeg is required for steganography processing")
            return binary

        response = self.post_with_tracked_tempdirs(
            "/api/stego/embed",
            {
                "metadata": json.dumps(valid_metadata()),
                "video": video_upload(),
            },
            patch.object(stego, "_require", side_effect=require_video_tool),
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["error"], "ffmpeg is required for steganography processing")

    def test_embed_ffprobe_failure_removes_temp_directory(self) -> None:
        def require_video_tool(binary: str) -> str:
            if binary == "ffprobe":
                raise RuntimeError("ffprobe is required for steganography processing")
            return binary

        response = self.post_with_tracked_tempdirs(
            "/api/stego/embed",
            {
                "metadata": json.dumps(valid_metadata()),
                "video": video_upload(),
            },
            patch.object(stego, "_require", side_effect=require_video_tool),
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["error"], "ffprobe is required for steganography processing")

    def test_extract_failure_removes_temp_directory(self) -> None:
        response = self.post_with_tracked_tempdirs(
            "/api/stego/extract",
            {"video": video_upload()},
            patch.object(app_module, "extract_metadata", side_effect=RuntimeError("metadata extraction failed")),
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["error"], "metadata extraction failed")

    def test_embed_database_failure_removes_temp_directory(self) -> None:
        def fake_embed(_source_path: str, output_path: str, _metadata: dict[str, object]) -> None:
            import urllib.request
            req = urllib.request.Request(output_path, data=b"embedded video bytes", method="PUT")
            urllib.request.urlopen(req)

        response = self.post_with_tracked_tempdirs(
            "/api/stego/embed",
            {
                "metadata": json.dumps(valid_metadata()),
                "video": video_upload(),
            },
            patch.object(app_module, "embed_metadata", side_effect=fake_embed),
            patch.object(app_module, "insert_proof_event", side_effect=RuntimeError("database write failed")),
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["error"], "database write failed")

    def test_extract_database_failure_removes_temp_directory(self) -> None:
        response = self.post_with_tracked_tempdirs(
            "/api/stego/extract",
            {"video": video_upload()},
            patch.object(app_module, "extract_metadata", return_value=valid_metadata()),
            patch.object(app_module, "insert_proof_event", side_effect=RuntimeError("database write failed")),
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["error"], "database write failed")

    def post_with_tracked_tempdirs(self, path: str, data: dict[str, object], *patches):
        observed: list[Path] = []
        workspace_factory = tracking_encrypted_workspace_factory(observed)
        with ExitStack() as stack:
            stack.enter_context(patch.object(app_module, "EncryptedWorkspace", workspace_factory))
            for patcher in patches:
                stack.enter_context(patcher)
            response = self.client.post(path, data=data, content_type="multipart/form-data")

        self.assertGreaterEqual(len(observed), 1)
        for temp_path in observed:
            self.assertFalse(temp_path.exists(), f"{temp_path} was not removed")
        return response

    def test_metrics_exposes_request_counts_status_and_latency(self) -> None:
        self.client.get("/health")
        response = self.client.get("/metrics")

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response.content_type)
        metrics_text = response.data.decode("utf-8")

        self.assertIn("# HELP harpocrates_requests_total", metrics_text)
        self.assertIn('# TYPE harpocrates_requests_total counter', metrics_text)
        self.assertIn('harpocrates_requests_total{endpoint="/health",method="GET",status="200"} 1', metrics_text)

        self.assertIn("# HELP harpocrates_request_duration_seconds", metrics_text)
        self.assertIn('# TYPE harpocrates_request_duration_seconds histogram', metrics_text)
        self.assertIn('harpocrates_request_duration_seconds_count{endpoint="/health",method="GET",status="200"} 1', metrics_text)

    def test_metrics_privacy_excludes_sensitive_identifiers_and_parameterizes_routes(self) -> None:
        video_hash = "a" * 64
        self.client.get(f"/api/proofs/by-video/{video_hash}")
        response = self.client.get("/metrics")

        self.assertEqual(response.status_code, 200)
        metrics_text = response.data.decode("utf-8")

        # Must NOT leak individual video hash parameter
        self.assertNotIn(video_hash, metrics_text)
        # Must expose parameterized route rule
        self.assertIn('endpoint="/api/proofs/by-video/<video_hash>"', metrics_text)

    def test_metrics_records_bounded_upload_size_histogram(self) -> None:
        self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps(valid_metadata()),
                "video": video_upload(),
            },
            content_type="multipart/form-data",
        )
        response = self.client.get("/metrics")

        self.assertEqual(response.status_code, 200)
        metrics_text = response.data.decode("utf-8")

        self.assertIn("# HELP harpocrates_upload_bytes_total", metrics_text)
        self.assertIn('# TYPE harpocrates_upload_bytes_total histogram', metrics_text)
        self.assertIn('harpocrates_upload_bytes_total_bucket{endpoint="/api/stego/embed",method="POST",le="', metrics_text)

    def test_metrics_protection_token_authentication(self) -> None:
        with patch.dict(app_module.os.environ, {"METRICS_TOKEN": "secret-scraping-token"}):
            token_app = app_module.create_app()
            token_client = token_app.test_client()

            token_client.get("/health")

            # Missing token -> 401
            res_unauth = token_client.get("/metrics")
            self.assertEqual(res_unauth.status_code, 401)
            self.assertEqual(res_unauth.json["error"], "unauthorized metrics access")

            # Invalid Bearer token -> 401
            res_invalid = token_client.get("/metrics", headers={"Authorization": "Bearer wrong-token"})
            self.assertEqual(res_invalid.status_code, 401)

            # Valid Bearer token -> 200
            res_bearer = token_client.get("/metrics", headers={"Authorization": "Bearer secret-scraping-token"})
            self.assertEqual(res_bearer.status_code, 200)
            self.assertIn("harpocrates_requests_total", res_bearer.data.decode("utf-8"))

            # Valid X-Metrics-Token -> 200
            res_header = token_client.get("/metrics", headers={"X-Metrics-Token": "secret-scraping-token"})
            self.assertEqual(res_header.status_code, 200)

    def test_metrics_isolation_disabled_endpoint(self) -> None:
        with patch.dict(app_module.os.environ, {"METRICS_ENABLED": "false"}):
            disabled_app = app_module.create_app()
            disabled_client = disabled_app.test_client()

            res = disabled_client.get("/metrics")
            self.assertEqual(res.status_code, 404)
            self.assertEqual(res.json["error"], "metrics service disabled")

    def test_redact_sensitive_redacts_nested_fields(self) -> None:
        value = {
            "Authorization": "Bearer secret",
            "proof": "secret-proof",
            "nested": {
                "publicInputs": ["secret-public-input"],
                "public_inputs": ["secret-public-input"],
                "items": [
                    {"credential_secret": "secret-credential"},
                    {"NullifierSecret": "secret-nullifier"},
                    {"compiledWitness": "secret-witness"},
                ],
            },
        }

        redacted = redact_sensitive(value)

        self.assertEqual(redacted["Authorization"], REDACTED_VALUE)
        self.assertEqual(redacted["proof"], REDACTED_VALUE)
        self.assertEqual(redacted["nested"]["publicInputs"], REDACTED_VALUE)
        self.assertEqual(redacted["nested"]["public_inputs"], REDACTED_VALUE)
        self.assertEqual(redacted["nested"]["items"][0]["credential_secret"], REDACTED_VALUE)
        self.assertEqual(redacted["nested"]["items"][1]["NullifierSecret"], REDACTED_VALUE)
        self.assertEqual(redacted["nested"]["items"][2]["compiledWitness"], REDACTED_VALUE)

    def test_redact_sensitive_preserves_safe_fields(self) -> None:
        value = {
            "videoHash": "11" * 32,
            "metadata": {"tier": "silent", "count": 2},
            "items": [{"status": "ok"}],
        }

        self.assertEqual(redact_sensitive(value), value)

    def test_embed_rejects_malformed_timestamp(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps({**valid_metadata(), "timestamp": "not-a-timestamp"}),
                "video": (io.BytesIO(b"video bytes"), "evidence.mp4", "video/mp4"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"]["code"], "METADATA_INVALID_FIELD")
        self.assertIn("ISO-8601", response.json["error"]["message"])

    def test_embed_rejects_non_utc_timestamp(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps({**valid_metadata(), "timestamp": "2026-06-18T00:00:00.000"}),
                "video": (io.BytesIO(b"video bytes"), "evidence.mp4", "video/mp4"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"]["code"], "METADATA_INVALID_FIELD")
        self.assertIn("timezone-aware", response.json["error"]["message"])

    def test_embed_rejects_far_future_timestamp(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps({**valid_metadata(), "timestamp": "2126-06-18T00:00:00.000Z"}),
                "video": (io.BytesIO(b"video bytes"), "evidence.mp4", "video/mp4"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"]["code"], "METADATA_INVALID_FIELD")
        self.assertIn("unreasonably far", response.json["error"]["message"])


def tracking_encrypted_workspace_factory(observed: list[Path]):
    class TrackingEncryptedWorkspace(app_module.EncryptedWorkspace):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            observed.append(Path(self.tmp_dir))
    return TrackingEncryptedWorkspace


# ---------------------------------------------------------------------------
# Registration authentication tests
# ---------------------------------------------------------------------------

class RegisterProofAuthTest(unittest.TestCase):
    """Positive and negative tests for /api/proofs/register authentication."""

    # --- Positive: open endpoint (no key configured) ---------------------

    def test_open_when_no_key_configured(self) -> None:
        """When REGISTER_API_KEY is not set the endpoint accepts any request."""
        with _client_no_key() as client:
            resp = _post_register(client)
        # 200 if DB available, 500 if DATABASE_URL absent – both indicate auth
        # was not the reason for failure.
        self.assertIn(resp.status_code, {200, 500})

    # --- Positive: valid Bearer token, no expiry -------------------------

    def test_accepts_valid_bearer_token(self) -> None:
        with _client_with_key(TEST_API_KEY) as client:
            resp = _post_register(client, token=TEST_API_KEY)
        self.assertIn(resp.status_code, {200, 500})

    # --- Positive: valid Bearer token, future expiry ---------------------

    def test_accepts_valid_token_with_future_expiry(self) -> None:
        with _client_with_key(TEST_API_KEY, expires="2099-12-31T23:59:59Z") as client:
            resp = _post_register(client, token=TEST_API_KEY)
        self.assertIn(resp.status_code, {200, 500})

    # --- Negative: missing Authorization header --------------------------

    def test_rejects_missing_auth_header(self) -> None:
        with _client_with_key(TEST_API_KEY) as client:
            resp = _post_register(client, token=None)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Authorization", resp.json["error"])

    # --- Negative: wrong token -------------------------------------------

    def test_rejects_wrong_token(self) -> None:
        with _client_with_key(TEST_API_KEY) as client:
            resp = _post_register(client, token="definitely-wrong")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid", resp.json["error"])

    # --- Negative: non-Bearer auth scheme --------------------------------

    def test_rejects_non_bearer_scheme(self) -> None:
        with _client_with_key(TEST_API_KEY) as client:
            resp = _post_register(client, auth_header=f"Basic {TEST_API_KEY}")
        self.assertEqual(resp.status_code, 401)

    # --- Negative: expired key -------------------------------------------

    def test_rejects_expired_key(self) -> None:
        with _client_with_key(TEST_API_KEY, expires="2000-06-01T00:00:00Z") as client:
            resp = _post_register(client, token=TEST_API_KEY)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("expired", resp.json["error"])

    # --- Negative: empty Bearer value ------------------------------------

    def test_rejects_empty_bearer_value(self) -> None:
        with _client_with_key(TEST_API_KEY) as client:
            resp = _post_register(client, auth_header="Bearer ")
        self.assertEqual(resp.status_code, 401)

    # --- Negative: wrong token, future expiry ----------------------------

    def test_rejects_wrong_token_with_future_expiry(self) -> None:
        with _client_with_key(TEST_API_KEY, expires="2099-01-01T00:00:00Z") as client:
            resp = _post_register(client, token="not-the-right-key")
        self.assertEqual(resp.status_code, 401)

    # --- Negative: expired even with correct token -----------------------

    def test_rejects_correct_token_when_expired(self) -> None:
        """Expiry check runs before token comparison; correct key still rejected."""
        with _client_with_key(TEST_API_KEY, expires="2000-01-01T00:00:00Z") as client:
            resp = _post_register(client, token=TEST_API_KEY)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("expired", resp.json["error"])


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def valid_metadata() -> dict[str, object]:
    return {
        "protocol": "harpocrates",
        "version": 1,
        "tier": "silent",
        "sourceHash": "11" * 32,
        "proofId": "22" * 32,
        "timestamp": "2026-06-18T00:00:00.000Z",
    }


def video_upload() -> tuple[io.BytesIO, str, str]:
    return (
        io.BytesIO(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 10),
        "evidence.mp4",
        "video/mp4",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def valid_register_payload(**overrides) -> dict[str, object]:
    """Return a well-formed /api/proofs/register payload."""
    base = {
        "fileName": "evidence.mp4",
        "videoHash": "aa" * 32,
        "metadataHash": "bb" * 32,
        "proofId": "cc" * 32,
        "tier": "source",
        "txHash": "dd" * 32,
        "txStatus": "confirmed",
        "sourceAddress": "GDVRSXIO4SK2KSMUKJTQHMDDHBBFC7NGZZ6WLVOPKAG47GYPYAZCZR7G",
        "contractId": "CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT",
    }
    base.update(overrides)
    return base


def _stub_event(payload: dict) -> dict:
    """Build a fake db row that matches the given payload, as upsert_register_event would return."""
    return {
        "id": 1,
        "event_type": "register",
        "file_name": payload.get("fileName"),
        "video_hash": payload["videoHash"],
        "metadata_hash": payload["metadataHash"],
        "proof_id": payload["proofId"],
        "tier": payload.get("tier"),
        "embedded_hash": None,
        "tx_hash": payload.get("txHash"),
        "tx_status": payload.get("txStatus"),
        "source_address": payload.get("sourceAddress"),
        "contract_id": payload.get("contractId"),
        "metadata": None,
        "created_at": "2026-07-24T00:00:00+00:00",
    }


# ---------------------------------------------------------------------------
# Idempotency tests
# ---------------------------------------------------------------------------

class ProofRegistrationIdempotencyTest(unittest.TestCase):
    """Tests for idempotent behaviour on /api/proofs/register."""

    def setUp(self) -> None:
        self.client = app_module.app.test_client()

    # ------------------------------------------------------------------
    # make_idempotency_key unit tests
    # ------------------------------------------------------------------

    def test_idempotency_key_is_deterministic(self) -> None:
        k1 = make_idempotency_key("aa" * 32, "bb" * 32, "cc" * 32)
        k2 = make_idempotency_key("aa" * 32, "bb" * 32, "cc" * 32)
        self.assertEqual(k1, k2)

    def test_idempotency_key_is_hex_64(self) -> None:
        k = make_idempotency_key("aa" * 32, "bb" * 32, None)
        self.assertEqual(len(k), 64)
        int(k, 16)  # must parse as hex

    def test_idempotency_key_differs_on_different_tx_hash(self) -> None:
        k1 = make_idempotency_key("aa" * 32, "bb" * 32, "cc" * 32)
        k2 = make_idempotency_key("aa" * 32, "bb" * 32, "dd" * 32)
        self.assertNotEqual(k1, k2)

    def test_idempotency_key_absent_tx_hash_equals_empty_string(self) -> None:
        k_none = make_idempotency_key("aa" * 32, "bb" * 32, None)
        k_empty = make_idempotency_key("aa" * 32, "bb" * 32, "")
        self.assertEqual(k_none, k_empty)

    def test_idempotency_key_differs_on_different_video_hash(self) -> None:
        k1 = make_idempotency_key("aa" * 32, "bb" * 32, None)
        k2 = make_idempotency_key("ee" * 32, "bb" * 32, None)
        self.assertNotEqual(k1, k2)

    def test_idempotency_key_differs_on_different_proof_id(self) -> None:
        k1 = make_idempotency_key("aa" * 32, "bb" * 32, None)
        k2 = make_idempotency_key("aa" * 32, "ff" * 32, None)
        self.assertNotEqual(k1, k2)

    # ------------------------------------------------------------------
    # Positive path: first submission creates the record (201)
    # ------------------------------------------------------------------

    def test_register_first_submission_returns_201(self) -> None:
        payload = valid_register_payload()
        db_row = _stub_event(payload)

        with patch.object(app_module, "upsert_register_event", return_value=(db_row, True)):
            response = self.client.post(
                "/api/proofs/register",
                json=payload,
            )

        self.assertEqual(response.status_code, 201)
        body = response.get_json()
        self.assertTrue(body["ok"])
        self.assertTrue(body["created"])
        self.assertEqual(body["db_event"]["video_hash"], payload["videoHash"])

    def test_register_accepts_all_protocol_tiers(self) -> None:
        for tier in ("silent", "source", "seal"):
            with self.subTest(tier=tier):
                payload = valid_register_payload(tier=tier)
                db_row = _stub_event(payload)

                with patch.object(app_module, "upsert_register_event", return_value=(db_row, True)) as upsert_mock:
                    response = self.client.post("/api/proofs/register", json=payload)

                self.assertEqual(response.status_code, 201)
                self.assertEqual(upsert_mock.call_args.kwargs["tier"], tier)
                self.assertEqual(response.get_json()["db_event"]["tier"], tier)

    def test_register_rejects_missing_tier_with_stable_error(self) -> None:
        payload = valid_register_payload()
        del payload["tier"]

        with patch.object(app_module, "upsert_register_event") as upsert_mock:
            response = self.client.post("/api/proofs/register", json=payload)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "VALIDATION_ERROR")
        self.assertEqual(
            response.get_json()["error"]["message"],
            "tier must be one of: silent, source, seal",
        )
        upsert_mock.assert_not_called()

    def test_register_rejects_invalid_tier_with_stable_error(self) -> None:
        payload = valid_register_payload(tier="premium")

        with patch.object(app_module, "upsert_register_event") as upsert_mock:
            response = self.client.post("/api/proofs/register", json=payload)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "VALIDATION_ERROR")
        self.assertEqual(
            response.get_json()["error"]["message"],
            "tier must be one of: silent, source, seal",
        )
        upsert_mock.assert_not_called()

    # ------------------------------------------------------------------
    # Positive path: idempotent retry returns original record (200)
    # ------------------------------------------------------------------

    def test_register_idempotent_retry_returns_200_with_existing_record(self) -> None:
        payload = valid_register_payload()
        db_row = _stub_event(payload)
        db_row["id"] = 42  # simulate pre-existing row

        with patch.object(app_module, "upsert_register_event", return_value=(db_row, False)):
            response = self.client.post(
                "/api/proofs/register",
                json=payload,
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["ok"])
        self.assertFalse(body["created"])
        self.assertEqual(body["db_event"]["id"], 42)

    def test_register_retry_response_contains_same_record_as_original(self) -> None:
        """Second call must return the *same* row content as the first."""
        payload = valid_register_payload()
        db_row = _stub_event(payload)
        db_row["id"] = 99

        # Both calls return the same row (created=False on second)
        with patch.object(app_module, "upsert_register_event", return_value=(db_row, False)):
            r1 = self.client.post("/api/proofs/register", json=payload)
            r2 = self.client.post("/api/proofs/register", json=payload)

        self.assertEqual(r1.status_code, r2.status_code)
        self.assertEqual(r1.get_json()["db_event"]["id"], r2.get_json()["db_event"]["id"])

    # ------------------------------------------------------------------
    # Negative path: conflicting reuse of idempotency key → 409
    # ------------------------------------------------------------------

    def test_register_conflict_returns_409(self) -> None:
        payload = valid_register_payload()
        conflict = ConflictError(
            idempotency_key=make_idempotency_key(payload["videoHash"], payload["proofId"], payload.get("txHash")),
            field="metadata_hash",
            existing_value="bb" * 32,
            incoming_value="ff" * 32,
        )

        with patch.object(app_module, "upsert_register_event", side_effect=conflict):
            response = self.client.post(
                "/api/proofs/register",
                json=payload,
            )

        self.assertEqual(response.status_code, 409)
        body = response.get_json()
        self.assertIn("conflict", body["error"])
        self.assertEqual(body["conflict_field"], "metadata_hash")

    def test_register_conflict_error_exposes_conflicting_field(self) -> None:
        """409 body must tell the caller which field differed."""
        payload = valid_register_payload()
        for differing_field in ("video_hash", "metadata_hash", "tier", "source_address", "contract_id"):
            conflict = ConflictError(
                idempotency_key="x" * 64,
                field=differing_field,
                existing_value="old",
                incoming_value="new",
            )
            with patch.object(app_module, "upsert_register_event", side_effect=conflict):
                response = self.client.post("/api/proofs/register", json=payload)

            self.assertEqual(response.status_code, 409, msg=f"field={differing_field}")
            self.assertEqual(response.get_json()["conflict_field"], differing_field)

    def test_register_missing_required_field_still_returns_400(self) -> None:
        """Validation errors before idempotency logic must still be 400."""
        payload = valid_register_payload()
        del payload["videoHash"]

        response = self.client.post("/api/proofs/register", json=payload)

        self.assertEqual(response.status_code, 400)
        self.assertIn("videoHash", response.get_json()["error"])

    def test_register_invalid_video_hash_format_returns_400(self) -> None:
        payload = valid_register_payload(videoHash="not-hex")
        response = self.client.post("/api/proofs/register", json=payload)
        self.assertEqual(response.status_code, 400)

    def test_register_normalizes_uppercase_tx_hash_and_status(self) -> None:
        payload = valid_register_payload(txHash="DD" * 32, txStatus="SUCCESS")
        db_row = _stub_event(payload)

        with patch.object(app_module, "upsert_register_event", return_value=(db_row, True)) as upsert_mock:
            response = self.client.post("/api/proofs/register", json=payload)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(upsert_mock.call_args.kwargs["tx_hash"], "dd" * 32)
        self.assertEqual(upsert_mock.call_args.kwargs["tx_status"], "confirmed")

    def test_register_rejects_invalid_tx_status(self) -> None:
        payload = valid_register_payload(txStatus="pending-ish")
        response = self.client.post("/api/proofs/register", json=payload)

        self.assertEqual(response.status_code, 400)
        self.assertIn("txStatus", response.get_json()["error"])

    def test_register_rejects_tx_hash_outside_hex_length_boundary(self) -> None:
        for tx_hash in ("d" * 63, "d" * 65):
            with self.subTest(tx_hash=tx_hash):
                payload = valid_register_payload(txHash=tx_hash)
                response = self.client.post("/api/proofs/register", json=payload)
                self.assertEqual(response.status_code, 400)
                self.assertIn("txHash", response.get_json()["error"])

    # ------------------------------------------------------------------
    # Concurrent submissions
    # ------------------------------------------------------------------

    def test_register_concurrent_identical_requests_one_created_rest_idempotent(self) -> None:
        """Simulate N threads submitting the same payload simultaneously.

        One thread wins the insert (created=True / 201); all others receive
        the pre-existing row (created=False / 200).  No 409 must be raised
        for truly identical payloads.
        """
        payload = valid_register_payload()
        db_row = _stub_event(payload)

        # Simulate the real DB race: the first call returns (row, True);
        # all subsequent calls return (row, False) — as ON CONFLICT DO NOTHING
        # followed by SELECT would behave.
        call_count = {"n": 0}
        lock = threading.Lock()

        def fake_upsert(**kwargs):
            with lock:
                call_count["n"] += 1
                created = call_count["n"] == 1
            return db_row, created

        results: list[tuple[int, dict]] = []
        results_lock = threading.Lock()

        def do_request() -> None:
            with patch.object(app_module, "upsert_register_event", side_effect=fake_upsert):
                resp = self.client.post("/api/proofs/register", json=payload)
            with results_lock:
                results.append((resp.status_code, resp.get_json()))

        threads = [threading.Thread(target=do_request) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        statuses = [r[0] for r in results]
        self.assertEqual(statuses.count(201), 1, "Exactly one thread should receive 201")
        self.assertEqual(statuses.count(200), 7, "All other threads should receive 200")
        # No 409 or 5xx
        for status, body in results:
            self.assertIn(status, {200, 201})
            self.assertTrue(body["ok"])

    def test_register_concurrent_conflicting_requests_raise_409(self) -> None:
        """Threads with genuinely different payloads for the same key get 409."""
        payload_a = valid_register_payload()
        payload_b = valid_register_payload(metadataHash="ff" * 32)  # different hash
        db_row = _stub_event(payload_a)

        def fake_upsert_conflict(**kwargs):
            raise ConflictError(
                idempotency_key="x" * 64,
                field="metadata_hash",
                existing_value=payload_a["metadataHash"],
                incoming_value=payload_b["metadataHash"],
            )

        with patch.object(app_module, "upsert_register_event", side_effect=fake_upsert_conflict):
            response = self.client.post("/api/proofs/register", json=payload_b)

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["conflict_field"], "metadata_hash")


class CorsConfigurationTest(unittest.TestCase):
    def test_production_rejects_wildcard_cors(self) -> None:
        with patch.dict("os.environ", {"APP_ENV": "production", "CORS_ORIGINS": "*", "ALLOW_WILDCARD_CORS": "true"}):
            with self.assertRaises(RuntimeError) as ctx:
                load_config()
            self.assertIn("Wildcard CORS origins are not permitted in production", str(ctx.exception))

    def test_production_accepts_explicit_cors_origins(self) -> None:
        with patch.dict("os.environ", {"APP_ENV": "production", "CORS_ORIGINS": "https://app.example.com"}):
            cfg = load_config()
            self.assertEqual(cfg.cors_origins, ["https://app.example.com"])

    def test_development_allows_wildcard_cors_when_flag_enabled(self) -> None:
        with patch.dict("os.environ", {"APP_ENV": "development", "CORS_ORIGINS": "*", "ALLOW_WILDCARD_CORS": "true"}):
            cfg = load_config()
            self.assertEqual(cfg.cors_origins, ["*"])

    def test_development_rejects_wildcard_cors_without_flag(self) -> None:
        with patch.dict("os.environ", {"APP_ENV": "development", "CORS_ORIGINS": "*"}, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                load_config()
            self.assertIn("Wildcard CORS requires ALLOW_WILDCARD_CORS=true", str(ctx.exception))

    def test_default_local_development_origins(self) -> None:
        with patch.dict("os.environ", {"APP_ENV": "development"}, clear=True):
            cfg = load_config()
            self.assertEqual(cfg.cors_origins, ["http://localhost:5173", "http://127.0.0.1:5173"])


class CorsPreflightAndHeadersTest(unittest.TestCase):
    def setUp(self) -> None:
        metrics_collector.reset()
        self.client = app_module.app.test_client()

    def test_preflight_positive_allowed_origin_method_and_headers(self) -> None:
        response = self.client.options(
            "/api/proofs/register",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, X-Request-ID",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "http://localhost:5173")
        allowed_methods = response.headers.get("Access-Control-Allow-Methods", "")
        self.assertIn("POST", allowed_methods)
        allowed_headers = response.headers.get("Access-Control-Allow-Headers", "")
        self.assertIn("Content-Type", allowed_headers)
        self.assertIn("X-Request-ID", allowed_headers)

    def test_preflight_negative_disallowed_method(self) -> None:
        response = self.client.options(
            "/api/proofs/register",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "DELETE",
            },
        )
        allowed_methods = response.headers.get("Access-Control-Allow-Methods", "")
        self.assertNotIn("DELETE", allowed_methods)

    def test_preflight_negative_disallowed_header(self) -> None:
        response = self.client.options(
            "/api/proofs/register",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "X-Forbidden-Header",
            },
        )
        allowed_headers = response.headers.get("Access-Control-Allow-Headers", "")
        self.assertNotIn("X-Forbidden-Header", allowed_headers)

    def test_preflight_negative_disallowed_origin(self) -> None:
        response = self.client.options(
            "/api/proofs/register",
            headers={
                "Origin": "http://unauthorized-domain.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertNotEqual(response.headers.get("Access-Control-Allow-Origin"), "http://unauthorized-domain.com")

    def test_cors_exposes_required_response_headers(self) -> None:
        response = self.client.get(
            "/health",
            headers={"Origin": "http://localhost:5173"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "http://localhost:5173")
        exposed = response.headers.get("Access-Control-Expose-Headers", "")
        self.assertIn("X-Request-ID", exposed)
        self.assertIn("X-Harpocrates-Source-Hash", exposed)



class HttpSecurityUnitTest(unittest.TestCase):
    """Pure-unit coverage for CORS / security header helpers (no Flask app)."""

    def test_cors_kwargs_positive_shape(self) -> None:
        kwargs = cors_kwargs(["https://app.example.com"])
        self.assertEqual(kwargs["origins"], ["https://app.example.com"])
        self.assertEqual(kwargs["methods"], list(CORS_METHODS))
        self.assertEqual(kwargs["allow_headers"], list(CORS_ALLOW_HEADERS))
        self.assertEqual(kwargs["expose_headers"], list(CORS_EXPOSE_HEADERS))
        self.assertIn("GET", kwargs["methods"])
        self.assertIn("POST", kwargs["methods"])
        self.assertIn("OPTIONS", kwargs["methods"])
        self.assertNotIn("DELETE", kwargs["methods"])
        self.assertNotIn("PUT", kwargs["methods"])

    def test_cors_kwargs_copies_lists(self) -> None:
        origins = ["https://a.example"]
        kwargs = cors_kwargs(origins)
        kwargs["origins"].append("https://b.example")
        self.assertEqual(origins, ["https://a.example"])

    def test_origin_allowlist_positive_negative_and_wildcard(self) -> None:
        allowed = ["http://localhost:5173", "https://app.example.com"]
        self.assertTrue(is_origin_allowed("http://localhost:5173", allowed))
        self.assertFalse(is_origin_allowed("http://unauthorized-domain.com", allowed))
        self.assertFalse(is_origin_allowed(None, allowed))
        self.assertFalse(is_origin_allowed("", allowed))
        self.assertTrue(is_origin_allowed("https://any.example", ["*"]))

    def test_cors_method_and_header_boundary_checks(self) -> None:
        self.assertTrue(is_cors_method_allowed("POST"))
        self.assertTrue(is_cors_method_allowed("get"))
        self.assertFalse(is_cors_method_allowed("DELETE"))
        self.assertFalse(is_cors_method_allowed(None))
        self.assertTrue(is_cors_request_header_allowed("Content-Type"))
        self.assertTrue(is_cors_request_header_allowed("x-request-id"))
        self.assertFalse(is_cors_request_header_allowed("X-Forbidden-Header"))
        self.assertFalse(is_cors_request_header_allowed(None))

    def test_apply_security_headers_enabled_positive(self) -> None:
        headers: dict[str, str] = {}
        apply_security_headers(headers, enabled=True)
        for name, value in SECURITY_HEADERS.items():
            self.assertEqual(headers[name], value)

    def test_apply_security_headers_disabled_negative(self) -> None:
        headers: dict[str, str] = {"X-Custom": "keep"}
        apply_security_headers(headers, enabled=False)
        self.assertEqual(headers, {"X-Custom": "keep"})
        for name in SECURITY_HEADERS:
            self.assertNotIn(name, headers)

    def test_apply_security_headers_setdefault_regression(self) -> None:
        headers = {"Cache-Control": "public, max-age=60"}
        apply_security_headers(headers, enabled=True)
        # Pre-set values must not be overwritten (setdefault semantics).
        self.assertEqual(headers["Cache-Control"], "public, max-age=60")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")


class SecurityHeadersToggleIntegrationTest(unittest.TestCase):
    """Integration coverage: SECURITY_HEADERS_ENABLED toggles live responses."""

    def test_security_headers_enabled_via_env(self) -> None:
        with _app_env(
            {
                "SECURITY_HEADERS_ENABLED": "true",
                "NOIR_WORKER_ENABLED": "false",
                "DATABASE_URL": "",
            }
        ) as client:
            response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        for name, value in SECURITY_HEADERS.items():
            self.assertEqual(response.headers.get(name), value)

    def test_security_headers_disabled_via_env(self) -> None:
        with _app_env(
            {
                "SECURITY_HEADERS_ENABLED": "false",
                "NOIR_WORKER_ENABLED": "false",
                "DATABASE_URL": "",
            }
        ) as client:
            response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        for name in SECURITY_HEADERS:
            self.assertIsNone(response.headers.get(name))

    def test_custom_cors_origin_accepted_and_rejected(self) -> None:
        with _app_env(
            {
                "CORS_ORIGINS": "https://wave.example",
                "APP_ENV": "development",
                "NOIR_WORKER_ENABLED": "false",
                "DATABASE_URL": "",
            }
        ) as client:
            ok = client.get("/health", headers={"Origin": "https://wave.example"})
            bad = client.get("/health", headers={"Origin": "https://evil.example"})
        self.assertEqual(ok.headers.get("Access-Control-Allow-Origin"), "https://wave.example")
        self.assertNotEqual(bad.headers.get("Access-Control-Allow-Origin"), "https://evil.example")



if __name__ == "__main__":
    unittest.main()
