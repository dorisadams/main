"""
Unit and integration tests for fetch_external.safe_urlopen and the
tx_verification / webhook callers that wrap it.

Coverage
--------
- safe_urlopen: connect timeout, read timeout, oversized response,
  HTTP error, URL error, success (2xx), chunked accumulation.
- tx_verification.verify_transaction_status: confirmed, failed, 404→missing,
  timeout fallback, oversized response fallback, multi-RPC failover.
- webhook.dispatch_webhook: success, HTTP error, timeout, oversized response.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from io import BytesIO
from unittest import mock

import pytest

# ── helpers ────────────────────────────────────────────────────────────────


class _FakeResponse:
    """Minimal fake urllib response that supports the context-manager protocol."""

    def __init__(self, body: bytes, status: int = 200):
        self.status = status
        self._buf = BytesIO(body)

    def read(self, size: int = -1) -> bytes:
        return self._buf.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _make_response(body: bytes, status: int = 200) -> _FakeResponse:
    return _FakeResponse(body, status)


# ── fetch_external.safe_urlopen ────────────────────────────────────────────


class TestSafeUrlopen:
    """Tests for fetch_external.safe_urlopen."""

    def _req(self, url: str = "https://example.com/test") -> urllib.request.Request:
        return urllib.request.Request(url)

    # --- success path ---

    def test_returns_status_and_body_on_success(self):
        from fetch_external import safe_urlopen

        body = b'{"ok": true}'
        fake_resp = _make_response(body)
        with mock.patch("urllib.request.urlopen", return_value=fake_resp):
            result = safe_urlopen(self._req(), connect_timeout=5.0, read_timeout=10.0, max_bytes=1024)
        assert result.status == 200
        assert result.body == body

    def test_passes_max_of_connect_and_read_as_socket_timeout(self):
        """The underlying urlopen timeout is max(connect, read)."""
        from fetch_external import safe_urlopen

        body = b"{}"
        fake_resp = _make_response(body)
        with mock.patch("urllib.request.urlopen", return_value=fake_resp) as mock_open:
            safe_urlopen(self._req(), connect_timeout=3.0, read_timeout=7.0, max_bytes=1024)
        _, kwargs = mock_open.call_args
        assert kwargs["timeout"] == 7.0  # max(3.0, 7.0)

    def test_passes_max_of_connect_and_read_reversed(self):
        from fetch_external import safe_urlopen

        body = b"{}"
        fake_resp = _make_response(body)
        with mock.patch("urllib.request.urlopen", return_value=fake_resp) as mock_open:
            safe_urlopen(self._req(), connect_timeout=12.0, read_timeout=5.0, max_bytes=1024)
        _, kwargs = mock_open.call_args
        assert kwargs["timeout"] == 12.0  # max(12.0, 5.0)

    # --- timeout errors ---

    def test_raises_fetch_timeout_on_socket_timeout(self):
        from fetch_external import FetchTimeoutError, safe_urlopen

        with mock.patch("urllib.request.urlopen", side_effect=socket.timeout("timed out")):
            with pytest.raises(FetchTimeoutError):
                safe_urlopen(self._req())

    def test_raises_fetch_timeout_on_builtin_timeout_error(self):
        from fetch_external import FetchTimeoutError, safe_urlopen

        with mock.patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with pytest.raises(FetchTimeoutError):
                safe_urlopen(self._req())

    # --- oversized response ---

    def test_raises_response_too_large_when_body_exceeds_limit(self):
        from fetch_external import ResponseTooLargeError, safe_urlopen

        # Body is 1001 bytes but max_bytes is 1000
        big_body = b"x" * 1001
        fake_resp = _make_response(big_body)
        with mock.patch("urllib.request.urlopen", return_value=fake_resp):
            with pytest.raises(ResponseTooLargeError):
                safe_urlopen(self._req(), max_bytes=1000)

    def test_accepts_body_at_exact_limit(self):
        from fetch_external import safe_urlopen

        body = b"y" * 500
        fake_resp = _make_response(body)
        with mock.patch("urllib.request.urlopen", return_value=fake_resp):
            result = safe_urlopen(self._req(), max_bytes=500)
        assert len(result.body) == 500

    def test_empty_body_is_accepted(self):
        from fetch_external import safe_urlopen

        fake_resp = _make_response(b"")
        with mock.patch("urllib.request.urlopen", return_value=fake_resp):
            result = safe_urlopen(self._req(), max_bytes=64)
        assert result.body == b""

    # --- HTTP errors propagate as-is ---

    def test_http_error_propagates(self):
        from fetch_external import safe_urlopen

        http_err = urllib.error.HTTPError(
            url="https://example.com", code=503, msg="Service Unavailable",
            hdrs=None, fp=None
        )
        with mock.patch("urllib.request.urlopen", side_effect=http_err):
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                safe_urlopen(self._req())
        assert exc_info.value.code == 503

    # --- parameter validation ---

    def test_rejects_non_positive_connect_timeout(self):
        from fetch_external import safe_urlopen

        with pytest.raises(ValueError, match="connect_timeout"):
            safe_urlopen(self._req(), connect_timeout=0.0)

    def test_rejects_non_positive_read_timeout(self):
        from fetch_external import safe_urlopen

        with pytest.raises(ValueError, match="read_timeout"):
            safe_urlopen(self._req(), read_timeout=-1.0)

    def test_rejects_non_positive_max_bytes(self):
        from fetch_external import safe_urlopen

        with pytest.raises(ValueError, match="max_bytes"):
            safe_urlopen(self._req(), max_bytes=0)

    # --- chunked accumulation ---

    def test_multi_chunk_accumulates_correctly(self):
        """Simulate a response where read() returns data across multiple calls."""
        from fetch_external import safe_urlopen

        chunks = [b"hello", b" ", b"world"]
        chunk_iter = iter(chunks)

        class _MultiChunkResp:
            status = 200

            def read(self, size):
                try:
                    return next(chunk_iter)
                except StopIteration:
                    return b""

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with mock.patch("urllib.request.urlopen", return_value=_MultiChunkResp()):
            result = safe_urlopen(self._req(), max_bytes=1024)
        assert result.body == b"hello world"


# ── tx_verification.verify_transaction_status ─────────────────────────────


class TestVerifyTransactionStatus:
    TX_HASH = "a" * 64

    def _patch_safe_urlopen(self, return_value=None, side_effect=None):
        if side_effect:
            return mock.patch("tx_verification.safe_urlopen", side_effect=side_effect)
        return mock.patch("tx_verification.safe_urlopen", return_value=return_value)

    def _result(self, body: bytes, status: int = 200):
        from fetch_external import FetchResult
        return FetchResult(status=status, body=body)

    # --- confirmed ---

    def test_returns_confirmed_when_successful_true(self):
        from tx_verification import verify_transaction_status

        body = json.dumps({"successful": True}).encode()
        with self._patch_safe_urlopen(return_value=self._result(body)):
            assert verify_transaction_status(self.TX_HASH) == "confirmed"

    # --- failed ---

    def test_returns_failed_when_successful_false(self):
        from tx_verification import verify_transaction_status

        body = json.dumps({"successful": False}).encode()
        with self._patch_safe_urlopen(return_value=self._result(body)):
            assert verify_transaction_status(self.TX_HASH) == "failed"

    # --- missing on 404 ---

    def test_returns_missing_when_all_rpcs_return_404(self):
        from tx_verification import verify_transaction_status

        http_err = urllib.error.HTTPError(
            url="https://example.com", code=404, msg="Not Found",
            hdrs=None, fp=None
        )
        with self._patch_safe_urlopen(side_effect=http_err):
            assert verify_transaction_status(self.TX_HASH) == "missing"

    # --- timeout fallback ---

    def test_returns_missing_when_all_rpcs_timeout(self):
        from fetch_external import FetchTimeoutError
        from tx_verification import verify_transaction_status

        with self._patch_safe_urlopen(side_effect=FetchTimeoutError("timed out")):
            assert verify_transaction_status(self.TX_HASH) == "missing"

    # --- oversized response fallback ---

    def test_returns_missing_when_all_rpcs_return_oversized_response(self):
        from fetch_external import ResponseTooLargeError
        from tx_verification import verify_transaction_status

        with self._patch_safe_urlopen(side_effect=ResponseTooLargeError("too large")):
            assert verify_transaction_status(self.TX_HASH) == "missing"

    # --- multi-RPC failover ---

    def test_falls_over_to_second_rpc_on_timeout(self):
        """First RPC times out; second RPC succeeds."""
        from fetch_external import FetchTimeoutError, FetchResult
        from tx_verification import verify_transaction_status

        body = json.dumps({"successful": True}).encode()
        ok_result = FetchResult(status=200, body=body)
        call_count = [0]

        def side_effect(req, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise FetchTimeoutError("first RPC timed out")
            return ok_result

        with mock.patch("tx_verification.safe_urlopen", side_effect=side_effect):
            status = verify_transaction_status(self.TX_HASH)

        assert status == "confirmed"
        assert call_count[0] == 2

    # --- custom timeout params are forwarded ---

    def test_custom_timeout_params_forwarded_to_safe_urlopen(self):
        from tx_verification import verify_transaction_status

        body = json.dumps({"successful": True}).encode()
        from fetch_external import FetchResult
        ok_result = FetchResult(status=200, body=body)

        with mock.patch("tx_verification.safe_urlopen", return_value=ok_result) as mock_su:
            verify_transaction_status(
                self.TX_HASH,
                connect_timeout=3.0,
                read_timeout=8.0,
                max_response_bytes=16384,
            )

        call_kwargs = mock_su.call_args[1]
        assert call_kwargs["connect_timeout"] == 3.0
        assert call_kwargs["read_timeout"] == 8.0
        assert call_kwargs["max_bytes"] == 16384

    # --- no PII in log messages ---

    def test_tx_hash_not_logged_at_warning_level(self, caplog):
        """The transaction hash must not appear in WARNING-level log output."""
        import logging
        from fetch_external import FetchTimeoutError
        from tx_verification import verify_transaction_status

        with self._patch_safe_urlopen(side_effect=FetchTimeoutError("timed out")):
            with caplog.at_level(logging.WARNING, logger="harpocrates.tx_verification"):
                verify_transaction_status(self.TX_HASH)

        for record in caplog.records:
            if record.levelno >= logging.WARNING:
                assert self.TX_HASH not in record.getMessage()


# ── webhook.dispatch_webhook ───────────────────────────────────────────────


class TestDispatchWebhook:
    def _delivery(self) -> dict:
        return {
            "delivery_id": 42,
            "retry_count": 0,
            "url": "https://subscriber.example/hook",
            "secret_key": "s3cr3t",
            "payload": {"event_type": "embed", "video_hash": "a" * 64},
        }

    def _patch(self, return_value=None, side_effect=None):
        if side_effect:
            return mock.patch("webhook.safe_urlopen", side_effect=side_effect)
        return mock.patch("webhook.safe_urlopen", return_value=return_value)

    def _result(self, status: int = 200):
        from fetch_external import FetchResult
        return FetchResult(status=status, body=b"ok")

    # --- success ---

    def test_marks_success_on_200(self):
        from webhook import dispatch_webhook

        with self._patch(return_value=self._result(200)):
            with mock.patch("webhook.update_delivery_status") as mock_update:
                dispatch_webhook(self._delivery())

        mock_update.assert_called_once()
        args = mock_update.call_args[0]
        assert args[1] is True   # success=True
        assert args[2] == 200    # status_code

    def test_marks_failure_on_non_2xx(self):
        from webhook import dispatch_webhook

        with self._patch(return_value=self._result(500)):
            with mock.patch("webhook.update_delivery_status") as mock_update:
                dispatch_webhook(self._delivery())

        args = mock_update.call_args[0]
        assert args[1] is False  # success=False

    # --- HTTP error ---

    def test_marks_failure_on_http_error(self):
        from webhook import dispatch_webhook

        http_err = urllib.error.HTTPError(
            url="https://subscriber.example/hook", code=422,
            msg="Unprocessable", hdrs=None, fp=None
        )
        with self._patch(side_effect=http_err):
            with mock.patch("webhook.update_delivery_status") as mock_update:
                dispatch_webhook(self._delivery())

        args = mock_update.call_args[0]
        assert args[1] is False
        assert args[2] == 422

    # --- timeout ---

    def test_marks_failure_on_fetch_timeout(self):
        from fetch_external import FetchTimeoutError
        from webhook import dispatch_webhook

        with self._patch(side_effect=FetchTimeoutError("timed out")):
            with mock.patch("webhook.update_delivery_status") as mock_update:
                dispatch_webhook(self._delivery())

        args = mock_update.call_args[0]
        assert args[1] is False

    # --- oversized response ---

    def test_marks_failure_on_oversized_response(self):
        from fetch_external import ResponseTooLargeError
        from webhook import dispatch_webhook

        with self._patch(side_effect=ResponseTooLargeError("too large")):
            with mock.patch("webhook.update_delivery_status") as mock_update:
                dispatch_webhook(self._delivery())

        args = mock_update.call_args[0]
        assert args[1] is False

    # --- custom timeout params forwarded ---

    def test_custom_timeout_params_forwarded(self):
        from webhook import dispatch_webhook

        with self._patch(return_value=self._result(200)) as mock_su:
            with mock.patch("webhook.update_delivery_status"):
                dispatch_webhook(
                    self._delivery(),
                    connect_timeout=2.0,
                    read_timeout=6.0,
                    max_response_bytes=8192,
                )

        kw = mock_su.call_args[1]
        assert kw["connect_timeout"] == 2.0
        assert kw["read_timeout"] == 6.0
        assert kw["max_bytes"] == 8192

    # --- URL not logged at WARNING level ---

    def test_subscriber_url_not_logged_at_warning_level(self, caplog):
        import logging
        from fetch_external import FetchTimeoutError
        from webhook import dispatch_webhook

        delivery = self._delivery()
        url = delivery["url"]

        with self._patch(side_effect=FetchTimeoutError("timed out")):
            with mock.patch("webhook.update_delivery_status"):
                with caplog.at_level(logging.WARNING, logger="harpocrates.webhook"):
                    dispatch_webhook(delivery)

        for record in caplog.records:
            if record.levelno >= logging.WARNING:
                assert url not in record.getMessage()


# ── config integration ─────────────────────────────────────────────────────


class TestConfigDefaults:
    """Verify the new AppConfig fields load with correct defaults."""

    def test_default_connect_timeout(self, monkeypatch):
        monkeypatch.delenv("EXTERNAL_FETCH_CONNECT_TIMEOUT_SECONDS", raising=False)
        from config import load_config
        cfg = load_config()
        assert cfg.external_fetch_connect_timeout_seconds == 5.0

    def test_default_read_timeout(self, monkeypatch):
        monkeypatch.delenv("EXTERNAL_FETCH_READ_TIMEOUT_SECONDS", raising=False)
        from config import load_config
        cfg = load_config()
        assert cfg.external_fetch_read_timeout_seconds == 10.0

    def test_default_max_response_bytes(self, monkeypatch):
        monkeypatch.delenv("EXTERNAL_FETCH_MAX_RESPONSE_BYTES", raising=False)
        from config import load_config
        cfg = load_config()
        assert cfg.external_fetch_max_response_bytes == 65_536

    def test_env_override_connect_timeout(self, monkeypatch):
        monkeypatch.setenv("EXTERNAL_FETCH_CONNECT_TIMEOUT_SECONDS", "3.5")
        from importlib import reload
        import config as config_module
        reload(config_module)
        cfg = config_module.load_config()
        assert cfg.external_fetch_connect_timeout_seconds == 3.5

    def test_env_override_read_timeout(self, monkeypatch):
        monkeypatch.setenv("EXTERNAL_FETCH_READ_TIMEOUT_SECONDS", "15.0")
        from importlib import reload
        import config as config_module
        reload(config_module)
        cfg = config_module.load_config()
        assert cfg.external_fetch_read_timeout_seconds == 15.0

    def test_env_override_max_response_bytes(self, monkeypatch):
        monkeypatch.setenv("EXTERNAL_FETCH_MAX_RESPONSE_BYTES", "131072")
        from importlib import reload
        import config as config_module
        reload(config_module)
        cfg = config_module.load_config()
        assert cfg.external_fetch_max_response_bytes == 131_072

    def test_non_positive_connect_timeout_raises(self, monkeypatch):
        monkeypatch.setenv("EXTERNAL_FETCH_CONNECT_TIMEOUT_SECONDS", "0")
        from importlib import reload
        import config as config_module
        reload(config_module)
        with pytest.raises(RuntimeError, match="EXTERNAL_FETCH_CONNECT_TIMEOUT_SECONDS"):
            config_module.load_config()

    def test_non_positive_max_response_bytes_raises(self, monkeypatch):
        monkeypatch.setenv("EXTERNAL_FETCH_MAX_RESPONSE_BYTES", "0")
        from importlib import reload
        import config as config_module
        reload(config_module)
        with pytest.raises(RuntimeError, match="EXTERNAL_FETCH_MAX_RESPONSE_BYTES"):
            config_module.load_config()
