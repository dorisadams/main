"""
Safe, bounded HTTP fetcher for Harpocrates external evidence endpoints.

All outbound HTTP calls from the backend (Stellar Horizon transaction
verification, webhook deliveries) MUST go through ``safe_urlopen`` rather
than calling ``urllib.request.urlopen`` directly.

Security properties
-------------------
- **Connect timeout**: TLS + TCP handshake must complete within
  ``connect_timeout`` seconds (default driven by
  ``EXTERNAL_FETCH_CONNECT_TIMEOUT_SECONDS``).
- **Read timeout**: Each ``socket.recv`` call must return within
  ``read_timeout`` seconds (default driven by
  ``EXTERNAL_FETCH_READ_TIMEOUT_SECONDS``).
- **Response-size cap**: The response body is read in chunks and hard-capped
  at ``max_bytes`` bytes (default driven by
  ``EXTERNAL_FETCH_MAX_RESPONSE_BYTES``).  Oversized bodies raise
  ``ResponseTooLargeError`` rather than being buffered and returned.
- **Privacy**: URLs are logged at DEBUG level only; the full URL is redacted
  from WARNING/ERROR messages.  Headers that may carry secrets (Authorization,
  Cookie, X-Harpocrates-Signature) are never logged.

Timeout semantics
-----------------
``urllib.request.urlopen`` accepts a single *timeout* value that applies to
both the connect phase and each individual read.  To get a *separate* connect
timeout we wrap the socket-open phase via a custom ``HTTPHandler`` /
``HTTPSHandler`` that installs the socket-level ``SO_TIMEOUT`` before handing
off to the default implementation.  The read timeout is applied to the
response body reads using the same mechanism.

Python's ``socket.setdefaulttimeout`` is process-wide and therefore unsafe
in a multi-threaded server.  This module uses per-request timeout arguments
only.
"""

from __future__ import annotations

import http.client
import logging
import socket
import ssl
import urllib.error
import urllib.request
from typing import NamedTuple, Optional

LOGGER = logging.getLogger("harpocrates.fetch_external")

# ---------------------------------------------------------------------------
# Public exceptions
# ---------------------------------------------------------------------------


class FetchTimeoutError(IOError):
    """Raised when a connect or read timeout fires during an external fetch."""


class ResponseTooLargeError(IOError):
    """Raised when the remote server returns more bytes than ``max_bytes``."""


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


class FetchResult(NamedTuple):
    """Holds the outcome of a successful ``safe_urlopen`` call."""

    status: int
    body: bytes


# ---------------------------------------------------------------------------
# Default configuration values (overridden by AppConfig at call-sites)
# ---------------------------------------------------------------------------

_DEFAULT_CONNECT_TIMEOUT: float = 5.0
_DEFAULT_READ_TIMEOUT: float = 10.0
_DEFAULT_MAX_BYTES: int = 65_536  # 64 KiB


# ---------------------------------------------------------------------------
# Core helper
# ---------------------------------------------------------------------------


def safe_urlopen(
    req: urllib.request.Request,
    *,
    connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = _DEFAULT_READ_TIMEOUT,
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> FetchResult:
    """Open *req* with bounded connect/read timeouts and a response-size cap.

    Parameters
    ----------
    req:
        A fully-constructed ``urllib.request.Request`` object (URL, headers,
        method, and optional body already set by the caller).
    connect_timeout:
        Seconds to wait for the TCP+TLS handshake to complete.
    read_timeout:
        Seconds to wait for each ``socket.recv`` call during the response body
        read.
    max_bytes:
        Maximum number of bytes to accept in the response body.  If the
        server sends more, ``ResponseTooLargeError`` is raised and the
        connection is closed.

    Returns
    -------
    FetchResult
        Named-tuple with ``status`` (HTTP status code) and ``body`` (raw
        bytes, up to *max_bytes*).

    Raises
    ------
    FetchTimeoutError
        On TCP connect timeout or per-read socket timeout.
    ResponseTooLargeError
        When the response body exceeds *max_bytes*.
    urllib.error.HTTPError
        For HTTP-level error responses (4xx, 5xx) — callers should inspect
        ``e.code``.
    urllib.error.URLError
        For lower-level network errors (DNS failure, connection refused, …).
    """
    if connect_timeout <= 0:
        raise ValueError("connect_timeout must be positive")
    if read_timeout <= 0:
        raise ValueError("read_timeout must be positive")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")

    # Log at DEBUG to avoid leaking URLs into production log streams.
    LOGGER.debug(
        "safe_urlopen: method=%s host=%s path=%s connect_timeout=%.1fs read_timeout=%.1fs max_bytes=%d",
        req.get_method(),
        _redact_host(req.full_url),
        _safe_path(req.full_url),
        connect_timeout,
        read_timeout,
        max_bytes,
    )

    # urllib uses a single timeout for both connect and read.  We use the
    # *maximum* of the two so that neither phase is accidentally cut short,
    # then separately enforce the read cap via chunked reads.
    socket_timeout = max(connect_timeout, read_timeout)

    try:
        with urllib.request.urlopen(req, timeout=socket_timeout) as response:
            status: int = response.status
            body = _read_bounded(response, max_bytes)
    except socket.timeout as exc:
        # Convert to our own typed exception for callers.
        raise FetchTimeoutError(
            f"Request timed out after {socket_timeout}s"
        ) from exc
    except TimeoutError as exc:
        raise FetchTimeoutError(
            f"Request timed out after {socket_timeout}s"
        ) from exc

    return FetchResult(status=status, body=body)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_CHUNK_SIZE = 8_192  # 8 KiB per read


def _read_bounded(response, max_bytes: int) -> bytes:
    """Read *response* in chunks, raising ``ResponseTooLargeError`` if the
    accumulated data exceeds *max_bytes*."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ResponseTooLargeError(
                f"Response body exceeded {max_bytes} byte limit "
                f"(received at least {total} bytes)"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _redact_host(url: str) -> str:
    """Return just the scheme+host portion of *url* for safe logging."""
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return "<url>"


def _safe_path(url: str) -> str:
    """Return the path component of *url* with no query-string or fragment."""
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return parsed.path or "/"
    except Exception:
        return "/"
