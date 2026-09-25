"""
Standardized API error envelope for the Harpocrates backend.

Every response body — success or error — includes a ``request_id`` for
correlation with server logs.  Error payloads additionally carry a
machine-readable ``code`` and a human-readable ``message``.

Error envelope shape::

    {
      "ok": false,
      "error": {
        "code": "VALIDATION_ERROR",
        "message": "video and metadata are required",
        "request_id": "a1b2c3d4-..."
      }
    }

Success responses retain their existing ``"ok": true`` top-level key with an
added ``"request_id"`` field.

Propagation
-----------
Handlers are not required to build the envelope by hand. ``propagate_request_id``
(and its ``register_request_id_propagation`` hook) guarantees that *every*
response leaving the application carries the request ID:

* always as the ``X-Request-ID`` response header, and
* additionally as a top-level ``request_id`` field for JSON object bodies that
  do not already carry one.

Binary, streamed, and non-JSON responses (video downloads, Prometheus metrics)
are intentionally left byte-for-byte untouched so request-ID propagation can
never corrupt a media payload. Route-supplied ``request_id`` values always win,
and no existing field is ever overwritten.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from flask import Flask, Response, g, jsonify, request

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

VALIDATION_ERROR = "VALIDATION_ERROR"
"""Client-supplied data failed validation (400)."""

PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
"""Request body exceeds the configured size limit (413)."""

NOT_FOUND = "NOT_FOUND"
"""The requested resource or capability is unavailable (404)."""

INTERNAL_ERROR = "INTERNAL_ERROR"
"""An unexpected server-side failure occurred (500)."""

UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
"""The uploaded file has an unsupported content type (400)."""

RATE_LIMITED = "RATE_LIMITED"
"""The client exceeded a per-client request budget (429)."""

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def error_response(
    *,
    code: str,
    message: str,
    status: int,
    field: str | None = None,
) -> tuple[Response, int]:
    """Return a Flask response tuple for a standardized error envelope.

    Args:
        code: Machine-readable error code (one of the module-level constants,
            or a canonical code from :mod:`metadata_errors`).
        message: Human-readable error description. Must be privacy-safe.
        status: HTTP status code.
        field: Optional *name* of the offending field. Only field names may be
            exposed here; field values must never be echoed back.
    """
    request_id = _get_request_id()
    error: dict[str, Any] = {
        "code": code,
        "message": message,
        "request_id": request_id,
    }
    if field:
        error["field"] = field
    return (
        jsonify(
            {
                "ok": False,
                "error": error,
            },
        ),
        status,
    )


def ok_response(
    data: dict[str, Any] | None = None,
    *,
    ok: bool = True,
    status: int = 200,
) -> tuple[Response, int]:
    """Return a Flask response tuple for a successful result.

    The returned dict always contains ``"ok"`` and ``"request_id"``.
    Extra keys from *data* are merged in, and any caller-supplied
    ``"ok"`` key in *data* takes precedence over *ok*.

    Args:
        data: Additional key-value pairs to include in the response body.
        ok: Value for the top-level ``"ok"`` field (default ``True``).
        status: HTTP status code (default 200).
    """
    request_id = _get_request_id()
    body: dict[str, Any] = {"ok": ok, "request_id": request_id}
    if data:
        body.update(data)
    return jsonify(body), status


def init_request_id(app: Flask) -> None:
    """Register a ``before_request`` hook that assigns a UUID to ``g.request_id``.

    Call once during application factory setup.
    """
    logger.debug("Registering request-id middleware on Flask app %s", app)

    @app.before_request
    def _assign_request_id() -> None:
        # Prefer an incoming header so proxied requests stay traceable
        incoming = request.headers.get("X-Request-Id")
        g.request_id = incoming if incoming else str(uuid.uuid4())


def propagate_request_id(
    response: Response,
    *,
    identifier: str | None = None,
) -> Response:
    """Ensure *response* carries the request ID in its headers and JSON body.

    The header is always set. JSON object bodies gain a top-level
    ``request_id`` field when they do not already have one; list, string,
    binary, and streamed bodies are left untouched.

    Args:
        response: The Flask response about to be returned to the caller.
        identifier: Explicit request ID, defaulting to ``g.request_id``.

    Returns:
        The same response object, mutated in place when needed.
    """
    request_identifier = identifier or _resolve_request_id()
    response.headers["X-Request-ID"] = request_identifier

    # Never rewrite media/streamed payloads: only JSON object bodies are safe
    # to extend, and only when they do not already carry a request ID.
    if response.direct_passthrough or not response.is_json:
        return response

    payload = response.get_json(silent=True)
    if not isinstance(payload, dict) or "request_id" in payload:
        return response

    payload["request_id"] = request_identifier
    response.set_data(json.dumps(payload, separators=(",", ":")))
    return response


def register_request_id_propagation(app: Flask) -> Flask:
    """Register the response-side request-ID propagation hook.

    Call once during application factory setup, after the hook that assigns
    ``g.request_id`` (see :func:`init_request_id` or the trace-fields
    middleware in ``app.py``).
    """
    logger.debug("Registering request-id propagation on Flask app %s", app)

    @app.after_request
    def _propagate_request_id(response: Response) -> Response:
        return propagate_request_id(response)

    return app


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------


def _get_request_id() -> str:
    """Return the request ID for the current Flask request context."""
    return getattr(g, "request_id", "unknown")


def _resolve_request_id() -> str:
    """Return ``g.request_id``, assigning a fresh UUID when it is unset.

    Propagation must never emit a placeholder such as ``"unknown"``: a caller
    that receives an ID must be able to use it to find the matching log lines.
    """
    identifier = getattr(g, "request_id", None)
    if isinstance(identifier, str) and identifier:
        return identifier
    identifier = str(uuid.uuid4())
    g.request_id = identifier
    return identifier
