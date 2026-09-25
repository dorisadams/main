"""Canonical metadata error taxonomy for the Harpocrates backend.

Single source of truth
----------------------
Metadata crosses several trust boundaries (Flask routes, the steganographic
envelope, Neon persistence, and verification services).  Before this module
each boundary raised an ad-hoc ``ValueError`` whose text leaked straight into
the HTTP response as ``VALIDATION_ERROR``.  Callers could not tell a malformed
envelope from an oversized payload, an unsupported version, an expired
artifact, or a dependency failure.

``metadata_errors`` defines one canonical code per failure class, its stable
HTTP status, and one serializer so every boundary produces the same
privacy-safe error envelope::

    {
      "ok": false,
      "error": {
        "code": "METADATA_MISSING_FIELD",
        "message": "metadata missing required field: proofId",
        "request_id": "…",
        "field": "proofId"
      }
    }

Trust boundary / privacy
------------------------
Messages are static strings or field *names* only.  Real media bytes, secrets,
witness values, private keys, and caller-supplied field *values* are never
echoed: :func:`classify_validation_error` intentionally discards the original
exception text so an unexpected ``ValueError`` cannot smuggle a secret into the
response body or logs.  ``field`` is always an allowlisted metadata key name.

Version / migration / compatibility
-----------------------------------
* ``TAXONOMY_VERSION`` is additive.  Codes are new names; the legacy
  ``VALIDATION_ERROR`` code remains for non-metadata request validation, so
  compatible callers keep working.
* ``MetadataError`` subclasses :class:`ValueError`, so existing ``except
  ValueError`` call sites and the app-level ``ValueError`` handler keep
  catching metadata failures after the taxonomy is adopted.
* The error envelope gains an optional ``field`` key only.  ``ok``, ``error``,
  ``code``, ``message``, and ``request_id`` are unchanged, so historical error
  shapes and stored evidence remain readable.
* Rollback is removing the ``MetadataError`` raises (reverting to plain
  ``ValueError``); the app-level handler then falls back to
  ``VALIDATION_ERROR`` with no schema migration required.
"""

from __future__ import annotations

from typing import Any

TAXONOMY_VERSION = "harpocrates-metadata-errors-v1"

# ---------------------------------------------------------------------------
# Canonical codes
# ---------------------------------------------------------------------------

METADATA_MALFORMED = "METADATA_MALFORMED"
"""The metadata is not a JSON object / cannot be decoded (400)."""

METADATA_MISSING_FIELD = "METADATA_MISSING_FIELD"
"""A required metadata field is absent (400)."""

METADATA_INVALID_FIELD = "METADATA_INVALID_FIELD"
"""A present field has the wrong type or an invalid value (400)."""

METADATA_UNSUPPORTED_VERSION = "METADATA_UNSUPPORTED_VERSION"
"""The metadata/envelope version is not supported by this build (400)."""

METADATA_OVERSIZED = "METADATA_OVERSIZED"
"""The metadata exceeds the configured/steganographic size ceiling (413)."""

METADATA_EXPIRED = "METADATA_EXPIRED"
"""The metadata references an artifact outside its validity window (400)."""

METADATA_REVOKED = "METADATA_REVOKED"
"""The metadata references a revoked issuer/proof capability (403)."""

METADATA_DEPENDENCY_FAILURE = "METADATA_DEPENDENCY_FAILURE"
"""A metadata dependency (DB, verifier, anchor) could not be reached (503)."""

_ERROR_STATUS: dict[str, int] = {
    METADATA_MALFORMED: 400,
    METADATA_MISSING_FIELD: 400,
    METADATA_INVALID_FIELD: 400,
    METADATA_UNSUPPORTED_VERSION: 400,
    METADATA_OVERSIZED: 413,
    METADATA_EXPIRED: 400,
    METADATA_REVOKED: 403,
    METADATA_DEPENDENCY_FAILURE: 503,
}

_DEFAULT_MESSAGES: dict[str, str] = {
    METADATA_MALFORMED: "metadata must be a JSON object",
    METADATA_MISSING_FIELD: "metadata is missing a required field",
    METADATA_INVALID_FIELD: "metadata contains an invalid field value",
    METADATA_UNSUPPORTED_VERSION: "metadata version is not supported",
    METADATA_OVERSIZED: "metadata payload exceeds the allowed size limit",
    METADATA_EXPIRED: "metadata artifact is expired",
    METADATA_REVOKED: "metadata artifact has been revoked",
    METADATA_DEPENDENCY_FAILURE: "a metadata dependency is unavailable",
}

# Ordered most-specific first.  Used only to map legacy ``ValueError`` text
# onto the taxonomy; never to produce a caller-visible message.
_CLASSIFY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (METADATA_OVERSIZED, ("exceeds the", "too large", "size limit", "capacity")),
    (
        METADATA_UNSUPPORTED_VERSION,
        ("unsupported metadata version", "unsupported version", "unknown version"),
    ),
    (METADATA_MISSING_FIELD, ("missing required field", "is required", "missing field")),
    (
        METADATA_MALFORMED,
        ("must be a json object", "valid json", "not a json", "must be an object"),
    ),
    (METADATA_EXPIRED, ("expired", "outside its validity", "validity window")),
    (METADATA_REVOKED, ("revoked", "revocation")),
    (
        METADATA_DEPENDENCY_FAILURE,
        ("dependency", "unavailable", "timed out", "timeout", "upstream"),
    ),
)


def is_known_code(code: object) -> bool:
    """Return ``True`` when *code* belongs to the canonical taxonomy."""
    return isinstance(code, str) and code in _ERROR_STATUS


def error_status(code: str) -> int:
    """Return the canonical HTTP status for *code*."""
    if not is_known_code(code):
        raise ValueError(f"unknown metadata error code: {code}")
    return _ERROR_STATUS[code]


def default_message(code: str) -> str:
    """Return the static, privacy-safe default message for *code*."""
    if not is_known_code(code):
        raise ValueError(f"unknown metadata error code: {code}")
    return _DEFAULT_MESSAGES[code]


def taxonomy() -> list[dict[str, Any]]:
    """Return the canonical taxonomy in stable code order (for docs/tests)."""
    return [
        {"code": code, "status": _ERROR_STATUS[code], "message": _DEFAULT_MESSAGES[code]}
        for code in sorted(_ERROR_STATUS)
    ]


class MetadataError(ValueError):
    """A metadata failure carrying a canonical taxonomy code.

    Subclasses :class:`ValueError` so existing ``except ValueError`` call sites
    (and the application-level ``ValueError`` handler) keep working while the
    taxonomy is adopted.
    """

    def __init__(
        self,
        code: str,
        message: str | None = None,
        *,
        field: str | None = None,
        status: int | None = None,
    ) -> None:
        if not is_known_code(code):
            raise ValueError(f"unknown metadata error code: {code}")
        self.code = code
        self.status = _ERROR_STATUS[code] if status is None else status
        # Field *names* are safe to expose; field *values* never are.
        self.field = field
        self.message = message or _DEFAULT_MESSAGES[code]
        super().__init__(self.message)

    def as_payload(self) -> dict[str, Any]:
        """Return the canonical ``error`` object (without ``request_id``)."""
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.field:
            payload["field"] = self.field
        return payload


def classify_validation_error(exc: BaseException) -> MetadataError:
    """Map a legacy metadata ``ValueError`` onto the canonical taxonomy.

    The original exception text is deliberately *not* copied into the
    returned error: an unexpected ``ValueError`` must never be able to echo
    sensitive material into a response body or log line.
    """
    text = str(exc).lower() if exc is not None else ""
    for code, needles in _CLASSIFY_RULES:
        if any(needle in text for needle in needles):
            return MetadataError(code)
    return MetadataError(METADATA_INVALID_FIELD)


def as_metadata_error(exc: BaseException) -> MetadataError:
    """Normalize *exc* to a :class:`MetadataError` (idempotent)."""
    if isinstance(exc, MetadataError):
        return exc
    return classify_validation_error(exc)


def metadata_error_response(exc: BaseException):
    """Serialize *exc* as the canonical metadata error envelope.

    Returns the ``(flask.Response, status)`` tuple produced by
    :func:`errors.error_response` so routes and error handlers can return it
    directly.  ``errors`` (and therefore Flask) is imported lazily to keep this
    module dependency-free for the envelope codec and unit tests.
    """
    from errors import error_response  # local import avoids import cycle

    error = as_metadata_error(exc)
    return error_response(
        code=error.code,
        message=error.message,
        status=error.status,
        field=error.field,
    )
