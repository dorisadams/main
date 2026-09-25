"""Bounded C2PA manifest parser and importer for Harpocrates.

Imports external C2PA manifests safely at public trust boundaries while:
1. Enforcing strict input size, depth, and collection bounds.
2. Mapping valid claims/assertions into canonical Harpocrates metadata.
3. Rejecting malformed, oversized, expired, revoked, or unsupported inputs.
4. Ensuring fail-safe, deterministic error responses with strict privacy redaction (no secrets, raw media, credentials, or private keys logged or returned).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# Named boundary constants
MAX_C2PA_PAYLOAD_BYTES = 256 * 1024  # 256 KiB
MAX_MANIFEST_DEPTH = 8
MAX_ASSERTIONS_COUNT = 32
MAX_INGREDIENTS_COUNT = 16
MAX_FIELD_LENGTH = 256

# Error codes
ERR_OVERSIZED = "ERR_OVERSIZED"
ERR_MALFORMED = "ERR_MALFORMED"
ERR_UNSUPPORTED_VERSION = "ERR_UNSUPPORTED_VERSION"
ERR_EXPIRED = "ERR_EXPIRED"
ERR_REVOKED = "ERR_REVOKED"
ERR_INVALID_SIGNATURE = "ERR_INVALID_SIGNATURE"
ERR_DEPENDENCY_FAILURE = "ERR_DEPENDENCY_FAILURE"

# Status constants
STATUS_VALID = "valid"
STATUS_MALFORMED = "malformed"
STATUS_OVERSIZED = "oversized"
STATUS_UNSUPPORTED = "unsupported"
STATUS_EXPIRED = "expired"
STATUS_REVOKED = "revoked"
STATUS_DEPENDENCY_FAILURE = "dependency_failure"

# Redaction pattern for sensitive terms
SENSITIVE_KEY_RE = re.compile(
    r"^(password|secret|private[_-]?key|witness|nullifier|credential|"
    r"proof[_-]?bytes|mnemonic|api[_-]?token|access[_-]?token|refresh[_-]?token)$",
    re.IGNORECASE,
)

HEX_32_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class C2PAParseResult:
    ok: bool
    status: str
    error_code: str | None = None
    error_message: str | None = None
    canonical_metadata: dict[str, Any] | None = None
    manifest_info: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "ok": self.ok,
            "status": self.status,
        }
        if self.error_code:
            res["errorCode"] = self.error_code
        if self.error_message:
            res["errorMessage"] = self.error_message
        if self.canonical_metadata is not None:
            res["canonicalMetadata"] = self.canonical_metadata
        if self.manifest_info is not None:
            res["manifestInfo"] = self.manifest_info
        return res


def _check_depth(obj: Any, current_depth: int = 1) -> bool:
    if current_depth > MAX_MANIFEST_DEPTH:
        return False
    if isinstance(obj, dict):
        return all(_check_depth(v, current_depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return all(_check_depth(v, current_depth + 1) for v in obj)
    return True


def _redact_sensitive(obj: Any) -> Any:
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            if SENSITIVE_KEY_RE.search(str(k)):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = _redact_sensitive(v)
        return cleaned
    if isinstance(obj, list):
        return [_redact_sensitive(item) for item in obj]
    if isinstance(obj, str):
        if "PRIVATE KEY" in obj or "SECRET" in obj:
            return "[REDACTED]"
        if len(obj) > MAX_FIELD_LENGTH:
            return obj[:MAX_FIELD_LENGTH] + "...[TRUNCATED]"
    return obj


def parse_c2pa_manifest(input_data: str | bytes | dict[str, Any]) -> C2PAParseResult:
    """Parse and validate C2PA manifest input with bounded memory, depth, and safety constraints."""
    raw_bytes: bytes
    parsed_dict: dict[str, Any]

    if isinstance(input_data, bytes):
        raw_bytes = input_data
        if len(raw_bytes) > MAX_C2PA_PAYLOAD_BYTES:
            return C2PAParseResult(
                ok=False,
                status=STATUS_OVERSIZED,
                error_code=ERR_OVERSIZED,
                error_message="manifest payload exceeds maximum byte limit",
            )
        try:
            parsed_dict = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return C2PAParseResult(
                ok=False,
                status=STATUS_MALFORMED,
                error_code=ERR_MALFORMED,
                error_message="manifest input is not valid JSON",
            )
    elif isinstance(input_data, str):
        raw_bytes = input_data.encode("utf-8")
        if len(raw_bytes) > MAX_C2PA_PAYLOAD_BYTES:
            return C2PAParseResult(
                ok=False,
                status=STATUS_OVERSIZED,
                error_code=ERR_OVERSIZED,
                error_message="manifest payload exceeds maximum byte limit",
            )
        try:
            parsed_dict = json.loads(input_data)
        except json.JSONDecodeError:
            return C2PAParseResult(
                ok=False,
                status=STATUS_MALFORMED,
                error_code=ERR_MALFORMED,
                error_message="manifest input is not valid JSON",
            )
    elif isinstance(input_data, dict):
        parsed_dict = input_data
        serialized = json.dumps(parsed_dict).encode("utf-8")
        if len(serialized) > MAX_C2PA_PAYLOAD_BYTES:
            return C2PAParseResult(
                ok=False,
                status=STATUS_OVERSIZED,
                error_code=ERR_OVERSIZED,
                error_message="manifest payload exceeds maximum byte limit",
            )
    else:
        return C2PAParseResult(
            ok=False,
            status=STATUS_MALFORMED,
            error_code=ERR_MALFORMED,
            error_message="manifest input must be JSON string, bytes, or dict",
        )

    if not isinstance(parsed_dict, dict):
        return C2PAParseResult(
            ok=False,
            status=STATUS_MALFORMED,
            error_code=ERR_MALFORMED,
            error_message="manifest must be a JSON object",
        )

    # Check structural depth
    if not _check_depth(parsed_dict):
        return C2PAParseResult(
            ok=False,
            status=STATUS_OVERSIZED,
            error_code=ERR_OVERSIZED,
            error_message="manifest depth exceeds maximum nesting limit",
        )

    # Sanitize and redact dictionary
    parsed_dict = _redact_sensitive(parsed_dict)

    # Check specification / version
    spec_version = parsed_dict.get("specVersion") or parsed_dict.get("active_manifest", {}).get("spec_version")
    if spec_version is not None and spec_version not in (1, "1.0", "2.0", "c2pa-v1", "c2pa-v2"):
        return C2PAParseResult(
            ok=False,
            status=STATUS_UNSUPPORTED,
            error_code=ERR_UNSUPPORTED_VERSION,
            error_message=f"unsupported manifest spec version: {spec_version}",
        )

    # Check active manifest structure or top-level manifest structure
    manifest_data = parsed_dict.get("manifest") or parsed_dict
    if not isinstance(manifest_data, dict):
        return C2PAParseResult(
            ok=False,
            status=STATUS_MALFORMED,
            error_code=ERR_MALFORMED,
            error_message="manifest payload structure is invalid",
        )

    # Check signature integrity
    signature_valid = parsed_dict.get("signatureValid") if "signatureValid" in parsed_dict else manifest_data.get("signatureValid")
    if signature_valid is False:
        return C2PAParseResult(
            ok=False,
            status=STATUS_MALFORMED,
            error_code=ERR_INVALID_SIGNATURE,
            error_message="manifest signature or integrity verification failed",
        )

    # Check expiration / revocation status
    status_claim = parsed_dict.get("status") or manifest_data.get("status")
    if status_claim == "expired":
        return C2PAParseResult(
            ok=False,
            status=STATUS_EXPIRED,
            error_code=ERR_EXPIRED,
            error_message="manifest assertion or certificate is expired",
        )
    if status_claim == "revoked":
        return C2PAParseResult(
            ok=False,
            status=STATUS_REVOKED,
            error_code=ERR_REVOKED,
            error_message="manifest assertion or certificate is revoked",
        )

    # Check bounds on assertions and ingredients
    assertions = manifest_data.get("assertions", [])
    if not isinstance(assertions, list):
        return C2PAParseResult(
            ok=False,
            status=STATUS_MALFORMED,
            error_code=ERR_MALFORMED,
            error_message="assertions field must be an array",
        )
    if len(assertions) > MAX_ASSERTIONS_COUNT:
        return C2PAParseResult(
            ok=False,
            status=STATUS_OVERSIZED,
            error_code=ERR_OVERSIZED,
            error_message=f"assertions count ({len(assertions)}) exceeds maximum limit ({MAX_ASSERTIONS_COUNT})",
        )

    ingredients = manifest_data.get("ingredients", [])
    if not isinstance(ingredients, list):
        return C2PAParseResult(
            ok=False,
            status=STATUS_MALFORMED,
            error_code=ERR_MALFORMED,
            error_message="ingredients field must be an array",
        )
    if len(ingredients) > MAX_INGREDIENTS_COUNT:
        return C2PAParseResult(
            ok=False,
            status=STATUS_OVERSIZED,
            error_code=ERR_OVERSIZED,
            error_message=f"ingredients count ({len(ingredients)}) exceeds maximum limit ({MAX_INGREDIENTS_COUNT})",
        )

    # Check time validity if timestamps present
    valid_until = manifest_data.get("validUntil") or parsed_dict.get("validUntil")
    if valid_until and isinstance(valid_until, str):
        try:
            ts = valid_until.replace("Z", "+00:00")
            expiry_dt = datetime.fromisoformat(ts)
            if expiry_dt.tzinfo is None:
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            if expiry_dt < datetime.now(timezone.utc):
                return C2PAParseResult(
                    ok=False,
                    status=STATUS_EXPIRED,
                    error_code=ERR_EXPIRED,
                    error_message="manifest claim is expired",
                )
        except ValueError:
            return C2PAParseResult(
                ok=False,
                status=STATUS_MALFORMED,
                error_code=ERR_MALFORMED,
                error_message="invalid date format in validUntil",
            )

    # Extract Harpocrates metadata if present in assertions or top-level claim
    extracted_metadata: dict[str, Any] | None = None

    # Search assertions for Harpocrates attestation assertion
    for assertion in assertions:
        if not isinstance(assertion, dict):
            continue
        label = assertion.get("label", "")
        data = assertion.get("data", {})
        if label in ("harpocrates.metadata", "c2pa.harpocrates") and isinstance(data, dict):
            extracted_metadata = data
            break

    if extracted_metadata is None and "harpocratesMetadata" in manifest_data:
        if isinstance(manifest_data["harpocratesMetadata"], dict):
            extracted_metadata = manifest_data["harpocratesMetadata"]

    # If canonical Harpocrates metadata was embedded, validate its fields
    if extracted_metadata:
        required_fields = {"protocol", "version", "tier", "sourceHash", "proofId", "timestamp"}
        missing = required_fields - set(extracted_metadata.keys())
        if missing:
            return C2PAParseResult(
                ok=False,
                status=STATUS_MALFORMED,
                error_code=ERR_MALFORMED,
                error_message=f"extracted metadata missing required field: {sorted(missing)[0]}",
            )
        if extracted_metadata.get("protocol") != "harpocrates":
            return C2PAParseResult(
                ok=False,
                status=STATUS_MALFORMED,
                error_code=ERR_MALFORMED,
                error_message="extracted metadata protocol must be 'harpocrates'",
            )
        if extracted_metadata.get("tier") not in ("silent", "source", "seal"):
            return C2PAParseResult(
                ok=False,
                status=STATUS_MALFORMED,
                error_code=ERR_MALFORMED,
                error_message="extracted metadata tier is invalid",
            )
        for field in ("sourceHash", "proofId"):
            val = extracted_metadata.get(field)
            if not isinstance(val, str) or not HEX_32_RE.match(val):
                return C2PAParseResult(
                    ok=False,
                    status=STATUS_MALFORMED,
                    error_code=ERR_MALFORMED,
                    error_message=f"extracted metadata {field} must be a 32-byte hex string",
                )

    manifest_info = {
        "title": str(manifest_data.get("title", "c2pa-manifest"))[:128],
        "format": str(manifest_data.get("format", "application/x-c2pa"))[:64],
        "assertionsCount": len(assertions),
        "ingredientsCount": len(ingredients),
    }
    if manifest_data.get("claimGenerator"):
        manifest_info["claimGenerator"] = str(manifest_data["claimGenerator"])[:128]

    return C2PAParseResult(
        ok=True,
        status=STATUS_VALID,
        canonical_metadata=extracted_metadata,
        manifest_info=manifest_info,
    )
