import hashlib
import json
import re
import struct
import zlib
from typing import Any
from datetime import datetime, timezone, timedelta

from metadata_errors import (
    METADATA_INVALID_FIELD,
    METADATA_MALFORMED,
    METADATA_MISSING_FIELD,
    METADATA_OVERSIZED,
    METADATA_UNSUPPORTED_VERSION,
    MetadataError,
)

MAGIC_V1 = b"HRPSTG1"
MAGIC_V2 = b"HRPSTG2"
MAX_PAYLOAD_BYTES = 64 * 1024
# Hard ceiling for the *inflated* metadata. A small, checksum-valid zlib member
# can expand to an arbitrarily large buffer (a "decompression bomb"), so
# decompression is bounded by this limit and any payload that would inflate past
# it is rejected instead of being materialised in memory. It matches the
# envelope body limit because legitimate metadata is already gated to well below
# this size at the API boundary.
MAX_DECOMPRESSED_BYTES = MAX_PAYLOAD_BYTES
ALLOWED_TIERS = {"silent", "source", "seal"}
_HEX_32_PATTERN = re.compile(r"[0-9a-fA-F]{64}")


def canonical_metadata_hash(metadata: dict[str, Any]) -> str:
    """Returns the canonical deterministic hash for any supported metadata."""
    return hashlib.sha256(_canonical_json(metadata)).hexdigest()


def _canonical_json(metadata: dict[str, Any]) -> bytes:
    return json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _is_hex_32(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    # ``int(value, 16)`` also accepts a ``0x`` prefix and surrounding whitespace,
    # which would let malformed hashes through; match the 32-byte hex shape exactly.
    return _HEX_32_PATTERN.fullmatch(value) is not None


def _validate_timestamp(value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise MetadataError(
            METADATA_INVALID_FIELD,
            "metadata timestamp must be a string",
            field="timestamp",
        )
    ts = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        raise MetadataError(
            METADATA_INVALID_FIELD,
            "metadata timestamp must be a timezone-aware ISO-8601 string",
            field="timestamp",
        )
    if dt.tzinfo is None:
        raise MetadataError(
            METADATA_INVALID_FIELD,
            "metadata timestamp must be timezone-aware",
            field="timestamp",
        )
    if dt > datetime.now(timezone.utc) + timedelta(seconds=300):
        raise MetadataError(
            METADATA_INVALID_FIELD,
            "metadata timestamp is unreasonably far in the future",
            field="timestamp",
        )


def validate_v1(metadata: dict[str, Any]) -> None:
    required = {"protocol", "version", "tier", "sourceHash", "proofId", "timestamp"}
    missing = required - set(metadata.keys())
    if missing:
        field = sorted(missing)[0]
        raise MetadataError(
            METADATA_MISSING_FIELD,
            f"metadata missing required field: {field}",
            field=field,
        )
    if metadata.get("protocol") != "harpocrates":
        raise MetadataError(
            METADATA_INVALID_FIELD,
            "metadata protocol must be harpocrates",
            field="protocol",
        )
    if metadata.get("tier") not in ALLOWED_TIERS:
        raise MetadataError(
            METADATA_INVALID_FIELD,
            "metadata tier is invalid",
            field="tier",
        )
    if not _is_hex_32(metadata.get("sourceHash")):
        raise MetadataError(
            METADATA_INVALID_FIELD,
            "metadata sourceHash must be a 32-byte hex string",
            field="sourceHash",
        )
    if not _is_hex_32(metadata.get("proofId")):
        raise MetadataError(
            METADATA_INVALID_FIELD,
            "metadata proofId must be a 32-byte hex string",
            field="proofId",
        )
    _validate_timestamp(metadata.get("timestamp"))


def validate_v2(metadata: dict[str, Any]) -> dict[str, Any]:
    # v2 enforces similar constraints but allows forward compatibility (stripping unknown fields or maintaining them)
    # Actually, to make it canonical and safe, we can enforce strict schema or pass through.
    # The requirement is "unknown-field behavior". Let's preserve unknown fields in V2 for forward compat.
    if not isinstance(metadata, dict):
        raise MetadataError(METADATA_MALFORMED, "metadata must be a JSON object")
    
    # Require same base fields
    validate_v1(metadata)
    
    # version in V2 must be >= 2
    if metadata.get("version", 1) < 2:
        # Auto-upgrade the version field if it's migrating
        metadata["version"] = 2
        
    return metadata


def pack_envelope(metadata: dict[str, Any], version: int = 2) -> bytes:
    if version == 1:
        validate_v1(metadata)
        magic = MAGIC_V1
    elif version == 2:
        metadata = validate_v2(dict(metadata))  # Copy and validate/upgrade
        magic = MAGIC_V2
    else:
        raise MetadataError(
            METADATA_UNSUPPORTED_VERSION,
            f"unsupported metadata version {version}",
        )

    canonical = _canonical_json(metadata)
    # Bound the metadata itself, not just its compressed form: a highly
    # compressible field must not be able to smuggle an oversized payload.
    if len(canonical) > MAX_DECOMPRESSED_BYTES:
        raise MetadataError(
            METADATA_OVERSIZED,
            "metadata payload exceeds the 64 KiB steganography limit",
        )

    body = zlib.compress(canonical, level=9)
    if len(body) > MAX_PAYLOAD_BYTES:
        raise MetadataError(
            METADATA_OVERSIZED,
            "metadata payload exceeds the 64 KiB steganography limit",
        )

    checksum = hashlib.sha256(body).digest()
    return magic + struct.pack(">I", len(body)) + checksum + body


def _decompress_metadata(body: bytes) -> bytes | None:
    """Inflate ``body`` while refusing to allocate more than the metadata ceiling.

    ``zlib.decompress`` expands a small, checksum-valid member into an
    arbitrarily large buffer, so a 64 KiB envelope body can be used as a
    decompression bomb. Streaming through a ``decompressobj`` with an explicit
    ``max_length`` keeps peak allocation bounded; anything that would inflate
    past ``MAX_DECOMPRESSED_BYTES`` (or that is truncated, or carries trailing
    bytes past the end of the member) is rejected rather than materialised.
    """
    decompressor = zlib.decompressobj()
    try:
        inflated = decompressor.decompress(body, MAX_DECOMPRESSED_BYTES + 1)
    except zlib.error:
        return None
    if len(inflated) > MAX_DECOMPRESSED_BYTES:
        return None
    if decompressor.unconsumed_tail:
        # The member inflates to more than ``MAX_DECOMPRESSED_BYTES`` bytes and
        # the rest is still pending; do not let the caller keep draining it.
        return None
    if not decompressor.eof:
        # Truncated or incomplete zlib stream.
        return None
    if decompressor.unused_data:
        # Bytes after the end of the zlib stream are not part of this member.
        return None
    return inflated


def unpack_envelope(data: bytes) -> dict[str, Any] | None:
    if len(data) < 7 + 4 + 32:
        return None

    magic = data[:7]
    if magic not in (MAGIC_V1, MAGIC_V2):
        return None

    size = struct.unpack(">I", data[7:11])[0]
    if size > MAX_PAYLOAD_BYTES:
        return None

    checksum_start = 11
    body_start = 43
    body_end = body_start + size
    if len(data) < body_end:
        return None

    checksum = data[checksum_start:body_start]
    body = data[body_start:body_end]
    if hashlib.sha256(body).digest() != checksum:
        return None

    inflated = _decompress_metadata(body)
    if inflated is None:
        return None

    try:
        value = json.loads(inflated.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(value, dict):
        return None
        
    try:
        # Validate based on the magic bytes to ensure safety
        if magic == MAGIC_V1:
            validate_v1(value)
            # Auto-migrate v1 to v2 representation in-memory?
            # Issue says: "preserve... unless versioned migration is included."
            # We can upgrade it on extraction so the rest of the system deals with V2 shape if needed, 
            # or just leave it as is. We'll just leave it and let the system handle it.
        elif magic == MAGIC_V2:
            value = validate_v2(value)
    except ValueError:
        return None

    return value
