from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class AppConfig:
    app_env: str
    cors_origins: list[str]
    max_content_length: int
    max_video_bytes: int
    max_json_bytes: int
    max_metadata_bytes: int
    expose_metadata_header: bool
    noir_worker_enabled: bool
    security_headers_enabled: bool
    ratelimit_enabled: bool
    trusted_proxies: list[str]
    ratelimit_embed: str
    ratelimit_extract: str
    ratelimit_silent_witness: str
    ratelimit_register: str
    ratelimit_upload_session: str
    ratelimit_upload_chunk: str
    release_id: str
    release_network: str
    metrics_enabled: bool
    metrics_token: str | None
    metrics_path: str
    max_concurrent_requests: int
    max_queue_size: int
    max_concurrent_per_identity: int
    admission_timeout_seconds: float
    verifier_cache_max_size: int
    verifier_cache_positive_ttl_seconds: float
    verifier_cache_negative_ttl_seconds: float
    # External evidence fetch safety bounds
    external_fetch_connect_timeout_seconds: float
    external_fetch_read_timeout_seconds: float
    external_fetch_max_response_bytes: int


def load_config() -> AppConfig:
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    cors_origins = _csv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    if "*" in cors_origins:
        if app_env == "production":
            raise RuntimeError("Wildcard CORS origins are not permitted in production")
        if os.getenv("ALLOW_WILDCARD_CORS") != "true":
            raise RuntimeError("Wildcard CORS requires ALLOW_WILDCARD_CORS=true")

    return AppConfig(
        app_env=app_env,
        cors_origins=cors_origins,
        max_content_length=_int_env("MAX_CONTENT_LENGTH", 314_572_800),
        max_video_bytes=_int_env("MAX_VIDEO_BYTES", 262_144_000),
        max_json_bytes=_int_env("MAX_JSON_BYTES", 1_048_576),
        max_metadata_bytes=_int_env("MAX_METADATA_BYTES", 16_384),
        expose_metadata_header=_bool_env("EXPOSE_METADATA_HEADER", False),
        noir_worker_enabled=_bool_env("NOIR_WORKER_ENABLED", app_env != "production"),
        security_headers_enabled=_bool_env("SECURITY_HEADERS_ENABLED", True),
        ratelimit_enabled=_bool_env("RATELIMIT_ENABLED", True),
        # Real client IP resolution behind proxies; empty list trusts no proxy.
        trusted_proxies=_csv("TRUSTED_PROXIES", ""),
        # Per-client rate limits (flask-limiter "N per <window>" strings).
        ratelimit_embed=_str_env("RATELIMIT_EMBED") or "30 per minute",
        ratelimit_extract=_str_env("RATELIMIT_EXTRACT") or "30 per minute",
        ratelimit_silent_witness=_str_env("RATELIMIT_SILENT_WITNESS") or "20 per minute",
        ratelimit_register=_str_env("RATELIMIT_REGISTER") or "30 per minute",
        ratelimit_upload_session=_str_env("RATELIMIT_UPLOAD_SESSION") or "60 per minute",
        ratelimit_upload_chunk=_str_env("RATELIMIT_UPLOAD_CHUNK") or "240 per minute",
        release_id=_release_id(os.getenv("HARPOCRATES_RELEASE_ID", "harpocrates-1.0.0")),
        release_network=_release_network(os.getenv("HARPOCRATES_RELEASE_NETWORK", "testnet")),
        metrics_enabled=_bool_env("METRICS_ENABLED", True),
        metrics_token=_str_env("METRICS_TOKEN"),
        metrics_path=os.getenv("METRICS_PATH", "/metrics").strip(),
        max_concurrent_requests=_int_env("MAX_CONCURRENT_REQUESTS", 50),
        max_queue_size=_int_env("MAX_QUEUE_SIZE", 100),
        max_concurrent_per_identity=_int_env("MAX_CONCURRENT_PER_IDENTITY", 5),
        admission_timeout_seconds=_float_env("ADMISSION_TIMEOUT_SECONDS", 5.0),
        verifier_cache_max_size=_int_env("VERIFIER_CACHE_MAX_SIZE", 10000),
        verifier_cache_positive_ttl_seconds=_float_env("VERIFIER_CACHE_POSITIVE_TTL_SECONDS", 86400.0),
        verifier_cache_negative_ttl_seconds=_float_env("VERIFIER_CACHE_NEGATIVE_TTL_SECONDS", 300.0),
        external_fetch_connect_timeout_seconds=_float_env("EXTERNAL_FETCH_CONNECT_TIMEOUT_SECONDS", 5.0),
        external_fetch_read_timeout_seconds=_float_env("EXTERNAL_FETCH_READ_TIMEOUT_SECONDS", 10.0),
        external_fetch_max_response_bytes=_int_env("EXTERNAL_FETCH_MAX_RESPONSE_BYTES", 65_536),
    )



def _upload_chunk_bytes() -> int:
    """Load UPLOAD_CHUNK_BYTES clamped into the supported streaming range."""
    raw = os.getenv("UPLOAD_CHUNK_BYTES")
    if raw is None or not raw.strip():
        return 65_536
    parsed = int(raw)
    if parsed < 4_096:
        return 4_096
    if parsed > 1_048_576:
        return 1_048_576
    return parsed


def _csv(name: str, default: str) -> list[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    parsed = int(value)
    if parsed <= 0:
        raise RuntimeError(f"{name} must be positive")
    return parsed


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _release_id(value: str) -> str:
    if value != "harpocrates-1.0.0":
        raise RuntimeError("HARPOCRATES_RELEASE_ID is not a supported compatibility release")
    return value


def _release_network(value: str) -> str:
    if value not in {"local", "testnet", "mainnet"}:
        raise RuntimeError("HARPOCRATES_RELEASE_NETWORK must be local, testnet, or mainnet")
    return value


def _str_env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    parsed = float(value)
    if parsed <= 0.0:
        raise RuntimeError(f"{name} must be positive")
    return parsed


