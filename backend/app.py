from __future__ import annotations

import base64
import functools
import ipaddress
import json
import logging
import os
import shutil
import tempfile
from workspace import EncryptedWorkspace
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


from flask import Flask, Response, g, jsonify, request, send_file
from flask_cors import CORS

from http_security import apply_security_headers, cors_kwargs
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from config import load_config
from errors import (
    INTERNAL_ERROR,
    NOT_FOUND,
    PAYLOAD_TOO_LARGE,
    RATE_LIMITED,
    VALIDATION_ERROR,
    error_response,
)
from db import (
    check_db,
    database_url,
    decode_proof_events_cursor,
    find_proof_events_by_video,
    find_lineage_by_output_digest,
    find_lineage_by_actor,
    init_db,
    insert_lineage_event,
    insert_proof_event,
    insert_proof_history_event,
    list_lineage_events,
    list_proof_events,
    list_proof_history_events,
    make_idempotency_key,
    upsert_register_event,
    set_legal_hold,
    ConflictError,
    enqueue_job,
    get_job,
    cancel_job,
)
from idempotency import idempotent
from lineage import (
    LineageValidationError,
    canonical_lineage_manifest,
    lineage_manifest_digest,
    validate_lineage_graph,
)
from storage import get_job_output_path
from retention import init_retention_worker
from metrics import collector as metrics_collector
from noir import generate_silent_witness, generate_aggregated_proof
from envelope import ALLOWED_TIERS, validate_v2 as validate_embed_metadata
from metadata_errors import (
    METADATA_MALFORMED,
    METADATA_OVERSIZED,
    MetadataError,
    classify_validation_error,
    metadata_error_response,
)
from schema import discover_schemas, resolve_schema, validate_selective_disclosure_input
from stego import canonical_metadata_hash, embed_metadata, extract_metadata, sha256_file
from logging_utils import log_structured, redact_sensitive
from errors import (
    INTERNAL_ERROR,
    NOT_FOUND,
    PAYLOAD_TOO_LARGE,
    VALIDATION_ERROR,
    error_response,
    ok_response,
    register_request_id_propagation,
)
from trace_fields import (
    build_trace_fields,
    format_traceparent,
    merge_trace_into_event,
)
from readiness import ReadinessManager
from admission import AdmissionController, require_capacity
from webhook import WebhookWorker, queue_webhook_deliveries
from quarantine import QuarantineError, isolate_upload
from strkey import validate_source_address, validate_contract_id
from streaming_upload import (
    StreamingFileStorage,
    create_streaming_file_storage,
    hash_paths_concat,
)
from werkzeug.datastructures import ImmutableMultiDict

# ---------------------------------------------------------------------------
# Bounded aggregation constants
# ---------------------------------------------------------------------------
# These MUST match the values in the Noir circuit and the Soroban contract.
MAX_AGGREGATION_SIZE = 8
AGGREGATION_ELEMENT_COST = 128  # bytes per aggregated public-input element

LOGGER = logging.getLogger("harpocrates.requests")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False


def _make_key_func(config):
    """Return a rate-limit key function that uses the real client IP.

    If ``trusted_proxies`` is configured the leftmost *untrusted* address in
    ``X-Forwarded-For`` is used, preventing spoofing by clients who inject
    extra entries.  When no trusted proxies are configured the WSGI
    ``REMOTE_ADDR`` is used unconditionally, which is always safe.
    """

    trusted = set()
    for entry in config.trusted_proxies:
        try:
            trusted.add(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass

    def _key_func() -> str:
        if not trusted:
            # No proxies trusted – use the direct peer address, cannot be spoofed.
            return get_remote_address()

        # Walk X-Forwarded-For right-to-left, skipping trusted proxy IPs.
        # The first address that is NOT a trusted proxy is the real client.
        xff = request.headers.get("X-Forwarded-For", "")
        addrs = [a.strip() for a in xff.split(",") if a.strip()]
        # Append the direct peer so we always have at least one candidate.
        addrs.append(request.remote_addr or "127.0.0.1")

        for addr in reversed(addrs):
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if not any(ip in net for net in trusted):
                return str(ip)

        # Fallback: direct peer (always safe).
        return get_remote_address()

    return _key_func


def create_app() -> Flask:
    load_dotenv()
    config = load_config()
    app = Flask(__name__)
    CORS(app, **cors_kwargs(config.cors_origins))
    app.config["MAX_CONTENT_LENGTH"] = config.max_content_length
    # Propagate the request id through every response (header + JSON body).
    register_request_id_propagation(app)

    # ------------------------------------------------------------------ #
    # Rate limiting                                                        #
    # ------------------------------------------------------------------ #
    limiter = Limiter(
        key_func=_make_key_func(config),
        app=app,
        enabled=config.ratelimit_enabled,
        # In-memory storage is fine for a single-process server; swap for
        # Redis via RATELIMIT_STORAGE_URI env var in multi-worker deployments.
        storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
        default_limits=[],   # No global limit – each endpoint opts in explicitly.
        headers_enabled=True,  # Emit X-RateLimit-* headers on every response.
        swallow_errors=True,   # Never crash the app due to storage errors.
    )

    @limiter.request_filter
    def _health_exempt():
        """Health and readiness probes must never be rate-limited."""
        return request.path in {"/health", "/ready"}

    init_db()
    init_retention_worker()

    readiness_manager = ReadinessManager(timeout_seconds=1.0, cache_ttl_seconds=5.0)
    readiness_manager.add_dependency("database", check_db, critical=True)
    readiness_manager.add_dependency("video_tools", video_tooling_ready, critical=True)

    admission_controller = AdmissionController(
        max_concurrent=config.max_concurrent_requests,
        max_queue=config.max_queue_size,
        max_per_identity=config.max_concurrent_per_identity,
        timeout_seconds=config.admission_timeout_seconds,
    )

    @app.before_request
    def start_request_context():
        g.start_time = time.perf_counter()
        g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        g.request_started_at = time.perf_counter()
        # Privacy-safe trace fields for log correlation (no secrets/media/PII).
        g.trace_fields = build_trace_fields(
            request.headers,
            request_id=g.request_id,
            method=request.method,
            route=request.url_rule.rule if request.url_rule else request.path,
            path=request.path,
        )
        # Keep request_id aligned with normalized opaque ID from trace builder.
        g.request_id = g.trace_fields["request_id"]

    @app.after_request
    def process_response(response: Response):
        # X-Request-ID and the body-level request_id are applied by the
        # request-id propagation hook registered in create_app().
        trace = current_trace_fields()
        if trace.get("trace_id"):
            response.headers["X-Trace-ID"] = str(trace["trace_id"])
        if trace.get("correlation_id"):
            response.headers["X-Correlation-ID"] = str(trace["correlation_id"])
        if trace.get("span_id"):
            response.headers["X-Span-ID"] = str(trace["span_id"])
        traceparent = format_traceparent(trace)
        if traceparent:
            response.headers["traceparent"] = traceparent
        apply_security_headers(
            response.headers,
            enabled=config.security_headers_enabled,
        )
        response.headers.setdefault("X-Harpocrates-Release", config.release_id)
        response.headers.setdefault("X-Harpocrates-Network", config.release_network)

        if config.metrics_enabled and request.path != config.metrics_path:
            start_time = getattr(g, "start_time", None)
            duration = time.perf_counter() - start_time if start_time is not None else 0.0
            endpoint_rule = request.url_rule.rule if request.url_rule else "unmatched"
            metrics_collector.record_request(
                method=request.method,
                endpoint=endpoint_rule,
                status=response.status_code,
                duration_seconds=duration,
                upload_bytes=request.content_length,
            )

        if response.status_code >= 400:
            log_error_response(response.status_code)
        log_structured(
            LOGGER,
            logging.INFO,
            merge_trace_into_event(
                {
                    "event": "request",
                    "request_id": request_id(),
                    "method": request.method,
                    "route": request_route(),
                    "path": request.path,
                    "status": response.status_code,
                    "duration_ms": request_duration_ms(),
                },
                trace,
            ),
        )
        return response

    def require_register_auth(fn):
        """Decorator that enforces Bearer token auth on proof registration.

        Behaviour:
        - If REGISTER_API_KEY is not configured the endpoint is open (development
          convenience identical to the previous behaviour).
        - Otherwise the request must carry ``Authorization: Bearer <key>``.
        - If REGISTER_API_KEY_EXPIRES is set and the current UTC time is at or
          past that instant the key is treated as expired and the request is
          rejected with 401.
        """

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            expected_key = config.register_api_key
            if expected_key is None:
                # No key configured – allow the request (dev mode).
                return fn(*args, **kwargs)

            # Check expiry before validating the key so that an expired key
            # is never accepted even if the token matches.
            expires = config.register_api_key_expires
            if expires is not None:
                from datetime import datetime as _dt

                now = _dt.now(tz=timezone.utc)
                if now >= expires:
                    return jsonify({"error": "API key has expired"}), 401

            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Authorization header with Bearer token is required"}), 401

            provided_key = auth_header[len("Bearer "):]
            # Constant-time comparison to mitigate timing attacks.
            import hmac as _hmac

            if not _hmac.compare_digest(provided_key, expected_key):
                return jsonify({"error": "Invalid API key"}), 401

            return fn(*args, **kwargs)

        return wrapper

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error: RequestEntityTooLarge):
        return error_response(
            code=PAYLOAD_TOO_LARGE,
            message="request body is too large",
            status=413,
        )

    @app.errorhandler(ValueError)
    def bad_request(error: ValueError):
        # Metadata failures carry a canonical taxonomy code; serialize them
        # with the shared metadata envelope so every boundary agrees.
        if isinstance(error, MetadataError):
            return metadata_error_response(error)
        return error_response(
            code=VALIDATION_ERROR,
            message=str(error),
            status=400,
        )

    @app.errorhandler(RuntimeError)
    def runtime_error(error: RuntimeError):
        app.logger.error("Unhandled runtime error: %s", error, exc_info=True)
        return error_response(
            code=INTERNAL_ERROR,
            message="internal server error",
            status=500,
        )

    @app.errorhandler(429)
    def rate_limit_exceeded(_error: Exception):
        """Stable, privacy-safe envelope for per-client throttle responses.

        Flask-Limiter injects the precise ``Retry-After`` value during
        ``after_request``; the fallback below keeps the response well formed
        for callers that exercise the handler directly.
        """
        response, status = error_response(
            code=RATE_LIMITED,
            message="rate limit exceeded",
            status=429,
        )
        response.headers.setdefault("Retry-After", "60")
        return response, status

    @app.get(config.metrics_path)
    def metrics():
        if not config.metrics_enabled:
            return jsonify({"error": "metrics service disabled"}), 404

        if config.metrics_token:
            auth_header = request.headers.get("Authorization", "")
            token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
            custom_token = request.headers.get("X-Metrics-Token", "").strip()
            if token != config.metrics_token and custom_token != config.metrics_token:
                return jsonify({"error": "unauthorized metrics access"}), 401

        output = metrics_collector.generate_prometheus_metrics()
        return Response(output, mimetype="text/plain; version=0.0.4; charset=utf-8")

    @app.get("/health")
    def health():
        trace = current_trace_fields()
        return jsonify(
            {
                "ok": True,
                "service": "harpocrates-stego",
                "release_id": config.release_id,
                "network": config.release_network,
                "request_id": request_id(),
                "trace_id": trace.get("trace_id"),
                "correlation_id": trace.get("correlation_id"),
            }
        )

    @app.get("/ready")
    def ready():
        status = readiness_manager.check()
        trace = current_trace_fields()
        return jsonify(
            {
                "ok": status["ok"],
                "service": "harpocrates-stego",
                "database": status.get("database", "not_configured"),
                "video_tools": status.get("video_tools", "missing"),
                "noir_worker": "enabled" if config.noir_worker_enabled else "disabled",
                "aggregation": "enabled" if config.noir_worker_enabled else "disabled",
                "max_aggregation_size": MAX_AGGREGATION_SIZE,
                "request_id": request_id(),
                "trace_id": trace.get("trace_id"),
                "correlation_id": trace.get("correlation_id"),
            }
        ), 200 if status["ok"] else 503

    def _enforce_video_size(video) -> bool:
        # StreamingFileStorage enforces the limit mid-stream during save();
        # avoid seek() which can force whole-body buffering on the WSGI input.
        if isinstance(video, StreamingFileStorage):
            if video.bytes_written > 0:
                return video.bytes_written <= config.max_video_bytes
            if request.content_length is not None:
                # Content-Length includes multipart overhead; still a useful gate.
                return request.content_length <= config.max_content_length
            return True
        video.seek(0, 2)
        size = video.tell()
        video.seek(0)
        return size <= config.max_video_bytes

    def _enable_streaming_for_large_uploads():
        """Wrap large multipart uploads with bounded-chunk stream hashing."""
        threshold = getattr(
            config, "upload_stream_threshold_bytes", 1_048_576
        )
        if not request.content_length or request.content_length <= threshold:
            return
        if not request.files:
            return

        g.upload_config = config
        # Access files first so the cached_property is populated, then replace.
        current = request.files
        new_items = []
        for field_name, field_storage in current.items(multi=True):
            new_items.append(
                (field_name, create_streaming_file_storage(field_storage))
            )
        # Shadow the cached_property with stream-hashing wrappers.
        request.__dict__["files"] = ImmutableMultiDict(new_items)

    def _enforce_json_size() -> int:
        raw = request.get_data()
        return len(raw) if raw else 0

    @app.post("/api/stego/embed")
    @limiter.limit(config.ratelimit_embed)
    @require_capacity(admission_controller)
    @idempotent("embed")
    def embed():
        # Enable streaming for large uploads
        _enable_streaming_for_large_uploads()
        
        video = request.files.get("video")
        metadata_raw = request.form.get("metadata")
        if video is None or metadata_raw is None:
            return jsonify({"error": "video and metadata are required"}), 400
        if not _enforce_video_size(video):
            return jsonify({"error": "video payload exceeds size limit"}), 413
        validate_video_upload(video)
        if len(metadata_raw.encode("utf-8")) > config.max_metadata_bytes:
            return metadata_error_response(
                MetadataError(METADATA_OVERSIZED, "metadata is too large")
            )

        try:
            metadata = json.loads(metadata_raw)
        except json.JSONDecodeError:
            return metadata_error_response(
                MetadataError(METADATA_MALFORMED, "metadata must be valid JSON")
            )
        try:
            validate_embed_metadata(metadata)
        except MetadataError as exc:
            return metadata_error_response(exc)
        except ValueError as exc:
            return metadata_error_response(classify_validation_error(exc))

        try:
            quarantine_context = isolate_upload(
                video,
                filename=video.filename,
                content_type=video.content_type,
            )
            with quarantine_context as quarantined_path, EncryptedWorkspace() as workspace:
                source_url = workspace.get_url("source.video")
                output_url = workspace.get_url("embedded.mp4")
                with quarantined_path.open("rb") as quarantined:
                    workspace.write_encrypted(
                        "source.video",
                        quarantined,
                        size=quarantined_path.stat().st_size,
                    )

                embed_metadata(source_url, output_url, metadata)
                output_bytes = workspace.read_decrypted("embedded.mp4")
                source_hash = workspace.sha256("source.video")
                embedded_hash = workspace.sha256("embedded.mp4")
                metadata_hash = canonical_metadata_hash(metadata)
        except QuarantineError as exc:
            return jsonify({"error": str(exc)}), 400

        db_event = insert_proof_event(
            event_type="embed",
            file_name=safe_filename(video.filename),
            video_hash=embedded_hash,
            metadata_hash=metadata_hash,
            proof_id=metadata.get("proofId"),
            tier=metadata.get("tier"),
            embedded_hash=embedded_hash,
            metadata=redact_metadata(metadata),
        )

        if db_event and db_event.get("id"):
            queue_webhook_deliveries(db_event["id"])

        response = Response(output_bytes, mimetype="video/mp4")
        response.headers["Content-Disposition"] = 'attachment; filename="harpocrates-evidence.mp4"'
        response.headers["X-Harpocrates-Source-Hash"] = source_hash
        response.headers["X-Harpocrates-Embedded-Hash"] = embedded_hash
        response.headers["X-Harpocrates-Metadata-Hash"] = metadata_hash
        response.headers["X-Harpocrates-Db-Event"] = str(db_event)
        if config.expose_metadata_header:
            response.headers["X-Harpocrates-Metadata"] = base64.b64encode(
                json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ).decode("ascii")
        return response

    @app.post("/api/stego/upload-session")
    @limiter.limit(config.ratelimit_upload_session)
    def create_upload_session():
        session_id = str(uuid.uuid4())
        session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"
        session_dir.mkdir(parents=True, exist_ok=True)
        return jsonify({"sessionId": session_id})

    @app.put("/api/stego/upload-session/<session_id>/chunk/<int:chunk_index>")
    @limiter.limit(config.ratelimit_upload_chunk)
    def upload_chunk(session_id: str, chunk_index: int):
        session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"
        if not session_dir.exists():
            return jsonify({"error": "session not found"}), 404
        
        chunk = request.files.get("chunk")
        if chunk is None:
            return jsonify({"error": "chunk is required"}), 400
        if chunk_index < 0:
            return jsonify({"error": "chunk_index must be non-negative"}), 400

        # Persist each session chunk with bounded-chunk hashing for integrity.
        g.upload_config = config
        streaming_chunk = create_streaming_file_storage(chunk)
        chunk_path = session_dir / f"chunk-{chunk_index}"
        try:
            streaming_chunk.save(str(chunk_path))
        except RequestEntityTooLarge:
            return jsonify({"error": "chunk exceeds size limit"}), 413
        return jsonify({
            "ok": True,
            "bytes": streaming_chunk.bytes_written,
            "sha256": streaming_chunk.computed_hash,
        })

    @app.post("/api/stego/upload-session/<session_id>/commit")
    @limiter.limit(config.ratelimit_upload_session)
    @require_capacity(admission_controller)
    def commit_upload_session(session_id: str):
        session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"
        if not session_dir.exists():
            return jsonify({"error": "session not found"}), 404

        metadata_raw = request.form.get("metadata")
        if metadata_raw is None:
            return jsonify({"error": "metadata is required"}), 400

        try:
            metadata = json.loads(metadata_raw)
        except json.JSONDecodeError:
            return metadata_error_response(
                MetadataError(METADATA_MALFORMED, "metadata must be valid JSON")
            )
        try:
            validate_embed_metadata(metadata)
        except MetadataError as exc:
            return metadata_error_response(exc)
        except ValueError as exc:
            return metadata_error_response(classify_validation_error(exc))

        combined_path = session_dir / "combined.video"
        chunk_files = sorted(
            [f for f in session_dir.iterdir() if f.name.startswith("chunk-")],
            key=lambda f: int(f.name.split("-")[1]),
        )
        if not chunk_files:
            return jsonify({"error": "session has no chunks"}), 400

        # Bounded-chunk concat + SHA-256 so commit never buffers whole chunks.
        source_hash, _written = hash_paths_concat(
            chunk_files,
            combined_path,
            chunk_size=getattr(config, "upload_chunk_bytes", None),
            max_size=getattr(config, "upload_max_bytes", config.max_video_bytes),
        )

        with tempfile.TemporaryDirectory(prefix="harpocrates-") as tmp_dir:
            output_path = Path(tmp_dir) / "embedded.mp4"
            embed_metadata(combined_path, output_path, metadata)
            output_bytes = output_path.read_bytes()
            embedded_hash = sha256_file(output_path)
            metadata_hash = canonical_metadata_hash(metadata)

        retention_class = request.headers.get("X-Harpocrates-Retention-Class") or metadata.get("retentionClass", "default")
        if retention_class not in config.retention_classes:
            return jsonify({"error": f"invalid retention class: {retention_class}"}), 400
        retention_days = config.retention_classes[retention_class]
        expires_at = None
        if retention_days >= 0:
            expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

        db_event = insert_proof_event(
            event_type="embed",
            file_name=safe_filename(metadata.get("fileName", "unknown.mp4")),
            video_hash=embedded_hash,
            metadata_hash=metadata_hash,
            proof_id=metadata.get("proofId"),
            tier=metadata.get("tier"),
            embedded_hash=embedded_hash,
            retention_class=retention_class,
            expires_at=expires_at,
            metadata=redact_metadata(metadata),
        )

        response = Response(output_bytes, mimetype="video/mp4")
        response.headers["Content-Disposition"] = 'attachment; filename="harpocrates-evidence.mp4"'
        response.headers["X-Harpocrates-Source-Hash"] = source_hash
        response.headers["X-Harpocrates-Embedded-Hash"] = embedded_hash
        response.headers["X-Harpocrates-Metadata-Hash"] = metadata_hash
        response.headers["X-Harpocrates-Db-Event"] = str(db_event)
        response.headers["X-Harpocrates-Retention-Class"] = retention_class
        if config.expose_metadata_header:
            response.headers["X-Harpocrates-Metadata"] = base64.b64encode(
                json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ).decode("ascii")

        import shutil
        shutil.rmtree(session_dir, ignore_errors=True)

        return response

    @app.post("/api/stego/extract")
    @limiter.limit(config.ratelimit_extract)
    @require_capacity(admission_controller)
    @idempotent("extract")
    def extract():
        # Enable streaming for large uploads
        _enable_streaming_for_large_uploads()
        
        video = request.files.get("video")
        if video is None:
            return jsonify({"error": "video is required"}), 400
        if not _enforce_video_size(video):
            return jsonify({"error": "video payload exceeds size limit"}), 413
        validate_video_upload(video)

        try:
            quarantine_context = isolate_upload(
                video,
                filename=video.filename,
                content_type=video.content_type,
            )
            with quarantine_context as quarantined_path, EncryptedWorkspace() as workspace:
                source_url = workspace.get_url("source.video")
                with quarantined_path.open("rb") as quarantined:
                    workspace.write_encrypted(
                        "source.video",
                        quarantined,
                        size=quarantined_path.stat().st_size,
                    )
                metadata = extract_metadata(source_url)
                video_hash = workspace.sha256("source.video")
                metadata_hash = canonical_metadata_hash(metadata) if metadata else None
        except QuarantineError as exc:
            return jsonify({"error": str(exc)}), 400

        retention_class = request.headers.get("X-Harpocrates-Retention-Class") or (metadata.get("retentionClass", "default") if metadata else "default")
        if retention_class not in config.retention_classes:
            return jsonify({"error": f"invalid retention class: {retention_class}"}), 400
        retention_days = config.retention_classes[retention_class]
        expires_at = None
        if retention_days >= 0:
            expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

        db_event = insert_proof_event(
            event_type="extract",
            file_name=safe_filename(video.filename),
            video_hash=video_hash,
            metadata_hash=metadata_hash,
            proof_id=metadata.get("proofId") if metadata else None,
            tier=metadata.get("tier") if metadata else None,
            retention_class=retention_class,
            expires_at=expires_at,
            metadata=redact_metadata(metadata),
        )

        if db_event and db_event.get("id"):
            queue_webhook_deliveries(db_event["id"])

        return jsonify(
            {
                "video_hash": video_hash,
                "metadata_hash": metadata_hash,
                "metadata": metadata,
                "db_event": db_event,
            }
        )

    @app.get("/api/proofs")
    def proofs():
        limit = request.args.get("limit", "25")
        cursor_token = request.args.get("cursor")
        try:
            parsed_limit = int(limit)
        except ValueError:
            return error_response(
                code=VALIDATION_ERROR,
                message="limit must be an integer",
                status=400,
            )

        cursor_id = None
        if cursor_token is not None and cursor_token != "":
            try:
                cursor_id = decode_proof_events_cursor(cursor_token)
            except ValueError:
                return jsonify({"error": "invalid cursor"}), 400

        events, next_cursor = list_proof_events(parsed_limit, cursor_id=cursor_id)
        return jsonify({"ok": True, "events": events, "nextCursor": next_cursor})

    @app.get("/api/proofs/lineage")
    def lineage_events():
        limit = request.args.get("limit", "25")
        try:
            parsed_limit = int(limit)
        except ValueError:
            return jsonify({"error": "limit must be an integer"}), 400
        return jsonify({"ok": True, "events": list_lineage_events(parsed_limit)})

    @app.get("/api/proofs/by-video/<video_hash>")
    def proof_by_video(video_hash: str):
        if not is_hex_32(video_hash):
            return error_response(
                code=VALIDATION_ERROR,
                message="video_hash must be a 32-byte hex string",
                status=400,
            )

        return ok_response({"events": find_proof_events_by_video(video_hash)})

    @app.get("/api/lineage/by-actor/<actor_address>")
    def lineage_by_actor(actor_address: str):
        limit = request.args.get("limit", "25")
        try:
            parsed_limit = int(limit)
        except ValueError:
            return jsonify({"error": "limit must be an integer"}), 400

        return jsonify({"ok": True, "events": find_lineage_by_actor(actor_address, parsed_limit)})

    @app.post("/api/proofs/lineage")
    def register_lineage_event():
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400

        output_digest = payload.get("outputDigest")
        if not output_digest:
            return jsonify({"error": "outputDigest is required"}), 400
        if not is_hex_32(output_digest):
            return jsonify({"error": "outputDigest must be a 32-byte hex string"}), 400

        try:
            manifest_canonical = canonical_lineage_manifest(payload)
            manifest_digest = lineage_manifest_digest(payload)
            parent_ids = payload.get("parentProofIds", [])
            actor_address = str(payload.get("actorAddress", ""))
            
            # Validate basic constraints
            validate_lineage_graph(
                parent_ids,
                depth=1,
                actor_address=actor_address,
                output_digest=output_digest,
                get_lineage_fn=find_lineage_by_output_digest,
            )
        except LineageValidationError as exc:
            return jsonify({"error": str(exc)}), 400

        # Check for duplicate submission
        existing = find_lineage_by_output_digest(output_digest)
        if existing:
            return jsonify({"error": "lineage already registered for this output digest"}), 409

        # Insert into lineage_events table
        db_event = insert_lineage_event(
            manifest_digest=manifest_digest,
            manifest=json.loads(manifest_canonical),
            actor_address=actor_address,
            parent_proof_ids=[str(parent) for parent in parent_ids],
        )
        
        if not db_event:
            return jsonify({"error": "failed to record lineage event"}), 500

        return jsonify({"ok": True, "manifestDigest": manifest_digest, "db_event": db_event})

    @app.post("/api/proofs/register")
    @limiter.limit(config.ratelimit_register)
    @idempotent("register")
    def register_proof_event():
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error_response(
                code=VALIDATION_ERROR,
                message="JSON body is required",
                status=400,
            )
        if len(json.dumps(payload, separators=(",", ":")).encode("utf-8")) > config.max_metadata_bytes:
            return jsonify({"error": "registration payload is too large"}), 413

        video_hash = payload.get("videoHash")
        metadata_hash = payload.get("metadataHash")
        proof_id = payload.get("proofId")
        tx_hash = payload.get("txHash")
        tx_status = payload.get("txStatus")

        for name, value in (
            ("videoHash", video_hash),
            ("metadataHash", metadata_hash),
            ("proofId", proof_id),
        ):
            if not is_hex_32(value):
                return error_response(
                    code=VALIDATION_ERROR,
                    message=f"{name} must be a 32-byte hex string",
                    status=400,
                )

        tier = payload.get("tier")
        if tier not in ALLOWED_TIERS:
            return error_response(
                code=VALIDATION_ERROR,
                message="tier must be one of: silent, source, seal",
                status=400,
            )

        try:
            normalized_tx_hash = normalize_tx_hash(tx_hash)
            normalized_tx_status = normalize_tx_status(tx_status)
            if normalized_tx_hash:
                normalized_tx_status = "pending"
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        # Validate Stellar identifiers with StrKey semantics
        try:
            validated_source_address = validate_source_address(payload.get("sourceAddress"))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        try:
            validated_contract_id = validate_contract_id(payload.get("contractId"))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        # Handle time attestation if provided
        time_attestation_data = None
        claimed_capture_time = None
        if "timeAttestation" in payload:
            from time_attestation import decode_time_attestation, validate_time_attestation, encode_time_attestation
            try:
                time_att = decode_time_attestation(payload["timeAttestation"])
                errors = validate_time_attestation(time_att, video_hash)
                if errors:
                    return jsonify({"error": "Invalid time attestation", "details": errors}), 400
                time_attestation_data = encode_time_attestation(time_att)
                if time_att.claimed_time:
                    from datetime import datetime, timezone
                    claimed_capture_time = datetime.fromtimestamp(
                        time_att.claimed_time.unix_ms / 1000, tz=timezone.utc
                    ).isoformat()
            except (ValueError, TypeError) as exc:
                return jsonify({"error": f"Time attestation error: {str(exc)}"}), 400

        idempotency_key = make_idempotency_key(video_hash, proof_id, normalized_tx_hash)

        retention_class = payload.get("retentionClass", "default")
        if retention_class not in config.retention_classes:
            return jsonify({"error": f"invalid retention class: {retention_class}"}), 400
        retention_days = config.retention_classes[retention_class]
        expires_at = None
        if retention_days >= 0:
            expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

        try:
            db_event, created = upsert_register_event(
                idempotency_key=idempotency_key,
                file_name=safe_filename(payload.get("fileName")),
                video_hash=video_hash,
                metadata_hash=metadata_hash,
                proof_id=proof_id,
                tier=tier,
                tx_hash=normalized_tx_hash,
                tx_status=normalized_tx_status,
                source_address=validated_source_address,
                contract_id=validated_contract_id,
                retention_class=retention_class,
                expires_at=expires_at,
                metadata=redact_metadata(payload),
                time_attestation=time_attestation_data,
                claimed_capture_time=claimed_capture_time,
            )
        except ConflictError as exc:
            return jsonify({
                "error": "idempotency key reused with conflicting payload",
                "conflict_field": exc.field,
            }), 409

        if db_event and db_event.get("id") and created:
            queue_webhook_deliveries(db_event["id"])
            if normalized_tx_hash:
                enqueue_job("verify_tx", {"proof_id": proof_id, "tx_hash": normalized_tx_hash, "contract_id": validated_contract_id})

        status = 201 if created else 200
        return jsonify({"ok": True, "db_event": db_event, "created": created}), status

    @app.post("/api/time-attestation/create")
    def create_time_attestation_endpoint():
        """Create a new time attestation envelope."""
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413
        
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400
        
        evidence_digest = payload.get("evidenceDigest")
        if not is_hex_32(evidence_digest):
            return jsonify({"error": "evidenceDigest must be a 32-byte hex string"}), 400
        
        from time_attestation import create_time_attestation, encode_time_attestation, check_backdating_risk
        
        claimed_time_ms = payload.get("claimedTimeMs")
        claimed_source_label = payload.get("claimedSourceLabel", "device_clock")
        uncertainty_ms = payload.get("uncertaintyMs", 0)
        
        try:
            attestation = create_time_attestation(
                evidence_digest=evidence_digest,
                claimed_time_ms=claimed_time_ms,
                claimed_source_label=claimed_source_label,
                uncertainty_ms=uncertainty_ms,
            )
            
            encoded = encode_time_attestation(attestation)
            risk_assessment = check_backdating_risk(attestation)
            
            return jsonify({
                "ok": True,
                "timeAttestation": encoded,
                "riskAssessment": risk_assessment,
            })
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/time-attestation/anchor")
    def anchor_time_attestation():
        """Add anchors to an existing time attestation."""
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413
        
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400
        
        from time_attestation import (
            decode_time_attestation,
            add_stellar_anchor,
            add_rfc3161_anchor,
            encode_time_attestation,
            check_backdating_risk,
        )
        
        try:
            attestation = decode_time_attestation(payload.get("timeAttestation", {}))
        except (ValueError, TypeError) as exc:
            return jsonify({"error": f"Invalid time attestation: {str(exc)}"}), 400
        
        # Add Stellar anchor if provided
        if "stellarAnchor" in payload:
            stellar = payload["stellarAnchor"]
            try:
                attestation = add_stellar_anchor(
                    attestation,
                    ledger_sequence=stellar["ledgerSequence"],
                    ledger_timestamp=stellar["ledgerTimestamp"],
                    transaction_hash=stellar["transactionHash"],
                    network_passphrase=stellar["networkPassphrase"],
                )
            except (ValueError, KeyError) as exc:
                return jsonify({"error": f"Invalid Stellar anchor: {str(exc)}"}), 400
        
        # Add RFC 3161 anchor if provided
        if "rfc3161Anchor" in payload:
            rfc3161 = payload["rfc3161Anchor"]
            try:
                attestation = add_rfc3161_anchor(
                    attestation,
                    token_bytes=rfc3161["tokenBytes"],
                    tsa_url=rfc3161["tsaUrl"],
                    gen_time=rfc3161["genTime"],
                    policy_oid=rfc3161.get("policyOid"),
                    cert_fingerprint=rfc3161.get("certFingerprint"),
                    verification_status=rfc3161.get("verificationStatus", "unverified"),
                    verification_error=rfc3161.get("verificationError"),
                )
            except (ValueError, KeyError) as exc:
                return jsonify({"error": f"Invalid RFC 3161 anchor: {str(exc)}"}), 400
        
        encoded = encode_time_attestation(attestation)
        risk_assessment = check_backdating_risk(attestation)
        
        return jsonify({
            "ok": True,
            "timeAttestation": encoded,
            "riskAssessment": risk_assessment,
        })

    @app.post("/api/time-attestation/validate")
    def validate_time_attestation_endpoint():
        """Validate a time attestation envelope."""
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413
        
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400
        
        evidence_digest = payload.get("evidenceDigest")
        if not is_hex_32(evidence_digest):
            return jsonify({"error": "evidenceDigest must be a 32-byte hex string"}), 400
        
        from time_attestation import (
            decode_time_attestation,
            validate_time_attestation,
            check_backdating_risk,
        )
        
        try:
            attestation = decode_time_attestation(payload.get("timeAttestation", {}))
            errors = validate_time_attestation(attestation, evidence_digest)
            risk_assessment = check_backdating_risk(attestation)
            
            return jsonify({
                "ok": len(errors) == 0,
                "errors": errors,
                "riskAssessment": risk_assessment,
            })
        except (ValueError, TypeError) as exc:
            return jsonify({"error": f"Invalid time attestation: {str(exc)}"}), 400

    @app.get("/api/proofs/history/<proof_id>")
    def proof_history(proof_id: str):
        if not is_hex_32(proof_id):
            return jsonify({"error": "proof_id must be a 32-byte hex string"}), 400

        limit = request.args.get("limit", "50")
        offset = request.args.get("offset", "0")
        try:
            parsed_limit = int(limit)
            parsed_offset = int(offset)
        except ValueError:
            return jsonify({"error": "limit and offset must be integers"}), 400

        return jsonify(
            {"ok": True, "events": list_proof_history_events(proof_id, parsed_limit, parsed_offset)}
        )

    @app.post("/api/proofs/history")
    def register_proof_history_event():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400

        proof_id = payload.get("proofId")
        action = payload.get("action")
        actor = payload.get("actor")
        reason_code = payload.get("reasonCode")
        contract_id = payload.get("contractId")
        tx_hash = payload.get("txHash")

        if not is_hex_32(proof_id):
            return jsonify({"error": "proofId must be a 32-byte hex string"}), 400
        if not isinstance(action, str) or not action:
            return jsonify({"error": "action is required"}), 400
        if reason_code is None or not isinstance(reason_code, int):
            return jsonify({"error": "reasonCode is required"}), 400

        db_event = insert_proof_history_event(
            proof_id=proof_id,
            action=action,
            actor=actor,
            reason_code=reason_code,
            contract_id=contract_id,
            tx_hash=tx_hash,
        )

        return ok_response({"db_event": db_event})

    @app.post("/api/noir/silent-witness")
    @limiter.limit(config.ratelimit_silent_witness)
    @require_capacity(admission_controller)
    @idempotent("silent-witness")
    def silent_witness_proof():
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413
        if not config.noir_worker_enabled:
            return error_response(
                code=NOT_FOUND,
                message="local Noir worker is disabled",
                status=404,
            )

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error_response(
                code=VALIDATION_ERROR,
                message="JSON body is required",
                status=400,
            )

        video_hash = payload.get("videoHash")
        if not is_hex_32(video_hash):
            return error_response(
                code=VALIDATION_ERROR,
                message="videoHash must be a 32-byte hex string",
                status=400,
            )
        credential_secret = payload.get("credentialSecret")
        nullifier_secret = payload.get("nullifierSecret")
        if not is_field_decimal(credential_secret):
            return error_response(
                code=VALIDATION_ERROR,
                message="credentialSecret must be a decimal field string",
                status=400,
            )
        if not is_field_decimal(nullifier_secret):
            return error_response(
                code=VALIDATION_ERROR,
                message="nullifierSecret must be a decimal field string",
                status=400,
            )

        verifier_scope = payload.get("verifierScope", "0")
        if not is_field_decimal(verifier_scope):
            return jsonify({"error": "verifierScope must be a decimal field string"}), 400
        epoch = payload.get("epoch", 0)
        if not isinstance(epoch, int) or epoch < 0:
            return jsonify({"error": "epoch must be a non-negative integer"}), 400

        try:
            proof = generate_silent_witness(
                video_hash,
                credential_secret,
                nullifier_secret,
                verifier_scope,
                epoch,
            )
        except RuntimeError as exc:
            app.logger.error("Noir proof generation failed: %s", exc, exc_info=True)
            return error_response(
                code=INTERNAL_ERROR,
                message="Noir proof generation failed",
                status=500,
            )

        return jsonify({"job_id": job_id, "status": "pending"}), 202

    @app.get("/api/jobs/<int:job_id>")
    def get_job_status(job_id: int):
        job = get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify({"ok": True, "job": job})

    @app.get("/api/jobs/<int:job_id>/download")
    def download_job_result(job_id: int):
        job = get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        if job["type"] != "embed" or job["status"] != "completed":
            return jsonify({"error": "No output available for download"}), 400
            
        output_path = get_job_output_path(job_id)
        if not output_path.exists():
            return jsonify({"error": "Output file missing"}), 404
            
        result = job.get("result", {})
        response = send_file(output_path, mimetype="video/mp4", as_attachment=True, download_name="harpocrates-evidence.mp4")
        if result.get("source_hash"):
            response.headers["X-Harpocrates-Source-Hash"] = result["source_hash"]
        if result.get("embedded_hash"):
            response.headers["X-Harpocrates-Embedded-Hash"] = result["embedded_hash"]
        if result.get("metadata_hash"):
            response.headers["X-Harpocrates-Metadata-Hash"] = result["metadata_hash"]
        if result.get("db_event"):
            response.headers["X-Harpocrates-Db-Event"] = str(result["db_event"])
            
        return response

    @app.post("/api/jobs/<int:job_id>/cancel")
    def cancel_job_endpoint(job_id: int):
        if cancel_job(job_id):
            return jsonify({"ok": True, "message": "Job cancelled"})
        return jsonify({"error": "Job cannot be cancelled or not found"}), 400

    # Start webhook worker if DB is enabled
    if database_url():
        webhook_worker = WebhookWorker()
        webhook_worker.start()
        app.webhook_worker = webhook_worker

    @app.post("/api/noir/silent-witness/aggregate")
    def silent_witness_aggregate():
        """Generate a bounded aggregated proof for multiple video hashes.

        Accepts up to ``MAX_AGGREGATION_SIZE`` (8) video hashes and produces
        a single UltraHonk proof that covers all of them under the same
        credential identity.

        Request body:
        ```json
        {
            "videoHashes": ["32-byte-hex", ...],  // 1-8 video hashes
            "credentialSecret": "decimal-field",
            "nullifierSecret": "decimal-field"
        }
        ```

        Response (200):
        ```json
        {
            "ok": true,
            "proof": { ... aggregated proof artifacts ... }
        }
        ```
        """
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413
        if not config.noir_worker_enabled:
            return jsonify({"error": "local Noir worker is disabled"}), 404

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400

        video_hashes = payload.get("videoHashes")
        if not isinstance(video_hashes, list) or len(video_hashes) == 0:
            return jsonify({"error": "videoHashes must be a non-empty array"}), 400

        if len(video_hashes) > MAX_AGGREGATION_SIZE:
            return jsonify({
                "error": f"videoHashes exceeds maximum aggregation size ({MAX_AGGREGATION_SIZE})"
            }), 400

        for i, video_hash in enumerate(video_hashes):
            if not is_hex_32(video_hash):
                return jsonify({"error": f"videoHashes[{i}] must be a 32-byte hex string"}), 400

        credential_secret = payload.get("credentialSecret")
        nullifier_secret = payload.get("nullifierSecret")
        if not is_field_decimal(credential_secret):
            return jsonify({"error": "credentialSecret must be a decimal field string"}), 400
        if not is_field_decimal(nullifier_secret):
            return jsonify({"error": "nullifierSecret must be a decimal field string"}), 400

        # Redact secrets from logs before calling the generator.
        safe_fields = {
            "event": "aggregate_proof_request",
            "request_id": request_id(),
            "batch_size": len(video_hashes),
        }
        log_structured(LOGGER, logging.INFO, safe_fields)

        try:
            proof = generate_aggregated_proof(
                video_hashes,
                credential_secret,
                nullifier_secret,
            )
        except (ValueError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 500

        return jsonify({"ok": True, "proof": proof})

    # -------------------------------------------------------------------
    # Schema discovery and selective disclosure
    # -------------------------------------------------------------------

    @app.get("/api/schemas")
    def list_schemas():
        schemas = discover_schemas()
        return jsonify({"ok": True, "schemas": schemas})

    @app.get("/api/schemas/<schema_hash>")
    def get_schema(schema_hash: str):
        if not is_hex_32(schema_hash):
            return jsonify({"error": "schemaHash must be a 32-byte hex string"}), 400
        schema = resolve_schema(schema_hash)
        if schema is None:
            return jsonify({"error": "schema not found"}), 404
        return jsonify({"ok": True, "schema": schema})

    @app.post("/api/verify/selective-disclosure")
    def verify_selective_disclosure():
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400

        err = validate_selective_disclosure_input(payload)
        if err is not None:
            return jsonify({"error": err}), 400

        return jsonify({
            "ok": True,
            "message": "Selective disclosure proof submission accepted.",
            "note": "On-chain verification must be performed via verify_selective_disclosure on the registry contract.",
        })

    return app


def request_id() -> str:
    return getattr(g, "request_id", "unknown")


def request_route() -> str:
    return request.url_rule.rule if request.url_rule else request.path


def request_duration_ms() -> float:
    started_at = getattr(g, "request_started_at", None)
    if started_at is None:
        return 0.0
    return round((time.perf_counter() - started_at) * 1000, 2)


def log_error_response(status: int) -> None:
    log_structured(
        LOGGER,
        logging.ERROR,
        merge_trace_into_event(
            {
                "event": "error",
                "request_id": request_id(),
                "method": request.method,
                "route": request_route(),
                "path": request.path,
                "status": status,
                "duration_ms": request_duration_ms(),
            },
            current_trace_fields(),
        ),
    )


def current_trace_fields() -> dict:
    fields = getattr(g, "trace_fields", None)
    if isinstance(fields, dict):
        return fields
    return build_trace_fields(
        getattr(request, "headers", None),
        request_id=request_id(),
        method=getattr(request, "method", None),
        route=request_route() if request else None,
        path=getattr(request, "path", None),
    )


def is_hex_32(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def normalize_tx_hash(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("txHash must be a 32-byte hex string")

    normalized = value.strip().lower()
    if not is_hex_32(normalized):
        raise ValueError("txHash must be a 32-byte hex string")
    return normalized


def normalize_tx_status(value: object) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError("txStatus must be one of: pending, confirmed, failed, missing")

    normalized = value.strip().lower()
    if normalized in {"pending", "confirmed", "failed", "missing"}:
        return normalized
    if normalized in {"success", "successful", "succeeded"}:
        return "confirmed"
    if normalized in {"failure", "failed", "error", "errored"}:
        return "failed"
    if normalized in {"not_found", "notfound"}:
        return "missing"
    raise ValueError("txStatus must be one of: pending, confirmed, failed, missing")


def is_field_decimal(value: object) -> bool:
    if not isinstance(value, str) or not value or not value.isdecimal():
        return False
    field_modulus = (
        21888242871839275222246405745257275088548364400416034343698204186575808495617
    )
    return 0 < int(value) < field_modulus


def validate_video_upload(video) -> None:
    if not video.filename:
        raise ValueError("video filename is required")
    content_type = (video.content_type or "").lower()
    if content_type and not content_type.startswith("video/") and content_type != "application/octet-stream":
        raise ValueError("video upload must use a video content type")




def safe_filename(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    sanitized = secure_filename(value)
    return sanitized[:160] if sanitized else None


def redact_metadata(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    return redact_sensitive(value)


def video_tooling_ready() -> bool:
    try:
        from stego import _require

        _require("ffmpeg")
        _require("ffprobe")
    except RuntimeError:
        return False
    return True


app = create_app()


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5050")), debug=debug)
