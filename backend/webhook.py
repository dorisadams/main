import hashlib
import hmac
import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional
import urllib.request
import urllib.error

from psycopg.types.json import Jsonb

from db import get_connection, database_url
from fetch_external import (
    FetchTimeoutError,
    ResponseTooLargeError,
    safe_urlopen,
)

LOGGER = logging.getLogger("harpocrates.webhook")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

# Module-level defaults — overridden by callers that pass explicit values
# (typically sourced from AppConfig).
_DEFAULT_CONNECT_TIMEOUT: float = 5.0
_DEFAULT_READ_TIMEOUT: float = 10.0
_DEFAULT_MAX_RESPONSE_BYTES: int = 65_536  # 64 KiB


MAX_RETRIES = 5
RETRY_BACKOFF_SECONDS = [10, 60, 300, 3600, 86400] # 10s, 1m, 5m, 1h, 1d


def get_active_subscriptions() -> List[dict]:
    if not database_url():
        return []
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, url, secret_key FROM webhook_subscriptions WHERE is_active = true"
            )
            return [dict(row) for row in cur.fetchall()]


def queue_webhook_deliveries(event_id: int) -> None:
    subs = get_active_subscriptions()
    if not subs:
        return

    if not database_url():
        return

    with get_connection() as conn:
        with conn.cursor() as cur:
            for sub in subs:
                cur.execute(
                    """
                    INSERT INTO webhook_deliveries (subscription_id, event_id, status)
                    VALUES (%s, %s, 'pending')
                    """,
                    (sub["id"], event_id)
                )
        conn.commit()


def lease_deliveries(limit: int = 10, lease_duration: int = 30) -> List[dict]:
    if not database_url():
        return []

    now = datetime.now(timezone.utc)
    lease_expires = now + timedelta(seconds=lease_duration)

    with get_connection() as conn:
        with conn.cursor() as cur:
            # Select pending or failed deliveries that are ready for retry, and aren't currently leased
            cur.execute(
                """
                UPDATE webhook_deliveries
                SET lease_expires_at = %s, updated_at = %s
                WHERE id IN (
                    SELECT id FROM webhook_deliveries
                    WHERE status IN ('pending', 'failed')
                      AND next_retry_at <= %s
                      AND (lease_expires_at IS NULL OR lease_expires_at <= %s)
                    ORDER BY next_retry_at ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                )
                RETURNING id, subscription_id, event_id, retry_count
                """,
                (lease_expires, now, now, now, limit)
            )
            deliveries = [dict(row) for row in cur.fetchall()]

            if not deliveries:
                return []

            # Fetch extra data for dispatch (url, secret, payload)
            results = []
            for d in deliveries:
                cur.execute(
                    """
                    SELECT s.url, s.secret_key, e.event_type, e.file_name, e.video_hash,
                           e.metadata_hash, e.proof_id, e.tier, e.embedded_hash,
                           e.tx_hash, e.tx_status, e.source_address, e.contract_id,
                           e.metadata, e.created_at
                    FROM webhook_subscriptions s
                    JOIN proof_events e ON e.id = %s
                    WHERE s.id = %s
                    """,
                    (d["event_id"], d["subscription_id"])
                )
                row = cur.fetchone()
                if row:
                    results.append({
                        "delivery_id": d["id"],
                        "retry_count": d["retry_count"],
                        "url": row["url"],
                        "secret_key": row["secret_key"],
                        "payload": {
                            "event_type": row["event_type"],
                            "file_name": row["file_name"],
                            "video_hash": row["video_hash"],
                            "metadata_hash": row["metadata_hash"],
                            "proof_id": row["proof_id"],
                            "tier": row["tier"],
                            "embedded_hash": row["embedded_hash"],
                            "tx_hash": row["tx_hash"],
                            "tx_status": row["tx_status"],
                            "source_address": row["source_address"],
                            "contract_id": row["contract_id"],
                            "metadata": row["metadata"],
                            "created_at": row["created_at"].isoformat() if row["created_at"] else None
                        }
                    })
        conn.commit()
        return results


def update_delivery_status(delivery_id: int, success: bool, status_code: Optional[int], retry_count: int) -> None:
    if not database_url():
        return
    now = datetime.now(timezone.utc)

    status = 'success'
    next_retry_at = now
    
    if not success:
        if retry_count >= MAX_RETRIES:
            status = 'dead_letter'
        else:
            status = 'failed'
            delay = RETRY_BACKOFF_SECONDS[retry_count] if retry_count < len(RETRY_BACKOFF_SECONDS) else RETRY_BACKOFF_SECONDS[-1]
            next_retry_at = now + timedelta(seconds=delay)
            retry_count += 1

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE webhook_deliveries
                SET status = %s, retry_count = %s, next_retry_at = %s,
                    last_response_code = %s, lease_expires_at = NULL, updated_at = %s
                WHERE id = %s
                """,
                (status, retry_count, next_retry_at, status_code, now, delivery_id)
            )
        conn.commit()


def sign_payload(payload_bytes: bytes, secret: str, timestamp: int) -> str:
    """Generate HMAC SHA-256 signature."""
    mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
    mac.update(f"{timestamp}.".encode("utf-8"))
    mac.update(payload_bytes)
    return mac.hexdigest()


def dispatch_webhook(
    delivery: dict,
    *,
    connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = _DEFAULT_READ_TIMEOUT,
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
) -> None:
    url = delivery["url"]
    secret = delivery["secret_key"]
    payload = delivery["payload"]

    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    timestamp = int(time.time())
    signature = sign_payload(payload_bytes, secret, timestamp)

    headers = {
        "Content-Type": "application/json",
        "X-Harpocrates-Signature": f"t={timestamp},v1={signature}",
        "User-Agent": "Harpocrates-Webhook/1.0",
    }

    req = urllib.request.Request(url, data=payload_bytes, headers=headers, method="POST")

    success = False
    status_code = None

    try:
        result = safe_urlopen(
            req,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            max_bytes=max_response_bytes,
        )
        status_code = result.status
        if 200 <= status_code < 300:
            success = True
        else:
            LOGGER.warning(
                "Webhook delivery %d: non-2xx status %d",
                delivery["delivery_id"],
                status_code,
            )

    except FetchTimeoutError as exc:
        LOGGER.warning(
            "Webhook delivery %d: timeout — %s",
            delivery["delivery_id"],
            exc,
        )

    except ResponseTooLargeError as exc:
        LOGGER.warning(
            "Webhook delivery %d: oversized response — %s",
            delivery["delivery_id"],
            exc,
        )

    except urllib.error.HTTPError as exc:
        status_code = exc.code
        LOGGER.warning(
            "Webhook delivery %d: HTTP error %d",
            delivery["delivery_id"],
            exc.code,
        )

    except Exception as exc:  # noqa: BLE001
        LOGGER.warning(
            "Webhook delivery %d: unexpected error — %s",
            delivery["delivery_id"],
            type(exc).__name__,
        )

    update_delivery_status(
        delivery["delivery_id"], success, status_code, delivery["retry_count"]
    )


class WebhookWorker(threading.Thread):
    def __init__(self, poll_interval: float = 2.0):
        super().__init__(daemon=True)
        self.poll_interval = poll_interval
        self.running = True

    def run(self):
        LOGGER.info("Starting webhook dispatcher thread")
        while self.running:
            try:
                deliveries = lease_deliveries()
                for delivery in deliveries:
                    dispatch_webhook(delivery)
                
                if not deliveries:
                    time.sleep(self.poll_interval)
            except Exception as e:
                LOGGER.error(f"Error in webhook dispatcher: {e}")
                time.sleep(self.poll_interval)

    def stop(self):
        self.running = False
