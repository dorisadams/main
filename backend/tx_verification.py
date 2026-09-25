"""
Stellar Horizon transaction verification with enforced timeouts.

All HTTP calls to Horizon are made through ``fetch_external.safe_urlopen``
so that:

- The TCP+TLS connect phase is capped at ``connect_timeout`` seconds.
- Each socket read is capped at ``read_timeout`` seconds.
- The full response body is hard-limited to ``max_response_bytes`` bytes.

Neither the raw transaction hash nor the full Horizon URL is emitted above
DEBUG level, preventing accidental leakage of correlation data.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from fetch_external import (
    FetchTimeoutError,
    ResponseTooLargeError,
    safe_urlopen,
)

LOGGER = logging.getLogger("harpocrates.tx_verification")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

# List of Horizon RPC URLs to try in order (failover).
RPC_URLS = [
    "https://horizon-testnet.stellar.org",
    "https://horizon.stellar.org",
]

# Module-level defaults — overridden by callers that pass explicit values
# (typically sourced from AppConfig).
_DEFAULT_CONNECT_TIMEOUT: float = 5.0
_DEFAULT_READ_TIMEOUT: float = 10.0
_DEFAULT_MAX_RESPONSE_BYTES: int = 65_536  # 64 KiB; Horizon tx response is < 10 KiB


def verify_transaction_status(
    tx_hash: str,
    *,
    connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = _DEFAULT_READ_TIMEOUT,
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
) -> str:
    """Check the status of a transaction on Stellar Horizon.

    Returns one of: ``'confirmed'``, ``'pending'``, ``'failed'``, ``'missing'``.

    Parameters
    ----------
    tx_hash:
        64-character lowercase hex Stellar transaction hash.
    connect_timeout:
        TCP+TLS connect phase limit in seconds.
    read_timeout:
        Per-socket-recv read limit in seconds.
    max_response_bytes:
        Maximum bytes to accept in the Horizon response body.
    """
    for rpc_url in RPC_URLS:
        url = f"{rpc_url}/transactions/{tx_hash}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            result = safe_urlopen(
                req,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                max_bytes=max_response_bytes,
            )
            data = json.loads(result.body.decode("utf-8"))
            if data.get("successful", False):
                return "confirmed"
            return "failed"

        except FetchTimeoutError as exc:
            LOGGER.warning(
                "tx_verification: timeout querying Horizon endpoint (host=%s): %s",
                rpc_url.split("//", 1)[-1],
                exc,
            )
            continue

        except ResponseTooLargeError as exc:
            LOGGER.warning(
                "tx_verification: oversized response from Horizon endpoint (host=%s): %s",
                rpc_url.split("//", 1)[-1],
                exc,
            )
            continue

        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # Not found on this RPC — try next, or fall through to 'missing'.
                continue
            LOGGER.warning(
                "tx_verification: HTTP %d from Horizon endpoint (host=%s)",
                exc.code,
                rpc_url.split("//", 1)[-1],
            )
            continue

        except Exception as exc:  # noqa: BLE001
            LOGGER.warning(
                "tx_verification: unexpected error querying Horizon endpoint (host=%s): %s",
                rpc_url.split("//", 1)[-1],
                type(exc).__name__,
            )
            continue

    return "missing"
