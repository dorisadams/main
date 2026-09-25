import time
import os
import logging
import threading
import traceback
from pathlib import Path

from db import lease_job, heartbeat_job, complete_job, fail_job, insert_proof_event, init_db
from envelope import canonical_metadata_hash
from stego import embed_metadata, extract_metadata, sha256_file
from noir import generate_silent_witness
from app import safe_filename, redact_metadata
from config import load_config

from storage import get_job_input_path, get_job_output_path
from tx_verification import verify_transaction_status

LOGGER = logging.getLogger("harpocrates.worker")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

WORKER_ID = f"worker-{os.getpid()}"

def process_embed(job: dict) -> dict:
    payload = job["payload"]
    job_id = job["id"]
    metadata = payload["metadata"]
    filename = payload["filename"]
    
    input_path = get_job_input_path(job_id)
    output_path = get_job_output_path(job_id)
    
    if not input_path.exists():
        raise RuntimeError(f"Input video file missing for job {job_id}")
        
    source_hash = sha256_file(input_path)
    
    embed_metadata(input_path, output_path, metadata)
    
    embedded_hash = sha256_file(output_path)
    metadata_hash = canonical_metadata_hash(metadata)
    
    db_event = insert_proof_event(
        event_type="embed",
        file_name=safe_filename(filename),
        video_hash=embedded_hash,
        metadata_hash=metadata_hash,
        proof_id=metadata.get("proofId"),
        tier=metadata.get("tier"),
        embedded_hash=embedded_hash,
        metadata=redact_metadata(metadata),
    )
    
    input_path.unlink(missing_ok=True)
    
    return {
        "source_hash": source_hash,
        "embedded_hash": embedded_hash,
        "metadata_hash": metadata_hash,
        "db_event": db_event
    }

def process_extract(job: dict) -> dict:
    payload = job["payload"]
    job_id = job["id"]
    filename = payload["filename"]
    
    input_path = get_job_input_path(job_id)
    
    if not input_path.exists():
        raise RuntimeError(f"Input video file missing for job {job_id}")
        
    metadata = extract_metadata(input_path)
    video_hash = sha256_file(input_path)
    metadata_hash = canonical_metadata_hash(metadata) if metadata else None
    
    db_event = insert_proof_event(
        event_type="extract",
        file_name=safe_filename(filename),
        video_hash=video_hash,
        metadata_hash=metadata_hash,
        proof_id=metadata.get("proofId") if metadata else None,
        tier=metadata.get("tier") if metadata else None,
        metadata=redact_metadata(metadata),
    )
    
    input_path.unlink(missing_ok=True)
    
    return {
        "video_hash": video_hash,
        "metadata_hash": metadata_hash,
        "metadata": metadata,
        "db_event": db_event
    }

def process_silent_witness(job: dict) -> dict:
    payload = job["payload"]
    
    video_hash = payload["video_hash"]
    credential_secret = payload["credential_secret"]
    nullifier_secret = payload["nullifier_secret"]
    
    proof = generate_silent_witness(
        video_hash,
        credential_secret,
        nullifier_secret,
    )
    
    return {"proof": proof}

def heartbeat_loop(job_id: int, stop_event: threading.Event):
    while not stop_event.is_set():
        heartbeat_job(job_id, progress=0.5, lease_duration=300)
        stop_event.wait(60)

def tx_verification_loop(stop_event: threading.Event):
    """
    Polls the database for pending Stellar transactions and verifies them against Horizon.
    """
    LOGGER.info("Starting transaction verification loop")

    # Load config once; the dataclass is frozen so these values are stable.
    _config = load_config()

    while not stop_event.is_set():
        try:
            if not database_url():
                stop_event.wait(10)
                continue
                
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, tx_hash 
                        FROM proof_events 
                        WHERE tx_hash IS NOT NULL AND tx_status = 'pending'
                        LIMIT 50
                        """
                    )
                    rows = [dict(row) for row in cur.fetchall()]
            
            for row in rows:
                if stop_event.is_set():
                    break
                    
                tx_hash = row["tx_hash"]
                LOGGER.info("Verifying transaction (hash redacted)")
                status = verify_transaction_status(
                    tx_hash,
                    connect_timeout=_config.external_fetch_connect_timeout_seconds,
                    read_timeout=_config.external_fetch_read_timeout_seconds,
                    max_response_bytes=_config.external_fetch_max_response_bytes,
                )
                
                # Update DB if terminal or missing
                if status in ('confirmed', 'failed', 'missing'):
                    LOGGER.info("Transaction resolved to %s", status)
                    update_tx_status(tx_hash, status)
                else:
                    # Still pending, we will check again next loop
                    pass

        except Exception as e:
            LOGGER.error("Error in tx verification loop: %s", type(e).__name__)
        
        stop_event.wait(15)


def run_worker():
    init_db()
    LOGGER.info(f"Starting worker {WORKER_ID}")
    
    stop_verification_event = threading.Event()
    verification_thread = threading.Thread(target=tx_verification_loop, args=(stop_verification_event,))
    verification_thread.daemon = True
    verification_thread.start()
    
    while True:
        try:
            job = lease_job(WORKER_ID, ["embed", "extract", "silent_witness"], lease_duration=300)
            if not job:
                time.sleep(2)
                continue
                
            job_id = job["id"]
            job_type = job["type"]
            LOGGER.info(f"Leased job {job_id} of type {job_type}")
            
            stop_event = threading.Event()
            hb_thread = threading.Thread(target=heartbeat_loop, args=(job_id, stop_event))
            hb_thread.start()
            
            try:
                if job_type == "embed":
                    result = process_embed(job)
                elif job_type == "extract":
                    result = process_extract(job)
                elif job_type == "silent_witness":
                    result = process_silent_witness(job)
                else:
                    raise ValueError(f"Unknown job type {job_type}")
                
                complete_job(job_id, result)
                LOGGER.info(f"Completed job {job_id}")
            except Exception as e:
                LOGGER.error(f"Failed job {job_id}: {e}")
                LOGGER.error(traceback.format_exc())
                is_fatal = isinstance(e, ValueError)
                fail_job(job_id, str(e), is_fatal=is_fatal)
            finally:
                stop_event.set()
                hb_thread.join()
                
        except Exception as e:
            LOGGER.error(f"Worker loop error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    run_worker()
