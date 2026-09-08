"""
GCS Bucket tools - store logs and incident artifacts in Cloud Storage buckets.
Bucket is source of truth for 'logs should be stored in buckets itself'.
Fallback to local file if bucket not configured or GCP unavailable.
"""
import os, json, logging
from typing import Optional
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger("gcs_tools")

def _get_bucket_name() -> Optional[str]:
    return os.getenv("LOG_BUCKET") or os.getenv("GCS_BUCKET") or os.getenv("INCIDENT_BUCKET")

def _get_client():
    try:
        from google.cloud import storage
        return storage.Client()
    except Exception as e:
        logger.warning(f"GCS client unavailable: {e}")
        return None

def _ensure_bucket(client, bucket_name: str):
    try:
        bucket = client.bucket(bucket_name)
        if not bucket.exists():
            logger.info(f"Bucket {bucket_name} does not exist, creating in {os.getenv('GOOGLE_CLOUD_REGION','us-central1')}")
            client.create_bucket(bucket_name, location=os.getenv("GOOGLE_CLOUD_REGION","us-central1"))
        return bucket
    except Exception as e:
        logger.warning(f"ensure_bucket failed {bucket_name}: {e}")
        return None

def upload_jsonl_to_bucket(bucket_name: str, blob_name: str, record: dict) -> bool:
    """Append JSONL record to GCS blob (read-modify-write). For low-volume audit/logs this is fine."""
    client = _get_client()
    if not client or not bucket_name:
        return False
    try:
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        existing = ""
        if blob.exists():
            existing = blob.download_as_text()
        new_content = existing + json.dumps(record) + "\n"
        blob.upload_from_string(new_content, content_type="application/jsonl")
        return True
    except Exception as e:
        logger.warning(f"GCS upload failed {bucket_name}/{blob_name}: {e}")
        return False

def upload_blob_text(bucket_name: str, blob_name: str, text: str, content_type: str="application/json") -> bool:
    client = _get_client()
    if not client or not bucket_name:
        return False
    try:
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        blob.upload_from_string(text, content_type=content_type)
        return True
    except Exception as e:
        logger.warning(f"GCS upload blob failed: {e}")
        return False

def list_blobs(bucket_name: str, prefix: str=""):
    client = _get_client()
    if not client or not bucket_name:
        return []
    try:
        bucket = client.bucket(bucket_name)
        return [b.name for b in client.list_blobs(bucket, prefix=prefix)]
    except Exception as e:
        logger.warning(f"GCS list failed: {e}")
        return []

def download_blob_text(bucket_name: str, blob_name: str) -> Optional[str]:
    client = _get_client()
    if not client or not bucket_name:
        return None
    try:
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        if blob.exists():
            return blob.download_as_text()
        return None
    except Exception as e:
        logger.warning(f"GCS download failed: {e}")
        return None

# Convenience: log bucket for all app logs
def get_log_bucket() -> Optional[str]:
    return _get_bucket_name()
