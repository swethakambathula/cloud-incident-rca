"""
Incident memory store - BigQuery preferred, file fallback.
"""
import os, json, logging
from typing import Optional
from pathlib import Path
from .schemas import IncidentMemoryRecord

logger = logging.getLogger("memory_store")

STORE_PATH = Path(__file__).parent.parent / "data" / "incident_memory.jsonl"
BQ_DATASET = os.getenv("INCIDENT_DATASET", "incident_memory")
BQ_TABLE_INCIDENTS = "incidents"

class MemoryStore:
    def __init__(self, use_bigquery: bool = None):
        if use_bigquery is None:
            use_bigquery = bool(os.getenv("GOOGLE_CLOUD_PROJECT") and os.getenv("USE_BIGQUERY", "false")=="true")
        self.use_bigquery = use_bigquery
        self._bq_client = None
        if use_bigquery:
            try:
                from google.cloud import bigquery
                self._bq_client = bigquery.Client()
            except Exception as e:
                logger.warning(f"BigQuery unavailable, falling back to file: {e}")
                self.use_bigquery = False

    def save(self, record: IncidentMemoryRecord) -> str:
        if self.use_bigquery and self._bq_client:
            try:
                from google.cloud import bigquery
                dataset_ref = f"{os.getenv('GOOGLE_CLOUD_PROJECT')}.{BQ_DATASET}"
                table_ref = f"{dataset_ref}.{BQ_TABLE_INCIDENTS}"
                # Ensure dataset exists - omitted for demo, just insert
                row = record.model_dump()
                # For demo, fallback if table not exists
                errors = self._bq_client.insert_rows_json(table_ref, [row])
                if errors:
                    logger.warning(f"BigQuery insert errors {errors}, falling back")
                    raise Exception(str(errors))
                return table_ref
            except Exception as e:
                logger.warning(f"BigQuery save failed {e}, using file")
        # File fallback (append-only) + GCS bucket mirror (bucket is source of truth if LOG_BUCKET set)
        STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(STORE_PATH, "a", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")
        # Also mirror to GCS bucket if configured
        try:
            from tools.gcs_tools import upload_jsonl_to_bucket, get_log_bucket, upload_blob_text
            bucket = get_log_bucket()
            if bucket:
                # Full incident JSON per incident
                blob_name = f"incidents/{record.incident_id}.json"
                upload_blob_text(bucket, blob_name, record.model_dump_json(indent=2), content_type="application/json")
                # Append to central memory JSONL in bucket
                upload_jsonl_to_bucket(bucket, "incidents/memory.jsonl", record.model_dump())
        except Exception as e:
            logger.warning(f"Bucket memory mirror failed: {e}")
        return str(STORE_PATH)

    def load_all(self):
        if not STORE_PATH.exists():
            return []
        records = []
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
        return records

    def get(self, incident_id: str) -> Optional[dict]:
        for r in self.load_all():
            if r.get("incident_id")==incident_id:
                return r
        return None
