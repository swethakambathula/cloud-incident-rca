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
        # File fallback (append-only)
        STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(STORE_PATH, "a", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")
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
