"""
Historical incident retrieval - structured similarity heuristics.
"""
from typing import List, Dict, Any

def _score(record: Dict, service: str, symptoms: List[str], category: str) -> float:
    score = 0.0
    if record.get("service")==service:
        score += 0.4
    if record.get("root_cause_category")==category:
        score += 0.4
    # symptom overlap
    rec_symptoms = " ".join(record.get("symptoms",[])).lower()
    overlap = sum(1 for s in symptoms if s.lower() in rec_symptoms)
    score += 0.2 * (overlap / max(1, len(symptoms)))
    return score

def find_similar_incidents(service: str, symptoms: List[str], root_cause_category: str, limit: int=5, store=None) -> List[Dict]:
    if store is None:
        from .store import MemoryStore
        store = MemoryStore(use_bigquery=False)
    all_recs = store.load_all()
    scored = [(r, _score(r, service, symptoms, root_cause_category)) for r in all_recs]
    scored.sort(key=lambda x: x[1], reverse=True)
    # Filter low scores
    filtered = [r for r,s in scored if s>0.2][:limit]
    return filtered
