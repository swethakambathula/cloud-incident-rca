from pathlib import Path

from fastapi.testclient import TestClient


def test_sample_upload_can_conclude_analysis(tmp_path, monkeypatch):
    from app.main import app
    from ingestion import upload_handler
    from projects import store
    from orchestration import analysis_sessions, incident_registry

    monkeypatch.setattr(upload_handler, 'BASE', str(tmp_path / 'uploads'))
    analysis_store = store.AnalysisStore(str(tmp_path / 'analyses.jsonl'))
    monkeypatch.setattr(store, 'AnalysisStore', lambda: analysis_store)
    session_store = analysis_sessions.AnalysisSessionStore(str(tmp_path / 'sessions.json'))
    monkeypatch.setattr(analysis_sessions, 'AnalysisSessionStore', lambda: session_store)
    monkeypatch.setattr(incident_registry, 'record_activity', lambda *a, **kw: None)
    sample = Path(__file__).resolve().parents[1] / 'data/test_logs/checkout_config_regression.jsonl'
    client = TestClient(app)
    upload = client.post('/api/logs/upload', files={'files': (sample.name, sample.read_bytes(), 'application/x-ndjson')})
    assert upload.status_code == 200, upload.text
    aid = upload.json()['analysis_id']
    result = client.post(f'/api/logs/{aid}/analyze?mode=analyze_only')
    assert result.status_code == 200, result.text
    data = result.json()
    assert data['root_cause']
    assert data['record_count'] == 20
    assert data['files'] == [sample.name]
    saved = client.get(f'/api/log-analyses/{aid}').json()
    assert saved['rca']['root_cause'] == data['root_cause']
