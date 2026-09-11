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

    import app.main as dashboard
    import json
    registry = incident_registry.IncidentRegistry(str(tmp_path / 'incidents.json'))
    monkeypatch.setattr(dashboard, '_registry', lambda: registry)
    monkeypatch.setattr(dashboard, 'SIMULATED_LOGS', [{'scenario': 'other', 'message': 'unrelated'}])
    replay = client.post(f'/api/logs/{aid}/analyze?mode=replay')
    assert replay.status_code == 200, replay.text
    result = replay.json()
    assert result['source'] == 'SIMULATION'
    assert result['replayed_records'] == 20
    assert result['root_cause_category'] == 'configuration_regression'
    assert registry.get(result['incident_id'])['source'] == 'SIMULATION'
    original = [json.loads(line) for line in sample.read_text().splitlines()]
    streamed = [r for r in dashboard.SIMULATED_LOGS if r.get('analysis_id') == aid]
    assert [r['message'] for r in streamed] == [r['message'] for r in original]
    assert [r['severity'] for r in streamed] == [r['severity'] for r in original]
    assert len(dashboard.SIMULATED_LOGS) == 21
    repeated = client.post(f'/api/logs/{aid}/analyze?mode=replay')
    assert repeated.status_code == 200
    assert len(dashboard.SIMULATED_LOGS) == 21
