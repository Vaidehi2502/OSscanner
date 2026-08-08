import pytest

import app as app_module


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module.db, "DB_PATH", str(tmp_path / "scans.db"))
    # Baseline: no API key configured, regardless of the host environment,
    # so tests are deterministic and auth-specific tests can opt in explicitly.
    monkeypatch.delenv("API_KEY", raising=False)
    app_module.db.init_db()
    app_module.app.testing = True
    return app_module.app.test_client()


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_get_unknown_scan_returns_404(client):
    resp = client.get("/api/scans/999")
    assert resp.status_code == 404


def test_list_scans_starts_empty(client):
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_cors_allows_known_frontend_origin(client):
    resp = client.get("/api/health", headers={"Origin": "http://localhost:3000"})
    assert resp.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"


def test_cors_rejects_arbitrary_origin(client):
    # A malicious/unrelated site should not get an Access-Control-Allow-Origin
    # header back - without it, the browser blocks the site's JS from
    # reading the response even though the request itself still goes through.
    resp = client.get("/api/health", headers={"Origin": "http://evil.example"})
    assert "Access-Control-Allow-Origin" not in resp.headers


def test_requests_unauthenticated_when_no_api_key_configured(client):
    # Documents the opt-in nature of auth: with no API_KEY set (the
    # fixture's baseline), endpoints work without any header at all.
    resp = client.get("/api/scans")
    assert resp.status_code == 200


def test_requires_api_key_when_configured(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "test-secret-key")
    resp = client.get("/api/scans")
    assert resp.status_code == 401


def test_accepts_correct_api_key(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "test-secret-key")
    resp = client.get("/api/scans", headers={"X-API-Key": "test-secret-key"})
    assert resp.status_code == 200


def test_rejects_wrong_api_key(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "test-secret-key")
    resp = client.get("/api/scans", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401


def test_health_accessible_without_api_key_even_when_configured(client, monkeypatch):
    # The health check is deliberately public even when auth is enabled,
    # so monitoring/liveness checks don't need a key.
    monkeypatch.setenv("API_KEY", "test-secret-key")
    resp = client.get("/api/health")
    assert resp.status_code == 200


def test_monitor_status_disabled_by_default(client):
    # monitor.start() is only ever called from app.py's __main__ block, so
    # importing/testing the app module never actually starts the thread.
    resp = client.get("/api/monitor")
    assert resp.status_code == 200
    assert resp.get_json() == {"enabled": False, "interval_seconds": 0}


def test_monitor_status_requires_api_key_when_configured(client, monkeypatch):
    # /api/monitor is under /api/* like everything except /api/health.
    monkeypatch.setenv("API_KEY", "test-secret-key")
    resp = client.get("/api/monitor")
    assert resp.status_code == 401


def test_run_scan_response_includes_scan_id_and_summary(client, monkeypatch):
    monkeypatch.setattr(
        app_module.scan_service,
        "run_all",
        lambda: [{"scanner": "x", "severity": "high", "title": "t", "description": "d"}],
    )
    resp = client.post("/api/scan")
    assert resp.status_code == 200
    body = resp.get_json()
    assert isinstance(body["scan_id"], int)
    assert body["summary"]


def test_run_av_scan_only_runs_file_and_yara_scanners(client, monkeypatch):
    calls = []

    def fake_run_selected(names):
        calls.append(tuple(names))
        return [{"scanner": "yara_scanner", "severity": "high", "title": "t", "description": "d"}]

    monkeypatch.setattr(app_module.scan_service, "run_selected", fake_run_selected)

    resp = client.post("/api/scan/av")
    assert resp.status_code == 200
    body = resp.get_json()
    assert calls == [("file", "yara")]
    assert body["scan_type"] == "av"
    assert isinstance(body["scan_id"], int)


def test_list_scans_includes_scan_type(client, monkeypatch):
    monkeypatch.setattr(
        app_module.scan_service,
        "run_all",
        lambda: [{"scanner": "x", "severity": "high", "title": "t", "description": "d"}],
    )
    client.post("/api/scan")

    scans = client.get("/api/scans").get_json()
    assert scans[0]["scan_type"] == "full"


def test_realtime_status_disabled_by_default(client):
    # realtime_protection.start() is only ever called from app.py's __main__
    # block, so importing/testing the app module never actually starts it.
    resp = client.get("/api/realtime/status")
    assert resp.status_code == 200
    assert resp.get_json() == {"enabled": False, "watched_paths": []}


def test_network_threat_status_disabled_by_default(client):
    # Same reasoning as realtime protection above: network_threat_detection
    # .start() only ever runs from app.py's __main__ block.
    resp = client.get("/api/network/status")
    assert resp.status_code == 200
    assert resp.get_json() == {"enabled": False, "poll_seconds": 0}


def test_network_threat_events_starts_empty(client):
    resp = client.get("/api/network/events")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_reputation_list_starts_empty(client):
    resp = client.get("/api/reputation")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_reputation_lookup_returns_404_for_unknown_hash(client):
    resp = client.get("/api/reputation/does-not-exist")
    assert resp.status_code == 404


def test_reputation_lookup_returns_the_stored_entry(client):
    app_module.db.record_file_reputation("abc123", "critical")

    resp = client.get("/api/reputation/abc123")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["hash"] == "abc123"
    assert body["risk"] == "critical"
    assert body["detection_count"] == 1


def test_network_threat_events_reflects_persisted_events(client):
    app_module.db.save_network_threat_event(
        "198.51.100.1", 4444, 51000, 123, "critical",
        "Connection to known-malicious port 4444/198.51.100.1", "test", {"remote_ip": "198.51.100.1"},
    )

    resp = client.get("/api/network/events")
    assert resp.status_code == 200
    events = resp.get_json()
    assert len(events) == 1
    assert events[0]["remote_ip"] == "198.51.100.1"
    assert events[0]["severity"] == "critical"


def test_realtime_events_starts_empty(client):
    resp = client.get("/api/realtime/events")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_quarantine_list_starts_empty(client):
    resp = client.get("/api/quarantine")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_restore_unknown_quarantine_item_returns_404(client):
    resp = client.post("/api/quarantine/999/restore")
    assert resp.status_code == 404


def test_delete_unknown_quarantine_item_returns_404(client):
    resp = client.delete("/api/quarantine/999")
    assert resp.status_code == 404


def test_restore_quarantine_item_via_api(client, monkeypatch, tmp_path):
    monkeypatch.setattr(app_module.realtime_protection, "QUARANTINE_DIR", str(tmp_path / "quarantine_store"))
    src = tmp_path / "shell.php"
    src.write_text('<?php system($_POST["cmd"]); ?>')
    monkeypatch.setattr(app_module.realtime_protection, "SETTLE_INTERVAL_SECONDS", 0)

    app_module.realtime_protection._handle_candidate(str(src))
    item_id = app_module.db.list_quarantine()[0]["id"]

    resp = client.post(f"/api/quarantine/{item_id}/restore")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "restored"
    assert src.exists()


def test_get_scan_returns_the_same_scan_id_and_summary_as_the_original_run(client, monkeypatch):
    # Regression test: report_json is persisted before scan_id is known and
    # before summarize() ran, so a naive get_scan() would silently drop both
    # fields for every historical scan fetched after the fact.
    monkeypatch.setattr(
        app_module.scan_service,
        "run_all",
        lambda: [{"scanner": "x", "severity": "high", "title": "t", "description": "d"}],
    )
    posted = client.post("/api/scan").get_json()

    fetched = client.get(f"/api/scans/{posted['scan_id']}").get_json()
    assert fetched["scan_id"] == posted["scan_id"]
    assert fetched["summary"] == posted["summary"]
