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
