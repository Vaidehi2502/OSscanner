import pytest

import app as app_module


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module.db, "DB_PATH", str(tmp_path / "scans.db"))
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
