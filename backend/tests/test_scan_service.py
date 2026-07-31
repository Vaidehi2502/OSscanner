"""Tests for the shared run-and-persist pipeline used by both the
POST /api/scan route and the background monitor.
"""
import scan_service


def test_run_and_persist_scan_saves_and_returns_scan_id_and_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service.db, "DB_PATH", str(tmp_path / "scans.db"))
    scan_service.db.init_db()
    monkeypatch.setattr(
        scan_service,
        "run_all",
        lambda: [{"scanner": "x", "severity": "high", "title": "t", "description": "d"}],
    )

    report = scan_service.run_and_persist_scan()

    assert isinstance(report["scan_id"], int)
    assert report["summary"]

    stored = scan_service.db.get_scan(report["scan_id"])
    assert stored["scan_id"] == report["scan_id"]
    assert stored["summary"] == report["summary"]
