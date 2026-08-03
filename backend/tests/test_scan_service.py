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
    assert report["scan_type"] == "full"


def test_run_and_persist_av_scan_runs_only_file_and_yara_scanners(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service.db, "DB_PATH", str(tmp_path / "scans.db"))
    scan_service.db.init_db()

    calls = []

    def fake_run_selected(names):
        calls.append(tuple(names))
        return [{"scanner": "yara_scanner", "severity": "high", "title": "t", "description": "d"}]

    monkeypatch.setattr(scan_service, "run_selected", fake_run_selected)

    report = scan_service.run_and_persist_av_scan()

    assert calls == [("file", "yara")]
    assert report["scan_type"] == "av"
    assert isinstance(report["scan_id"], int)

    stored = scan_service.db.get_scan(report["scan_id"])
    assert stored["scan_type"] == "av"
