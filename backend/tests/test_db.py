"""Tests for database/db.py, focused on the scan_type migration path -
everything else is already exercised indirectly via test_scan_service.py
and test_app.py.
"""
import sqlite3

from database import db


def _create_pre_migration_schema(path):
    """Build a scans table as it looked before scan_type was added, so
    migrate() has something real to patch.
    """
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            total_findings INTEGER,
            report_json TEXT
        )"""
    )
    conn.execute(
        "INSERT INTO scans (started_at, finished_at, risk_score, risk_level, total_findings, report_json) "
        "VALUES ('2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 10, 'low', 0, '{}')"
    )
    conn.commit()
    conn.close()


def test_migrate_adds_scan_type_column_to_pre_existing_db(tmp_path, monkeypatch):
    db_path = tmp_path / "scans.db"
    _create_pre_migration_schema(str(db_path))
    monkeypatch.setattr(db, "DB_PATH", str(db_path))

    db.migrate()

    scans = db.list_scans()
    assert len(scans) == 1
    assert scans[0]["scan_type"] == "full"


def test_migrate_is_a_no_op_on_an_already_current_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "scans.db"))
    db.init_db()

    db.migrate()  # should not raise (e.g. by trying to add a duplicate column)

    assert db.list_scans() == []


# --- record_file_reputation / get_file_reputation / list_file_reputation --

def _fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "scans.db"))
    db.init_db()


def test_record_file_reputation_returns_none_for_a_falsy_hash(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    assert db.record_file_reputation(None) is None
    assert db.record_file_reputation("") is None


def test_first_sighting_of_a_clean_file_has_zero_detections_and_none_risk(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)

    entry = db.record_file_reputation("abc123")

    assert entry["hash"] == "abc123"
    assert entry["first_seen"] == entry["last_seen"]
    assert entry["detection_count"] == 0
    assert entry["risk"] == "none"


def test_first_sighting_with_a_severity_counts_as_a_detection(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)

    entry = db.record_file_reputation("abc123", "high")

    assert entry["detection_count"] == 1
    assert entry["risk"] == "high"


def test_later_sighting_bumps_last_seen_and_detection_count(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    first = db.record_file_reputation("abc123", "medium")

    second = db.record_file_reputation("abc123", "medium")

    assert second["first_seen"] == first["first_seen"]
    assert second["detection_count"] == 2
    assert second["risk"] == "medium"


def test_a_clean_later_sighting_does_not_add_a_detection_or_change_risk(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    db.record_file_reputation("abc123", "high")

    entry = db.record_file_reputation("abc123")  # re-scanned clean this time

    assert entry["detection_count"] == 1  # unchanged
    assert entry["risk"] == "high"  # unchanged


def test_risk_only_ratchets_up_never_down(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    db.record_file_reputation("abc123", "critical")

    entry = db.record_file_reputation("abc123", "low")  # a weaker finding later

    assert entry["risk"] == "critical"  # not downgraded to low
    assert entry["detection_count"] == 2  # still counted as a detection


def test_get_file_reputation_returns_none_for_unknown_hash(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    assert db.get_file_reputation("nope") is None


def test_get_file_reputation_returns_the_stored_row(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    db.record_file_reputation("abc123", "critical")

    entry = db.get_file_reputation("abc123")

    assert entry["hash"] == "abc123"
    assert entry["risk"] == "critical"


def test_list_file_reputation_orders_worst_risk_first(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    db.record_file_reputation("low-hash", "low")
    db.record_file_reputation("critical-hash", "critical")
    db.record_file_reputation("clean-hash")
    db.record_file_reputation("high-hash", "high")

    entries = db.list_file_reputation()

    assert [e["hash"] for e in entries] == ["critical-hash", "high-hash", "low-hash", "clean-hash"]
