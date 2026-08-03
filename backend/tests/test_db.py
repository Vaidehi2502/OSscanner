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
