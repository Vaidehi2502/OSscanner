"""SQLite helpers for persisting scan reports."""
import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with open(SCHEMA_PATH) as f:
        schema = f.read()
    conn = get_connection()
    try:
        conn.executescript(schema)
        conn.commit()
    finally:
        conn.close()


def save_report(report):
    """Persist an analyzer report and its findings. Returns the new scan id."""
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO scans (started_at, finished_at, risk_score, risk_level, total_findings, report_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                report["generated_at"],
                datetime.now(timezone.utc).isoformat(),
                report["risk_score"],
                report["risk_level"],
                report["total_findings"],
                json.dumps(report),
            ),
        )
        scan_id = cur.lastrowid

        for finding in report["findings"]:
            conn.execute(
                """INSERT INTO findings (scan_id, scanner, severity, title, description, evidence_json)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    finding.get("scanner", ""),
                    finding.get("severity", "low"),
                    finding.get("title", ""),
                    finding.get("description", ""),
                    json.dumps(finding.get("evidence", {})),
                ),
            )

        conn.commit()
        return scan_id
    finally:
        conn.close()


def list_scans(limit=20):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, started_at, finished_at, risk_score, risk_level, total_findings "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_scan(scan_id):
    conn = get_connection()
    try:
        row = conn.execute("SELECT report_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return json.loads(row["report_json"]) if row else None
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Initialized database at {DB_PATH}")
