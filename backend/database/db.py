"""SQLite helpers for persisting scan reports."""
import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

# Ordered best-to-worst; index comparison lets record_file_reputation only
# ever ratchet a hash's stored risk up, never down.
RISK_ORDER = ["none", "low", "medium", "high", "critical"]


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
        _migrate(conn)
    finally:
        conn.close()


def migrate():
    """Patch an already-existing database file up to the current schema.

    init_db()'s CREATE TABLE IF NOT EXISTS never touches a table that
    already exists, so a scans.db created before a column was added (e.g.
    scan_type) needs this run separately against it.
    """
    conn = get_connection()
    try:
        _migrate(conn)
    finally:
        conn.close()


def _migrate(conn):
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
    if "scan_type" not in columns:
        conn.execute("ALTER TABLE scans ADD COLUMN scan_type TEXT NOT NULL DEFAULT 'full'")
        conn.commit()

    # CREATE TABLE IF NOT EXISTS is idempotent, so re-running the whole
    # schema here is a cheap way to add tables (e.g. quarantine,
    # realtime_events) introduced after a scans.db file already existed,
    # without a dedicated ALTER step per table.
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    conn.commit()


def save_report(report, scan_type="full"):
    """Persist an analyzer report and its findings. Returns the new scan id."""
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO scans (started_at, finished_at, risk_score, risk_level, total_findings, report_json, scan_type)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                report["generated_at"],
                datetime.now(timezone.utc).isoformat(),
                report["risk_score"],
                report["risk_level"],
                report["total_findings"],
                json.dumps(report),
                scan_type,
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
            "SELECT id, started_at, finished_at, risk_score, risk_level, total_findings, scan_type "
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
        if row is None:
            return None
        report = json.loads(row["report_json"])
        report["scan_id"] = scan_id
        return report
    finally:
        conn.close()


def save_quarantine_item(original_path, quarantine_path, sha256, severity, risk_score, findings):
    """Record a file real-time protection moved into quarantine. Returns the new row id."""
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO quarantine
                   (detected_at, original_path, quarantine_path, sha256, severity, risk_score, findings_json, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'quarantined')""",
            (
                datetime.now(timezone.utc).isoformat(),
                original_path,
                quarantine_path,
                sha256,
                severity,
                risk_score,
                json.dumps(findings),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def _load_findings(row):
    item = dict(row)
    item["findings"] = json.loads(item.pop("findings_json") or "[]")
    return item


def list_quarantine(status=None, limit=100):
    conn = get_connection()
    try:
        if status:
            rows = conn.execute(
                "SELECT * FROM quarantine WHERE status = ? ORDER BY id DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM quarantine ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_load_findings(row) for row in rows]
    finally:
        conn.close()


def get_quarantine_item(item_id):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM quarantine WHERE id = ?", (item_id,)).fetchone()
        return _load_findings(row) if row else None
    finally:
        conn.close()


def set_quarantine_status(item_id, status):
    conn = get_connection()
    try:
        conn.execute("UPDATE quarantine SET status = ? WHERE id = ?", (status, item_id))
        conn.commit()
    finally:
        conn.close()


def save_realtime_event(path, sha256, severity, risk_score, findings, quarantined, quarantine_id=None):
    """Record a real-time protection detection. Returns the new row id."""
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO realtime_events
                   (detected_at, path, sha256, severity, risk_score, findings_json, quarantined, quarantine_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                path,
                sha256,
                severity,
                risk_score,
                json.dumps(findings),
                1 if quarantined else 0,
                quarantine_id,
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_realtime_events(limit=50):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM realtime_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_load_findings(row) for row in rows]
    finally:
        conn.close()


def save_network_threat_event(remote_ip, remote_port, local_port, pid, severity, title, description, evidence):
    """Record a network threat detection event. Returns the new row id."""
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO network_threat_events
                   (detected_at, remote_ip, remote_port, local_port, pid, severity, title, description, evidence_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                remote_ip,
                remote_port,
                local_port,
                pid,
                severity,
                title,
                description,
                json.dumps(evidence),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_network_threat_events(limit=50):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM network_threat_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["evidence"] = json.loads(item.pop("evidence_json") or "{}")
            results.append(item)
        return results
    finally:
        conn.close()


def record_file_reputation(sha256, severity=None):
    """Record that a file with this hash was observed, optionally flagged
    at `severity` (None means this particular observation was clean).

    First sighting: inserts a row with first_seen == last_seen and
    detection_count 1 if severity else 0. Later sightings: bumps
    last_seen, adds 1 to detection_count only if severity is given, and
    raises risk to severity if that's worse than what's stored - a later
    clean re-scan never lowers a hash's risk. Returns the resulting row,
    or None if sha256 is falsy.
    """
    if not sha256:
        return None

    now = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM file_reputation WHERE hash = ?", (sha256,)).fetchone()
        if row is None:
            conn.execute(
                """INSERT INTO file_reputation (hash, first_seen, last_seen, detection_count, risk)
                   VALUES (?, ?, ?, ?, ?)""",
                (sha256, now, now, 1 if severity else 0, severity or "none"),
            )
        else:
            detection_count = row["detection_count"] + (1 if severity else 0)
            risk = row["risk"]
            if severity and RISK_ORDER.index(severity) > RISK_ORDER.index(risk):
                risk = severity
            conn.execute(
                "UPDATE file_reputation SET last_seen = ?, detection_count = ?, risk = ? WHERE hash = ?",
                (now, detection_count, risk, sha256),
            )
        conn.commit()
        return dict(conn.execute("SELECT * FROM file_reputation WHERE hash = ?", (sha256,)).fetchone())
    finally:
        conn.close()


def get_file_reputation(sha256):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM file_reputation WHERE hash = ?", (sha256,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_file_reputation(limit=100):
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT * FROM file_reputation ORDER BY
                   CASE risk WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
                   last_seen DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Initialized database at {DB_PATH}")
