CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    total_findings INTEGER,
    report_json TEXT,
    scan_type TEXT NOT NULL DEFAULT 'full'
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);

-- Files moved aside by real-time protection. status is one of
-- 'quarantined' (still isolated), 'restored' (moved back to original_path),
-- or 'deleted' (permanently removed from quarantine_path).
CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at TEXT NOT NULL,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    sha256 TEXT,
    severity TEXT NOT NULL,
    risk_score INTEGER,
    findings_json TEXT,
    status TEXT NOT NULL DEFAULT 'quarantined'
);

-- One row per file real-time protection flagged (i.e. produced at least one
-- finding for) - a lighter-weight, single-file counterpart to the `scans`
-- table, for the dashboard's live detection feed.
CREATE TABLE IF NOT EXISTS realtime_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT,
    severity TEXT NOT NULL,
    risk_score INTEGER,
    findings_json TEXT,
    quarantined INTEGER NOT NULL DEFAULT 0,
    quarantine_id INTEGER REFERENCES quarantine(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_realtime_events_detected_at ON realtime_events(detected_at);

-- One row per connection network threat detection flagged: a match against
-- a known-malicious IP/port, a new external connection, or a suspected
-- port scan. Detection-only - there is no quarantine/blocking counterpart
-- here (see network_threat_detection.py).
CREATE TABLE IF NOT EXISTS network_threat_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at TEXT NOT NULL,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER,
    local_port INTEGER,
    pid INTEGER,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_network_threat_events_detected_at ON network_threat_events(detected_at);

-- One row per distinct file hash ever observed (by real-time protection or
-- a full/AV scan's file_scanner), tracking how long it's been seen around
-- and the worst severity it's ever been flagged at. risk is 'none' until
-- the hash is flagged at least once, then only ever ratchets up (see
-- db.RISK_ORDER) - a later clean re-scan doesn't erase a past detection.
CREATE TABLE IF NOT EXISTS file_reputation (
    hash TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    detection_count INTEGER NOT NULL DEFAULT 0,
    risk TEXT NOT NULL DEFAULT 'none'
);

CREATE INDEX IF NOT EXISTS idx_file_reputation_risk ON file_reputation(risk);
