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
