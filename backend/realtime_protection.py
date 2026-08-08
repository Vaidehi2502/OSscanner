"""Real-time file protection: watches high-risk directories for newly
created files and immediately hashes, YARA-scans, and heuristically checks
each one, quarantining anything with a high/critical finding.

Pipeline per new file: SHA256 -> YARA -> heuristic -> score -> quarantine.
"AI" here is the same rule-based scorer used by the rest of the app
(ai/analyzer.py is templated, not a model call - see README) rather than a
separate model.

Off by default - see README / backend/.env.example. Enable with
REALTIME_PROTECTION=1.
"""
import os
import queue
import shutil
import stat
import threading
import time
import uuid

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAVE_WATCHDOG = True
except ImportError:
    HAVE_WATCHDOG = False

from database import db
from scanners import yara_scanner
from utils.hashing import hash_file
from utils.score import SEVERITY_WEIGHTS, score_findings

QUARANTINE_DIR = os.path.join(os.path.dirname(__file__), "quarantine_store")

# Highest-risk drop zones: browser downloads, common user document dirs,
# and world-writable temp locations. Removable media (USB drives) is
# discovered dynamically - see _discover_removable_mounts.
DEFAULT_WATCH_DIRS = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Documents"),
    "/tmp",
    "/dev/shm",
]
REMOVABLE_MEDIA_PREFIXES = ("/media", "/run/media", "/mnt")
MOUNT_POLL_SECONDS = 10

# Give a file a moment to finish writing before hashing/scanning it, so an
# in-progress download isn't read (and possibly quarantined) mid-write.
SETTLE_CHECKS = 3
SETTLE_INTERVAL_SECONDS = 1.0

# A single YARA/heuristic finding at this severity is enough to quarantine
# the file it belongs to - unlike the aggregate 0-100 risk score (tuned for
# a whole-system scan's worth of findings), a real-time decision is about
# one file, so it's driven by the worst individual finding, not a sum.
QUARANTINE_SEVERITIES = {"high", "critical"}

_lock = threading.Lock()
_observer = None
_watched_paths = set()
_event_queue = queue.Queue()
_rules_cache = "unset"
_STARTED = False


def _is_executable(mode):
    return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _get_yara_rules():
    # Cached (including a cached "unavailable" result) so a busy watched
    # directory doesn't recompile the ruleset on every single new file.
    global _rules_cache
    if _rules_cache == "unset":
        _rules_cache = yara_scanner._compile_rules()
    return _rules_cache


def _max_severity(findings):
    if not findings:
        return None
    return max(findings, key=lambda f: SEVERITY_WEIGHTS.get(f.get("severity", "low"), 0))["severity"]


def _wait_until_settled(path):
    """Poll file size until it stops changing. Returns False if the file
    disappeared (e.g. a browser's temp download file got renamed away)."""
    last_size = -1
    for _ in range(SETTLE_CHECKS):
        try:
            size = os.stat(path).st_size
        except OSError:
            return False
        if size == last_size:
            return True
        last_size = size
        time.sleep(SETTLE_INTERVAL_SECONDS)
    return True


def assess_file(path):
    """Hash + YARA + executable-heuristic a single file.

    Returns (sha256, findings). findings is empty for a clean/unreadable
    file; sha256 is None if the file couldn't be hashed.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None, []
    if not stat.S_ISREG(st.st_mode):
        return None, []

    sha256 = hash_file(path)
    findings = []

    rules = _get_yara_rules()
    if rules is not None and st.st_size <= yara_scanner.MAX_FILE_SIZE:
        try:
            matches = rules.match(path)
        except Exception:
            matches = []
        for match in matches:
            findings.append({
                "scanner": "yara_scanner",
                "severity": match.meta.get("severity", "high"),
                "title": f"YARA match: {match.rule}",
                "description": match.meta.get("description", "File matched a YARA detection rule."),
                "evidence": {"path": path, "rule": match.rule, "tags": list(match.tags)},
            })

    if _is_executable(st.st_mode):
        findings.append({
            "scanner": "realtime_protection",
            "severity": "medium",
            "title": "New executable file dropped",
            "description": "A file created in a real-time-protected location is executable.",
            "evidence": {"path": path, "mtime": st.st_mtime},
        })

    return sha256, findings


def _quarantine_file(path, sha256, severity, score, findings):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    dest = os.path.join(QUARANTINE_DIR, f"{uuid.uuid4().hex}_{os.path.basename(path)}")
    try:
        # shutil.move (not os.rename) since the source may be on a
        # different filesystem than QUARANTINE_DIR (tmpfs /dev/shm, a USB
        # mount, ...), which a plain rename can't cross.
        shutil.move(path, dest)
        os.chmod(dest, 0o000)
    except OSError as exc:
        print(f"WARNING: failed to quarantine {path}: {exc}")
        return None
    return db.save_quarantine_item(path, dest, sha256, severity, score, findings)


def restore_quarantine_item(item_id):
    """Move a quarantined file back to where it was found. Raises
    ValueError if the item isn't currently quarantined, or FileExistsError
    if something now occupies the original path."""
    item = db.get_quarantine_item(item_id)
    if item is None:
        return None
    if item["status"] != "quarantined":
        raise ValueError(f"quarantine item {item_id} is not currently quarantined (status={item['status']})")
    if os.path.exists(item["original_path"]):
        raise FileExistsError(f"original path is occupied: {item['original_path']}")

    os.makedirs(os.path.dirname(item["original_path"]), exist_ok=True)
    os.chmod(item["quarantine_path"], 0o644)
    shutil.move(item["quarantine_path"], item["original_path"])
    db.set_quarantine_status(item_id, "restored")
    item["status"] = "restored"
    return item


def delete_quarantine_item(item_id):
    """Permanently delete a quarantined file. Raises ValueError if the item
    isn't currently quarantined."""
    item = db.get_quarantine_item(item_id)
    if item is None:
        return None
    if item["status"] != "quarantined":
        raise ValueError(f"quarantine item {item_id} is not currently quarantined (status={item['status']})")

    try:
        os.remove(item["quarantine_path"])
    except FileNotFoundError:
        pass
    db.set_quarantine_status(item_id, "deleted")
    item["status"] = "deleted"
    return item


def _handle_candidate(path):
    if not _wait_until_settled(path):
        return

    sha256, findings = assess_file(path)
    severity = _max_severity(findings)
    if sha256:
        # Every settled file gets a reputation sighting, clean or not -
        # first_seen/last_seen track how long a hash has been seen around,
        # not just the ones that ended up flagged.
        db.record_file_reputation(sha256, severity)
    if not findings:
        return  # clean file - nothing worth recording

    score = score_findings(findings)

    quarantine_id = None
    if severity in QUARANTINE_SEVERITIES:
        quarantine_id = _quarantine_file(path, sha256, severity, score, findings)

    db.save_realtime_event(path, sha256, severity, score, findings, quarantine_id is not None, quarantine_id)


def _worker_loop():
    while True:
        path = _event_queue.get()
        try:
            _handle_candidate(path)
        except Exception as exc:
            print(f"WARNING: real-time protection failed on {path}: {exc}")


if HAVE_WATCHDOG:
    class _NewFileHandler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                _event_queue.put(event.src_path)

        def on_moved(self, event):
            # Covers browser-style downloads that write to a temp name
            # (e.g. file.crdownload) and rename to the final name on
            # completion - on_created alone would only see the temp file.
            if not event.is_directory:
                _event_queue.put(event.dest_path)

    _handler = _NewFileHandler()


def _resolve_watch_dirs():
    raw = os.environ.get("REALTIME_WATCH_DIRS", "")
    if raw.strip():
        return [d.strip() for d in raw.split(",") if d.strip()]
    return list(DEFAULT_WATCH_DIRS)


def _discover_removable_mounts():
    mounts = set()
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                mountpoint = parts[1]
                if mountpoint.startswith(REMOVABLE_MEDIA_PREFIXES):
                    mounts.add(mountpoint)
    except OSError:
        pass
    return mounts


def _add_watch(path):
    if not os.path.isdir(path) or path in _watched_paths:
        return
    try:
        _observer.schedule(_handler, path, recursive=True)
        _watched_paths.add(path)
        print(f"Real-time protection: watching {path}")
    except OSError as exc:
        print(f"WARNING: real-time protection could not watch {path}: {exc}")


def _mount_poll_loop():
    while True:
        for mountpoint in _discover_removable_mounts():
            _add_watch(mountpoint)
        time.sleep(MOUNT_POLL_SECONDS)


def start(watch_dirs=None):
    """Start real-time file protection if configured. Idempotent - safe to
    call unconditionally at app startup. Returns whether it's (now, or
    already) running.

    `watch_dirs`, if given, overrides REALTIME_PROTECTION/REALTIME_WATCH_DIRS
    and force-enables regardless of environment (used by tests).
    """
    global _observer, _STARTED

    if watch_dirs is None:
        if os.environ.get("REALTIME_PROTECTION", "0") != "1":
            return False
        watch_dirs = _resolve_watch_dirs()

    if not HAVE_WATCHDOG:
        print("WARNING: watchdog is not installed - real-time protection cannot start (pip install watchdog).")
        return False

    with _lock:
        if _STARTED:
            return True

        os.makedirs(QUARANTINE_DIR, exist_ok=True)

        _observer = Observer()
        for path in watch_dirs:
            _add_watch(path)
        for mountpoint in _discover_removable_mounts():
            _add_watch(mountpoint)
        _observer.start()

        threading.Thread(target=_worker_loop, daemon=True).start()
        threading.Thread(target=_mount_poll_loop, daemon=True).start()

        _STARTED = True

    print(f"Real-time protection enabled: watching {sorted(_watched_paths)}")
    return True


def status():
    return {"enabled": _STARTED, "watched_paths": sorted(_watched_paths)}
