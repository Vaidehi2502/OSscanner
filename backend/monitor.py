"""Optional background thread that runs and persists a scan on a fixed
interval, so history builds up automatically instead of only on manual
POST /api/scan calls.

Off by default. Enable by setting MONITOR_INTERVAL_SECONDS to a positive
integer (see README / backend/.env.example).
"""
import os
import threading
import time

import scan_service

_STARTED = False
_STARTED_INTERVAL = 0
_lock = threading.Lock()


def _run_once_safely():
    try:
        scan_service.run_and_persist_scan()
    except Exception as exc:
        # A single bad scan (e.g. a transient scanner error) shouldn't
        # kill background monitoring for the rest of the process.
        print(f"WARNING: background monitor scan failed: {exc}")


def _loop(interval_seconds):
    while True:
        time.sleep(interval_seconds)
        _run_once_safely()


def start(interval_seconds=None):
    """Start the background monitor thread if configured. Idempotent -
    safe to call unconditionally at app startup; a second call is a no-op.
    Returns whether the monitor is (now, or already) running.
    """
    global _STARTED, _STARTED_INTERVAL

    if interval_seconds is None:
        raw = os.environ.get("MONITOR_INTERVAL_SECONDS", "")
        try:
            interval_seconds = int(raw) if raw.strip() else 0
        except ValueError:
            interval_seconds = 0

    if interval_seconds <= 0:
        return False

    with _lock:
        if _STARTED:
            return True
        threading.Thread(target=_loop, args=(interval_seconds,), daemon=True).start()
        _STARTED = True
        _STARTED_INTERVAL = interval_seconds

    print(f"Live monitoring enabled: scanning every {interval_seconds}s in the background.")
    return True


def status():
    return {"enabled": _STARTED, "interval_seconds": _STARTED_INTERVAL}
