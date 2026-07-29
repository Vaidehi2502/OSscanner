"""Scans common dropper locations for recently modified or executable files."""
import os
import stat
import time

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from utils.hashing import hash_file  # noqa: E402

WATCHED_DIRS = ["/tmp", "/var/tmp", "/dev/shm"]
RECENT_SECONDS = 24 * 60 * 60


def _is_executable(path):
    try:
        mode = os.stat(path).st_mode
        return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except OSError:
        return False


def scan():
    findings = []
    now = time.time()

    for directory in WATCHED_DIRS:
        if not os.path.isdir(directory):
            continue

        for root, _, files in os.walk(directory):
            for name in files:
                path = os.path.join(root, name)
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue

                recent = (now - mtime) <= RECENT_SECONDS
                executable = _is_executable(path)

                if executable and recent:
                    findings.append({
                        "scanner": "file_scanner",
                        "severity": "high",
                        "title": f"Recently modified executable in {directory}",
                        "description": "A world-writable location contains an executable modified in the last 24h.",
                        "evidence": {"path": path, "mtime": mtime, "sha256": hash_file(path)},
                    })
                elif executable:
                    findings.append({
                        "scanner": "file_scanner",
                        "severity": "low",
                        "title": f"Executable file present in {directory}",
                        "description": "Temp/shared-memory directories should not typically contain executables.",
                        "evidence": {"path": path, "mtime": mtime, "sha256": hash_file(path)},
                    })

    return findings


if __name__ == "__main__":
    for finding in scan():
        print(finding)
