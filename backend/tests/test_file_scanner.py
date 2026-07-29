"""Tests for file_scanner.py's dropper-detection logic.

Uses real temp files (WATCHED_DIRS monkeypatched to a tmp_path) so real
mtimes and mode bits are exercised, including real Unix sockets to cover
the regular-file-only regression.
"""
import os
import socket
import stat
import time

import scanners.file_scanner as file_scanner


def _scan_dir(monkeypatch, directory):
    monkeypatch.setattr(file_scanner, "WATCHED_DIRS", [str(directory)])
    return file_scanner.scan()


def test_flags_recent_executable_as_high_severity(tmp_path, monkeypatch):
    f = tmp_path / "dropped.sh"
    f.write_text("#!/bin/sh\n")
    os.chmod(f, 0o755)

    findings = _scan_dir(monkeypatch, tmp_path)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["evidence"]["sha256"] is not None


def test_flags_old_executable_as_low_severity(tmp_path, monkeypatch):
    f = tmp_path / "old_tool.sh"
    f.write_text("#!/bin/sh\n")
    os.chmod(f, 0o755)
    old_time = time.time() - file_scanner.RECENT_SECONDS - 3600
    os.utime(f, (old_time, old_time))

    findings = _scan_dir(monkeypatch, tmp_path)
    assert len(findings) == 1
    assert findings[0]["severity"] == "low"


def test_does_not_flag_non_executable_file(tmp_path, monkeypatch):
    f = tmp_path / "notes.txt"
    f.write_text("just some text")
    os.chmod(f, 0o644)

    findings = _scan_dir(monkeypatch, tmp_path)
    assert findings == []


def test_does_not_flag_unix_socket(tmp_path, monkeypatch):
    # Regression test: _is_executable used to only check permission bits,
    # so Unix sockets (commonly created with wide-open execute bits, e.g.
    # X11's /tmp/.X11-unix/X0 as srwxrwxrwx) were misidentified as dropped
    # executables. Confirmed live on a real desktop: 8 false positives,
    # all sockets (X11, ICE, Chrome, an MCP bridge), zero real droppers.
    sock_path = tmp_path / "some.sock"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(sock_path))
        os.chmod(sock_path, 0o777)  # matches real-world wide-open socket perms
        findings = _scan_dir(monkeypatch, tmp_path)
        assert findings == []
    finally:
        sock.close()


def test_does_not_flag_directory_entries_beyond_walk(tmp_path, monkeypatch):
    (tmp_path / "subdir").mkdir()
    findings = _scan_dir(monkeypatch, tmp_path)
    assert findings == []
