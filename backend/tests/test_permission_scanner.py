"""Tests for permission_scanner.py's world-writable and SUID/SGID checks.

These use real temp files with real permission bits (chmod) rather than
mocking os.lstat, since the behavior we care about - the kernel's actual
mode bits - is exactly what a mock would hand-wave away. SENSITIVE_DIRS is
monkeypatched to point at the temp directory so no real system paths are
touched.
"""
import os
import stat

import pytest

import scanners.permission_scanner as permission_scanner


def _scan_dir(monkeypatch, directory):
    monkeypatch.setattr(permission_scanner, "SENSITIVE_DIRS", [str(directory)])
    return permission_scanner.scan()


def test_flags_world_writable_file(tmp_path, monkeypatch):
    f = tmp_path / "world_writable.txt"
    f.write_text("x")
    os.chmod(f, 0o666)  # rw-rw-rw-

    findings = _scan_dir(monkeypatch, tmp_path)
    titles = [f["title"] for f in findings]
    assert any("World-writable file" in t for t in titles)


def test_does_not_flag_symlink_as_world_writable(tmp_path, monkeypatch):
    target = tmp_path / "target.txt"
    target.write_text("x")
    os.chmod(target, 0o600)
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    findings = _scan_dir(monkeypatch, tmp_path)
    assert not any("link.txt" in f["evidence"]["path"] for f in findings)


def test_does_not_flag_normal_file(tmp_path, monkeypatch):
    f = tmp_path / "normal.txt"
    f.write_text("x")
    os.chmod(f, 0o644)

    findings = _scan_dir(monkeypatch, tmp_path)
    assert findings == []


def test_flags_unknown_suid_binary(tmp_path, monkeypatch):
    f = tmp_path / "mystery_tool"
    f.write_text("x")
    os.chmod(f, 0o644 | stat.S_ISUID)

    findings = _scan_dir(monkeypatch, tmp_path)
    assert len(findings) == 1
    assert "Unexpected SUID binary" in findings[0]["title"]
    assert findings[0]["severity"] == "high"


def test_does_not_flag_known_suid_binary(tmp_path, monkeypatch):
    f = tmp_path / "sudo"
    f.write_text("x")
    os.chmod(f, 0o644 | stat.S_ISUID)

    findings = _scan_dir(monkeypatch, tmp_path)
    assert findings == []


@pytest.mark.parametrize("name", ["pppd", "vmware-authd"])
def test_does_not_flag_whitelisted_suid_binary(tmp_path, monkeypatch, name):
    f = tmp_path / name
    f.write_text("x")
    os.chmod(f, 0o644 | stat.S_ISUID)

    findings = _scan_dir(monkeypatch, tmp_path)
    assert findings == []


def test_flags_unknown_sgid_binary(tmp_path, monkeypatch):
    # Regression test: the SGID check was entirely missing despite the
    # module's own docstring claiming to cover "SUID/SGID binaries".
    f = tmp_path / "mystery_group_tool"
    f.write_text("x")
    os.chmod(f, 0o644 | stat.S_ISGID)

    findings = _scan_dir(monkeypatch, tmp_path)
    assert len(findings) == 1
    assert "Unexpected SGID binary" in findings[0]["title"]
    assert findings[0]["severity"] == "high"


def test_does_not_flag_known_sgid_binary(tmp_path, monkeypatch):
    f = tmp_path / "crontab"
    f.write_text("x")
    os.chmod(f, 0o644 | stat.S_ISGID)

    findings = _scan_dir(monkeypatch, tmp_path)
    assert findings == []


def test_flags_both_suid_and_sgid_on_same_file(tmp_path, monkeypatch):
    f = tmp_path / "both_bits_tool"
    f.write_text("x")
    os.chmod(f, 0o644 | stat.S_ISUID | stat.S_ISGID)

    findings = _scan_dir(monkeypatch, tmp_path)
    titles = {f["title"] for f in findings}
    assert len(findings) == 2
    assert any("SUID" in t for t in titles)
    assert any("SGID" in t for t in titles)
