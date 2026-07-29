"""Tests for log_scanner.py's failed-login counting and root-login detection.

Uses a real temp file with real log lines (LOG_CANDIDATES monkeypatched to
point at it) rather than mocking _tail, so the actual regex/threshold
behavior is exercised end to end.
"""
import scanners.log_scanner as log_scanner


def _scan_log(monkeypatch, tmp_path, content):
    log_path = tmp_path / "auth.log"
    log_path.write_text(content)
    monkeypatch.setattr(log_scanner, "LOG_CANDIDATES", [str(log_path)])
    return log_scanner.scan()


def test_scan_returns_empty_when_no_log_file_exists(monkeypatch):
    monkeypatch.setattr(log_scanner, "LOG_CANDIDATES", ["/nonexistent/auth.log"])
    assert log_scanner.scan() == []


def test_scan_flags_repeated_failed_logins_from_same_ip(monkeypatch, tmp_path):
    line = "Jul 29 12:00:00 host sshd[1]: Failed password for root from 192.168.1.5 port 4444 ssh2\n"
    findings = _scan_log(monkeypatch, tmp_path, line * log_scanner.FAILED_THRESHOLD)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "192.168.1.5" in findings[0]["title"]


def test_scan_does_not_flag_failed_logins_below_threshold(monkeypatch, tmp_path):
    line = "Jul 29 12:00:00 host sshd[1]: Failed password for root from 192.168.1.5 port 4444 ssh2\n"
    findings = _scan_log(monkeypatch, tmp_path, line * (log_scanner.FAILED_THRESHOLD - 1))
    assert findings == []


def test_scan_counts_ipv6_failed_logins(monkeypatch, tmp_path):
    # Regression test: the IP regex used to be digits-only ([\d.]+), which
    # truncated IPv6 addresses to their leading hex group (e.g. "2001:db8::1"
    # became just "2001"), miscounting or misattributing IPv6 attackers.
    line = (
        "Jul 29 12:00:00 host sshd[1]: Failed password for invalid user x "
        "from 2001:db8::dead:beef port 4444 ssh2\n"
    )
    findings = _scan_log(monkeypatch, tmp_path, line * log_scanner.FAILED_THRESHOLD)
    assert len(findings) == 1
    assert findings[0]["evidence"]["ip"] == "2001:db8::dead:beef"


def test_scan_flags_password_root_login(monkeypatch, tmp_path):
    line = "Jul 29 12:00:00 host sshd[2]: Accepted password for root from 10.0.0.5 port 22 ssh2\n"
    findings = _scan_log(monkeypatch, tmp_path, line)
    assert len(findings) == 1
    assert findings[0]["title"] == "Root login detected"


def test_scan_flags_publickey_root_login(monkeypatch, tmp_path):
    # Regression test: only password-based root logins were detected before;
    # key-based root logins (at least as common, arguably more security
    # relevant) went completely unnoticed.
    line = "Jul 29 12:00:00 host sshd[2]: Accepted publickey for root from 10.0.0.5 port 22 ssh2\n"
    findings = _scan_log(monkeypatch, tmp_path, line)
    assert len(findings) == 1
    assert findings[0]["title"] == "Root login detected"


def test_scan_does_not_flag_routine_cron_root_session(monkeypatch, tmp_path):
    # Regression test: this phrase fires on every root cron job (confirmed
    # 155 occurrences in one real day's worth of auth.log on a dev
    # machine), not just actual logins, and must not be treated as one.
    line = (
        "Jul 29 11:35:01 host CRON[37812]: pam_unix(cron:session): "
        "session opened for user root(uid=0) by root(uid=0)\n"
    )
    findings = _scan_log(monkeypatch, tmp_path, line * 50)
    assert findings == []


def test_scan_does_not_flag_non_root_login(monkeypatch, tmp_path):
    line = "Jul 29 12:00:00 host sshd[2]: Accepted password for alice from 10.0.0.5 port 22 ssh2\n"
    findings = _scan_log(monkeypatch, tmp_path, line)
    assert findings == []
