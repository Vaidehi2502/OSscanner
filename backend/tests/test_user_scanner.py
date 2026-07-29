"""Tests for user_scanner.py's UID-0 and empty-password checks.

pwd.struct_passwd/spwd.struct_spwd can't be constructed directly, so
_passwd_entries and _shadow_entry are monkeypatched with lightweight fakes
carrying just the attributes scan() actually reads.
"""
from collections import namedtuple

import scanners.user_scanner as user_scanner

_PasswdEntry = namedtuple("passwd", ["pw_name", "pw_uid", "pw_shell"])
_ShadowEntry = namedtuple("shadow", ["sp_pwd"])


def test_is_login_shell_recognizes_non_login_shells_regardless_of_path():
    # Regression test: the old check hardcoded exact full paths and missed
    # real variants present on this machine (/usr/bin/false, /bin/sync).
    assert not user_scanner._is_login_shell("/bin/false")
    assert not user_scanner._is_login_shell("/usr/bin/false")
    assert not user_scanner._is_login_shell("/usr/sbin/nologin")
    assert not user_scanner._is_login_shell("/sbin/nologin")
    assert not user_scanner._is_login_shell("/bin/sync")
    assert not user_scanner._is_login_shell("")


def test_is_login_shell_recognizes_real_shells():
    assert user_scanner._is_login_shell("/bin/bash")
    assert user_scanner._is_login_shell("/usr/bin/zsh")


def _run_scan(monkeypatch, passwd_entries, shadow_by_user=None):
    monkeypatch.setattr(user_scanner, "_passwd_entries", lambda: passwd_entries)
    monkeypatch.setattr(
        user_scanner, "_shadow_entry", lambda name: (shadow_by_user or {}).get(name)
    )
    return user_scanner.scan()


def test_flags_non_root_account_with_uid_zero(monkeypatch):
    entries = [_PasswdEntry("root", 0, "/bin/bash"), _PasswdEntry("backdoor", 0, "/bin/bash")]
    findings = _run_scan(monkeypatch, entries)
    titles = [f["title"] for f in findings]
    assert any("backdoor" in t for t in titles)
    assert not any(t.endswith(": root") for t in titles)


def test_does_not_flag_root_itself(monkeypatch):
    entries = [_PasswdEntry("root", 0, "/bin/bash")]
    findings = _run_scan(monkeypatch, entries)
    assert not any("UID 0" in f["title"] for f in findings)


def test_flags_empty_password_on_login_capable_account(monkeypatch):
    entries = [_PasswdEntry("alice", 1000, "/bin/bash")]
    findings = _run_scan(monkeypatch, entries, {"alice": _ShadowEntry("")})
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "alice" in findings[0]["title"]


def test_does_not_check_password_for_non_login_shell_account(monkeypatch):
    # A service account with /usr/bin/false (or any non-login shell) isn't
    # login-capable in the first place, so its shadow entry is never even
    # consulted - regardless of what's in it.
    entries = [_PasswdEntry("daemon", 1, "/usr/bin/false")]
    findings = _run_scan(monkeypatch, entries, {"daemon": _ShadowEntry("")})
    assert findings == []


def test_does_not_flag_account_with_real_password_hash(monkeypatch):
    entries = [_PasswdEntry("alice", 1000, "/bin/bash")]
    findings = _run_scan(monkeypatch, entries, {"alice": _ShadowEntry("$6$somesalt$somehash")})
    assert findings == []


def test_does_not_flag_locked_account(monkeypatch):
    entries = [_PasswdEntry("alice", 1000, "/bin/bash")]
    findings = _run_scan(monkeypatch, entries, {"alice": _ShadowEntry("!")})
    assert findings == []


def test_handles_missing_shadow_entry_gracefully(monkeypatch):
    # _shadow_entry returns None when unreadable (e.g. not running as root) -
    # must not crash and must not produce a finding out of missing data.
    entries = [_PasswdEntry("alice", 1000, "/bin/bash")]
    findings = _run_scan(monkeypatch, entries, {})
    assert findings == []
