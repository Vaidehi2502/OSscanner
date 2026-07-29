"""Scans local user accounts for privilege anomalies (extra UID-0 users, unlocked accounts)."""
import pwd
import spwd


def _passwd_entries():
    try:
        return pwd.getpwall()
    except Exception:
        return []


def _shadow_entry(username):
    try:
        return spwd.getspnam(username)
    except (KeyError, PermissionError, OSError):
        return None


def scan():
    findings = []

    for entry in _passwd_entries():
        if entry.pw_uid == 0 and entry.pw_name != "root":
            findings.append({
                "scanner": "user_scanner",
                "severity": "critical",
                "title": f"Non-root account with UID 0: {entry.pw_name}",
                "description": "Account has root-equivalent privileges under a different username.",
                "evidence": {"user": entry.pw_name, "uid": entry.pw_uid},
            })

        if entry.pw_shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin", ""):
            shadow = _shadow_entry(entry.pw_name)
            if shadow and shadow.sp_pwd in ("", None):
                findings.append({
                    "scanner": "user_scanner",
                    "severity": "high",
                    "title": f"Account with empty password: {entry.pw_name}",
                    "description": "Login-capable account has no password set.",
                    "evidence": {"user": entry.pw_name},
                })

    return findings


if __name__ == "__main__":
    for finding in scan():
        print(finding)
