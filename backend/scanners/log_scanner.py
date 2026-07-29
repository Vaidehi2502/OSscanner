"""Scans auth logs for failed login bursts and other suspicious auth events."""
import os
import re
from collections import Counter

LOG_CANDIDATES = ["/var/log/auth.log", "/var/log/secure"]
# Character class covers both IPv4 (digits/dots) and IPv6 (hex groups/colons) -
# a digits-only class truncated IPv6 addresses to their first hex group,
# e.g. "2001:db8::1" was captured as just "2001".
FAILED_LOGIN_PATTERNS = [
    re.compile(r"Failed password for .* from (?P<ip>[0-9a-fA-F.:]+)"),
    re.compile(r"authentication failure.*rhost=(?P<ip>[0-9a-fA-F.:]+)"),
]
ROOT_LOGIN_PATTERNS = [
    re.compile(r"Accepted \S+ for root from"),
]
FAILED_THRESHOLD = 5
TAIL_LINES = 5000


def _tail(path, n):
    try:
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()
        return lines[-n:]
    except (OSError, PermissionError):
        return []


def scan():
    findings = []
    log_path = next((p for p in LOG_CANDIDATES if os.path.isfile(p)), None)

    if not log_path:
        return findings

    failed_by_ip = Counter()
    accepted_new_user = []

    for line in _tail(log_path, TAIL_LINES):
        for pattern in FAILED_LOGIN_PATTERNS:
            match = pattern.search(line)
            if match:
                failed_by_ip[match.group("ip")] += 1

        # Matches interactive authentication as root only (password or
        # publickey). Deliberately does NOT match generic PAM "session
        # opened for user root" lines - those also fire for routine,
        # non-interactive root activity like cron jobs, which on a typical
        # system vastly outnumber real root logins and would drown any
        # real signal in noise.
        if any(pattern.search(line) for pattern in ROOT_LOGIN_PATTERNS):
            accepted_new_user.append(line.strip())

    for ip, count in failed_by_ip.items():
        if count >= FAILED_THRESHOLD:
            findings.append({
                "scanner": "log_scanner",
                "severity": "high",
                "title": f"Repeated failed logins from {ip}",
                "description": f"{count} failed authentication attempts detected - possible brute force.",
                "evidence": {"ip": ip, "count": count, "log": log_path},
            })

    for line in accepted_new_user:
        findings.append({
            "scanner": "log_scanner",
            "severity": "medium",
            "title": "Root login detected",
            "description": "A direct root session was opened; confirm this was expected.",
            "evidence": {"line": line, "log": log_path},
        })

    return findings


if __name__ == "__main__":
    for finding in scan():
        print(finding)
