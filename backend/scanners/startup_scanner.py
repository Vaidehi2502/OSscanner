"""Scans persistence/autostart locations: cron, systemd, rc.local, shell profiles."""
import glob
import os
import subprocess

CRON_PATHS = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"]
SHELL_PROFILES = ["~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc"]
AUTOSTART_GLOBS = ["/etc/xdg/autostart/*.desktop", "~/.config/autostart/*.desktop"]


def _read_cron_entries():
    entries = []
    for cron_path in CRON_PATHS:
        if os.path.isdir(cron_path):
            for f in glob.glob(os.path.join(cron_path, "*")):
                entries.append(f)
        elif os.path.isfile(cron_path):
            entries.append(cron_path)
    return entries


def _systemd_enabled_units():
    try:
        out = subprocess.check_output(
            ["systemctl", "list-unit-files", "--state=enabled", "--no-legend"],
            text=True, timeout=5,
        )
        return [line.split()[0] for line in out.splitlines() if line.strip()]
    except (OSError, subprocess.SubprocessError):
        return []


def scan():
    findings = []

    for cron_file in _read_cron_entries():
        findings.append({
            "scanner": "startup_scanner",
            "severity": "low",
            "title": f"Cron entry present: {cron_file}",
            "description": "Review scheduled job for unexpected persistence mechanisms.",
            "evidence": {"path": cron_file},
        })

    for unit in _systemd_enabled_units():
        if unit.endswith(".service"):
            findings.append({
                "scanner": "startup_scanner",
                "severity": "low",
                "title": f"Enabled systemd service: {unit}",
                "description": "Service starts automatically at boot; confirm it is expected.",
                "evidence": {"unit": unit},
            })

    for profile in SHELL_PROFILES:
        path = os.path.expanduser(profile)
        if os.path.isfile(path):
            findings.append({
                "scanner": "startup_scanner",
                "severity": "low",
                "title": f"Shell profile present: {profile}",
                "description": "Shell profiles can be used for persistence; review for injected commands.",
                "evidence": {"path": path},
            })

    for pattern in AUTOSTART_GLOBS:
        for path in glob.glob(os.path.expanduser(pattern)):
            findings.append({
                "scanner": "startup_scanner",
                "severity": "low",
                "title": f"Autostart entry: {os.path.basename(path)}",
                "description": "Desktop autostart entries run automatically on login.",
                "evidence": {"path": path},
            })

    return findings


if __name__ == "__main__":
    for finding in scan():
        print(finding)
