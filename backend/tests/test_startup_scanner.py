"""Tests for startup_scanner.py's persistence-location detection."""
import os

import scanners.startup_scanner as startup_scanner


def test_read_cron_entries_finds_direct_file(tmp_path, monkeypatch):
    crontab = tmp_path / "crontab"
    crontab.write_text("* * * * * root /bin/true\n")
    monkeypatch.setattr(startup_scanner, "CRON_PATHS", [str(crontab)])

    assert startup_scanner._read_cron_entries() == [str(crontab)]


def test_read_cron_entries_finds_files_in_directory(tmp_path, monkeypatch):
    cron_d = tmp_path / "cron.d"
    cron_d.mkdir()
    (cron_d / "myjob").write_text("* * * * * root /bin/true\n")
    monkeypatch.setattr(startup_scanner, "CRON_PATHS", [str(cron_d)])

    entries = startup_scanner._read_cron_entries()
    assert entries == [str(cron_d / "myjob")]


def test_read_cron_entries_skips_nested_directories(tmp_path, monkeypatch):
    # Regression test: on Debian/Ubuntu, /var/spool/cron is a directory
    # that itself contains a "crontabs" subdirectory. Globbing it without
    # a file-type check would list that subdirectory as if it were a cron
    # file, rather than the actual crontab files inside it.
    spool = tmp_path / "spool_cron"
    spool.mkdir()
    (spool / "crontabs").mkdir()  # a subdirectory, not a cron file
    (spool / "crontabs" / "alice").write_text("* * * * * /bin/true\n")
    monkeypatch.setattr(startup_scanner, "CRON_PATHS", [str(spool)])

    entries = startup_scanner._read_cron_entries()
    assert str(spool / "crontabs") not in entries


def test_systemd_enabled_units_filters_to_services(monkeypatch):
    sample_output = (
        "accounts-daemon.service enabled\n"
        "cron.service            enabled\n"
        "some.timer              enabled\n"
        "some.socket             enabled\n"
    )
    monkeypatch.setattr(
        startup_scanner.subprocess, "check_output", lambda *a, **k: sample_output
    )
    units = startup_scanner._systemd_enabled_units()
    assert "accounts-daemon.service" in units
    assert "cron.service" in units
    assert "some.timer" in units  # returned by the helper; scan() does the .service filtering


def test_systemd_enabled_units_returns_empty_on_command_failure(monkeypatch):
    def _raise(*a, **k):
        raise OSError("systemctl not found")

    monkeypatch.setattr(startup_scanner.subprocess, "check_output", _raise)
    assert startup_scanner._systemd_enabled_units() == []


def test_scan_flags_enabled_service_but_not_other_unit_types(monkeypatch):
    monkeypatch.setattr(startup_scanner, "CRON_PATHS", [])
    monkeypatch.setattr(startup_scanner, "SHELL_PROFILES", [])
    monkeypatch.setattr(startup_scanner, "AUTOSTART_GLOBS", [])
    monkeypatch.setattr(
        startup_scanner,
        "_systemd_enabled_units",
        lambda: ["accounts-daemon.service", "some.timer"],
    )

    findings = startup_scanner.scan()
    assert len(findings) == 1
    assert "accounts-daemon.service" in findings[0]["title"]


def test_scan_flags_existing_shell_profile(tmp_path, monkeypatch):
    profile = tmp_path / ".bashrc"
    profile.write_text("export PATH=$PATH:/usr/local/bin\n")

    monkeypatch.setattr(startup_scanner, "CRON_PATHS", [])
    monkeypatch.setattr(startup_scanner, "_systemd_enabled_units", lambda: [])
    monkeypatch.setattr(startup_scanner, "SHELL_PROFILES", [str(profile)])
    monkeypatch.setattr(startup_scanner, "AUTOSTART_GLOBS", [])

    findings = startup_scanner.scan()
    assert len(findings) == 1
    assert "Shell profile present" in findings[0]["title"]


def test_scan_flags_autostart_entry(tmp_path, monkeypatch):
    autostart_dir = tmp_path / "autostart"
    autostart_dir.mkdir()
    (autostart_dir / "app.desktop").write_text("[Desktop Entry]\n")

    monkeypatch.setattr(startup_scanner, "CRON_PATHS", [])
    monkeypatch.setattr(startup_scanner, "_systemd_enabled_units", lambda: [])
    monkeypatch.setattr(startup_scanner, "SHELL_PROFILES", [])
    monkeypatch.setattr(startup_scanner, "AUTOSTART_GLOBS", [str(autostart_dir / "*.desktop")])

    findings = startup_scanner.scan()
    assert len(findings) == 1
    assert "app.desktop" in findings[0]["title"]
