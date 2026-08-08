"""Tests for network_threat_detection.py's per-poll detection logic and
start()/status() orchestration.

_list_connections() is monkeypatched in every detection test so nothing
here touches real sockets or shells out to `ss` - only the pure matching/
dedup/port-scan logic is under test. start()/status()'s decision logic
(mirroring test_monitor.py) is covered separately, with _loop patched out
so no test actually sleeps for a real poll interval.
"""
import time

import pytest

import network_threat_detection as ntd
from database import db


def _conn(remote_ip="8.8.8.8", remote_port=443, local_port=51000, pid=123, status="ESTABLISHED"):
    return {"remote_ip": remote_ip, "remote_port": remote_port, "local_port": local_port, "pid": pid, "status": status}


@pytest.fixture(autouse=True)
def isolate_state(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "scans.db"))
    db.init_db()
    monkeypatch.setattr(ntd, "_seen_connections", set())
    monkeypatch.setattr(ntd, "_portscan_tracker", {})
    monkeypatch.setattr(ntd, "_alerted_scanners", set())
    monkeypatch.setattr(ntd, "_STARTED", False)
    monkeypatch.setattr(ntd, "_STARTED_INTERVAL", 0)
    monkeypatch.setattr(ntd, "_load_malicious_ips", lambda: {})
    monkeypatch.setattr(ntd, "_load_malicious_ports", lambda: {})


# --- poll_once: malicious IP / port matching -----------------------------

def test_flags_connection_to_known_malicious_ip(monkeypatch):
    monkeypatch.setattr(ntd, "_load_malicious_ips", lambda: {"1.2.3.4": "test C2 IP"})
    monkeypatch.setattr(ntd, "_list_connections", lambda: [_conn(remote_ip="1.2.3.4")])

    findings = ntd.poll_once()

    assert len(findings) == 1
    assert "known-malicious IP" in findings[0][2]
    events = db.list_network_threat_events()
    assert len(events) == 1
    assert events[0]["severity"] == "critical"
    assert events[0]["remote_ip"] == "1.2.3.4"


def test_flags_connection_to_known_malicious_port(monkeypatch):
    monkeypatch.setattr(ntd, "_load_malicious_ports", lambda: {4444: "Metasploit default listener"})
    monkeypatch.setattr(ntd, "_list_connections", lambda: [_conn(remote_ip="203.0.113.9", remote_port=4444)])

    findings = ntd.poll_once()

    assert len(findings) == 1
    assert findings[0][1] == "critical"
    assert "known-malicious port" in findings[0][2]


def test_flags_new_external_connection_at_low_severity(monkeypatch):
    monkeypatch.setattr(ntd, "_list_connections", lambda: [_conn(remote_ip="8.8.8.8")])

    findings = ntd.poll_once()

    assert len(findings) == 1
    assert findings[0][1] == "low"
    assert "New external connection" in findings[0][2]


def test_does_not_flag_private_ip_connections(monkeypatch):
    monkeypatch.setattr(ntd, "_list_connections", lambda: [_conn(remote_ip="192.168.1.5")])

    findings = ntd.poll_once()

    assert findings == []
    assert db.list_network_threat_events() == []


def test_same_connection_is_not_re_alerted_on_a_later_poll(monkeypatch):
    monkeypatch.setattr(ntd, "_list_connections", lambda: [_conn(remote_ip="8.8.8.8")])

    first = ntd.poll_once()
    second = ntd.poll_once()

    assert len(first) == 1
    assert second == []
    assert len(db.list_network_threat_events()) == 1


def test_no_findings_for_empty_connection_list(monkeypatch):
    monkeypatch.setattr(ntd, "_list_connections", lambda: [])
    assert ntd.poll_once() == []


# --- poll_once: port-scan detection ---------------------------------------

def test_flags_possible_port_scan_once_threshold_is_reached(monkeypatch):
    conns = [_conn(remote_ip="198.51.100.5", remote_port=9000 + i, local_port=1000 + i)
             for i in range(ntd.PORTSCAN_PORT_THRESHOLD)]
    monkeypatch.setattr(ntd, "_list_connections", lambda: conns)

    findings = ntd.poll_once()

    scan_findings = [f for f in findings if "port scan" in f[2]]
    assert len(scan_findings) == 1
    assert scan_findings[0][1] == "high"


def test_port_scan_is_not_flagged_below_threshold(monkeypatch):
    conns = [_conn(remote_ip="198.51.100.5", remote_port=9000 + i, local_port=1000 + i)
             for i in range(ntd.PORTSCAN_PORT_THRESHOLD - 1)]
    monkeypatch.setattr(ntd, "_list_connections", lambda: conns)

    findings = ntd.poll_once()

    assert all("port scan" not in f[2] for f in findings)


def test_port_scan_finding_is_not_repeated_on_a_later_poll(monkeypatch):
    conns = [_conn(remote_ip="198.51.100.5", remote_port=9000 + i, local_port=1000 + i)
             for i in range(ntd.PORTSCAN_PORT_THRESHOLD)]
    monkeypatch.setattr(ntd, "_list_connections", lambda: conns)

    ntd.poll_once()
    more_conns = conns + [_conn(remote_ip="198.51.100.5", remote_port=9999, local_port=2000)]
    monkeypatch.setattr(ntd, "_list_connections", lambda: more_conns)
    second = ntd.poll_once()

    assert all("port scan" not in f[2] for f in second)


def test_port_scan_tracker_resets_after_the_window_expires(monkeypatch):
    conns = [_conn(remote_ip="198.51.100.5", remote_port=9000 + i, local_port=1000 + i)
             for i in range(ntd.PORTSCAN_PORT_THRESHOLD)]
    monkeypatch.setattr(ntd, "_list_connections", lambda: conns)
    ntd.poll_once()

    # Simulate the window having elapsed by backdating first_seen.
    ntd._portscan_tracker["198.51.100.5"]["first_seen"] = time.time() - ntd.PORTSCAN_WINDOW_SECONDS - 1

    new_conns = [_conn(remote_ip="198.51.100.5", remote_port=9500 + i, local_port=1000 + i)
                 for i in range(ntd.PORTSCAN_PORT_THRESHOLD)]
    monkeypatch.setattr(ntd, "_list_connections", lambda: new_conns)
    second = ntd.poll_once()

    assert any("port scan" in f[2] for f in second)


# --- start()/status() ------------------------------------------------------

def test_start_is_a_noop_when_not_enabled(monkeypatch):
    monkeypatch.delenv("NETWORK_THREAT_DETECTION", raising=False)
    assert ntd.start() is False
    assert ntd.status() == {"enabled": False, "poll_seconds": 0}


def test_start_reads_poll_seconds_from_env(monkeypatch):
    monkeypatch.setattr(ntd, "_loop", lambda poll_seconds: None)
    monkeypatch.setenv("NETWORK_THREAT_DETECTION", "1")
    monkeypatch.setenv("NETWORK_THREAT_POLL_SECONDS", "30")

    assert ntd.start() is True
    assert ntd.status() == {"enabled": True, "poll_seconds": 30}


def test_start_defaults_poll_seconds_when_unset(monkeypatch):
    monkeypatch.setattr(ntd, "_loop", lambda poll_seconds: None)
    monkeypatch.setenv("NETWORK_THREAT_DETECTION", "1")
    monkeypatch.delenv("NETWORK_THREAT_POLL_SECONDS", raising=False)

    assert ntd.start() is True
    assert ntd.status()["poll_seconds"] == ntd.DEFAULT_POLL_SECONDS


def test_start_launches_background_thread_for_explicit_poll_seconds(monkeypatch):
    calls = []
    monkeypatch.setattr(ntd, "_loop", lambda poll_seconds: calls.append(poll_seconds))

    assert ntd.start(5) is True
    time.sleep(0.05)  # let the (patched, instant) daemon thread actually run

    assert calls == [5]
    assert ntd.status() == {"enabled": True, "poll_seconds": 5}


def test_start_is_idempotent(monkeypatch):
    calls = []
    monkeypatch.setattr(ntd, "_loop", lambda poll_seconds: calls.append(poll_seconds))

    ntd.start(5)
    ntd.start(10)  # already running - should be ignored
    time.sleep(0.05)

    assert calls == [5]
    assert ntd.status()["poll_seconds"] == 5


def test_poll_once_safely_survives_a_failing_poll(monkeypatch, capsys):
    def _boom():
        raise RuntimeError("connection listing exploded")

    monkeypatch.setattr(ntd, "poll_once", _boom)

    ntd._poll_once_safely()  # should not raise

    assert "network threat detection poll failed" in capsys.readouterr().out
