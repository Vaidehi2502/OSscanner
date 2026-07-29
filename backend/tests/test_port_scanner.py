"""Tests for port_scanner.py's parsing and rule-matching logic.

We never let these tests touch the real system: `_listening_ports_ss`'s
subprocess call and `scan()`'s port source are both monkeypatched with
canned data, so results are deterministic regardless of what's actually
listening on the machine running the tests.
"""
from collections import namedtuple

import psutil

import scanners.port_scanner as port_scanner

_Addr = namedtuple("addr", ["ip", "port"])
_Conn = namedtuple("sconn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


def _tcp_listen(port, pid=123):
    return _Conn(0, 2, 1, _Addr("0.0.0.0", port), (), psutil.CONN_LISTEN, pid)


def _udp_bound(port, pid=None):
    """An unconnected/bound UDP socket - the real equivalent of "listening"."""
    return _Conn(0, 2, 2, _Addr("0.0.0.0", port), (), "NONE", pid)


def _udp_connected(local_port, pid=None):
    """A UDP socket connected to a remote peer (e.g. outbound DNS/DHCP
    traffic) - must NOT be treated as a listening/exposed service."""
    return _Conn(0, 2, 2, _Addr("0.0.0.0", local_port), _Addr("1.2.3.4", 53), "NONE", pid)

# A representative `ss -tuln` output: header row, IPv4 tcp/udp listeners,
# an IPv6 listener, and a malformed short line that should be skipped.
SAMPLE_SS_OUTPUT = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*
tcp   LISTEN 0      128    [::]:22            [::]:*
udp   UNCONN 0      0      0.0.0.0:68         0.0.0.0:*
tcp   LISTEN 0      128    127.0.0.1:4444     0.0.0.0:*
garbage line
"""


def test_listening_ports_ss_parses_typical_output(monkeypatch):
    monkeypatch.setattr(
        port_scanner.subprocess, "check_output", lambda *a, **k: SAMPLE_SS_OUTPUT
    )
    ports = port_scanner._listening_ports_ss()
    assert {"port": 22, "pid": None, "proto": "tcp"} in ports
    assert {"port": 68, "pid": None, "proto": "udp"} in ports
    assert {"port": 4444, "pid": None, "proto": "tcp"} in ports
    # the header row and the malformed "garbage line" must not produce entries
    assert len(ports) == 4  # two :22 entries (v4 + v6) + :68 + :4444


def test_listening_ports_ss_returns_empty_on_command_failure(monkeypatch):
    def _raise(*a, **k):
        raise OSError("ss not found")

    monkeypatch.setattr(port_scanner.subprocess, "check_output", _raise)
    assert port_scanner._listening_ports_ss() == []


def _run_scan_with_ports(monkeypatch, ports):
    monkeypatch.setattr(port_scanner, "HAVE_PSUTIL", False)
    monkeypatch.setattr(port_scanner, "_listening_ports_ss", lambda: ports)
    return port_scanner.scan()


def test_scan_flags_known_malicious_port(monkeypatch):
    findings = _run_scan_with_ports(
        monkeypatch, [{"port": 4444, "pid": None, "proto": "tcp"}]
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert "4444" in findings[0]["title"]


def test_scan_flags_watch_range_port_as_low_severity(monkeypatch):
    findings = _run_scan_with_ports(
        monkeypatch, [{"port": 50000, "pid": None, "proto": "tcp"}]
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "low"


def test_scan_ignores_benign_port(monkeypatch):
    findings = _run_scan_with_ports(
        monkeypatch, [{"port": 80, "pid": None, "proto": "tcp"}]
    )
    assert findings == []


def test_listening_ports_psutil_includes_tcp_listen_and_bound_udp(monkeypatch):
    monkeypatch.setattr(port_scanner, "HAVE_PSUTIL", True)
    conns = [_tcp_listen(22), _udp_bound(53)]
    monkeypatch.setattr(port_scanner.psutil, "net_connections", lambda kind: conns)

    ports = port_scanner._listening_ports_psutil()
    assert {"port": 22, "pid": 123, "proto": "tcp"} in ports
    assert {"port": 53, "pid": None, "proto": "udp"} in ports
    assert len(ports) == 2


def test_listening_ports_psutil_excludes_connected_udp_socket(monkeypatch):
    # Regression test: a UDP socket connected to a remote peer (e.g. the
    # local end of an outbound DNS/DHCP request) is not a listening service
    # and must not show up as one, even though UDP has no LISTEN state.
    monkeypatch.setattr(port_scanner, "HAVE_PSUTIL", True)
    conns = [_udp_connected(local_port=58806)]
    monkeypatch.setattr(port_scanner.psutil, "net_connections", lambda kind: conns)

    ports = port_scanner._listening_ports_psutil()
    assert ports == []


def test_scan_dedupes_repeated_port(monkeypatch):
    findings = _run_scan_with_ports(
        monkeypatch,
        [
            {"port": 4444, "pid": None, "proto": "tcp"},
            {"port": 4444, "pid": None, "proto": "udp"},
        ],
    )
    assert len(findings) == 1
