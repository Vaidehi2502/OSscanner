"""Tests for network_scanner.py's private/external classification and parsing.

As with port_scanner, we never let these tests depend on real system
connections: `_connections_ss`'s subprocess call and scan()'s connection
source are monkeypatched with canned data.
"""
from collections import namedtuple

import scanners.network_scanner as network_scanner

_Addr = namedtuple("addr", ["ip", "port"])
_Conn = namedtuple("sconn", ["laddr", "raddr", "status", "pid"])


def test_is_private_ipv4_rfc1918_and_loopback():
    assert network_scanner._is_private("192.168.1.5")
    assert network_scanner._is_private("10.0.0.1")
    assert network_scanner._is_private("172.16.5.5")
    assert network_scanner._is_private("127.0.0.1")


def test_is_private_ipv4_public_is_not_private():
    assert not network_scanner._is_private("8.8.8.8")


def test_is_private_ipv6_loopback_link_local_and_ula():
    # Regression test: an earlier version only checked an IPv4 allowlist,
    # so IPv6 loopback/link-local/ULA addresses were misclassified as
    # "external" and generated false-positive findings.
    assert network_scanner._is_private("::1")
    assert network_scanner._is_private("fe80::1")
    assert network_scanner._is_private("fc00::1")


def test_is_private_ipv6_public_is_not_private():
    assert not network_scanner._is_private("2001:4860:4860::8888")


def test_is_private_malformed_address_defaults_to_private():
    # Fail-closed: an unparsable value shouldn't generate a finding.
    assert network_scanner._is_private("not-an-ip")


SAMPLE_SS_OUTPUT = """Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
tcp   ESTAB 0      0      192.168.1.5:53240  8.8.8.8:443
tcp   ESTAB 0      0      [::1]:53240        [2001:4860:4860::8888]:443
garbage line
"""


def test_connections_ss_parses_typical_output(monkeypatch):
    monkeypatch.setattr(
        network_scanner.subprocess, "check_output", lambda *a, **k: SAMPLE_SS_OUTPUT
    )
    conns = network_scanner._connections_ss()
    remote_ips = {c["remote_ip"] for c in conns}
    assert remote_ips == {"8.8.8.8", "2001:4860:4860::8888"}


def test_connections_ss_returns_empty_on_command_failure(monkeypatch):
    def _raise(*a, **k):
        raise OSError("ss not found")

    monkeypatch.setattr(network_scanner.subprocess, "check_output", _raise)
    assert network_scanner._connections_ss() == []


def _run_scan_with_conns(monkeypatch, conns):
    monkeypatch.setattr(network_scanner, "HAVE_PSUTIL", False)
    monkeypatch.setattr(network_scanner, "_connections_ss", lambda: conns)
    return network_scanner.scan()


def test_scan_flags_public_ipv4_connection(monkeypatch):
    findings = _run_scan_with_conns(
        monkeypatch,
        [{"laddr": "192.168.1.5:53240", "raddr": "8.8.8.8:443", "pid": None, "remote_ip": "8.8.8.8"}],
    )
    assert len(findings) == 1
    assert "8.8.8.8" in findings[0]["title"]
    assert findings[0]["severity"] == "low"


def test_scan_does_not_flag_private_connection(monkeypatch):
    findings = _run_scan_with_conns(
        monkeypatch,
        [{"laddr": "192.168.1.5:53240", "raddr": "192.168.1.1:443", "pid": None, "remote_ip": "192.168.1.1"}],
    )
    assert findings == []


def test_scan_does_not_flag_ipv6_loopback_connection(monkeypatch):
    findings = _run_scan_with_conns(
        monkeypatch,
        [{"laddr": "[::1]:53240", "raddr": "[::1]:8080", "pid": None, "remote_ip": "::1"}],
    )
    assert findings == []
