"""Scans active outbound/inbound network connections for suspicious remote endpoints."""
import ipaddress
import subprocess

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

# Private/loopback/link-local addresses are considered normal; anything
# else on an established connection is reported at low severity for the
# operator to triage (this scanner is intentionally conservative - it
# flags for review rather than assuming malice).
#
# `ipaddress`'s built-in is_private covers IPv4 (RFC1918, loopback,
# link-local) and IPv6 (::1, fe80::/10 link-local, fc00::/7 ULA) - an
# earlier version of this function reimplemented an IPv4-only allowlist,
# which meant any IPv6 loopback/link-local/ULA traffic was misclassified
# as an external connection.
def _is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private


def _connections_psutil():
    conns = []
    for c in psutil.net_connections(kind="inet"):
        if c.status == "ESTABLISHED" and c.raddr:
            conns.append({"laddr": f"{c.laddr.ip}:{c.laddr.port}", "raddr": f"{c.raddr.ip}:{c.raddr.port}",
                          "pid": c.pid, "remote_ip": c.raddr.ip})
    return conns


def _connections_ss():
    conns = []
    try:
        out = subprocess.check_output(["ss", "-tun", "state", "established"], text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return conns

    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        local, remote = parts[4], parts[5]
        remote_ip = remote.rsplit(":", 1)[0].strip("[]")
        conns.append({"laddr": local, "raddr": remote, "pid": None, "remote_ip": remote_ip})
    return conns


def scan():
    findings = []
    conns = _connections_psutil() if HAVE_PSUTIL else _connections_ss()

    for conn in conns:
        if not _is_private(conn["remote_ip"]):
            findings.append({
                "scanner": "network_scanner",
                "severity": "low",
                "title": f"Established connection to external host {conn['remote_ip']}",
                "description": "Outbound connection to a non-private IP address; review if unexpected.",
                "evidence": conn,
            })

    return findings


if __name__ == "__main__":
    for finding in scan():
        print(finding)
