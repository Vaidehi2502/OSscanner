"""Scans locally listening TCP/UDP ports against the malicious_ports rule set."""
import json
import os
import subprocess

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "malicious_ports.json")


def _load_rules():
    with open(RULES_PATH) as f:
        return json.load(f)


def _listening_ports_psutil():
    ports = []
    for conn in psutil.net_connections(kind="inet"):
        is_listening_tcp = conn.status == psutil.CONN_LISTEN
        # UDP has no LISTEN state - a bound-but-unconnected socket (no raddr)
        # is the closest equivalent to "listening"; a socket with a raddr is
        # an established outbound flow (e.g. DNS/DHCP client traffic), not a
        # service accepting inbound connections, and must not be flagged.
        is_bound_udp = conn.type == 2 and not conn.raddr
        if is_listening_tcp or is_bound_udp:
            ports.append({"port": conn.laddr.port, "pid": conn.pid, "proto": "tcp" if conn.type == 1 else "udp"})
    return ports


def _listening_ports_ss():
    ports = []
    try:
        out = subprocess.check_output(["ss", "-tuln"], text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return ports

    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = "tcp" if line.lower().startswith("tcp") else "udp"
        local_addr = parts[4]
        try:
            port = int(local_addr.rsplit(":", 1)[-1])
        except ValueError:
            continue
        ports.append({"port": port, "pid": None, "proto": proto})
    return ports


def scan():
    rules = _load_rules()
    malicious = {p["port"]: p["desc"] for p in rules["known_malicious_ports"]}
    watch_ranges = rules.get("watch_ranges", [])

    findings = []
    ports = _listening_ports_psutil() if HAVE_PSUTIL else _listening_ports_ss()

    seen = set()
    for entry in ports:
        port = entry["port"]
        if port in seen:
            continue
        seen.add(port)

        if port in malicious:
            findings.append({
                "scanner": "port_scanner",
                "severity": "critical",
                "title": f"Known malicious port open: {port}/{entry['proto']}",
                "description": malicious[port],
                "evidence": entry,
            })
            continue

        for rng in watch_ranges:
            if rng["start"] <= port <= rng["end"]:
                findings.append({
                    "scanner": "port_scanner",
                    "severity": "low",
                    "title": f"Listening port in watched range: {port}/{entry['proto']}",
                    "description": rng["desc"],
                    "evidence": entry,
                })
                break

    return findings


if __name__ == "__main__":
    for finding in scan():
        print(finding)
