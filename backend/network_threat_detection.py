"""Real-time network threat detection: polls active network connections on
an interval and flags malicious remote endpoints, known-bad destination
ports, and simple port-scan behavior as they happen - a continuous
counterpart to the one-shot network_scanner/port_scanner used by a full
scan.

Detection only. Unlike real-time file protection this never blocks a
connection or touches firewall rules from a background thread - it just
records an event so the dashboard/API can surface it for a human to act on.

Off by default - see README / backend/.env.example. Enable with
NETWORK_THREAT_DETECTION=1.
"""
import json
import os
import subprocess
import threading
import time

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

from database import db
from scanners.network_scanner import _is_private
from scanners.port_scanner import _load_rules as _load_port_rules

IP_RULES_PATH = os.path.join(os.path.dirname(__file__), "rules", "malicious_ips.json")

DEFAULT_POLL_SECONDS = 5

# A single remote host touching this many distinct local ports within the
# window looks like a port scan rather than normal client traffic.
PORTSCAN_PORT_THRESHOLD = 8
PORTSCAN_WINDOW_SECONDS = 30

_lock = threading.Lock()
_STARTED = False
_STARTED_INTERVAL = 0

# (remote_ip, remote_port, local_port) tuples already turned into an event,
# so a long-lived connection isn't re-alerted on every poll - mirrors
# realtime_protection only reacting to *new* filesystem events.
_seen_connections = set()
# remote_ip -> {"ports": set(local ports touched), "first_seen": epoch seconds}
_portscan_tracker = {}
# remote_ips already flagged as a scanner within the current window, so the
# same host doesn't generate a fresh finding on every subsequent poll.
_alerted_scanners = set()


def _load_malicious_ips():
    try:
        with open(IP_RULES_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return {entry["ip"]: entry["desc"] for entry in data.get("known_malicious_ips", [])}


def _load_malicious_ports():
    try:
        rules = _load_port_rules()
    except (OSError, json.JSONDecodeError):
        return {}
    return {p["port"]: p["desc"] for p in rules.get("known_malicious_ports", [])}


def _connections_psutil():
    conns = []
    for c in psutil.net_connections(kind="inet"):
        if c.raddr:
            conns.append({
                "local_port": c.laddr.port if c.laddr else None,
                "remote_ip": c.raddr.ip,
                "remote_port": c.raddr.port,
                "pid": c.pid,
                "status": c.status,
            })
    return conns


def _connections_ss():
    conns = []
    try:
        # No "state" filter (unlike network_scanner's established-only
        # query) - port-scan detection needs to see short-lived/non-
        # established sockets too, not just settled connections.
        out = subprocess.check_output(["ss", "-tun"], text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return conns

    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        status, local, remote = parts[1], parts[4], parts[5]
        remote_ip = remote.rsplit(":", 1)[0].strip("[]")
        try:
            remote_port = int(remote.rsplit(":", 1)[-1])
            local_port = int(local.rsplit(":", 1)[-1])
        except ValueError:
            continue
        conns.append({"local_port": local_port, "remote_ip": remote_ip, "remote_port": remote_port,
                       "pid": None, "status": status})
    return conns


def _list_connections():
    return _connections_psutil() if HAVE_PSUTIL else _connections_ss()


def _check_connection(conn, malicious_ips, malicious_ports, findings):
    remote_ip, remote_port, local_port = conn["remote_ip"], conn["remote_port"], conn.get("local_port")
    key = (remote_ip, remote_port, local_port)
    if key in _seen_connections:
        return
    _seen_connections.add(key)

    if remote_ip in malicious_ips:
        findings.append((conn, "critical", f"Connection to known-malicious IP {remote_ip}", malicious_ips[remote_ip]))
        return

    if remote_port in malicious_ports:
        findings.append((conn, "critical", f"Connection to known-malicious port {remote_port}/{remote_ip}",
                          malicious_ports[remote_port]))
        return

    if not _is_private(remote_ip):
        findings.append((conn, "low", f"New external connection observed: {remote_ip}",
                          "Connection to a non-private IP address; review if unexpected."))


def _track_portscan(conn, now, findings):
    remote_ip, local_port = conn["remote_ip"], conn.get("local_port")
    if local_port is None:
        return

    tracker = _portscan_tracker.setdefault(remote_ip, {"ports": set(), "first_seen": now})
    if now - tracker["first_seen"] > PORTSCAN_WINDOW_SECONDS:
        tracker["ports"] = set()
        tracker["first_seen"] = now
        _alerted_scanners.discard(remote_ip)
    tracker["ports"].add(local_port)

    if len(tracker["ports"]) >= PORTSCAN_PORT_THRESHOLD and remote_ip not in _alerted_scanners:
        _alerted_scanners.add(remote_ip)
        findings.append((
            conn, "high", f"Possible port scan from {remote_ip}",
            f"{remote_ip} touched {len(tracker['ports'])} distinct local ports within {PORTSCAN_WINDOW_SECONDS}s.",
        ))


def poll_once():
    """Run one detection pass over current connections and persist any new
    findings as network_threat_events. Returns the findings recorded."""
    malicious_ips = _load_malicious_ips()
    malicious_ports = _load_malicious_ports()
    conns = _list_connections()

    findings = []
    now = time.time()
    for conn in conns:
        _track_portscan(conn, now, findings)
        _check_connection(conn, malicious_ips, malicious_ports, findings)

    for conn, severity, title, description in findings:
        evidence = {"remote_ip": conn["remote_ip"], "remote_port": conn.get("remote_port"),
                     "local_port": conn.get("local_port"), "pid": conn.get("pid")}
        db.save_network_threat_event(conn["remote_ip"], conn.get("remote_port"), conn.get("local_port"),
                                      conn.get("pid"), severity, title, description, evidence)

    return findings


def _poll_once_safely():
    try:
        poll_once()
    except Exception as exc:
        # A single bad poll (e.g. a transient `ss`/psutil error) shouldn't
        # kill detection for the rest of the process.
        print(f"WARNING: network threat detection poll failed: {exc}")


def _loop(poll_seconds):
    while True:
        _poll_once_safely()
        time.sleep(poll_seconds)


def start(poll_seconds=None):
    """Start network threat detection if configured. Idempotent - safe to
    call unconditionally at app startup. Returns whether it's (now, or
    already) running.

    `poll_seconds`, if given, overrides NETWORK_THREAT_DETECTION/
    NETWORK_THREAT_POLL_SECONDS and force-enables regardless of environment
    (used by tests).
    """
    global _STARTED, _STARTED_INTERVAL

    if poll_seconds is None:
        if os.environ.get("NETWORK_THREAT_DETECTION", "0") != "1":
            return False
        raw = os.environ.get("NETWORK_THREAT_POLL_SECONDS", "")
        try:
            poll_seconds = int(raw) if raw.strip() else DEFAULT_POLL_SECONDS
        except ValueError:
            poll_seconds = DEFAULT_POLL_SECONDS

    with _lock:
        if _STARTED:
            return True
        threading.Thread(target=_loop, args=(poll_seconds,), daemon=True).start()
        _STARTED = True
        _STARTED_INTERVAL = poll_seconds

    print(f"Network threat detection enabled: polling every {poll_seconds}s.")
    return True


def status():
    return {"enabled": _STARTED, "poll_seconds": _STARTED_INTERVAL if _STARTED else 0}
