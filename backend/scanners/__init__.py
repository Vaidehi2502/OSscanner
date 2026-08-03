"""Registry of all available scanners, keyed by name.

Each scanner module exposes a `scan() -> list[dict]` function returning
findings shaped as:
    {"scanner": str, "severity": "low"|"medium"|"high"|"critical",
     "title": str, "description": str, "evidence": dict}
"""
from . import (
    process_scanner,
    network_scanner,
    file_scanner,
    startup_scanner,
    permission_scanner,
    log_scanner,
    user_scanner,
    port_scanner,
    yara_scanner,
)

SCANNERS = {
    "process": process_scanner,
    "network": network_scanner,
    "file": file_scanner,
    "startup": startup_scanner,
    "permission": permission_scanner,
    "log": log_scanner,
    "user": user_scanner,
    "port": port_scanner,
    "yara": yara_scanner,
}


def run_selected(names):
    """Run the named registered scanners and return a flat list of findings."""
    findings = []
    for name in names:
        module = SCANNERS[name]
        try:
            findings.extend(module.scan())
        except Exception as exc:
            findings.append({
                "scanner": name,
                "severity": "low",
                "title": f"Scanner error: {name}",
                "description": str(exc),
                "evidence": {},
            })
    return findings


def run_all():
    """Run every registered scanner and return a flat list of findings."""
    return run_selected(SCANNERS.keys())
