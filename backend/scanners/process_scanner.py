"""Scans running processes for suspicious names, paths, or resource usage.

Uses psutil when available; falls back to reading /proc directly on Linux
so the scanner still works in minimal environments.
"""
import json
import os
import time

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "suspicious_processes.json")

# psutil's non-blocking cpu_percent() always returns a meaningless 0.0 on
# the first call for a given process handle - it needs a "prime" call, a
# gap, then a second call to measure real usage over that interval. This
# sample window is that gap.
CPU_SAMPLE_SECONDS = 0.2


def _load_rules():
    with open(RULES_PATH) as f:
        return json.load(f)


def _iter_processes_psutil():
    procs = list(psutil.process_iter(["pid", "name", "exe", "cmdline"]))

    for p in procs:
        try:
            p.cpu_percent(None)  # prime; return value is meaningless here
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    time.sleep(CPU_SAMPLE_SECONDS)

    for p in procs:
        try:
            info = p.info
            cpu = p.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        yield {
            "pid": info.get("pid"),
            "name": info.get("name") or "",
            "exe": info.get("exe") or "",
            "cpu_percent": cpu or 0,
            "cmdline": " ".join(info.get("cmdline") or []),
        }


def _iter_processes_proc():
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/comm") as f:
                name = f.read().strip()
            exe = os.readlink(f"/proc/{pid}/exe") if os.path.exists(f"/proc/{pid}/exe") else ""
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode(errors="ignore").strip()
            yield {"pid": int(pid), "name": name, "exe": exe, "cpu_percent": 0, "cmdline": cmdline}
        except (OSError, ProcessLookupError):
            continue


def scan():
    rules = _load_rules()
    findings = []
    processes = _iter_processes_psutil() if HAVE_PSUTIL else _iter_processes_proc()

    for proc in processes:
        name = proc["name"].lower()
        exe = proc["exe"]

        # Exact match on process name, not substring - "nc" as a substring
        # check would also match completely unrelated processes like
        # "systemd-timesyncd" or "*-launcher" (anything containing "nc").
        if name in rules["suspicious_names"]:
            findings.append({
                "scanner": "process_scanner",
                "severity": "high",
                "title": f"Suspicious process name: {proc['name']}",
                "description": "Process name matches a known suspicious tool signature.",
                "evidence": proc,
            })

        if exe and any(exe.startswith(p) for p in rules["suspicious_paths"]):
            findings.append({
                "scanner": "process_scanner",
                "severity": "medium",
                "title": f"Process running from suspicious path: {exe}",
                "description": "Executable is running from a world-writable or temp directory.",
                "evidence": proc,
            })

        if proc["cpu_percent"] >= rules.get("max_cpu_percent", 90):
            findings.append({
                "scanner": "process_scanner",
                "severity": "low",
                "title": f"High CPU usage process: {proc['name']}",
                "description": "Process is consuming an unusually high share of CPU.",
                "evidence": proc,
            })

    return findings


if __name__ == "__main__":
    for finding in scan():
        print(finding)
