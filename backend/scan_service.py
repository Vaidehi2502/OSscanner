"""Runs scanners, builds a report, and persists it - the single canonical
scan pipeline shared by the scan routes (full and antivirus-only) and the
background monitor, so there's exactly one place this logic lives.
"""
from scanners import run_all, run_selected
from ai.analyzer import analyze, summarize
from database import db

# The antivirus-focused scan runs only the malware-detection scanners
# (dropped-executable heuristics + YARA signature matching), skipping the
# OS-hygiene checks (processes, ports, users, ...) so it's fast to run on
# demand and its report reads as a dedicated AV result rather than a mix.
AV_SCANNERS = ("file", "yara")


def _finalize(findings, scan_type):
    report = analyze(findings)
    report["summary"] = summarize(report)
    report["scan_type"] = scan_type
    report["scan_id"] = db.save_report(report, scan_type=scan_type)
    return report


def run_and_persist_scan():
    return _finalize(run_all(), "full")


def run_and_persist_av_scan():
    return _finalize(run_selected(AV_SCANNERS), "av")
