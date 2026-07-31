"""Runs every scanner, builds a report, and persists it - the single
canonical scan pipeline shared by the POST /api/scan route and the
background monitor, so there's exactly one place this logic lives.
"""
from scanners import run_all
from ai.analyzer import analyze, summarize
from database import db


def run_and_persist_scan():
    findings = run_all()
    report = analyze(findings)
    report["summary"] = summarize(report)
    report["scan_id"] = db.save_report(report)
    return report
