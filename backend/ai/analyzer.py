"""Aggregates raw scanner findings into a scored, deduplicated security report.

This is a rule-based baseline (no external model call) so the whole
pipeline runs offline. Swap `summarize()` for an LLM call later if you
want natural-language narrative summaries on top of the scored findings.
"""
import sys
import os
from collections import Counter
from datetime import datetime, timezone

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from utils.score import score_findings, risk_level, SEVERITY_WEIGHTS  # noqa: E402


def _dedupe(findings):
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("scanner"), f.get("title"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def analyze(findings):
    """Turn a flat list of scanner findings into a structured report."""
    findings = _dedupe(findings)
    score = score_findings(findings)
    severity_counts = Counter(f.get("severity", "low") for f in findings)

    by_scanner = Counter(f.get("scanner", "unknown") for f in findings)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "risk_score": score,
        "risk_level": risk_level(score),
        "severity_counts": dict(severity_counts),
        "findings_by_scanner": dict(by_scanner),
        "findings": findings,
    }


def summarize(report):
    """Produce a short human-readable summary line for the report."""
    if report["total_findings"] == 0:
        return "No issues detected. System appears clean."

    top = sorted(
        report["findings"],
        key=lambda f: SEVERITY_WEIGHTS.get(f.get("severity", "low"), 1),
        reverse=True,
    )[:3]
    top_titles = "; ".join(f["title"] for f in top)
    return (
        f"Risk level: {report['risk_level'].upper()} (score {report['risk_score']}/100). "
        f"{report['total_findings']} findings across {len(report['findings_by_scanner'])} scanners. "
        f"Top issues: {top_titles}."
    )


if __name__ == "__main__":
    from scanners import run_all

    result = analyze(run_all())
    print(summarize(result))
