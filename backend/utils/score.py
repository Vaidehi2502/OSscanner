"""Risk scoring helpers shared by scanners and the AI analyzer.

Each scanner finding is a dict with at least a "severity" key
("low" | "medium" | "high" | "critical"). This module turns a list
of findings into a single 0-100 risk score.
"""
import math

SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 3,
    "high": 7,
    "critical": 12,
}

MAX_SCORE = 100


def score_findings(findings):
    """Weight findings by severity and squash into a 0-100 scale.

    Repeated findings of the same severity are summed with diminishing
    returns (weight * sqrt(count)) rather than added linearly, so a large
    pile of routine low-severity findings (e.g. one per outbound network
    connection) can't by itself saturate the score to CRITICAL.
    """
    if not findings:
        return 0

    counts = {}
    for f in findings:
        severity = f.get("severity", "low")
        counts[severity] = counts.get(severity, 0) + 1

    raw = sum(SEVERITY_WEIGHTS.get(sev, 1) * math.sqrt(n) for sev, n in counts.items())
    return min(MAX_SCORE, round(raw))


def risk_level(score):
    if score >= 75:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "none"
