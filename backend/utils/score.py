"""Risk scoring helpers shared by scanners and the AI analyzer.

Each scanner finding is a dict with at least a "severity" key
("low" | "medium" | "high" | "critical"). This module turns a list
of findings into a single 0-100 risk score.
"""

SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 3,
    "high": 7,
    "critical": 12,
}

MAX_SCORE = 100


def score_findings(findings):
    """Sum severity weights and squash into a 0-100 scale."""
    if not findings:
        return 0

    raw = sum(SEVERITY_WEIGHTS.get(f.get("severity", "low"), 1) for f in findings)
    return min(MAX_SCORE, raw)


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
