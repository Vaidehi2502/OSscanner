from utils.score import score_findings, risk_level


def test_score_findings_empty():
    assert score_findings([]) == 0


def test_score_findings_sums_severity_weights():
    findings = [{"severity": "low"}, {"severity": "medium"}, {"severity": "high"}]
    assert score_findings(findings) == 1 + 3 + 7


def test_score_findings_caps_at_max_score():
    findings = [{"severity": "critical"}] * 100
    assert score_findings(findings) == 100


def test_score_findings_unknown_severity_defaults_to_low_weight():
    assert score_findings([{"severity": "unknown"}]) == 1


def test_score_findings_volume_of_low_severity_does_not_saturate():
    # A large pile of routine low-severity findings (e.g. one per outbound
    # network connection) shouldn't alone push the score into CRITICAL.
    findings = [{"severity": "low"}] * 126
    assert score_findings(findings) < 75


def test_score_findings_diminishing_returns_for_repeated_severity():
    # Ten low findings should score less than 10x a single low finding.
    one = score_findings([{"severity": "low"}])
    ten = score_findings([{"severity": "low"}] * 10)
    assert one == 1
    assert ten < one * 10


def test_risk_level_thresholds():
    assert risk_level(0) == "none"
    assert risk_level(1) == "low"
    assert risk_level(20) == "medium"
    assert risk_level(45) == "high"
    assert risk_level(75) == "critical"
    assert risk_level(100) == "critical"
