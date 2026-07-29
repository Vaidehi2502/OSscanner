from ai.analyzer import analyze, summarize


def _finding(scanner, title, severity="low"):
    return {"scanner": scanner, "title": title, "severity": severity, "description": "", "evidence": {}}


def test_analyze_dedupes_same_scanner_and_title():
    findings = [
        _finding("port", "Open port 22"),
        _finding("port", "Open port 22"),
        _finding("process", "Suspicious process"),
    ]
    report = analyze(findings)
    assert report["total_findings"] == 2


def test_analyze_empty_findings():
    report = analyze([])
    assert report["total_findings"] == 0
    assert report["risk_score"] == 0
    assert report["risk_level"] == "none"


def test_analyze_counts_by_scanner_and_severity():
    findings = [
        _finding("port", "Open port 22", "high"),
        _finding("process", "Suspicious process", "low"),
    ]
    report = analyze(findings)
    assert report["findings_by_scanner"] == {"port": 1, "process": 1}
    assert report["severity_counts"] == {"high": 1, "low": 1}


def test_summarize_no_findings():
    report = analyze([])
    assert summarize(report) == "No issues detected. System appears clean."


def test_summarize_top_issues_ranked_by_actual_severity_not_alphabetically():
    # Four distinct severities so the top-3 truncation actually has to choose.
    # Alphabetically "critical" < "high" < "low" < "medium", which is the
    # opposite of true severity order - a naive string sort would drop the
    # critical finding and keep the low one instead.
    findings = [
        _finding("port", "Low issue", "low"),
        _finding("process", "Critical issue", "critical"),
        _finding("network", "Medium issue", "medium"),
        _finding("user", "High issue", "high"),
    ]
    report = analyze(findings)
    summary = summarize(report)
    assert "Critical issue" in summary
    assert "Low issue" not in summary
