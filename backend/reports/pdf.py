"""Renders an analyzed scan report to PDF.

Uses reportlab when installed. If it isn't available, falls back to
writing a plain-text report with the same content so report generation
never hard-fails just because an optional dependency is missing.
"""
import os

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    HAVE_REPORTLAB = True
except ImportError:
    HAVE_REPORTLAB = False

SEVERITY_COLORS = {
    "critical": "#B00020",
    "high": "#E65100",
    "medium": "#F9A825",
    "low": "#2E7D32",
}


def _write_text_fallback(report, output_path):
    txt_path = os.path.splitext(output_path)[0] + ".txt"
    with open(txt_path, "w") as f:
        f.write(f"SentinelOS Scan Report - {report['generated_at']}\n")
        f.write(f"Risk level: {report['risk_level'].upper()} (score {report['risk_score']}/100)\n")
        f.write(f"Total findings: {report['total_findings']}\n\n")
        for finding in report["findings"]:
            f.write(f"[{finding['severity'].upper()}] {finding['title']} ({finding['scanner']})\n")
            f.write(f"  {finding['description']}\n")
            if finding.get("evidence"):
                f.write(f"  evidence: {finding['evidence']}\n")
            f.write("\n")
    return txt_path


def generate_pdf_report(report, output_path="scan_report.pdf"):
    """Write `report` (as produced by ai.analyzer.analyze) to `output_path`.

    Returns the actual path written (may differ if reportlab is missing
    and the fallback .txt path was used instead).
    """
    if not HAVE_REPORTLAB:
        return _write_text_fallback(report, output_path)

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    story = [
        Paragraph("SentinelOS Scan Report", styles["Title"]),
        Paragraph(f"Generated: {report['generated_at']}", styles["Normal"]),
        Paragraph(
            f"Risk level: <b>{report['risk_level'].upper()}</b> "
            f"(score {report['risk_score']}/100) — {report['total_findings']} findings",
            styles["Normal"],
        ),
        Spacer(1, 16),
    ]

    table_data = [["Severity", "Scanner", "Title", "Description"]]
    for finding in report["findings"]:
        table_data.append([
            finding.get("severity", "").upper(),
            finding.get("scanner", ""),
            finding.get("title", ""),
            finding.get("description", ""),
        ])

    table = Table(table_data, repeatRows=1, colWidths=[60, 80, 150, 200])
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for row_idx, finding in enumerate(report["findings"], start=1):
        color = SEVERITY_COLORS.get(finding.get("severity", "low"), "#000000")
        style_commands.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), colors.HexColor(color)))

    table.setStyle(TableStyle(style_commands))
    story.append(table)

    doc.build(story)
    return output_path
