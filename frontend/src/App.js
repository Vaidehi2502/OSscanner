import React, { useState } from "react";
import { runScan, pdfUrl } from "./api";
import RiskGauge from "./components/RiskGauge";
import FindingsTable from "./components/FindingsTable";

export default function App() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleScan() {
    setLoading(true);
    setError(null);
    try {
      const result = await runScan();
      setReport(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ maxWidth: 960, margin: "0 auto", padding: "32px 16px" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h1 style={{ margin: 0 }}>SentinelOS</h1>
        <button
          onClick={handleScan}
          disabled={loading}
          style={{
            padding: "10px 20px",
            borderRadius: 6,
            border: "none",
            background: "#3949AB",
            color: "#fff",
            fontWeight: 600,
            cursor: loading ? "not-allowed" : "pointer",
          }}
        >
          {loading ? "Scanning..." : "Run Scan"}
        </button>
      </header>

      {error && <p style={{ color: "#E65100" }}>Error: {error}</p>}

      {report && (
        <section style={{ marginTop: 32 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <RiskGauge score={report.risk_score} level={report.risk_level} />
            {report.scan_id && (
              <a
                href={pdfUrl(report.scan_id)}
                style={{ color: "#90CAF9" }}
                target="_blank"
                rel="noreferrer"
              >
                Download report
              </a>
            )}
          </div>

          <p style={{ opacity: 0.8, marginTop: 16 }}>{report.summary}</p>

          <h2 style={{ marginTop: 32 }}>Findings ({report.total_findings})</h2>
          <FindingsTable findings={report.findings} />
        </section>
      )}

      {!report && !loading && (
        <p style={{ marginTop: 32, opacity: 0.6 }}>
          Click "Run Scan" to check this machine for suspicious processes, ports,
          startup items, and more.
        </p>
      )}
    </div>
  );
}
