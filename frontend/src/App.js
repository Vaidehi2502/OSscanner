import React, { useEffect, useState } from "react";
import { runScan, downloadPdf, listScans } from "./api";
import RiskGauge from "./components/RiskGauge";
import FindingsTable from "./components/FindingsTable";
import ScanHistory from "./components/ScanHistory";

export default function App() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scans, setScans] = useState([]);

  async function refreshHistory() {
    try {
      setScans(await listScans());
    } catch {
      // History is a secondary view; a failed refresh shouldn't block scanning.
    }
  }

  useEffect(() => {
    refreshHistory();
  }, []);

  async function handleScan() {
    setLoading(true);
    setError(null);
    try {
      const result = await runScan();
      setReport(result);
      await refreshHistory();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleDownload(scanId) {
    try {
      await downloadPdf(scanId);
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1 className="page-title">SentinelOS</h1>
          <p className="page-subtitle">OS security scanner &mdash; processes, ports, users, and more.</p>
        </div>
        <button className="btn btn-primary" onClick={handleScan} disabled={loading}>
          {loading && <span className="spinner" />}
          {loading ? "Scanning..." : "Run Scan"}
        </button>
      </header>

      {error && (
        <div className="alert alert-error">
          <span>Error: {error}</span>
        </div>
      )}

      {report && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <RiskGauge score={report.risk_score} level={report.risk_level} />
            {report.scan_id && (
              <button className="btn-link" onClick={() => handleDownload(report.scan_id)}>
                Download report
              </button>
            )}
          </div>

          <p className="text-dim" style={{ marginTop: 20, lineHeight: 1.6 }}>
            {report.summary}
          </p>

          <div className="section-title" style={{ marginTop: 32 }}>
            {`Findings (${report.total_findings})`}
          </div>
          <FindingsTable findings={report.findings} />
        </div>
      )}

      {!report && !loading && (
        <div className="card empty-state">
          Click "Run Scan" to check this machine for suspicious processes, ports,
          startup items, and more.
        </div>
      )}

      <div className="card-section card">
        <div className="section-title">Scan history</div>
        <ScanHistory scans={scans} />
      </div>
    </div>
  );
}
