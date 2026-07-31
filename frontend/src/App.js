import React, { useEffect, useState } from "react";
import { runScan, downloadPdf, listScans, getScan, getMonitorStatus } from "./api";
import { formatTimestamp } from "./format";
import RiskGauge from "./components/RiskGauge";
import FindingsTable from "./components/FindingsTable";
import ScanHistory from "./components/ScanHistory";

const LIVE_POLL_INTERVAL_MS = 10000;

export default function App() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [viewingScanId, setViewingScanId] = useState(null);
  const [error, setError] = useState(null);
  const [scans, setScans] = useState([]);
  const [monitorStatus, setMonitorStatus] = useState(null);
  const [liveEnabled, setLiveEnabled] = useState(true);

  async function refreshHistory() {
    try {
      setScans(await listScans());
    } catch {
      // History is a secondary view; a failed refresh shouldn't block scanning.
    }
  }

  useEffect(() => {
    refreshHistory();
    getMonitorStatus()
      .then(setMonitorStatus)
      .catch(() => {
        // Background-monitor status is informational only; ignore failures.
      });
  }, []);

  // Polls for scans completed by any source (the background monitor, or a
  // scan run from another tab/user) and follows the latest one - but only
  // when the viewer isn't deliberately looking at an older scan already.
  useEffect(() => {
    if (!liveEnabled) return undefined;

    const wasViewingLatest = viewingScanId === null || viewingScanId === scans[0]?.id;

    const id = setInterval(async () => {
      try {
        const latest = await listScans();
        setScans(latest);

        const newestId = latest[0]?.id;
        if (wasViewingLatest && newestId !== undefined && newestId !== viewingScanId) {
          setReport(await getScan(newestId));
          setViewingScanId(newestId);
        }
      } catch {
        // Transient poll failure - just try again next tick.
      }
    }, LIVE_POLL_INTERVAL_MS);

    return () => clearInterval(id);
  }, [liveEnabled, scans, viewingScanId]);

  async function handleScan() {
    setLoading(true);
    setError(null);
    try {
      const result = await runScan();
      setReport(result);
      setViewingScanId(result.scan_id ?? null);
      await refreshHistory();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleSelectScan(scanId) {
    setError(null);
    setViewingScanId(scanId);
    try {
      setReport(await getScan(scanId));
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (err) {
      setError(err.message);
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
          <p className="page-subtitle">
            OS security scanner &mdash; processes, ports, users, and more.
            {monitorStatus?.enabled && ` Background scanning every ${monitorStatus.interval_seconds}s.`}
          </p>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <button
            className={`tab ${liveEnabled ? "active" : ""}`}
            onClick={() => setLiveEnabled((v) => !v)}
            title={liveEnabled ? "Pause auto-refresh" : "Resume auto-refresh"}
          >
            <span className={`live-dot ${liveEnabled ? "" : "live-dot-off"}`} />
            Live
          </button>
          <button className="btn btn-primary" onClick={handleScan} disabled={loading}>
            {loading && <span className="spinner" />}
            {loading ? "Scanning..." : "Run Scan"}
          </button>
        </div>
      </header>

      {error && (
        <div className="alert alert-error">
          <span>Error: {error}</span>
        </div>
      )}

      {report && scans.length > 0 && viewingScanId !== scans[0].id && (
        <div className="alert alert-info">
          <span>Viewing a past scan{report.generated_at ? ` from ${formatTimestamp(report.generated_at)}` : ""}.</span>
          <button className="btn-link" onClick={() => handleSelectScan(scans[0].id)}>
            View latest
          </button>
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
        <ScanHistory scans={scans} selectedId={viewingScanId} onSelect={handleSelectScan} />
      </div>
    </div>
  );
}
