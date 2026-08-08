import React, { useEffect, useState } from "react";
import {
  getRealtimeStatus,
  listRealtimeEvents,
  listQuarantine,
  restoreQuarantineItem,
  deleteQuarantineItem,
} from "../api";
import { formatTimestamp } from "../format";

const POLL_INTERVAL_MS = 10000;

export default function RealTimeProtection() {
  const [status, setStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [quarantine, setQuarantine] = useState([]);
  const [error, setError] = useState(null);
  const [busyId, setBusyId] = useState(null);

  async function refresh() {
    try {
      const [s, e, q] = await Promise.all([getRealtimeStatus(), listRealtimeEvents(20), listQuarantine()]);
      setStatus(s);
      setEvents(e || []);
      setQuarantine(q || []);
    } catch {
      // Secondary panel - a failed refresh shouldn't block the rest of the dashboard.
    }
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, []);

  async function handleRestore(id) {
    setBusyId(id);
    setError(null);
    try {
      await restoreQuarantineItem(id);
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(id) {
    setBusyId(id);
    setError(null);
    try {
      await deleteQuarantineItem(id);
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyId(null);
    }
  }

  const activeQuarantine = quarantine.filter((q) => q.status === "quarantined");
  const watchedCount = status?.watched_paths?.length || 0;

  return (
    <div className="card-section card">
      <div className="section-title">
        <span className={`live-dot ${status?.enabled ? "" : "live-dot-off"}`} />
        Real-time protection
        <span className="count">
          {status?.enabled ? `watching ${watchedCount} location${watchedCount === 1 ? "" : "s"}` : "off"}
        </span>
      </div>

      {!status?.enabled && (
        <p className="text-dim">
          Not running. Set <code>REALTIME_PROTECTION=1</code> on the backend to watch Downloads, Desktop, Documents,
          removable media, and temp directories for new files and quarantine anything malicious on sight.
        </p>
      )}

      {error && (
        <div className="alert alert-error">
          <span>Error: {error}</span>
        </div>
      )}

      <div className="section-title" style={{ fontSize: 14, marginTop: 16 }}>
        {`Quarantined files (${activeQuarantine.length})`}
      </div>
      {activeQuarantine.length === 0 ? (
        <p className="text-dim">Nothing in quarantine.</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Detected</th>
              <th>Severity</th>
              <th>Original path</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {activeQuarantine.map((item) => (
              <tr key={item.id}>
                <td className="text-dim">{formatTimestamp(item.detected_at)}</td>
                <td>
                  <span className={`pill pill-${item.severity}`}>{item.severity}</span>
                </td>
                <td>{item.original_path}</td>
                <td>
                  <div style={{ display: "flex", gap: 12 }}>
                    <button className="btn-link" disabled={busyId === item.id} onClick={() => handleRestore(item.id)}>
                      Restore
                    </button>
                    <button className="btn-link" disabled={busyId === item.id} onClick={() => handleDelete(item.id)}>
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="section-title" style={{ fontSize: 14, marginTop: 24 }}>
        Recent detections
      </div>
      {events.length === 0 ? (
        <p className="text-dim">No detections yet.</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Detected</th>
              <th>Severity</th>
              <th>Path</th>
              <th>Action taken</th>
            </tr>
          </thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.id}>
                <td className="text-dim">{formatTimestamp(ev.detected_at)}</td>
                <td>
                  <span className={`pill pill-${ev.severity}`}>{ev.severity}</span>
                </td>
                <td>{ev.path}</td>
                <td className="text-dim">{ev.quarantined ? "Quarantined" : "Alerted only"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
