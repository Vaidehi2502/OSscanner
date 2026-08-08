import React, { useEffect, useState } from "react";
import { getNetworkThreatStatus, listNetworkThreatEvents } from "../api";
import { formatTimestamp } from "../format";

const POLL_INTERVAL_MS = 10000;

export default function NetworkThreatDetection() {
  const [status, setStatus] = useState(null);
  const [events, setEvents] = useState([]);

  async function refresh() {
    try {
      const [s, e] = await Promise.all([getNetworkThreatStatus(), listNetworkThreatEvents(20)]);
      setStatus(s);
      setEvents(e || []);
    } catch {
      // Secondary panel - a failed refresh shouldn't block the rest of the dashboard.
    }
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="card-section card">
      <div className="section-title">
        <span className={`live-dot ${status?.enabled ? "" : "live-dot-off"}`} />
        Network threat detection
        <span className="count">{status?.enabled ? `polling every ${status.poll_seconds}s` : "off"}</span>
      </div>

      {!status?.enabled && (
        <p className="text-dim">
          Not running. Set <code>NETWORK_THREAT_DETECTION=1</code> on the backend to watch active connections for
          known-malicious IPs/ports, new external connections, and possible port scans as they happen.
        </p>
      )}

      <div className="section-title" style={{ fontSize: 14, marginTop: 16 }}>
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
              <th>Remote endpoint</th>
              <th>Title</th>
            </tr>
          </thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.id}>
                <td className="text-dim">{formatTimestamp(ev.detected_at)}</td>
                <td>
                  <span className={`pill pill-${ev.severity}`}>{ev.severity}</span>
                </td>
                <td>
                  {ev.remote_ip}
                  {ev.remote_port ? `:${ev.remote_port}` : ""}
                </td>
                <td className="text-dim">{ev.title}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
