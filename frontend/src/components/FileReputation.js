import React, { useEffect, useState } from "react";
import { listFileReputation } from "../api";
import { formatTimestamp } from "../format";

const POLL_INTERVAL_MS = 10000;

function truncateHash(hash) {
  return hash.length > 20 ? `${hash.slice(0, 10)}...${hash.slice(-8)}` : hash;
}

export default function FileReputation() {
  const [entries, setEntries] = useState([]);

  async function refresh() {
    try {
      setEntries((await listFileReputation(20)) || []);
    } catch {
      // Secondary panel - a failed refresh shouldn't block the rest of the dashboard.
    }
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, []);

  const flaggedCount = entries.filter((e) => e.risk !== "none").length;

  return (
    <div className="card-section card">
      <div className="section-title">
        File reputation
        <span className="count">{`${flaggedCount} flagged / ${entries.length} known`}</span>
      </div>

      {entries.length === 0 ? (
        <p className="text-dim">
          No files hashed yet. Entries appear here as real-time protection observes files and as scans produce
          file/YARA findings.
        </p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Hash</th>
              <th>Risk</th>
              <th>Detections</th>
              <th>First seen</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr key={entry.hash}>
                <td className="text-dim" title={entry.hash}>
                  {truncateHash(entry.hash)}
                </td>
                <td>
                  <span className={`pill pill-${entry.risk}`}>{entry.risk}</span>
                </td>
                <td>{entry.detection_count}</td>
                <td className="text-dim">{formatTimestamp(entry.first_seen)}</td>
                <td className="text-dim">{formatTimestamp(entry.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
