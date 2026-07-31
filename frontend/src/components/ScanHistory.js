import React from "react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";

function formatTimestamp(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) +
        " " +
        d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

export default function ScanHistory({ scans }) {
  if (!scans || scans.length === 0) {
    return <p className="text-dim">No past scans yet.</p>;
  }

  // The API returns newest-first; charts read left-to-right chronologically.
  const chronological = [...scans].reverse().map((s) => ({
    ...s,
    label: formatTimestamp(s.started_at),
  }));

  return (
    <div>
      <div style={{ width: "100%", height: 200 }}>
        <ResponsiveContainer>
          <LineChart data={chronological} margin={{ top: 8, right: 16, left: -16, bottom: 0 }}>
            <CartesianGrid stroke="#262b36" strokeDasharray="3 3" />
            <XAxis dataKey="label" tick={{ fill: "#6b7280", fontSize: 12 }} />
            <YAxis domain={[0, 100]} tick={{ fill: "#6b7280", fontSize: 12 }} />
            <Tooltip
              contentStyle={{ background: "#14171f", border: "1px solid #262b36", borderRadius: 8 }}
              labelStyle={{ color: "#e8e9ec" }}
            />
            <Line
              type="monotone"
              dataKey="risk_score"
              name="Risk score"
              stroke="#4c5fd8"
              strokeWidth={2}
              dot={{ r: 3 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <table className="data-table" style={{ marginTop: 16 }}>
        <thead>
          <tr>
            <th>Date</th>
            <th>Score</th>
            <th>Level</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((s) => (
            <tr key={s.id}>
              <td className="text-dim">{formatTimestamp(s.started_at)}</td>
              <td>{s.risk_score}</td>
              <td>
                <span className={`pill pill-${s.risk_level}`}>{s.risk_level}</span>
              </td>
              <td className="text-dim">{s.total_findings}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
