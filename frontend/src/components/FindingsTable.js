import React from "react";

const SEVERITY_COLORS = {
  low: "#2E7D32",
  medium: "#F9A825",
  high: "#E65100",
  critical: "#B00020",
};

export default function FindingsTable({ findings }) {
  if (!findings || findings.length === 0) {
    return <p style={{ opacity: 0.7 }}>No findings to display.</p>;
  }

  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
      <thead>
        <tr style={{ textAlign: "left", borderBottom: "1px solid #333" }}>
          <th style={{ padding: 8 }}>Severity</th>
          <th style={{ padding: 8 }}>Scanner</th>
          <th style={{ padding: 8 }}>Title</th>
          <th style={{ padding: 8 }}>Description</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f, i) => (
          <tr key={i} style={{ borderBottom: "1px solid #222" }}>
            <td style={{ padding: 8 }}>
              <span
                style={{
                  color: SEVERITY_COLORS[f.severity] || "#999",
                  fontWeight: 700,
                  textTransform: "uppercase",
                  fontSize: 12,
                }}
              >
                {f.severity}
              </span>
            </td>
            <td style={{ padding: 8, opacity: 0.8 }}>{f.scanner}</td>
            <td style={{ padding: 8 }}>{f.title}</td>
            <td style={{ padding: 8, opacity: 0.8 }}>{f.description}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
