import React from "react";

const LEVEL_COLORS = {
  none: "#2E7D32",
  low: "#2E7D32",
  medium: "#F9A825",
  high: "#E65100",
  critical: "#B00020",
};

export default function RiskGauge({ score, level }) {
  const color = LEVEL_COLORS[level] || "#555";

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
      <div
        style={{
          width: 72,
          height: 72,
          borderRadius: "50%",
          border: `6px solid ${color}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 20,
          fontWeight: 700,
        }}
      >
        {score}
      </div>
      <div>
        <div style={{ fontSize: 12, opacity: 0.7 }}>RISK LEVEL</div>
        <div style={{ fontSize: 22, fontWeight: 700, color, textTransform: "uppercase" }}>
          {level}
        </div>
      </div>
    </div>
  );
}
