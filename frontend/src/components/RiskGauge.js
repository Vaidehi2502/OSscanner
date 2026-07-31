import React from "react";

const LEVEL_COLORS = {
  none: "#43a047",
  low: "#43a047",
  medium: "#f5a623",
  high: "#ef6c00",
  critical: "#ef4444",
};

export default function RiskGauge({ score, level }) {
  const color = LEVEL_COLORS[level] || "#6b7280";
  const pct = Math.max(0, Math.min(100, score || 0));

  return (
    <div className="risk-gauge">
      <div
        className="risk-ring"
        style={{
          background: `conic-gradient(${color} ${pct * 3.6}deg, #262b36 0deg)`,
        }}
      >
        <div className="risk-ring-inner">{score}</div>
      </div>
      <div>
        <div className="risk-label-eyebrow">Risk level</div>
        <div className="risk-label-value" style={{ color }}>
          {level}
        </div>
      </div>
    </div>
  );
}
