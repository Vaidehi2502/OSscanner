import React, { useMemo, useState } from "react";

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const PAGE_SIZE = 20;

function matchesSearch(finding, query) {
  if (!query) return true;
  const haystack = `${finding.title} ${finding.scanner} ${finding.description || ""}`.toLowerCase();
  return haystack.includes(query.toLowerCase());
}

export default function FindingsTable({ findings }) {
  const [severityFilter, setSeverityFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings || []) {
      if (c[f.severity] !== undefined) c[f.severity] += 1;
    }
    return c;
  }, [findings]);

  const filtered = useMemo(() => {
    const sorted = [...(findings || [])].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );
    return sorted
      .filter((f) => severityFilter === "all" || f.severity === severityFilter)
      .filter((f) => matchesSearch(f, query));
  }, [findings, severityFilter, query]);

  if (!findings || findings.length === 0) {
    return <p className="text-dim">No findings to display.</p>;
  }

  const visible = filtered.slice(0, visibleCount);

  function selectSeverity(severity) {
    setSeverityFilter(severity);
    setVisibleCount(PAGE_SIZE);
  }

  return (
    <div>
      <div className="tabs">
        <button
          className={`tab ${severityFilter === "all" ? "active" : ""}`}
          onClick={() => selectSeverity("all")}
        >
          All ({findings.length})
        </button>
        {SEVERITY_ORDER.filter((sev) => counts[sev] > 0).map((sev) => (
          <button
            key={sev}
            className={`tab ${severityFilter === sev ? "active" : ""}`}
            onClick={() => selectSeverity(sev)}
          >
            {sev[0].toUpperCase() + sev.slice(1)} ({counts[sev]})
          </button>
        ))}
      </div>

      <div className="toolbar">
        <input
          className="input"
          type="text"
          placeholder="Search findings..."
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setVisibleCount(PAGE_SIZE);
          }}
        />
      </div>

      {filtered.length === 0 ? (
        <p className="text-dim">No findings match this filter.</p>
      ) : (
        <>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Scanner</th>
                <th>Title</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((f, i) => (
                <tr key={i}>
                  <td>
                    <span className={`pill pill-${f.severity}`}>{f.severity}</span>
                  </td>
                  <td className="text-dim">{f.scanner}</td>
                  <td>{f.title}</td>
                  <td className="text-dim">{f.description}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {visibleCount < filtered.length && (
            <div className="show-more-row">
              <button
                className="btn"
                style={{ background: "transparent", border: "1px solid var(--border)", color: "var(--text-dim)" }}
                onClick={() => setVisibleCount((n) => n + PAGE_SIZE)}
              >
                Show more ({filtered.length - visibleCount} remaining)
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
