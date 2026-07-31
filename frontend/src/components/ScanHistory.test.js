import { render, screen } from "@testing-library/react";
import ScanHistory from "./ScanHistory";

test("renders placeholder text when there are no past scans", () => {
  render(<ScanHistory scans={[]} />);
  expect(screen.getByText("No past scans yet.")).toBeInTheDocument();
});

test("renders placeholder text when scans is undefined", () => {
  render(<ScanHistory />);
  expect(screen.getByText("No past scans yet.")).toBeInTheDocument();
});

test("renders a table row per scan with its details", () => {
  const scans = [
    { id: 2, started_at: "2026-07-31T09:00:00Z", risk_score: 18, risk_level: "low", total_findings: 12 },
    { id: 1, started_at: "2026-07-30T09:00:00Z", risk_score: 90, risk_level: "critical", total_findings: 126 },
  ];

  render(<ScanHistory scans={scans} />);

  expect(screen.getByText("18")).toBeInTheDocument();
  expect(screen.getByText("90")).toBeInTheDocument();
  expect(screen.getByText("low")).toBeInTheDocument();
  expect(screen.getByText("critical")).toBeInTheDocument();
  // header row + one row per scan
  expect(screen.getAllByRole("row")).toHaveLength(scans.length + 1);
});
