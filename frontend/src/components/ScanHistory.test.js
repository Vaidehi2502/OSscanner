import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

test("shows an Antivirus badge for av scans and a Full badge otherwise", () => {
  const scans = [
    { id: 2, started_at: "2026-07-31T09:00:00Z", risk_score: 18, risk_level: "low", total_findings: 1, scan_type: "av" },
    { id: 1, started_at: "2026-07-30T09:00:00Z", risk_score: 90, risk_level: "critical", total_findings: 1, scan_type: "full" },
  ];

  render(<ScanHistory scans={scans} />);

  expect(screen.getByText("Antivirus")).toBeInTheDocument();
  expect(screen.getByText("Full")).toBeInTheDocument();
});

test("clicking a row calls onSelect with that scan's id", async () => {
  const scans = [
    { id: 2, started_at: "2026-07-31T09:00:00Z", risk_score: 18, risk_level: "low", total_findings: 1 },
  ];
  const onSelect = jest.fn();
  const user = userEvent.setup();

  render(<ScanHistory scans={scans} onSelect={onSelect} />);
  await user.click(screen.getByRole("row", { name: /View scan from/ }));

  expect(onSelect).toHaveBeenCalledWith(2);
});

test("highlights the selected row", () => {
  const scans = [
    { id: 2, started_at: "2026-07-31T09:00:00Z", risk_score: 18, risk_level: "low", total_findings: 1 },
    { id: 1, started_at: "2026-07-30T09:00:00Z", risk_score: 90, risk_level: "critical", total_findings: 1 },
  ];

  render(<ScanHistory scans={scans} selectedId={1} />);

  expect(screen.getByRole("row", { name: /View scan from Jul 30/ })).toHaveClass("row-selected");
  expect(screen.getByRole("row", { name: /View scan from Jul 31/ })).not.toHaveClass("row-selected");
});
