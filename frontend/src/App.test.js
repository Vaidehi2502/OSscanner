import { act } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App";
import * as api from "./api";

jest.mock("./api");

beforeEach(() => {
  api.listScans.mockResolvedValue([]);
});

afterEach(() => {
  jest.clearAllMocks();
});

// handleScan/handleDownload are async and update state (loading, report,
// error) after their awaited call resolves. Since the mocked promises
// resolve immediately, user.click()'s own flushing doesn't reliably cover
// every one of those trailing setState calls - wrapping the click itself
// in act() flushes all of them within one boundary instead of relying on
// incidental timing.
async function clickAndFlush(user, element) {
  await act(async () => {
    await user.click(element);
  });
}

test("shows the initial prompt before any scan has run", async () => {
  render(<App />);
  expect(screen.getByText(/Click "Run Scan"/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Download report" })).not.toBeInTheDocument();
  // Flush the mount-time listScans() fetch so its setState doesn't leak into the next test.
  await act(async () => {});
});

test("loads and displays past scans on mount", async () => {
  api.listScans.mockResolvedValue([
    { id: 2, started_at: "2026-07-31T09:00:00Z", risk_score: 18, risk_level: "low", total_findings: 12 },
    { id: 1, started_at: "2026-07-30T09:00:00Z", risk_score: 90, risk_level: "critical", total_findings: 126 },
  ]);

  render(<App />);

  expect(await screen.findByText("18")).toBeInTheDocument();
  expect(screen.getByText("90")).toBeInTheDocument();
});

test("refreshes scan history after running a new scan", async () => {
  api.listScans.mockResolvedValueOnce([]);
  api.runScan.mockResolvedValue({
    scan_id: 9,
    risk_score: 10,
    risk_level: "low",
    total_findings: 0,
    summary: "clean",
    findings: [],
  });

  const user = userEvent.setup();
  render(<App />);
  await screen.findByText("No past scans yet.");

  api.listScans.mockResolvedValueOnce([
    { id: 9, started_at: "2026-07-31T09:00:00Z", risk_score: 10, risk_level: "low", total_findings: 0 },
  ]);
  await clickAndFlush(user, screen.getByRole("button", { name: "Run Scan" }));

  expect(api.listScans).toHaveBeenCalledTimes(2);
  expect(screen.getByRole("cell", { name: "10" })).toBeInTheDocument();
});

test("running a scan displays the report and findings", async () => {
  api.runScan.mockResolvedValue({
    scan_id: 7,
    risk_score: 55,
    risk_level: "high",
    total_findings: 1,
    summary: "Risk level: HIGH (score 55/100). 1 findings across 1 scanners.",
    findings: [
      { severity: "high", scanner: "process_scanner", title: "Suspicious process", description: "d" },
    ],
  });

  const user = userEvent.setup();
  render(<App />);
  await clickAndFlush(user, screen.getByRole("button", { name: "Run Scan" }));

  expect(screen.getByText("Suspicious process")).toBeInTheDocument();
  expect(screen.getByText("Findings (1)")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Download report" })).toBeInTheDocument();
});

test("shows an error message when the scan request fails", async () => {
  api.runScan.mockRejectedValue(new Error("Request to /scan failed with status 401"));

  const user = userEvent.setup();
  render(<App />);
  await clickAndFlush(user, screen.getByRole("button", { name: "Run Scan" }));

  expect(screen.getByText(/Error: Request to \/scan failed with status 401/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Run Scan" })).toBeInTheDocument();
});

test("does not show a download button when the report has no scan_id", async () => {
  api.runScan.mockResolvedValue({
    risk_score: 0,
    risk_level: "none",
    total_findings: 0,
    summary: "No issues detected.",
    findings: [],
  });

  const user = userEvent.setup();
  render(<App />);
  await clickAndFlush(user, screen.getByRole("button", { name: "Run Scan" }));

  expect(screen.getByText("No issues detected.")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Download report" })).not.toBeInTheDocument();
});

test("clicking download report calls downloadPdf with the scan id", async () => {
  api.runScan.mockResolvedValue({
    scan_id: 9,
    risk_score: 10,
    risk_level: "low",
    total_findings: 0,
    summary: "clean",
    findings: [],
  });
  api.downloadPdf.mockResolvedValue(undefined);

  const user = userEvent.setup();
  render(<App />);
  await clickAndFlush(user, screen.getByRole("button", { name: "Run Scan" }));
  await clickAndFlush(user, screen.getByRole("button", { name: "Download report" }));

  expect(api.downloadPdf).toHaveBeenCalledWith(9);
});

test("shows an error message when the PDF download fails", async () => {
  api.runScan.mockResolvedValue({
    scan_id: 9,
    risk_score: 10,
    risk_level: "low",
    total_findings: 0,
    summary: "clean",
    findings: [],
  });
  api.downloadPdf.mockRejectedValue(new Error("Request to /scans/9/pdf failed with status 401"));

  const user = userEvent.setup();
  render(<App />);
  await clickAndFlush(user, screen.getByRole("button", { name: "Run Scan" }));
  await clickAndFlush(user, screen.getByRole("button", { name: "Download report" }));

  expect(screen.getByText(/Error: Request to \/scans\/9\/pdf failed with status 401/)).toBeInTheDocument();
});
