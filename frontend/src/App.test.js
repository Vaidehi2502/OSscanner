import { act } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App";
import * as api from "./api";

jest.mock("./api");

beforeEach(() => {
  api.listScans.mockResolvedValue([]);
  api.getMonitorStatus.mockResolvedValue({ enabled: false, interval_seconds: 0 });
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
  expect(screen.getByText(/Click "Run Antivirus Scan"/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Download report" })).not.toBeInTheDocument();
  // Flush the mount-time listScans() fetch so its setState doesn't leak into the next test.
  await act(async () => {});
});

test("running an antivirus scan displays the report and findings", async () => {
  api.runAvScan.mockResolvedValue({
    scan_id: 11,
    scan_type: "av",
    risk_score: 30,
    risk_level: "medium",
    total_findings: 1,
    summary: "Risk level: MEDIUM (score 30/100). 1 findings across 1 scanners.",
    findings: [
      { severity: "high", scanner: "yara_scanner", title: "YARA match: PHP_Webshell_Command_Exec", description: "d" },
    ],
  });

  const user = userEvent.setup();
  render(<App />);
  await clickAndFlush(user, screen.getByRole("button", { name: "Run Antivirus Scan" }));

  expect(screen.getByText("YARA match: PHP_Webshell_Command_Exec")).toBeInTheDocument();
  expect(api.runAvScan).toHaveBeenCalledTimes(1);
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

test("clicking a past scan in history loads and displays that scan's report", async () => {
  api.listScans.mockResolvedValue([
    { id: 2, started_at: "2026-07-31T09:00:00Z", risk_score: 18, risk_level: "low", total_findings: 1 },
    { id: 1, started_at: "2026-07-30T09:00:00Z", risk_score: 90, risk_level: "critical", total_findings: 1 },
  ]);
  api.getScan.mockResolvedValue({
    scan_id: 1,
    generated_at: "2026-07-30T09:00:00Z",
    risk_score: 90,
    risk_level: "critical",
    total_findings: 1,
    summary: "Risk level: CRITICAL (score 90/100). 1 findings across 1 scanners.",
    findings: [{ severity: "critical", scanner: "port_scanner", title: "Old finding", description: "d" }],
  });

  const user = userEvent.setup();
  render(<App />);
  await screen.findByText("90"); // history table loaded

  await clickAndFlush(user, screen.getByRole("row", { name: /View scan from Jul 30/ }));

  expect(api.getScan).toHaveBeenCalledWith(1);
  expect(screen.getByText("Old finding")).toBeInTheDocument();
  expect(screen.getByText(/Viewing a past scan/)).toBeInTheDocument();
});

test("clicking View latest returns to the most recent scan", async () => {
  api.listScans.mockResolvedValue([
    { id: 2, started_at: "2026-07-31T09:00:00Z", risk_score: 18, risk_level: "low", total_findings: 1 },
    { id: 1, started_at: "2026-07-30T09:00:00Z", risk_score: 90, risk_level: "critical", total_findings: 1 },
  ]);
  api.getScan.mockImplementation((id) =>
    Promise.resolve({
      scan_id: id,
      generated_at: "2026-07-30T09:00:00Z",
      risk_score: id === 1 ? 90 : 18,
      risk_level: id === 1 ? "critical" : "low",
      total_findings: 1,
      summary: "s",
      findings: [{ severity: "low", scanner: "x", title: `Finding for scan ${id}`, description: "d" }],
    })
  );

  const user = userEvent.setup();
  render(<App />);
  await screen.findByText("90");

  await clickAndFlush(user, screen.getByRole("row", { name: /View scan from Jul 30/ }));
  expect(screen.getByText("Finding for scan 1")).toBeInTheDocument();

  await clickAndFlush(user, screen.getByRole("button", { name: "View latest" }));

  expect(api.getScan).toHaveBeenLastCalledWith(2);
  expect(screen.getByText("Finding for scan 2")).toBeInTheDocument();
  expect(screen.queryByText(/Viewing a past scan/)).not.toBeInTheDocument();
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

test("shows the background scanning interval in the subtitle when the monitor is enabled", async () => {
  api.getMonitorStatus.mockResolvedValue({ enabled: true, interval_seconds: 300 });

  render(<App />);

  expect(await screen.findByText(/Background scanning every 300s/)).toBeInTheDocument();
});

describe("live polling", () => {
  // Flush the pending microtasks from the interval callback's chained
  // awaits (listScans -> possibly getScan -> setState) after advancing the
  // fake timer - jest's fake timers only fake the clock, not the
  // microtask queue, so real awaits still need real "ticks" to resolve.
  async function advanceLivePoll() {
    await act(async () => {
      jest.advanceTimersByTime(10000);
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
  }

  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  test("automatically loads a newly completed scan while viewing the latest", async () => {
    api.listScans.mockResolvedValue([
      { id: 1, started_at: "2026-07-31T09:00:00Z", risk_score: 10, risk_level: "low", total_findings: 1 },
    ]);

    render(<App />);
    await act(async () => {
      await Promise.resolve();
    });

    api.listScans.mockResolvedValue([
      { id: 2, started_at: "2026-07-31T09:10:00Z", risk_score: 40, risk_level: "medium", total_findings: 3 },
      { id: 1, started_at: "2026-07-31T09:00:00Z", risk_score: 10, risk_level: "low", total_findings: 1 },
    ]);
    api.getScan.mockResolvedValue({
      scan_id: 2,
      generated_at: "2026-07-31T09:10:00Z",
      risk_score: 40,
      risk_level: "medium",
      total_findings: 3,
      summary: "s",
      findings: [{ severity: "medium", scanner: "x", title: "New live finding", description: "d" }],
    });

    await advanceLivePoll();

    expect(api.getScan).toHaveBeenCalledWith(2);
    expect(screen.getByText("New live finding")).toBeInTheDocument();
  });

  test("does not disturb the view when looking at a past scan", async () => {
    api.listScans.mockResolvedValue([
      { id: 2, started_at: "2026-07-31T09:10:00Z", risk_score: 40, risk_level: "medium", total_findings: 3 },
      { id: 1, started_at: "2026-07-30T09:00:00Z", risk_score: 10, risk_level: "low", total_findings: 1 },
    ]);
    api.getScan.mockResolvedValue({
      scan_id: 1,
      generated_at: "2026-07-30T09:00:00Z",
      risk_score: 10,
      risk_level: "low",
      total_findings: 1,
      summary: "s",
      findings: [{ severity: "low", scanner: "x", title: "Old finding", description: "d" }],
    });

    const user = userEvent.setup({ delay: null });
    render(<App />);
    await act(async () => {
      await Promise.resolve();
    });

    await act(async () => {
      await user.click(screen.getByRole("row", { name: /View scan from Jul 30/ }));
    });
    expect(screen.getByText("Old finding")).toBeInTheDocument();

    api.listScans.mockResolvedValue([
      { id: 3, started_at: "2026-07-31T09:20:00Z", risk_score: 80, risk_level: "high", total_findings: 5 },
      { id: 2, started_at: "2026-07-31T09:10:00Z", risk_score: 40, risk_level: "medium", total_findings: 3 },
      { id: 1, started_at: "2026-07-30T09:00:00Z", risk_score: 10, risk_level: "low", total_findings: 1 },
    ]);

    await advanceLivePoll();

    expect(screen.getByText("Old finding")).toBeInTheDocument();
    expect(api.getScan).not.toHaveBeenCalledWith(3);
  });

  test("toggling Live off stops polling", async () => {
    api.listScans.mockResolvedValue([
      { id: 1, started_at: "2026-07-31T09:00:00Z", risk_score: 10, risk_level: "low", total_findings: 1 },
    ]);

    const user = userEvent.setup({ delay: null });
    render(<App />);
    await act(async () => {
      await Promise.resolve();
    });

    await act(async () => {
      await user.click(screen.getByRole("button", { name: /Live/ }));
    });

    const callsBeforeAdvance = api.listScans.mock.calls.length;
    await advanceLivePoll();

    expect(api.listScans.mock.calls.length).toBe(callsBeforeAdvance);
  });
});
