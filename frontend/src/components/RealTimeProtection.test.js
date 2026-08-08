import { act } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import RealTimeProtection from "./RealTimeProtection";
import * as api from "../api";

jest.mock("../api");

beforeEach(() => {
  api.getRealtimeStatus.mockResolvedValue({ enabled: false, watched_paths: [] });
  api.listRealtimeEvents.mockResolvedValue([]);
  api.listQuarantine.mockResolvedValue([]);
});

afterEach(() => {
  jest.clearAllMocks();
});

async function clickAndFlush(user, element) {
  await act(async () => {
    await user.click(element);
  });
}

test("shows off state and a hint when real-time protection is disabled", async () => {
  render(<RealTimeProtection />);
  expect(await screen.findByText("off")).toBeInTheDocument();
  expect(screen.getByText(/REALTIME_PROTECTION=1/)).toBeInTheDocument();
});

test("shows the watched location count when enabled", async () => {
  api.getRealtimeStatus.mockResolvedValue({
    enabled: true,
    watched_paths: ["/tmp", "/dev/shm", "/home/user/Downloads"],
  });

  render(<RealTimeProtection />);

  expect(await screen.findByText("watching 3 locations")).toBeInTheDocument();
});

test("lists quarantined files with severity and original path", async () => {
  api.listQuarantine.mockResolvedValue([
    {
      id: 1,
      detected_at: "2026-08-06T09:00:00Z",
      original_path: "/home/user/Downloads/shell.php",
      severity: "high",
      status: "quarantined",
    },
  ]);

  render(<RealTimeProtection />);

  expect(await screen.findByText("/home/user/Downloads/shell.php")).toBeInTheDocument();
  expect(screen.getByText("Quarantined files (1)")).toBeInTheDocument();
});

test("excludes restored/deleted items from the active quarantine count", async () => {
  api.listQuarantine.mockResolvedValue([
    { id: 1, detected_at: "2026-08-06T09:00:00Z", original_path: "/a", severity: "high", status: "restored" },
    { id: 2, detected_at: "2026-08-06T09:00:00Z", original_path: "/b", severity: "high", status: "deleted" },
  ]);

  render(<RealTimeProtection />);

  expect(await screen.findByText("Quarantined files (0)")).toBeInTheDocument();
  expect(screen.getByText("Nothing in quarantine.")).toBeInTheDocument();
});

test("lists recent detections including alert-only (non-quarantined) events", async () => {
  api.listRealtimeEvents.mockResolvedValue([
    { id: 1, detected_at: "2026-08-06T09:00:00Z", path: "/tmp/eicar.txt", severity: "medium", quarantined: 0 },
  ]);

  render(<RealTimeProtection />);

  expect(await screen.findByText("/tmp/eicar.txt")).toBeInTheDocument();
  expect(screen.getByText("Alerted only")).toBeInTheDocument();
});

test("restoring a quarantined file calls the API and refreshes the list", async () => {
  api.listQuarantine.mockResolvedValueOnce([
    { id: 5, detected_at: "2026-08-06T09:00:00Z", original_path: "/a/shell.php", severity: "high", status: "quarantined" },
  ]);
  api.restoreQuarantineItem.mockResolvedValue({ id: 5, status: "restored" });

  const user = userEvent.setup();
  render(<RealTimeProtection />);
  await screen.findByText("/a/shell.php");

  api.listQuarantine.mockResolvedValueOnce([
    { id: 5, detected_at: "2026-08-06T09:00:00Z", original_path: "/a/shell.php", severity: "high", status: "restored" },
  ]);
  await clickAndFlush(user, screen.getByRole("button", { name: "Restore" }));

  expect(api.restoreQuarantineItem).toHaveBeenCalledWith(5);
  expect(screen.getByText("Nothing in quarantine.")).toBeInTheDocument();
});

test("deleting a quarantined file calls the API and refreshes the list", async () => {
  api.listQuarantine.mockResolvedValueOnce([
    { id: 5, detected_at: "2026-08-06T09:00:00Z", original_path: "/a/shell.php", severity: "high", status: "quarantined" },
  ]);
  api.deleteQuarantineItem.mockResolvedValue({ id: 5, status: "deleted" });

  const user = userEvent.setup();
  render(<RealTimeProtection />);
  await screen.findByText("/a/shell.php");

  api.listQuarantine.mockResolvedValueOnce([
    { id: 5, detected_at: "2026-08-06T09:00:00Z", original_path: "/a/shell.php", severity: "high", status: "deleted" },
  ]);
  await clickAndFlush(user, screen.getByRole("button", { name: "Delete" }));

  expect(api.deleteQuarantineItem).toHaveBeenCalledWith(5);
  expect(screen.getByText("Nothing in quarantine.")).toBeInTheDocument();
});

test("shows an error message when restoring fails", async () => {
  api.listQuarantine.mockResolvedValue([
    { id: 5, detected_at: "2026-08-06T09:00:00Z", original_path: "/a/shell.php", severity: "high", status: "quarantined" },
  ]);
  api.restoreQuarantineItem.mockRejectedValue(new Error("Request to /quarantine/5/restore failed with status 409"));

  const user = userEvent.setup();
  render(<RealTimeProtection />);
  await screen.findByText("/a/shell.php");

  await clickAndFlush(user, screen.getByRole("button", { name: "Restore" }));

  expect(screen.getByText(/Error: Request to \/quarantine\/5\/restore failed with status 409/)).toBeInTheDocument();
});
