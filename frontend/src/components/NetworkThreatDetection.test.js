import { act } from "react";
import { render, screen } from "@testing-library/react";
import NetworkThreatDetection from "./NetworkThreatDetection";
import * as api from "../api";

jest.mock("../api");

beforeEach(() => {
  api.getNetworkThreatStatus.mockResolvedValue({ enabled: false, poll_seconds: 0 });
  api.listNetworkThreatEvents.mockResolvedValue([]);
});

afterEach(() => {
  jest.clearAllMocks();
});

test("shows off state and a hint when network threat detection is disabled", async () => {
  render(<NetworkThreatDetection />);
  expect(await screen.findByText("off")).toBeInTheDocument();
  expect(screen.getByText(/NETWORK_THREAT_DETECTION=1/)).toBeInTheDocument();
});

test("shows the poll interval when enabled", async () => {
  api.getNetworkThreatStatus.mockResolvedValue({ enabled: true, poll_seconds: 5 });

  render(<NetworkThreatDetection />);

  expect(await screen.findByText("polling every 5s")).toBeInTheDocument();
});

test("lists recent detections with severity and remote endpoint", async () => {
  api.listNetworkThreatEvents.mockResolvedValue([
    {
      id: 1,
      detected_at: "2026-08-06T09:00:00Z",
      severity: "critical",
      remote_ip: "198.51.100.1",
      remote_port: 4444,
      title: "Connection to known-malicious port 4444/198.51.100.1",
    },
  ]);

  render(<NetworkThreatDetection />);

  expect(await screen.findByText("198.51.100.1:4444")).toBeInTheDocument();
  expect(screen.getByText("Connection to known-malicious port 4444/198.51.100.1")).toBeInTheDocument();
  expect(screen.getByText("critical")).toBeInTheDocument();
});

test("omits the port suffix when a detection has no remote port", async () => {
  api.listNetworkThreatEvents.mockResolvedValue([
    {
      id: 1,
      detected_at: "2026-08-06T09:00:00Z",
      severity: "high",
      remote_ip: "198.51.100.5",
      remote_port: null,
      title: "Possible port scan from 198.51.100.5",
    },
  ]);

  render(<NetworkThreatDetection />);

  expect(await screen.findByText("198.51.100.5")).toBeInTheDocument();
});

test("shows nothing-yet message when there are no detections", async () => {
  render(<NetworkThreatDetection />);
  expect(await screen.findByText("No detections yet.")).toBeInTheDocument();
});

test("does not blow up when refreshing fails", async () => {
  api.getNetworkThreatStatus.mockRejectedValue(new Error("Request to /network/status failed with status 500"));

  render(<NetworkThreatDetection />);

  expect(await screen.findByText("off")).toBeInTheDocument();
});
