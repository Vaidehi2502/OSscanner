import { render, screen } from "@testing-library/react";
import FileReputation from "./FileReputation";
import * as api from "../api";

jest.mock("../api");

beforeEach(() => {
  api.listFileReputation.mockResolvedValue([]);
});

afterEach(() => {
  jest.clearAllMocks();
});

test("shows an empty-state message when no files have been hashed yet", async () => {
  render(<FileReputation />);
  expect(await screen.findByText(/No files hashed yet/)).toBeInTheDocument();
});

test("lists reputation entries with risk, detections, and truncated hash", async () => {
  const hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
  api.listFileReputation.mockResolvedValue([
    {
      hash,
      risk: "critical",
      detection_count: 3,
      first_seen: "2026-08-06T09:00:00Z",
      last_seen: "2026-08-07T09:00:00Z",
    },
  ]);

  render(<FileReputation />);

  expect(await screen.findByText("critical")).toBeInTheDocument();
  expect(screen.getByText("3")).toBeInTheDocument();
  expect(screen.getByText(`${hash.slice(0, 10)}...${hash.slice(-8)}`)).toBeInTheDocument();
  expect(screen.getByTitle(hash)).toBeInTheDocument();
});

test("shows the flagged-vs-known count in the header", async () => {
  api.listFileReputation.mockResolvedValue([
    { hash: "a".repeat(64), risk: "none", detection_count: 0, first_seen: "t", last_seen: "t" },
    { hash: "b".repeat(64), risk: "high", detection_count: 2, first_seen: "t", last_seen: "t" },
  ]);

  render(<FileReputation />);

  expect(await screen.findByText("1 flagged / 2 known")).toBeInTheDocument();
});

test("does not truncate a short hash", async () => {
  api.listFileReputation.mockResolvedValue([
    { hash: "short123", risk: "none", detection_count: 0, first_seen: "t", last_seen: "t" },
  ]);

  render(<FileReputation />);

  expect(await screen.findByText("short123")).toBeInTheDocument();
});

test("does not blow up when refreshing fails", async () => {
  api.listFileReputation.mockRejectedValue(new Error("Request to /reputation failed with status 500"));

  render(<FileReputation />);

  expect(await screen.findByText(/No files hashed yet/)).toBeInTheDocument();
});
