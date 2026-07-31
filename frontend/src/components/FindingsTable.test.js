import { act } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import FindingsTable from "./FindingsTable";

// Filtering/search handlers fire two setState calls (filter or query, plus a
// pagination reset) in one handler; wrapping the interaction itself in act()
// flushes both within one boundary instead of relying on user-event's own
// (incomplete, for this case) flushing.
async function clickAndFlush(user, element) {
  await act(async () => {
    await user.click(element);
  });
}

async function typeAndFlush(user, element, text) {
  await act(async () => {
    await user.type(element, text);
  });
}

test("renders placeholder text when there are no findings", () => {
  render(<FindingsTable findings={[]} />);
  expect(screen.getByText("No findings to display.")).toBeInTheDocument();
});

test("renders placeholder text when findings is undefined", () => {
  render(<FindingsTable />);
  expect(screen.getByText("No findings to display.")).toBeInTheDocument();
});

test("renders a row per finding with its details", () => {
  const findings = [
    {
      severity: "critical",
      scanner: "port_scanner",
      title: "Known malicious port open: 4444/tcp",
      description: "Common Metasploit default listener",
    },
    {
      severity: "low",
      scanner: "network_scanner",
      title: "Established connection to external host 8.8.8.8",
      description: "Outbound connection to a non-private IP address",
    },
  ];

  render(<FindingsTable findings={findings} />);

  expect(screen.getByText("Known malicious port open: 4444/tcp")).toBeInTheDocument();
  expect(screen.getByText("Established connection to external host 8.8.8.8")).toBeInTheDocument();
  expect(screen.getByText("Common Metasploit default listener")).toBeInTheDocument();
  // header row + one row per finding
  expect(screen.getAllByRole("row")).toHaveLength(findings.length + 1);
});

test("renders the raw severity text (styling, not casing, is what makes it uppercase)", () => {
  render(
    <FindingsTable
      findings={[{ severity: "critical", scanner: "x", title: "t", description: "d" }]}
    />
  );
  expect(screen.getByText("critical")).toBeInTheDocument();
});

test("sorts findings by severity, most severe first", () => {
  const findings = [
    { severity: "low", scanner: "a", title: "Low one", description: "d" },
    { severity: "critical", scanner: "b", title: "Critical one", description: "d" },
    { severity: "medium", scanner: "c", title: "Medium one", description: "d" },
  ];

  render(<FindingsTable findings={findings} />);

  const rows = screen.getAllByRole("row").slice(1); // drop header row
  expect(rows[0]).toHaveTextContent("Critical one");
  expect(rows[1]).toHaveTextContent("Medium one");
  expect(rows[2]).toHaveTextContent("Low one");
});

test("filtering by severity tab shows only matching findings", async () => {
  const findings = [
    { severity: "critical", scanner: "a", title: "Critical finding", description: "d" },
    { severity: "low", scanner: "b", title: "Low finding", description: "d" },
  ];

  const user = userEvent.setup();
  render(<FindingsTable findings={findings} />);

  await clickAndFlush(user, screen.getByRole("button", { name: /Critical \(1\)/ }));

  expect(screen.getByText("Critical finding")).toBeInTheDocument();
  expect(screen.queryByText("Low finding")).not.toBeInTheDocument();
});

test("searching filters findings by title", async () => {
  const findings = [
    { severity: "high", scanner: "process_scanner", title: "Suspicious process xmrig", description: "d" },
    { severity: "high", scanner: "port_scanner", title: "Unusual port 4444 open", description: "d" },
  ];

  const user = userEvent.setup();
  render(<FindingsTable findings={findings} />);

  await typeAndFlush(user, screen.getByPlaceholderText("Search findings..."), "xmrig");

  expect(screen.getByText("Suspicious process xmrig")).toBeInTheDocument();
  expect(screen.queryByText("Unusual port 4444 open")).not.toBeInTheDocument();
});

test("shows a message when no findings match the current filter", async () => {
  const findings = [{ severity: "low", scanner: "a", title: "Low finding", description: "d" }];

  const user = userEvent.setup();
  render(<FindingsTable findings={findings} />);

  await typeAndFlush(user, screen.getByPlaceholderText("Search findings..."), "nothing matches this");

  expect(screen.getByText("No findings match this filter.")).toBeInTheDocument();
});

test("paginates long lists behind a Show more button", async () => {
  const findings = Array.from({ length: 25 }, (_, i) => ({
    severity: "low",
    scanner: "network_scanner",
    title: `Finding ${i}`,
    description: "d",
  }));

  const user = userEvent.setup();
  render(<FindingsTable findings={findings} />);

  // header row + first 20 findings
  expect(screen.getAllByRole("row")).toHaveLength(21);
  expect(screen.getByRole("button", { name: "Show more (5 remaining)" })).toBeInTheDocument();

  await clickAndFlush(user, screen.getByRole("button", { name: "Show more (5 remaining)" }));

  expect(screen.getAllByRole("row")).toHaveLength(26);
  expect(screen.queryByRole("button", { name: /Show more/ })).not.toBeInTheDocument();
});
