import { render, screen } from "@testing-library/react";
import FindingsTable from "./FindingsTable";

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
