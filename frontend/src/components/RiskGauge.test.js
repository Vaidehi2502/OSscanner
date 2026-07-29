import { render, screen } from "@testing-library/react";
import RiskGauge from "./RiskGauge";

test("renders the numeric score and risk level", () => {
  render(<RiskGauge score={42} level="high" />);
  expect(screen.getByText("42")).toBeInTheDocument();
  expect(screen.getByText("high")).toBeInTheDocument();
});

test("renders a zero score correctly (falsy, not treated as missing)", () => {
  render(<RiskGauge score={0} level="none" />);
  expect(screen.getByText("0")).toBeInTheDocument();
});

test("does not crash on an unrecognized level and still shows it", () => {
  render(<RiskGauge score={10} level="unrecognized-level" />);
  expect(screen.getByText("unrecognized-level")).toBeInTheDocument();
});
