import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { buildSchema } from "@/components/form";
import { SourceHealth } from "@/components/source-health";
import { layout, type GEdge, type GNode } from "@/components/graph-view";

const source = (over: Record<string, any>) => ({
  source: "nvd",
  status: "healthy",
  message: "Checked recently.",
  last_success_at: "2026-10-22T08:00:00Z",
  latest: { started_at: "2026-10-22T08:00:00Z", status: "succeeded", attempts: 1, records_seen: 120, records_new: 3, records_updated: 1, records_rejected: 2, catalog_version: "" },
  ...over,
});

describe("SourceHealth", () => {
  it("shows a failing source explicitly instead of an empty, reassuring list", () => {
    render(<SourceHealth health={{ any_problem: true, sources: [source({ status: "failing", message: "The latest attempt failed: HTTP 503. Results may be missing advisories." })] }} />);
    expect(screen.getByText("Failing")).toBeInTheDocument();
    expect(screen.getByText(/HTTP 503/)).toBeInTheDocument();
  });
  it("distinguishes stale, never-run and healthy sources and shows rejected records", () => {
    render(
      <SourceHealth
        health={{
          any_problem: true,
          sources: [source({ status: "stale", message: "No successful check in the last 6 hours; data may be out of date." }), source({ source: "kev", status: "never_run", latest: null, last_success_at: null, message: "This source has never been checked." })],
        }}
      />,
    );
    expect(screen.getByText("Stale")).toBeInTheDocument();
    expect(screen.getByText("Never run")).toBeInTheDocument();
    expect(screen.getByText(/out of date/)).toBeInTheDocument();
    expect(screen.getByText("Rejected records")).toBeInTheDocument();
    expect(screen.getAllByText("never").length).toBeGreaterThan(0);
  });
  it("renders a loading state while health is unknown", () => {
    render(<SourceHealth health={undefined} />);
    expect(screen.getByLabelText("Loading")).toBeInTheDocument();
  });
});

describe("form schema (Zod)", () => {
  const schema = buildSchema([
    { name: "name", label: "Name", required: true, maxLength: 10 },
    { name: "notes", label: "Notes" },
    { name: "exposed", label: "Exposed", type: "checkbox" },
  ]);
  it("requires required fields and enforces length limits", () => {
    expect(schema.safeParse({ name: "" }).success).toBe(false);
    expect(schema.safeParse({ name: "   " }).success).toBe(false); // whitespace only
    expect(schema.safeParse({ name: "x".repeat(11) }).success).toBe(false);
    expect(schema.safeParse({ name: "ok", notes: "", exposed: true }).success).toBe(true);
  });
});

describe("graph layout with cycles and many nodes", () => {
  const n = (id: string): GNode => ({ id, type: "asset", entity_id: id, label: id });
  const e = (s: string, t: string): GEdge => ({ id: `${s}>${t}`, source: s, target: t, type: "DEPENDS_ON", derived: false, verification_status: "verified", confidence: "high", access_scope: "" });
  it("terminates on a cycle and positions every node", () => {
    const nodes = ["a", "b", "c"].map(n);
    const pos = layout(nodes, [e("a", "b"), e("b", "c"), e("c", "a")]);
    expect(Object.keys(pos).sort()).toEqual(["a", "b", "c"]);
  });
  it("lays out a few hundred nodes quickly", () => {
    const nodes = Array.from({ length: 300 }, (_, i) => n(`n${i}`));
    const edges = nodes.slice(1).map((x, i) => e(`n${Math.floor(i / 3)}`, x.id));
    const t = performance.now();
    expect(Object.keys(layout(nodes, edges))).toHaveLength(300);
    expect(performance.now() - t).toBeLessThan(2000);
  });
});
