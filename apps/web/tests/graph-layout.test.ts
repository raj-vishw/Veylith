import { describe, expect, it } from "vitest";
import { layout, type GEdge, type GNode } from "@/components/graph-view";

const node = (id: string, type: string): GNode => ({ id, type, entity_id: id, label: id });
const edge = (s: string, t: string): GEdge => ({ id: `${s}-${t}`, source: s, target: t, type: "USES_VENDOR", derived: false, verification_status: "verified", confidence: "high", access_scope: "" });

describe("graph layout", () => {
  it("places every node exactly once, left to right along edges", () => {
    const nodes = [node("client-1", "client"), node("vendor-1", "vendor"), node("asset-1", "asset")];
    const pos = layout(nodes, [edge("client-1", "vendor-1"), edge("vendor-1", "asset-1")]);
    expect(Object.keys(pos).sort()).toEqual(["asset-1", "client-1", "vendor-1"]);
    expect(pos["client-1"].x).toBeLessThan(pos["vendor-1"].x);
    expect(pos["vendor-1"].x).toBeLessThan(pos["asset-1"].x);
  });
  it("is deterministic and handles an empty graph", () => {
    const nodes = [node("a-1", "asset"), node("b-1", "asset")];
    expect(layout(nodes, [])).toEqual(layout(nodes, []));
    expect(layout([], [])).toEqual({});
  });
});
