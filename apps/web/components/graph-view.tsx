"use client";
import "reactflow/dist/style.css";
import dagre from "@dagrejs/dagre";
import { useEffect, useMemo } from "react";
import ReactFlow, { Background, Controls, Handle, MarkerType, MiniMap, Position, ReactFlowProvider, useReactFlow, type Edge, type Node, type NodeProps } from "reactflow";
import { REL_LABEL } from "@/lib/labels";

export interface GNode {
  id: string;
  type: string;
  entity_id: string;
  label: string;
  subtype?: string;
  criticality?: string;
  version?: string;
  verification_status?: string;
  access_level?: string;
}
export interface GEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  derived: boolean;
  verification_status: string;
  confidence: string;
  access_scope: string;
  has_evidence?: boolean;
}

export const NODE_W = 184;
export const NODE_H = 56;

const KIND: Record<string, { bg: string; border: string; glyph: string; name: string }> = {
  client: { bg: "#dfe9ec", border: "#1f4d61", glyph: "▣", name: "Client" },
  vendor: { bg: "#e6dff0", border: "#4a3474", glyph: "◈", name: "Third party" },
  product: { bg: "#f3e7bd", border: "#946f0f", glyph: "◆", name: "Product" },
  asset: { bg: "#d9e8dc", border: "#286a42", glyph: "▤", name: "Resource" },
};
const CRIT: Record<string, string> = { critical: "#b5361a", high: "#c4701b", medium: "#946f0f", low: "#286a42" };

interface NodeData {
  node: GNode;
  dim: boolean;
  selected: boolean;
}

/** Distinct styles per entity type. Criticality and verification markers appear only when the record has those values. */
function VeylithNode({ data }: NodeProps<NodeData>) {
  const { node, dim, selected } = data;
  const k = KIND[node.type] ?? KIND.asset;
  const crit = node.criticality ? CRIT[node.criticality] : undefined;
  return (
    <div
      role="group"
      aria-label={`${k.name}: ${node.label}`}
      style={{ width: NODE_W, height: NODE_H, background: k.bg, border: `${selected ? 3 : 1.5}px solid ${k.border}`, opacity: dim ? 0.25 : 1, borderRadius: 10, padding: "6px 8px" }}
      className="relative flex items-center gap-2 text-xs shadow-sm"
    >
      <Handle type="target" position={Position.Left} style={{ background: k.border }} />
      <span aria-hidden style={{ color: k.border, fontSize: 18, lineHeight: 1 }}>
        {k.glyph}
      </span>
      <div className="min-w-0 flex-1">
        <div className="truncate font-semibold text-slate-900">{node.label}</div>
        <div className="truncate text-[10px] uppercase tracking-wide text-slate-600">
          {node.type === "asset" ? (node.subtype ?? "").replace(/_/g, " ") : node.type === "product" && node.version ? `v${node.version}` : k.name}
        </div>
      </div>
      {crit && <span title={`${node.criticality} criticality`} aria-label={`${node.criticality} criticality`} style={{ background: crit }} className="h-2.5 w-2.5 shrink-0 rounded-full" />}
      {node.type === "asset" && node.verification_status && (
        <span title={`Verification: ${node.verification_status}`} className={node.verification_status === "verified" ? "text-emerald-700" : "text-amber-700"}>
          {node.verification_status === "verified" ? "✓" : "?"}
        </span>
      )}
      <Handle type="source" position={Position.Right} style={{ background: k.border }} />
    </div>
  );
}

const nodeTypes = { veylith: VeylithNode }; // stable identity: React Flow re-mounts nodes if this object changes

/** Hierarchical layout, deterministic for a given graph. */
export function layout(nodes: GNode[], edges: GEdge[]): Record<string, { x: number; y: number }> {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "LR", nodesep: 24, ranksep: 90 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((n) => g.setNode(n.id, { width: NODE_W, height: NODE_H }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  const out: Record<string, { x: number; y: number }> = {};
  nodes.forEach((n) => {
    const p = g.node(n.id);
    out[n.id] = { x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 };
  });
  return out;
}

function Inner({
  nodes,
  edges,
  selected,
  highlight,
  centerOn,
  onSelectNode,
  onSelectEdge,
  onExpand,
  onPaneClick,
}: {
  nodes: GNode[];
  edges: GEdge[];
  selected?: string | null;
  highlight: Set<string> | null;
  centerOn?: string | null;
  onSelectNode: (id: string) => void;
  onSelectEdge: (id: string) => void;
  onExpand: (id: string) => void;
  onPaneClick?: () => void;
}) {
  const positions = useMemo(() => layout(nodes, edges), [nodes, edges]);
  const rf = useReactFlow();

  const rfNodes: Node<NodeData>[] = useMemo(
    () =>
      nodes.map((n) => ({
        id: n.id,
        type: "veylith",
        position: positions[n.id],
        data: { node: n, dim: !!highlight && !highlight.has(n.id), selected: selected === n.id },
      })),
    [nodes, positions, selected, highlight],
  );
  const rfEdges: Edge[] = useMemo(
    () =>
      edges.map((e) => {
        const dim = highlight && !(highlight.has(e.source) && highlight.has(e.target));
        const unverified = !e.derived && e.verification_status !== "verified";
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: `${REL_LABEL[e.type] ?? e.type}${e.has_evidence ? " •" : ""}`,
          labelStyle: { fontSize: 10, fill: "#55503f" },
          labelBgStyle: { fill: "#fbf9f3" },
          markerEnd: { type: MarkerType.ArrowClosed },
          style: { stroke: e.derived ? "#9b9482" : "#14130e", strokeDasharray: unverified ? "6 4" : e.derived ? "2 3" : undefined, opacity: dim ? 0.15 : 1, strokeWidth: 1.5 },
        };
      }),
    [edges, highlight],
  );

  useEffect(() => {
    const t = setTimeout(() => rf.fitView({ padding: 0.2, duration: 200 }), 50);
    return () => clearTimeout(t);
  }, [nodes.length, edges.length, rf]);

  // Search / navigation: bring the requested node into view.
  useEffect(() => {
    if (!centerOn) return;
    const t = setTimeout(() => rf.fitView({ nodes: [{ id: centerOn }], padding: 1.5, duration: 300, maxZoom: 1.2 }), 60);
    return () => clearTimeout(t);
  }, [centerOn, rf]);

  return (
    <ReactFlow
      nodes={rfNodes}
      edges={rfEdges}
      nodeTypes={nodeTypes}
      nodesDraggable
      nodesConnectable={false}
      onNodeClick={(_, n) => onSelectNode(n.id)}
      onNodeDoubleClick={(_, n) => onExpand(n.id)}
      onEdgeClick={(_, e) => onSelectEdge(e.id)}
      onPaneClick={onPaneClick}
      minZoom={0.1}
      fitView
      proOptions={{ hideAttribution: true }}
    >
      <Background gap={20} />
      <Controls showInteractive={false} fitViewOptions={{ padding: 0.2 }} />
      <MiniMap pannable zoomable nodeColor={(n) => (KIND[String(n.id).split("-")[0]] ?? KIND.asset).border} />
    </ReactFlow>
  );
}

export function GraphView(props: React.ComponentProps<typeof Inner>) {
  return (
    <ReactFlowProvider>
      <Inner {...props} />
    </ReactFlowProvider>
  );
}
