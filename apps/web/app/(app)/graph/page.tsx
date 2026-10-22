"use client";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useCallback, useMemo, useState } from "react";
import useSWR from "swr";
import { GraphView, type GEdge, type GNode } from "@/components/graph-view";
import { Badge, Button, Card, Empty, ErrorBox, Input, Loading, Notice, PageHeader, Select } from "@/components/ui";
import { ApiError, get, qs } from "@/lib/api";
import { ASSET_TYPES, REL_LABEL, REL_TYPES } from "@/lib/labels";
import { cn, formatDateTime, humanize } from "@/lib/utils";

const NODE_TYPES = [
  { id: "client", label: "Clients" },
  { id: "vendor", label: "Vendors" },
  { id: "product", label: "Products" },
  { id: "asset", label: "Assets" },
];
const DEFAULT_BOUND = 80; // without a client or focus the graph is a bounded sample, never the whole inventory

function recordHref(n: GNode) {
  if (n.type === "vendor") return `/vendors/${n.entity_id}`;
  if (n.type === "client") return `/clients/${n.entity_id}`;
  if (n.type === "asset") return `/assets/${n.entity_id}`;
  return null;
}

function GraphPage() {
  const params = useSearchParams();
  const [clientId, setClientId] = useState("");
  const [relType, setRelType] = useState("");
  const [verification, setVerification] = useState("");
  const [assetType, setAssetType] = useState("");
  const [criticality, setCriticality] = useState("");
  const [visibleTypes, setVisibleTypes] = useState<string[]>(NODE_TYPES.map((t) => t.id));
  const [search, setSearch] = useState("");
  const [focus, setFocus] = useState(params.get("focus") ?? "");
  // Neighbourhoods added by double-click, valid only for the filter set (key) they were fetched under.
  const [expanded, setExpanded] = useState<{ key: string; nodes: GNode[]; edges: GEdge[] }>({ key: "", nodes: [], edges: [] });
  const [expandError, setExpandError] = useState<unknown>(null);
  const [selNode, setSelNode] = useState<string | null>(null);
  const [selEdge, setSelEdge] = useState<string | null>(null);
  const [pathTo, setPathTo] = useState("");
  const [pathEdges, setPathEdges] = useState<GEdge[] | null>(null);

  const { data: clients } = useSWR<any>("/clients?limit=100", get);
  const bounded = !clientId && !focus;
  const allTypes = visibleTypes.length === NODE_TYPES.length;
  const key = `/graph${qs({
    client_id: clientId,
    focus,
    max_depth: focus ? 2 : undefined,
    node_type: allTypes ? undefined : visibleTypes.join(","),
    rel_type: relType,
    verification_status: verification,
    asset_type: assetType,
    criticality,
    max_nodes: bounded ? DEFAULT_BOUND : undefined,
  })}`;
  const { data, error, isLoading, isValidating, mutate } = useSWR<any>(key, get, { shouldRetryOnError: false });

  const graph = useMemo(() => {
    if (!data) return null;
    const extra = expanded.key === key ? expanded : { nodes: [] as GNode[], edges: [] as GEdge[] };
    const nodes = new Map<string, GNode>(data.nodes.map((n: GNode) => [n.id, n]));
    const edges = new Map<string, GEdge>(data.edges.map((e: GEdge) => [e.id, e]));
    extra.nodes.forEach((n) => nodes.set(n.id, n));
    extra.edges.forEach((e) => edges.set(e.id, e));
    return { nodes: [...nodes.values()], edges: [...edges.values()] };
  }, [data, expanded, key]);

  const expand = useCallback(
    async (id: string) => {
      setExpandError(null);
      try {
        const more = await get<any>(`/graph/neighborhood/${id}${qs({ max_depth: 1, max_nodes: 60 })}`);
        setExpanded((cur) => {
          const base = cur.key === key ? cur : { key, nodes: [], edges: [] };
          return { key, nodes: [...base.nodes, ...more.nodes], edges: [...base.edges, ...more.edges] };
        });
      } catch (e) {
        setExpandError(e);
      }
    },
    [key],
  );

  const { data: nodeDetail } = useSWR<any>(selNode ? `/graph/nodes/${selNode}` : null, get);
  const { data: edgeDetail } = useSWR<any>(selEdge && selEdge.startsWith("rel-") ? `/graph/edges/${selEdge}` : null, get);
  const { data: blast } = useSWR<any>(selNode?.startsWith("vendor-") ? `/vendors/${selNode.slice(7)}/blast-radius` : null, get);

  const needle = search.trim().toLowerCase();
  const matches = useMemo(() => (graph && needle.length >= 2 ? graph.nodes.filter((n) => n.label.toLowerCase().includes(needle)) : []), [graph, needle]);
  const highlight = useMemo(() => {
    if (!graph) return null;
    if (pathEdges) return new Set(pathEdges.flatMap((e) => [e.source, e.target]));
    if (needle.length >= 2) return new Set(matches.map((n) => n.id));
    if (selNode) {
      const set = new Set([selNode]);
      graph.edges.forEach((e) => {
        if (e.source === selNode) set.add(e.target);
        if (e.target === selNode) set.add(e.source);
      });
      return set;
    }
    return null;
  }, [graph, selNode, needle, matches, pathEdges]);

  const selected: GNode | undefined = graph?.nodes.find((n) => n.id === selNode);
  const selectionHidden = !!selNode && !!graph && !selected;
  const labelOf = (id: string) => graph?.nodes.find((n) => n.id === id)?.label ?? id;
  const filtersActive = !!(focus || clientId || relType || verification || assetType || criticality || !allTypes || search);
  const reset = () => {
    setFocus("");
    setClientId("");
    setRelType("");
    setVerification("");
    setAssetType("");
    setCriticality("");
    setSearch("");
    setVisibleTypes(NODE_TYPES.map((t) => t.id));
  };

  async function trace() {
    if (!selNode || !pathTo) return;
    const r = await get<any>(`/graph/path?from=${selNode}&to=${pathTo}`);
    setPathEdges(r.found ? r.edges : []);
  }
  const toggleType = (id: string) => setVisibleTypes((cur) => (cur.includes(id) ? (cur.length > 1 ? cur.filter((t) => t !== id) : cur) : [...cur, id]));
  const errorStatus = error instanceof ApiError ? error.status : 0;

  return (
    <>
      <PageHeader
        title="Exposure graph"
        description="Recorded relationships between clients, vendors, products and assets. Dashed lines are unverified; • marks a relationship with recorded evidence. Double-click a node to expand its neighbours."
        actions={
          <>
            {data?.generated_at && <span className="text-xs text-slate-500">Updated {formatDateTime(data.generated_at)}</span>}
            <Button variant="secondary" onClick={() => mutate()} disabled={isValidating}>
              {isValidating ? "Refreshing…" : "Refresh"}
            </Button>
          </>
        }
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Input aria-label="Search nodes" className="max-w-[14rem]" placeholder="Search nodes…" value={search} onChange={(e) => setSearch(e.target.value)} />
        <Select aria-label="Client" className="max-w-[12rem]" value={clientId} onChange={(e) => { setClientId(e.target.value); setFocus(""); }}>
          <option value="">Select a client…</option>
          {clients?.items.map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </Select>
        <Select aria-label="Relationship type" className="max-w-[12rem]" value={relType} onChange={(e) => setRelType(e.target.value)}>
          <option value="">All relationships</option>
          {[...REL_TYPES, "SUPPLIED_BY", "BELONGS_TO"].map((t) => <option key={t} value={t}>{REL_LABEL[t]}</option>)}
        </Select>
        <Select aria-label="Verification" className="max-w-[11rem]" value={verification} onChange={(e) => setVerification(e.target.value)}>
          <option value="">Any verification</option>
          {["verified", "unverified", "disputed", "stale"].map((t) => <option key={t} value={t}>{humanize(t)}</option>)}
        </Select>
        <Select aria-label="Asset type" className="max-w-[12rem]" value={assetType} onChange={(e) => setAssetType(e.target.value)}>
          <option value="">Any asset type</option>
          {ASSET_TYPES.map((t) => <option key={t} value={t}>{humanize(t)}</option>)}
        </Select>
        <Select aria-label="Criticality" className="max-w-[10rem]" value={criticality} onChange={(e) => setCriticality(e.target.value)}>
          <option value="">Any criticality</option>
          {["low", "medium", "high", "critical"].map((t) => <option key={t} value={t}>{humanize(t)}</option>)}
        </Select>
        {filtersActive && <Button variant="ghost" size="sm" onClick={reset}>Clear filters</Button>}
      </div>
      <div className="mb-3 flex flex-wrap items-center gap-2" role="group" aria-label="Node types">
        <span className="text-xs text-slate-500">Show:</span>
        {NODE_TYPES.map((t) => (
          <button key={t.id} aria-pressed={visibleTypes.includes(t.id)} onClick={() => toggleType(t.id)} className={cn("rounded-full border px-3 py-1 text-xs", visibleTypes.includes(t.id) ? "border-brand bg-brand-soft text-brand" : "border-slate-300 bg-white text-slate-500")}>
            {t.label}
          </button>
        ))}
        {needle.length >= 2 && <span className="text-xs text-slate-500">{matches.length} match{matches.length === 1 ? "" : "es"}</span>}
      </div>

      {error && (
        <div className="mb-3 space-y-2">
          <ErrorBox error={errorStatus === 403 ? new Error("You are not authorised to view this graph.") : error} />
          <Button size="sm" variant="secondary" onClick={() => mutate()}>Try again</Button>
        </div>
      )}
      <ErrorBox error={expandError} />
      {data && bounded && !data.truncated && graph && graph.nodes.length > 0 && <div className="mb-2"><Notice>Showing a bounded view. Select a client to focus on one environment.</Notice></div>}
      {data?.truncated && <div className="mb-2"><Notice tone="warn">Too many nodes to draw: showing the first {data.node_count}. Select a client, search, or focus a node to narrow the view.</Notice></div>}
      {selectionHidden && (
        <div className="mb-2"><Notice tone="warn">The selected node is hidden by the current filters. <button className="font-medium underline" onClick={() => setSelNode(null)}>Clear selection</button></Notice></div>
      )}

      <div className="grid gap-4 lg:grid-cols-[1fr_22rem]">
        <div className="h-[34rem] overflow-hidden rounded-lg border border-slate-200 bg-white" data-testid="graph-canvas">
          {isLoading || (!graph && !error) ? (
            <div className="p-6"><Loading rows={4} /></div>
          ) : graph && graph.nodes.length === 0 ? (
            <div className="p-6">
              {filtersActive ? (
                <Empty title="No nodes match these filters"><Button size="sm" variant="secondary" onClick={reset}>Clear filters</Button></Empty>
              ) : (
                <Empty title="Your inventory has no relationships yet">Add vendors, assets and relationships to see the exposure graph.</Empty>
              )}
            </div>
          ) : graph ? (
            <GraphView
              nodes={graph.nodes}
              edges={graph.edges}
              selected={selected ? selNode : null}
              highlight={highlight}
              centerOn={needle.length >= 2 ? matches[0]?.id : null}
              onSelectNode={(id) => { setSelNode(id); setSelEdge(null); setPathEdges(null); }}
              onSelectEdge={(id) => { setSelEdge(id); setSelNode(null); }}
              onExpand={expand}
              onPaneClick={() => { setSelNode(null); setSelEdge(null); }}
            />
          ) : null}
        </div>

        <aside className="space-y-3" aria-label="Details">
          <div className="flex flex-wrap gap-2 text-xs">
            <Badge tone="info">Client</Badge><Badge tone="purple">Vendor</Badge><Badge tone="medium">Product</Badge><Badge tone="low">Asset</Badge>
          </div>
          {!selected && !selEdge && <Empty title="Select a node or an edge">Click to inspect metadata, permissions and evidence.</Empty>}

          {selected && nodeDetail && (
            <Card title={<>{selected.label} <span className="font-normal text-slate-500">· {selected.type}</span></>}>
              <div className="space-y-3 text-sm">
                <dl className="grid grid-cols-2 gap-2">
                  {Object.entries(nodeDetail.attributes).filter(([k, v]) => v !== "" && v !== null && !["id", "aliases", "client_id", "vendor_id"].includes(k) && typeof v !== "object").slice(0, 10).map(([k, v]) => (
                    <div key={k}><dt className="text-xs text-slate-500">{humanize(k)}</dt><dd className="break-words">{typeof v === "boolean" ? (v ? "Yes" : "No") : String(v)}</dd></div>
                  ))}
                </dl>
                {recordHref(selected) && <Link className="text-brand hover:underline" href={recordHref(selected)!}>Open record →</Link>}
                <div className="flex gap-2">
                  <Button size="sm" variant="secondary" onClick={() => setFocus(selected.id)}>Focus here</Button>
                  <Button size="sm" variant="secondary" onClick={() => expand(selected.id)}>Expand</Button>
                </div>
                <div className="border-t border-slate-100 pt-3">
                  <p className="mb-1 text-xs font-medium uppercase text-slate-500">Trace path to…</p>
                  <div className="flex gap-2">
                    <Select aria-label="Trace to" value={pathTo} onChange={(e) => setPathTo(e.target.value)}>
                      <option value="">Select a node</option>
                      {graph?.nodes.filter((n) => n.id !== selNode).map((n) => <option key={n.id} value={n.id}>{n.type}: {n.label}</option>)}
                    </Select>
                    <Button size="sm" disabled={!pathTo} onClick={trace}>Trace</Button>
                  </div>
                  {pathEdges && (pathEdges.length === 0 ? <p className="mt-2 text-xs text-slate-500">No recorded path.</p> : (
                    <ol className="mt-2 list-decimal pl-4 text-xs text-slate-700">
                      {pathEdges.map((e) => <li key={e.id}>{labelOf(e.source)} → <em>{REL_LABEL[e.type]}</em> → {labelOf(e.target)}</li>)}
                    </ol>
                  ))}
                </div>
                {blast && blast.clients.length > 0 && (
                  <div className="border-t border-slate-100 pt-3">
                    <p className="mb-1 text-xs font-medium uppercase text-slate-500">Connected clients</p>
                    <ul className="space-y-1">
                      {blast.clients.map((c: any) => (
                        <li key={c.client_id} className="flex items-center justify-between text-xs">
                          <span>{c.client}</span>
                          <span className="space-x-1">
                            <Badge tone={c.relation === "direct" ? "info" : "purple"}>{c.relation}</Badge>
                            {c.sensitive_access && <Badge tone="high">sensitive access</Badge>}
                            {c.insufficient_data && <Badge>needs data</Badge>}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </Card>
          )}

          {selEdge && (
            <Card title="Relationship">
              {!selEdge.startsWith("rel-") ? (
                <p className="text-sm text-slate-600">This link is derived from a recorded foreign key ({selEdge.startsWith("supplied") ? "product supplied by vendor" : "asset belongs to client"}).</p>
              ) : !edgeDetail ? <Loading rows={2} /> : (
                <div className="space-y-2 text-sm">
                  <p><Badge tone="info">{REL_LABEL[edgeDetail.rel_type]}</Badge></p>
                  <p>{labelOf(`${edgeDetail.source_type}-${edgeDetail.source_id}`)} → {labelOf(`${edgeDetail.target_type}-${edgeDetail.target_id}`)}</p>
                  <p><span className="text-xs text-slate-500">Permissions / scope</span><br />{edgeDetail.access_scope || "—"}</p>
                  <p><span className="text-xs text-slate-500">Evidence</span><br />{edgeDetail.evidence || (edgeDetail.has_evidence ? "Recorded (visible to analysts)" : "None recorded")}</p>
                  <p className="flex gap-2"><Badge tone={edgeDetail.verification_status === "verified" ? "low" : "medium"}>{humanize(edgeDetail.verification_status)}</Badge><Badge>{humanize(edgeDetail.confidence)} confidence</Badge></p>
                  {edgeDetail.verification_method && <p className="text-xs text-slate-500">Verified by: {humanize(edgeDetail.verification_method)}</p>}
                  <p className="text-xs text-slate-500">Source: {edgeDetail.source}</p>
                </div>
              )}
            </Card>
          )}
        </aside>
      </div>
    </>
  );
}

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <GraphPage />
    </Suspense>
  );
}
