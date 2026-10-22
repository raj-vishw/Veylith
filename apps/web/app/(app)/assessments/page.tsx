"use client";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import useSWR from "swr";
import { Badge, DataTable, Empty, ErrorBox, Input, Loading, PageHeader, Pagination, PriorityBadge, Select, StateBadge } from "@/components/ui";
import { get, qs } from "@/lib/api";
import { STATE_LABEL, VERSION_LABEL } from "@/lib/labels";
import { formatDate, humanize } from "@/lib/utils";

const LIMIT = 25;

function Assessments() {
  const router = useRouter();
  const params = useSearchParams();
  const [filters, setFilters] = useState({
    state: params.get("state") ?? "",
    review_status: params.get("review_status") ?? "",
    priority: params.get("priority") ?? "",
    severity: params.get("severity") ?? "",
    client_id: params.get("client_id") ?? "",
    vendor_id: params.get("vendor_id") ?? "",
    known_exploited: params.get("known_exploited") ?? "",
    match_status: params.get("match_status") ?? "",
    asset_criticality: params.get("asset_criticality") ?? "",
    published_after: params.get("published_after") ?? "",
  });
  const [offset, setOffset] = useState(0);
  const { data: clients } = useSWR<any>("/clients?limit=100", get);
  const { data: vendors } = useSWR<any>("/vendors?limit=100", get);
  const { data, error } = useSWR<any>(`/assessments${qs({ ...filters, limit: LIMIT, offset })}`, get);
  const set = (k: keyof typeof filters) => (e: React.ChangeEvent<HTMLSelectElement>) => { setFilters({ ...filters, [k]: e.target.value }); setOffset(0); };

  return (
    <>
      <PageHeader title="Impact assessments" description="Where a published advisory meets a product in your inventory. Each assessment shows what is known, what is not, and what to verify next — a match is potential impact, never proof of compromise." />
      <div className="mb-3 flex flex-wrap gap-3">
        <Select aria-label="State" className="max-w-[13rem]" value={filters.state} onChange={set("state")}>
          <option value="">Any state</option>
          {Object.entries(STATE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </Select>
        <Select aria-label="Review status" className="max-w-[11rem]" value={filters.review_status} onChange={set("review_status")}>
          <option value="">Any review status</option>
          {["unreviewed", "reviewed", "dismissed"].map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
        </Select>
        <Select aria-label="Priority" className="max-w-[10rem]" value={filters.priority} onChange={set("priority")}>
          <option value="">Any priority</option>
          {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
        </Select>
        <Select aria-label="Advisory severity" className="max-w-[12rem]" value={filters.severity} onChange={set("severity")}>
          <option value="">Any severity</option>
          {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
        </Select>
        <Select aria-label="Client" className="max-w-[13rem]" value={filters.client_id} onChange={set("client_id")}>
          <option value="">All clients</option>
          {clients?.items.map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </Select>
        <Select aria-label="Vendor" className="max-w-[13rem]" value={filters.vendor_id} onChange={set("vendor_id")}>
          <option value="">All vendors</option>
          {vendors?.items.map((v: any) => <option key={v.id} value={v.id}>{v.name}</option>)}
        </Select>
        <Select aria-label="Exploitation" className="max-w-[12rem]" value={filters.known_exploited} onChange={set("known_exploited")}>
          <option value="">Any exploitation</option>
          <option value="true">Known exploited</option>
          <option value="false">Not known exploited</option>
        </Select>
        <Select aria-label="Match status" className="max-w-[12rem]" value={filters.match_status} onChange={set("match_status")}>
          <option value="">Any match status</option>
          {["matched", "needs_review", "insufficient_data", "no_match"].map((m) => <option key={m} value={m}>{humanize(m)}</option>)}
        </Select>
        <Select aria-label="Asset criticality" className="max-w-[12rem]" value={filters.asset_criticality} onChange={set("asset_criticality")}>
          <option value="">Any asset criticality</option>
          {["critical", "high", "medium", "low"].map((m) => <option key={m} value={m}>{humanize(m)}</option>)}
        </Select>
        <label className="flex items-center gap-2 text-sm text-slate-600">
          Published after
          <Input type="date" aria-label="Published after" className="max-w-[10rem]" value={filters.published_after.slice(0, 10)} onChange={(e) => { setFilters({ ...filters, published_after: e.target.value ? `${e.target.value}T00:00:00Z` : "" }); setOffset(0); }} />
        </label>
      </div>
      <ErrorBox error={error} />
      {!data ? <Loading /> : (
        <>
          <DataTable
            rows={data.items}
            onRowClick={(a: any) => router.push(`/assessments/${a.id}`)}
            empty={<Empty title="No assessments">No advisory matches the recorded inventory with these filters. That does not prove safety if the inventory is incomplete.</Empty>}
            columns={[
              { header: "Priority", cell: (a: any) => <PriorityBadge value={a.priority} /> },
              { header: "Advisory", cell: (a: any) => (<div><span className="font-medium">{a.advisory}</span> {a.known_exploited && <Badge tone="critical">Exploited</Badge>} {a.synthetic && <Badge tone="purple">Synthetic</Badge>}</div>) },
              { header: "Vendor / product", cell: (a: any) => (<div>{a.vendor}<div className="text-xs text-slate-500">{a.product}</div></div>) },
              { header: "Client", cell: (a: any) => a.client ?? <span className="text-slate-400">not linked</span> },
              { header: "State", cell: (a: any) => (<div className="space-y-1"><StateBadge value={a.state} /><div className="text-xs text-slate-500">{VERSION_LABEL[a.version_status]}</div></div>) },
              { header: "Dimensions", cell: (a: any) => (<div className="space-y-0.5 text-xs text-slate-600"><div>Match: {humanize(a.match_status)}</div><div>Exposure: {humanize(a.exposure_status)}</div><div>Compromise: {humanize(a.compromise_status)}</div></div>) },
              { header: "Review", cell: (a: any) => <Badge tone={a.review_status === "unreviewed" ? "medium" : "low"}>{humanize(a.review_status)}</Badge> },
              { header: "Updated", cell: (a: any) => formatDate(a.updated_at) },
            ]}
          />
          <Pagination total={data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}

export default function Page() {
  return <Suspense fallback={<Loading />}><Assessments /></Suspense>;
}
