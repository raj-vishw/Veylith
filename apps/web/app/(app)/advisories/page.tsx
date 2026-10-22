"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import useSWR from "swr";
import { Badge, DataTable, Empty, ErrorBox, Input, Loading, PageHeader, Pagination, PriorityBadge, Select } from "@/components/ui";
import { get, qs } from "@/lib/api";
import { formatDate, humanize } from "@/lib/utils";

const LIMIT = 25;

export default function AdvisoriesPage() {
  const router = useRouter();
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [exploited, setExploited] = useState("");
  const [matched, setMatched] = useState(false);
  const [offset, setOffset] = useState(0);
  const { data, error } = useSWR<any>(`/advisories${qs({ q, severity, known_exploited: exploited, matched_only: matched || undefined, limit: LIMIT, offset })}`, get);
  const reset = () => setOffset(0);

  return (
    <>
      <PageHeader title="Advisories" description="Vulnerability intelligence from NIST NVD and the CISA Known Exploited Vulnerabilities catalog. A listed vulnerability is not a confirmed breach of any client." />
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Input aria-label="Search advisories" className="max-w-xs" placeholder="Search CVE or title…" value={q} onChange={(e) => { setQ(e.target.value); reset(); }} />
        <Select aria-label="Severity" className="max-w-[10rem]" value={severity} onChange={(e) => { setSeverity(e.target.value); reset(); }}>
          <option value="">Any severity</option>
          {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
        </Select>
        <Select aria-label="Exploitation" className="max-w-[12rem]" value={exploited} onChange={(e) => { setExploited(e.target.value); reset(); }}>
          <option value="">Any exploitation</option>
          <option value="true">Known exploited</option>
          <option value="false">Not known exploited</option>
        </Select>
        <label className="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" checked={matched} onChange={(e) => { setMatched(e.target.checked); reset(); }} /> Matched to my inventory</label>
      </div>
      <ErrorBox error={error} />
      {!data ? <Loading /> : (
        <>
          <DataTable
            rows={data.items}
            onRowClick={(a: any) => router.push(`/advisories/${a.id}`)}
            empty={<Empty title="No advisories">Load sources from Settings → Intelligence sources, or adjust the filters.</Empty>}
            columns={[
              { header: "Advisory", cell: (a: any) => <span className="font-medium">{a.advisory_id}</span> },
              { header: "Title", cell: (a: any) => <span className="line-clamp-2 max-w-md">{a.title}</span> },
              { header: "Severity", cell: (a: any) => <PriorityBadge value={a.severity === "unknown" ? null : a.severity} /> },
              { header: "Signals", cell: (a: any) => (<div className="flex flex-wrap gap-1">{a.known_exploited && <Badge tone="critical">Known exploited</Badge>}{a.is_synthetic && <Badge tone="purple">Synthetic</Badge>}</div>) },
              { header: "Source", cell: (a: any) => a.source.toUpperCase() },
              { header: "Published", cell: (a: any) => formatDate(a.published_at) },
            ]}
          />
          <Pagination total={data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}
