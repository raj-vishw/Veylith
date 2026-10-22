"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import useSWR from "swr";
import { Badge, Card, Definition, ErrorBox, Loading, Notice, PageHeader, PriorityBadge, StateBadge } from "@/components/ui";
import { get } from "@/lib/api";
import { formatDate, formatDateTime, safeUrl } from "@/lib/utils";

export default function AdvisoryDetail() {
  const { id } = useParams<{ id: string }>();
  const { data: a, error } = useSWR<any>(`/advisories/${id}`, get);
  const { data: assessments } = useSWR<any>(`/assessments?advisory_id=${id}&include_no_match=true&limit=100`, get);
  if (error) return <ErrorBox error={error} />;
  if (!a) return <Loading rows={6} />;

  return (
    <>
      <PageHeader title={a.advisory_id} description={a.title} actions={<>{a.known_exploited && <Badge tone="critical">Known exploited</Badge>}<PriorityBadge value={a.severity === "unknown" ? null : a.severity} /></>} />
      {a.synthetic_notice && <div className="mb-4"><Notice tone="demo"><strong>Synthetic demonstration data.</strong> {a.synthetic_notice}</Notice></div>}
      <div className="grid gap-5 lg:grid-cols-3">
        <Card title="Summary" className="lg:col-span-2">
          <p className="mb-4 whitespace-pre-wrap text-sm">{a.description || "No description."}</p>
          <Definition items={[
            ["Source", a.source.toUpperCase()],
            ["Source URL", safeUrl(a.source_url) ? <a className="break-all text-brand hover:underline" href={safeUrl(a.source_url)!} target="_blank" rel="noopener noreferrer">{a.source_url}</a> : a.source_url || "—"],
            ["CVSS", a.cvss_score ?? "—"],
            ["Published (by source)", formatDateTime(a.published_at)],
            ["Modified (by source)", formatDateTime(a.modified_at)],
            ["First observed by Veylith", formatDateTime(a.first_seen_at)],
            ["Last ingested", formatDateTime(a.last_ingested_at)],
            ["KEV added / due", a.kev_added_at ? `${formatDate(a.kev_added_at)} / ${formatDate(a.kev_due_date)}` : "—"],
          ]} />
          {a.mitigation && <div className="mt-4"><p className="text-xs font-medium uppercase text-slate-500">Mitigation / required action</p><p className="mt-1 whitespace-pre-wrap break-words text-sm">{a.mitigation}</p></div>}
        </Card>

        <Card title="Matching inventory products">
          {!a.matching_products?.length ? <p className="text-sm text-slate-500">No recorded product matches. That does not prove safety if the inventory is incomplete.</p> : (
            <ul className="divide-y divide-slate-100 text-sm">
              {a.matching_products.map((m: any) => (
                <li key={m.match_id} className="py-2">
                  <Link className="font-medium hover:underline" href={`/vendors/${m.vendor_id}`}>{m.vendor}</Link> · {m.product}
                  <div className="mt-1 flex flex-wrap gap-1"><Badge tone={m.status === "matched" ? "medium" : "neutral"}>{m.status.replace("_", " ")}</Badge><Badge>{m.method}</Badge><Badge>{m.version_status.replace("_", " ")}</Badge></div>
                  <Link className="text-xs text-brand hover:underline" href={`/graph?focus=product-${m.product_id}`}>Open in exposure graph →</Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Matched in your inventory">
          {!assessments ? <Loading rows={2} /> : assessments.items.length === 0 ? (
            <p className="text-sm text-slate-500">No recorded product matches this advisory. That does not prove safety if the inventory is incomplete.</p>
          ) : (
            <ul className="divide-y divide-slate-100 text-sm">
              {assessments.items.map((s: any) => (
                <li key={s.id} className="py-2">
                  <Link className="font-medium hover:underline" href={`/assessments/${s.id}`}>{s.vendor} {s.product}</Link>
                  <div className="mt-1 flex flex-wrap gap-1"><StateBadge value={s.state} /><PriorityBadge value={s.priority} /></div>
                  <div className="text-xs text-slate-500">{s.client ?? "no client linked"}</div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Affected products as published" className="lg:col-span-2">
          {a.affected_products.length === 0 ? <p className="text-sm text-slate-500">The source did not publish affected-product details, so this advisory cannot be matched automatically.</p> : (
            <ul className="space-y-1 text-sm">
              {a.affected_products.map((p: any, i: number) => (
                <li key={i}><code className="text-xs">{p.vendor}:{p.product}</code> {p.version && p.version !== "?" ? <span>version {p.version}</span> : p.version === "?" ? <Badge tone="medium">versions not specified</Badge> : null}
                  {p.start_including && <> from {p.start_including}</>}{p.start_excluding && <> after {p.start_excluding}</>}{p.end_including && <> up to {p.end_including}</>}{p.end_excluding && <> before {p.end_excluding}</>}</li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Revision history">
          {a.revisions.length === 0 ? <p className="text-sm text-slate-500">No upstream changes observed.</p> : (
            <ul className="space-y-2 text-xs">
              {a.revisions.map((r: any, i: number) => (
                <li key={i}><div className="font-medium">{formatDateTime(r.changed_at)}</div>{Object.entries(r.changes).map(([k, v]: any) => <div key={k} className="text-slate-600">{k}: {typeof v === "object" ? `${v.from} → ${v.to}` : String(v)}</div>)}</li>
              ))}
            </ul>
          )}
        </Card>

        {a.references.length > 0 && (
          <Card title="References" className="lg:col-span-3">
            <ul className="space-y-1 text-sm">{a.references.map((r: any, i: number) => <li key={i}>{safeUrl(r.url) ? <a className="break-all text-brand hover:underline" href={safeUrl(r.url)!} target="_blank" rel="noopener noreferrer">{r.url}</a> : <span className="break-all text-slate-600">{r.url}</span>}</li>)}</ul>
          </Card>
        )}
      </div>
    </>
  );
}
