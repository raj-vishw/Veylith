"use client";
import Link from "next/link";
import useSWR from "swr";
import { SourceHealth } from "@/components/source-health";
import { Badge, Card, Empty, ErrorBox, Loading, Notice, PageHeader, PriorityBadge, StateBadge } from "@/components/ui";
import { get } from "@/lib/api";
import { formatDate, formatDateTime } from "@/lib/utils";

function Count({ label, value, href, hint }: { label: string; value: number; href: string; hint: string }) {
  return (
    <Link href={href} className="rounded-sm border border-slate-300 border-t-2 border-t-slate-900 bg-white p-4 hover:border-t-brand" title={hint}>
      <div className="kicker text-slate-500">{label}</div>
      <div className="numeral mt-2 text-5xl font-light">{value}</div>
      <div className="mt-1 text-xs text-slate-500">{hint}</div>
    </Link>
  );
}

export default function IntelligencePage() {
  const { data, error } = useSWR<any>("/dashboard", get, { refreshInterval: 15000 });
  if (error) return <ErrorBox error={error} />;
  if (!data) return <Loading rows={8} />;
  const c = data.counts;
  const problems = data.sources.sources.filter((s: any) => s.status !== "healthy");

  return (
    <>
      <PageHeader title="Intelligence" description="Advisories matched against your recorded inventory. Counts come straight from the database; a match is potential impact until an analyst verifies exposure." />

      {problems.length > 0 && (
        <div className="mb-5 space-y-2" role="status">
          {problems.map((s: any) => (
            <Notice key={s.source} tone="warn">
              <strong>{s.source === "nvd" ? "NVD" : "CISA KEV"}: {s.status.replace("_", " ")}.</strong> {s.message} <span className="text-xs">An empty advisory list does not mean there is nothing new.</span>
            </Notice>
          ))}
        </div>
      )}

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Count label="Requiring review" value={c.unreviewed} href="/assessments?review_status=unreviewed" hint="Unreviewed assessments" />
        <Count label="Potential exposure" value={c.potential} href="/assessments?state=potential_impact" hint="Matched or uncertain; not verified" />
        <Count label="Exposure verified" value={c.exposure_verified} href="/assessments?state=exposure_verified" hint="Confirmed by an analyst" />
        <Count label="Compromise confirmed" value={c.compromise_confirmed} href="/assessments?state=compromise_confirmed" hint="Requires verified evidence" />
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Assessments requiring review" actions={<Link className="text-xs text-brand hover:underline" href="/assessments?review_status=unreviewed">View all</Link>}>
          {data.high_priority_assessments.length === 0 ? <p className="text-sm text-slate-500">Nothing high-priority is waiting.</p> : (
            <ul className="divide-y divide-slate-100">
              {data.high_priority_assessments.map((a: any) => (
                <li key={a.id} className="py-2 text-sm">
                  <Link href={`/assessments/${a.id}`} className="font-medium hover:underline">{a.advisory}</Link> <PriorityBadge value={a.priority} /> <StateBadge value={a.state} /> {a.known_exploited && <Badge tone="critical">Known exploited</Badge>}
                  <div className="text-xs text-slate-500">{a.vendor} · {a.product} · {a.client ?? "no client linked"}</div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Potentially affected clients">
          {data.affected_clients.length === 0 ? <p className="text-sm text-slate-500">No client is linked to an active assessment.</p> : (
            <ul className="divide-y divide-slate-100 text-sm">
              {data.affected_clients.map((x: any) => (
                <li key={x.client_id} className="flex items-center justify-between py-2"><Link className="font-medium hover:underline" href={`/clients/${x.client_id}`}>{x.client}</Link><span className="text-slate-500">{x.assessments} assessment(s)</span></li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="High-priority assets">
          {data.high_priority_assets.length === 0 ? <p className="text-sm text-slate-500">No asset is on a high-priority path.</p> : (
            <ul className="divide-y divide-slate-100 text-sm">
              {data.high_priority_assets.map((a: any) => (
                <li key={a.asset_id} className="flex items-center justify-between py-2">
                  <Link className="font-medium hover:underline" href={`/assets/${a.asset_id}`}>{a.name}</Link>
                  <span className="space-x-1"><PriorityBadge value={a.criticality} />{a.internet_exposed && <Badge tone="high">exposed</Badge>}<span className="text-xs text-slate-500">{a.assessments} path(s)</span></span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Recent advisories" actions={<Link className="text-xs text-brand hover:underline" href="/advisories">View all</Link>}>
          {data.new_advisories.length === 0 ? <p className="text-sm text-slate-500">No advisories ingested yet.</p> : (
            <ul className="divide-y divide-slate-100 text-sm">
              {data.new_advisories.map((a: any) => (
                <li key={a.id} className="py-2">
                  <Link href={`/advisories/${a.id}`} className="font-medium hover:underline">{a.advisory_id}</Link> <PriorityBadge value={a.severity === "unknown" ? null : a.severity} /> {a.known_exploited && <Badge tone="critical">Known exploited</Badge>} {a.is_synthetic && <Badge tone="purple">Synthetic</Badge>}
                  <div className="text-xs text-slate-500">Published {formatDate(a.published_at)} · first observed {formatDate(a.first_seen_at)}</div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Recent assessment changes" className="lg:col-span-2">
          {data.recently_changed_assessments.length === 0 ? <Empty title="No changes yet" /> : (
            <ul className="divide-y divide-slate-100 text-sm">
              {data.recently_changed_assessments.map((a: any) => (
                <li key={a.id} className="flex flex-wrap items-center gap-2 py-2">
                  <Link href={`/assessments/${a.id}`} className="font-medium hover:underline">{a.advisory}</Link><StateBadge value={a.state} />
                  <span className="text-slate-500">{a.client ?? "no client"}</span><span className="ml-auto text-xs text-slate-500">updated {formatDateTime(a.updated_at)}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Source health and freshness" className="lg:col-span-2">
          <SourceHealth health={data.sources} />
        </Card>
      </div>
    </>
  );
}
