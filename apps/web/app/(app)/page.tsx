"use client";
import Link from "next/link";
import useSWR from "swr";
import { SourceHealth } from "@/components/source-health";
import { Badge, Card, Empty, ErrorBox, Loading, PageHeader, PriorityBadge, StateBadge } from "@/components/ui";
import { get } from "@/lib/api";
import { formatDate, formatDateTime } from "@/lib/utils";

function Stat({ label, value, href, tone }: { label: string; value: number; href: string; tone?: string }) {
  return (
    <Link href={href} className="group rounded-sm border border-slate-300 border-t-2 border-t-slate-900 bg-white p-4 hover:border-t-brand">
      <div className="kicker text-slate-500">{label}</div>
      <div className={`numeral mt-2 text-5xl font-light ${tone ?? "text-slate-900"}`}>{value}</div>
    </Link>
  );
}

export default function Overview() {
  const { data, error } = useSWR<any>("/dashboard", get, { refreshInterval: 15000 });
  const { data: health } = useSWR<any>("/ingestion-health", get, { refreshInterval: 30000 });
  if (error) return <ErrorBox error={error} />;
  if (!data) return <Loading rows={6} />;
  const c = data.counts;
  const inv = data.inventory;
  const hasAnything = c.active_assessments > 0 || data.new_advisories.length > 0;
  const empty = inv.clients + inv.vendors + inv.assets === 0;

  return (
    <>
      <PageHeader title="Overview" description="What changed, what needs review first, and which clients are involved. Assessments are potential impact until an analyst verifies them." />
      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4" aria-label="Inventory">
        <Stat label="Clients" value={inv.clients} href="/clients" />
        <Stat label="Vendors" value={inv.vendors} href="/vendors" />
        <Stat label="Assets" value={inv.assets} href="/assets" />
        <Stat label="Relationships" value={inv.relationships} href="/graph" />
      </div>
      {empty && (
        <div className="mb-6 rounded-lg border border-brand/30 bg-brand-soft p-4 text-sm">
          <p className="font-medium text-slate-900">Welcome — your workspace is empty. Get set up in five steps:</p>
          <ol className="mt-2 list-decimal space-y-1 pl-5 text-slate-700">
            <li><Link className="text-brand underline" href="/clients">Add a client</Link> (a customer environment you manage).</li>
            <li><Link className="text-brand underline" href="/vendors">Add or import vendors</Link> and the products/versions they supply.</li>
            <li><Link className="text-brand underline" href="/assets">Register assets</Link> (repositories, cloud resources, applications).</li>
            <li>Record relationships between them on a vendor page.</li>
            <li>Load advisories in <Link className="text-brand underline" href="/settings">Settings → Intelligence sources</Link> and review the assessments.</li>
          </ol>
        </div>
      )}
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat label="Active assessments" value={c.active_assessments} href="/assessments" />
        <Stat label="Unreviewed" value={c.unreviewed} href="/assessments?review_status=unreviewed" tone="text-amber-600" />
        <Stat label="High priority" value={c.high_priority} href="/assessments?priority=high" tone="text-red-600" />
        <Stat label="Insufficient data" value={c.insufficient_data} href="/assessments?state=insufficient_data" />
        <Stat label="Open cases" value={c.open_cases} href="/cases" />
      </div>

      {(data.failed_ingestion_runs.length > 0 || data.failed_correlation_runs.length > 0) && (
        <div role="alert" className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-900">
          <strong>Pipeline problems.</strong>
          <ul className="mt-1 list-disc pl-5">
            {data.failed_ingestion_runs.map((r: any) => (
              <li key={r.id}>
                Ingestion of {r.source.toUpperCase()} failed {formatDateTime(r.started_at)}: {r.error || "unknown error"}
              </li>
            ))}
            {data.failed_correlation_runs.map((r: any) => (
              <li key={r.id}>
                Correlation failed {formatDateTime(r.started_at)}: {r.error || "unknown error"}
              </li>
            ))}
          </ul>
        </div>
      )}

      {!hasAnything && (
        <Empty title="No intelligence matched yet">
          Add <Link className="text-brand underline" href="/vendors">vendors</Link> and products, record relationships, then load advisories from <Link className="text-brand underline" href="/settings">Settings → Intelligence sources</Link>.
        </Empty>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="High-priority assessments" actions={<Link className="text-xs text-brand hover:underline" href="/assessments">View all</Link>}>
          {data.high_priority_assessments.length === 0 ? (
            <p className="text-sm text-slate-500">None right now.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {data.high_priority_assessments.map((a: any) => (
                <li key={a.id} className="py-2">
                  <Link href={`/assessments/${a.id}`} className="block hover:bg-slate-50">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">{a.advisory}</span>
                      <PriorityBadge value={a.priority} />
                      <StateBadge value={a.state} />
                      {a.known_exploited && <Badge tone="critical">Known exploited</Badge>}
                    </div>
                    <div className="text-xs text-slate-500">
                      {a.vendor} · {a.product} · {a.client ?? "no client linked"}
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Potentially affected clients">
          {data.affected_clients.length === 0 ? (
            <p className="text-sm text-slate-500">No client is linked to an active assessment.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {data.affected_clients.map((c: any) => (
                <li key={c.client_id} className="flex items-center justify-between py-2 text-sm">
                  <Link className="font-medium hover:underline" href={`/assessments?client_id=${c.client_id}`}>
                    {c.client}
                  </Link>
                  <span className="text-slate-500">{c.assessments} assessment(s)</span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="New advisories" actions={<Link className="text-xs text-brand hover:underline" href="/advisories">View all</Link>}>
          {data.new_advisories.length === 0 ? (
            <p className="text-sm text-slate-500">No advisories ingested yet.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {data.new_advisories.map((a: any) => (
                <li key={a.id} className="py-2 text-sm">
                  <Link href={`/advisories/${a.id}`} className="font-medium hover:underline">
                    {a.advisory_id}
                  </Link>{" "}
                  <PriorityBadge value={a.severity === "unknown" ? null : a.severity} />{" "}
                  {a.known_exploited && <Badge tone="critical">Known exploited</Badge>} {a.is_synthetic && <Badge tone="purple">Synthetic</Badge>}
                  <div className="truncate text-xs text-slate-500">{a.title}</div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Recently changed assessments">
          {data.recently_changed_assessments.length === 0 ? (
            <p className="text-sm text-slate-500">Nothing yet.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {data.recently_changed_assessments.map((a: any) => (
                <li key={a.id} className="py-2 text-sm">
                  <Link href={`/assessments/${a.id}`} className="font-medium hover:underline">
                    {a.advisory}
                  </Link>{" "}
                  <StateBadge value={a.state} />
                  <div className="text-xs text-slate-500">
                    {a.client ?? "no client"} · updated {formatDate(a.updated_at)}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Intelligence source health" className="lg:col-span-2">
          <SourceHealth health={health} />
        </Card>
      </div>
    </>
  );
}
