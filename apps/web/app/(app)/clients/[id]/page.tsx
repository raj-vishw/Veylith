"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import useSWR from "swr";
import { Badge, Card, DataTable, Definition, Empty, ErrorBox, Loading, PageHeader, PriorityBadge, StateBadge } from "@/components/ui";
import { get } from "@/lib/api";
import { formatDate, humanize } from "@/lib/utils";

export default function ClientDetail() {
  const { id } = useParams<{ id: string }>();
  const { data: c, error } = useSWR<any>(`/clients/${id}`, get);
  const { data: assets } = useSWR<any>(`/assets?client_id=${id}&limit=100`, get);
  const { data: vendors } = useSWR<any>(`/vendors?client_id=${id}&limit=100`, get);
  const { data: assessments } = useSWR<any>(`/assessments?client_id=${id}&limit=50`, get);
  const { data: cases } = useSWR<any>(`/cases?client_id=${id}&limit=50`, get);
  if (error) return <ErrorBox error={error} />;
  if (!c) return <Loading rows={6} />;

  return (
    <>
      <PageHeader title={c.name} description={c.notes || "Client environment"} actions={<Badge tone={c.status === "active" ? "low" : "neutral"}>{humanize(c.status)}</Badge>} />
      <div className="grid gap-5 lg:grid-cols-3">
        <Card title="Details">
          <Definition items={[["Industry", c.industry || "—"], ["Criticality", <PriorityBadge key="c" value={c.criticality} />], ["Internal owner", c.owner || "—"], ["Added", formatDate(c.created_at)], ["Last modified", formatDate(c.updated_at)]]} />
        </Card>
        <Card title="Vendors this client uses" className="lg:col-span-2">
          {!vendors ? <Loading rows={2} /> : vendors.items.length === 0 ? <p className="text-sm text-slate-500">No vendors recorded for this client (record a USES_VENDOR relationship on a vendor page).</p> : (
            <ul className="divide-y divide-slate-100 text-sm">
              {vendors.items.map((v: any) => (
                <li key={v.id} className="flex items-center justify-between py-2"><Link className="font-medium text-brand hover:underline" href={`/vendors/${v.id}`}>{v.name}</Link><span className="space-x-1"><PriorityBadge value={v.criticality} /><Badge>{humanize(v.access_level)} access</Badge></span></li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Assets" className="lg:col-span-3">
          <DataTable
            rows={assets?.items ?? []}
            empty={<Empty title="No assets recorded" />}
            columns={[
              { header: "Asset", cell: (a: any) => <span className="font-medium">{a.name}</span> },
              { header: "Type", cell: (a: any) => humanize(a.type) },
              { header: "Environment", cell: (a: any) => humanize(a.environment) },
              { header: "Criticality", cell: (a: any) => <PriorityBadge value={a.criticality} /> },
              { header: "Verification", cell: (a: any) => <Badge tone={a.verification_status === "verified" ? "low" : "medium"}>{humanize(a.verification_status)}</Badge> },
            ]}
          />
        </Card>
        <Card title="Assessments" className="lg:col-span-2">
          {!assessments ? <Loading rows={2} /> : assessments.items.length === 0 ? <p className="text-sm text-slate-500">No active assessments.</p> : (
            <ul className="divide-y divide-slate-100 text-sm">
              {assessments.items.map((a: any) => (
                <li key={a.id} className="flex flex-wrap items-center gap-2 py-2"><Link className="font-medium hover:underline" href={`/assessments/${a.id}`}>{a.advisory}</Link><span className="text-slate-500">{a.vendor} {a.product}</span><StateBadge value={a.state} /><PriorityBadge value={a.priority} /></li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Cases">
          {!cases ? <Loading rows={2} /> : cases.items.length === 0 ? <p className="text-sm text-slate-500">No cases.</p> : (
            <ul className="space-y-1 text-sm">{cases.items.map((k: any) => <li key={k.id}><Link className="text-brand hover:underline" href={`/cases/${k.id}`}>{k.reference} · {k.title}</Link></li>)}</ul>
          )}
        </Card>
      </div>
    </>
  );
}
