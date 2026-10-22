"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import useSWR from "swr";
import { Badge, Card, DataTable, Definition, Empty, ErrorBox, Loading, PageHeader, PriorityBadge } from "@/components/ui";
import { get } from "@/lib/api";
import { REL_LABEL } from "@/lib/labels";
import { formatDate, humanize } from "@/lib/utils";

export default function AssetDetail() {
  const { id } = useParams<{ id: string }>();
  const { data: a, error } = useSWR<any>(`/assets/${id}`, get);
  const { data: client } = useSWR<any>(a ? `/clients/${a.client_id}` : null, get);
  const { data: rels } = useSWR<any>(`/relationships?entity_id=${id}&limit=100`, get);
  const { data: graph } = useSWR<any>(`/graph?focus=asset-${id}&max_depth=2`, get);
  if (error) return <ErrorBox error={error} />;
  if (!a) return <Loading rows={6} />;
  const label = (nodeId: string) => graph?.nodes.find((n: any) => n.id === nodeId)?.label ?? nodeId.slice(0, 14);

  return (
    <>
      <PageHeader
        title={a.name}
        description={a.description || "Client asset"}
        actions={<Link className="text-sm text-brand hover:underline" href={`/graph?focus=asset-${id}`}>Open in exposure graph →</Link>}
      />
      <div className="grid gap-5 lg:grid-cols-3">
        <Card title="Details" className="lg:col-span-2">
          <Definition
            items={[
              ["Client", client ? <Link key="c" className="text-brand hover:underline" href={`/clients/${client.id}`}>{client.name}</Link> : "—"],
              ["Type", humanize(a.type)],
              ["Environment", humanize(a.environment)],
              ["Criticality", <PriorityBadge key="p" value={a.criticality} />],
              ["Data sensitivity", humanize(a.data_sensitivity)],
              ["Exposure", a.internet_exposed ? <Badge key="e" tone="high">Internet-exposed</Badge> : "Internal"],
              ["Product / version", a.product_name ? `${a.product_name} ${a.product_version}` : "—"],
              ["Verification", <Badge key="v" tone={a.verification_status === "verified" ? "low" : "medium"}>{humanize(a.verification_status)}</Badge>],
              ["Source of record", a.source],
              ["Added / modified", `${formatDate(a.created_at)} / ${formatDate(a.updated_at)}`],
            ]}
          />
        </Card>
        <Card title="Why this matters">
          <p className="text-sm text-slate-600">Assessments reach this asset through the recorded relationships below. Unverified or stale relationships lower confidence; disputed ones are ignored.</p>
        </Card>
        <Card title="Relationships" className="lg:col-span-3">
          <DataTable
            rows={rels?.items ?? []}
            empty={<Empty title="No relationships recorded">Record which vendors and products this asset depends on, or which vendors can access it.</Empty>}
            columns={[
              { header: "From", cell: (r: any) => label(`${r.source_type}-${r.source_id}`) },
              { header: "Relationship", cell: (r: any) => <Badge tone="info">{REL_LABEL[r.rel_type]}</Badge> },
              { header: "To", cell: (r: any) => label(`${r.target_type}-${r.target_id}`) },
              { header: "Scope", cell: (r: any) => r.access_scope || "—" },
              { header: "Evidence", cell: (r: any) => (r.has_evidence ? "Recorded" : "None") },
              { header: "Verification", cell: (r: any) => <Badge tone={r.verification_status === "verified" ? "low" : "medium"}>{humanize(r.verification_status)}</Badge> },
            ]}
          />
        </Card>
      </div>
    </>
  );
}
