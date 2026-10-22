"use client";
import { useState } from "react";
import useSWR from "swr";
import { FormModal } from "@/components/form";
import { useSession } from "@/components/session";
import { Badge, Button, ConfirmDialog, DataTable, Empty, ErrorBox, Input, Loading, PageHeader, Pagination, PriorityBadge, Select } from "@/components/ui";
import { ASSET_FIELDS } from "@/lib/fields";
import { del, get, patch, post, qs } from "@/lib/api";
import { ASSET_TYPES } from "@/lib/labels";
import { humanize } from "@/lib/utils";

const LIMIT = 25;

export default function AssetsPage() {
  const { can } = useSession();
  const [q, setQ] = useState("");
  const [clientId, setClientId] = useState("");
  const [type, setType] = useState("");
  const [offset, setOffset] = useState(0);
  const [editing, setEditing] = useState<any | "new" | null>(null);
  const [toDelete, setToDelete] = useState<any | null>(null);
  const { data: clients } = useSWR<any>("/clients?limit=100", get);
  const { data, error, mutate } = useSWR<any>(`/assets${qs({ q, client_id: clientId, type, limit: LIMIT, offset })}`, get);
  const clientName = (id: string) => clients?.items.find((c: any) => c.id === id)?.name ?? "—";
  const fields = [
    { name: "client_id", label: "Client", type: "select" as const, required: true, options: (clients?.items ?? []).map((c: any) => ({ value: c.id, label: c.name })) },
    ...ASSET_FIELDS,
  ];

  return (
    <>
      <PageHeader
        title="Assets"
        description="Repositories, cloud accounts, applications and environments that belong to a client. Criticality and exposure feed prioritisation."
        actions={can("analyst") && <Button onClick={() => setEditing("new")} disabled={!clients?.items.length}>Add asset</Button>}
      />
      <div className="mb-3 flex flex-wrap gap-3">
        <Input aria-label="Search assets" className="max-w-xs" placeholder="Search assets…" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
        <Select aria-label="Filter by client" className="max-w-[14rem]" value={clientId} onChange={(e) => { setClientId(e.target.value); setOffset(0); }}>
          <option value="">All clients</option>
          {clients?.items.map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </Select>
        <Select aria-label="Filter by type" className="max-w-[12rem]" value={type} onChange={(e) => { setType(e.target.value); setOffset(0); }}>
          <option value="">All types</option>
          {ASSET_TYPES.map((t) => <option key={t} value={t}>{humanize(t)}</option>)}
        </Select>
      </div>
      <ErrorBox error={error} />
      {clients && !clients.items.length && <Empty title="Create a client first">Assets belong to a client environment.</Empty>}
      {!data ? <Loading /> : (
        <>
          <DataTable
            rows={data.items}
            empty={clients?.items.length ? <Empty title="No assets yet">Record the systems that use or are accessed by your vendors.</Empty> : <></>}
            columns={[
              { header: "Asset", cell: (a: any) => <span className="font-medium">{a.name}</span> },
              { header: "Client", cell: (a: any) => clientName(a.client_id) },
              { header: "Type", cell: (a: any) => humanize(a.type) },
              { header: "Environment", cell: (a: any) => humanize(a.environment) },
              { header: "Criticality", cell: (a: any) => <PriorityBadge value={a.criticality} /> },
              { header: "Exposure", cell: (a: any) => (a.internet_exposed ? <Badge tone="high">Internet-exposed</Badge> : <Badge>Internal</Badge>) },
              { header: "", cell: (a: any) => can("analyst") && (<div className="flex justify-end gap-1"><Button size="sm" variant="secondary" onClick={() => setEditing(a)}>Edit</Button><Button size="sm" variant="ghost" onClick={() => setToDelete(a)}>Delete</Button></div>) },
            ]}
          />
          <Pagination total={data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
      <FormModal
        open={!!editing}
        title={editing === "new" ? "Add asset" : "Edit asset"}
        fields={editing === "new" ? fields : fields.filter((f) => f.name !== "client_id")}
        initial={editing === "new" ? { type: "repository", environment: "production", criticality: "medium", data_sensitivity: "internal", verification_status: "unverified", source: "manual", client_id: clientId || undefined } : editing ?? undefined}
        onClose={() => setEditing(null)}
        onSubmit={async (v) => { editing === "new" ? await post("/assets", v) : await patch(`/assets/${editing.id}`, v); mutate(); }}
      />
      <ConfirmDialog open={!!toDelete} danger title="Delete asset?" message={<>Delete <strong>{toDelete?.name}</strong>? Relationships to it stop appearing in the graph. History is kept in the audit trail.</>} confirmLabel="Delete" onClose={() => setToDelete(null)} onConfirm={async () => { await del(`/assets/${toDelete.id}`); setToDelete(null); mutate(); }} />
    </>
  );
}
