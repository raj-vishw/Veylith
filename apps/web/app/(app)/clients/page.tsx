"use client";
import { useState } from "react";
import Link from "next/link";
import useSWR from "swr";
import { FormModal, type FieldDef } from "@/components/form";
import { useSession } from "@/components/session";
import { Button, ConfirmDialog, DataTable, Empty, ErrorBox, Input, Loading, PageHeader, Pagination, PriorityBadge, Badge } from "@/components/ui";
import { get, patch, post, qs } from "@/lib/api";
import { LEVELS } from "@/lib/labels";
import { formatDate } from "@/lib/utils";

const FIELDS: FieldDef[] = [
  { name: "name", label: "Name", required: true, maxLength: 200 },
  { name: "industry", label: "Industry" },
  { name: "criticality", label: "Business criticality", type: "select", options: LEVELS, required: true },
  { name: "owner", label: "Internal owner / responsible team" },
  { name: "notes", label: "Notes", type: "textarea" },
];
const LIMIT = 25;

export default function ClientsPage() {
  const { can } = useSession();
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [archived, setArchived] = useState(false);
  const [editing, setEditing] = useState<any | "new" | null>(null);
  const [toArchive, setToArchive] = useState<any | null>(null);
  const { data, error, mutate } = useSWR<any>(`/clients${qs({ q, limit: LIMIT, offset, include_archived: archived })}`, get);

  return (
    <>
      <PageHeader
        title="Clients"
        description="Each client is a separate environment with its own assets. Vendors and relationships connect to them."
        actions={can("analyst") && <Button onClick={() => setEditing("new")}>Add client</Button>}
      />
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Input aria-label="Search clients" className="max-w-xs" placeholder="Search clients…" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
        <label className="flex items-center gap-2 text-sm text-slate-600">
          <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} /> Show archived
        </label>
      </div>
      <ErrorBox error={error} />
      {!data ? (
        <Loading />
      ) : (
        <>
          <DataTable
            rows={data.items}
            empty={<Empty title="No clients yet">Create a client to start recording its assets and vendor relationships.</Empty>}
            columns={[
              { header: "Client", cell: (c: any) => <Link className="font-medium text-brand hover:underline" href={`/clients/${c.id}`}>{c.name}</Link> },
              { header: "Industry", cell: (c: any) => c.industry || "—" },
              { header: "Owner", cell: (c: any) => c.owner || "—" },
              { header: "Criticality", cell: (c: any) => <PriorityBadge value={c.criticality} /> },
              { header: "Status", cell: (c: any) => (c.archived_at ? <Badge>Archived</Badge> : <Badge tone="low">Active</Badge>) },
              { header: "Added", cell: (c: any) => formatDate(c.created_at) },
              {
                header: "",
                cell: (c: any) =>
                  can("analyst") && (
                    <div className="flex justify-end gap-1">
                      <Button size="sm" variant="secondary" onClick={() => setEditing(c)}>Edit</Button>
                      {c.archived_at ? (
                        <Button size="sm" variant="secondary" onClick={async () => { await post(`/clients/${c.id}/restore`); mutate(); }}>Restore</Button>
                      ) : (
                        <Button size="sm" variant="ghost" onClick={() => setToArchive(c)}>Archive</Button>
                      )}
                    </div>
                  ),
              },
            ]}
          />
          <Pagination total={data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
      <FormModal
        open={!!editing}
        title={editing === "new" ? "Add client" : "Edit client"}
        fields={FIELDS}
        initial={editing === "new" ? { criticality: "medium" } : (editing ?? undefined)}
        onClose={() => setEditing(null)}
        onSubmit={async (v) => { editing === "new" ? await post("/clients", v) : await patch(`/clients/${editing.id}`, v); mutate(); }}
      />
      <ConfirmDialog
        open={!!toArchive}
        title="Archive client?"
        message={<>Archiving hides <strong>{toArchive?.name}</strong> from lists and the graph. Its history and audit trail are kept, and it can be restored.</>}
        confirmLabel="Archive"
        danger
        onClose={() => setToArchive(null)}
        onConfirm={async () => { await post(`/clients/${toArchive.id}/archive`); setToArchive(null); mutate(); }}
      />
    </>
  );
}
