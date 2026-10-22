"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import useSWR from "swr";
import { FormModal } from "@/components/form";
import { useSession } from "@/components/session";
import { Badge, Button, DataTable, Empty, ErrorBox, Input, Loading, PageHeader, Pagination, PriorityBadge, Select, SeverityBadge } from "@/components/ui";
import { get, post, qs } from "@/lib/api";
import { CASE_STATUS_LABEL, LEVELS } from "@/lib/labels";
import { formatDate, humanize, isOverdue } from "@/lib/utils";

const ageInDays = (iso: string) => Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000));

const LIMIT = 25;

export default function CasesPage() {
  const router = useRouter();
  const { can, me } = useSession();
  const [f, setF] = useState({ status: "", priority: "", severity: "", client_id: "", assignee_id: "", overdue: false, q: "", sort: "created_at", direction: "desc" });
  const [offset, setOffset] = useState(0);
  const [creating, setCreating] = useState(false);
  const { data: clients } = useSWR<any>("/clients?limit=100", get);
  const { data: members } = useSWR<any>("/members", get);
  const { data, error } = useSWR<any>(`/cases${qs({ ...f, overdue: f.overdue || undefined, limit: LIMIT, offset })}`, get);
  const upd = (k: string, v: any) => { setF({ ...f, [k]: v }); setOffset(0); };

  return (
    <>
      <PageHeader title="Investigation cases" description="Move a finding from detection through verification and remediation to a documented resolution." actions={can("analyst") && <Button onClick={() => setCreating(true)}>New case</Button>} />
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Input aria-label="Search cases" className="max-w-[14rem]" placeholder="Search title or VEY-0001…" value={f.q} onChange={(e) => upd("q", e.target.value)} />
        <Select aria-label="Status" className="max-w-[11rem]" value={f.status} onChange={(e) => upd("status", e.target.value)}>
          <option value="">Any status</option>
          {Object.entries(CASE_STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </Select>
        <Select aria-label="Priority" className="max-w-[10rem]" value={f.priority} onChange={(e) => upd("priority", e.target.value)}>
          <option value="">Any priority</option>
          {LEVELS.map((l) => <option key={l} value={l}>{humanize(l)}</option>)}
        </Select>
        <Select aria-label="Severity" className="max-w-[10rem]" value={f.severity} onChange={(e) => upd("severity", e.target.value)}>
          <option value="">Any severity</option>
          {LEVELS.map((l) => <option key={l} value={l}>{humanize(l)}</option>)}
        </Select>
        <Select aria-label="Client" className="max-w-[13rem]" value={f.client_id} onChange={(e) => upd("client_id", e.target.value)}>
          <option value="">All clients</option>
          {clients?.items.map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </Select>
        <Select aria-label="Assignee" className="max-w-[13rem]" value={f.assignee_id} onChange={(e) => upd("assignee_id", e.target.value)}>
          <option value="">Anyone</option>
          {members?.items.map((m: any) => <option key={m.user_id} value={m.user_id}>{m.display_name || m.email}{m.user_id === me.user.id ? " (me)" : ""}</option>)}
        </Select>
        <Select aria-label="Sort by" className="max-w-[12rem]" value={`${f.sort}:${f.direction}`} onChange={(e) => { const [sort, direction] = e.target.value.split(":"); setF({ ...f, sort, direction }); setOffset(0); }}>
          <option value="created_at:desc">Newest first</option>
          <option value="created_at:asc">Oldest first</option>
          <option value="updated_at:desc">Recently updated</option>
          <option value="due_date:asc">Due soonest</option>
          <option value="priority:desc">Priority</option>
          <option value="severity:desc">Severity</option>
        </Select>
        <label className="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" checked={f.overdue} onChange={(e) => upd("overdue", e.target.checked)} /> Overdue</label>
      </div>
      <ErrorBox error={error} />
      {!data ? <Loading /> : (
        <>
          <DataTable
            rows={data.items}
            onRowClick={(c: any) => router.push(`/cases/${c.id}`)}
            empty={<Empty title="No cases">Open a case from an assessment, or create one manually.</Empty>}
            columns={[
              { header: "Case", cell: (c: any) => <span className="font-mono text-xs text-slate-500">{c.reference}</span> },
              { header: "Title", cell: (c: any) => <span className="font-medium">{c.title}</span> },
              { header: "Client", cell: (c: any) => c.client ?? "—" },
              { header: "Status", cell: (c: any) => <Badge tone={c.status === "closed" ? "neutral" : c.status === "resolved" ? "low" : "info"}>{CASE_STATUS_LABEL[c.status]}</Badge> },
              { header: "Severity", cell: (c: any) => <SeverityBadge value={c.severity} /> },
              { header: "Priority", cell: (c: any) => <PriorityBadge value={c.priority} /> },
              { header: "Remediation", cell: (c: any) => c.open_tasks ? <span className={c.overdue_tasks ? "font-medium text-red-700" : ""}>{c.open_tasks} open{c.overdue_tasks ? ` · ${c.overdue_tasks} overdue` : ""}</span> : <span className="text-slate-400">—</span> },
              { header: "Age", cell: (c: any) => <span title={`Updated ${formatDate(c.updated_at)}`}>{ageInDays(c.created_at)}d</span> },
              { header: "Assignee", cell: (c: any) => c.assignee ?? <span className="text-slate-400">Unassigned</span> },
              { header: "Due", cell: (c: any) => <span className={isOverdue(c.due_date) && !["resolved", "closed"].includes(c.status) ? "font-medium text-red-600" : ""}>{formatDate(c.due_date)}</span> },
            ]}
          />
          <Pagination total={data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
      <FormModal
        open={creating}
        title="New case"
        fields={[
          { name: "title", label: "Title", required: true },
          { name: "description", label: "Description", type: "textarea" },
          { name: "client_id", label: "Client", type: "select", options: (clients?.items ?? []).map((c: any) => ({ value: c.id, label: c.name })) },
          { name: "priority", label: "Priority", type: "select", options: LEVELS },
          { name: "severity", label: "Severity", type: "select", options: LEVELS, hint: "Leave blank to take it from the linked advisory." },
          { name: "due_date", label: "Target resolution date", type: "date" },
        ]}
        onClose={() => setCreating(false)}
        onSubmit={async (v) => { const c = await post("/cases", v); router.push(`/cases/${c.id}`); }}
      />
    </>
  );
}
