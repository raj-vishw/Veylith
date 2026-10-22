"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useRef, useState } from "react";
import useSWR from "swr";
import { FormModal } from "@/components/form";
import { useSession } from "@/components/session";
import { Badge, Button, Card, DataTable, Definition, Empty, ErrorBox, Field, Input, Loading, Modal, Notice, PageHeader, PriorityBadge, Select, SeverityBadge, StateBadge, Tabs, Textarea } from "@/components/ui";
import { ApiError, del, download, get, patch, post, upload } from "@/lib/api";
import { CASE_STATUS_LABEL, LEVELS, REPORT_STATUS_LABEL, TASK_STATUS_LABEL, VERIFICATION_LABEL } from "@/lib/labels";
import { formatBytes, formatDate, formatDateTime, humanize, isOverdue, safeUrl } from "@/lib/utils";

function readDraft(key: string): string {
  try { return sessionStorage.getItem(key) ?? ""; } catch { return ""; }
}

function useDraft(key: string): [string, (v: string) => void] {
  // Unsaved notes survive navigation and reloads (per case, this browser only).
  const [state, setState] = useState(() => ({ key, value: readDraft(key) }));
  const value = state.key === key ? state.value : readDraft(key);
  return [value, (next: string) => {
    setState({ key, value: next });
    try { next ? sessionStorage.setItem(key, next) : sessionStorage.removeItem(key); } catch {}
  }];
}

function TransitionDialog({ c, to, open, unverified, onClose, onDone }: { c: any; to: string; open: boolean; unverified: number; onClose: () => void; onDone: () => void }) {
  const [note, setNote] = useState("");
  const [summary, setSummary] = useState("");
  const [reason, setReason] = useState("resolved");
  const [error, setError] = useState<unknown>(null);
  const needsSummary = to === "resolved" || to === "closed";
  async function submit() {
    setError(null);
    try {
      await post(`/cases/${c.id}/transition`, { to, version: c.version, note, resolution_summary: summary, closure_reason: to === "closed" ? reason : undefined });
      onDone();
      onClose();
    } catch (e) {
      setError(e);
    }
  }
  return (
    <Modal open={open} title={c.status === "closed" ? "Reopen case" : `Move to ${CASE_STATUS_LABEL[to]}`} onClose={onClose}>
      <div className="space-y-3">
        {(to === "resolved" || to === "closed") && unverified > 0 && (
          <Notice tone="warn">{unverified} completed task{unverified === 1 ? " has" : "s have"} not been verified. Completion is the assignee&apos;s claim; verification records that someone checked it. The report will say so.</Notice>
        )}
        {to === "closed" && (
          <Field label="Closure reason">
            <Select value={reason} onChange={(e) => setReason(e.target.value)}>{["resolved", "false_positive", "accepted_risk", "duplicate"].map((r) => <option key={r} value={r}>{humanize(r)}</option>)}</Select>
          </Field>
        )}
        {needsSummary && <Field label="Resolution summary"><Textarea rows={3} value={summary} onChange={(e) => setSummary(e.target.value)} /></Field>}
        <Field label={c.status === "closed" ? "Reason for reopening (required)" : "Note (optional)"}><Textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)} /></Field>
        <ErrorBox error={error} />
        <div className="flex justify-end gap-2"><Button variant="secondary" onClick={onClose}>Cancel</Button><Button onClick={submit}>Confirm</Button></div>
      </div>
    </Modal>
  );
}

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>();
  const { can, me } = useSession();
  const [tab, setTab] = useState("overview");
  const { data: c, error, mutate } = useSWR<any>(`/cases/${id}`, get);
  const { data: tl, mutate: mTl } = useSWR<any>(tab === "timeline" || tab === "overview" ? `/cases/${id}/timeline` : null, get);
  const { data: tasks, mutate: mTasks } = useSWR<any>(`/cases/${id}/tasks`, get);
  const { data: evidence, mutate: mEv } = useSWR<any>(`/cases/${id}/evidence`, get);
  const { data: notes, mutate: mNotes } = useSWR<any>(`/cases/${id}/notes`, get);
  const { data: reports, mutate: mRep } = useSWR<any>(`/cases/${id}/reports`, get, { refreshInterval: (d) => (d?.items.some((r: any) => r.status === "queued" || r.status === "processing") ? 2000 : 0) });
  const { data: members } = useSWR<any>("/members", get);
  const assessmentIds: string[] = c?.assessment_ids ?? [];
  const { data: assessments } = useSWR<any>(assessmentIds.length ? `assessments:${assessmentIds.join(",")}` : null, async () => Promise.all(assessmentIds.map((a) => get(`/assessments/${a}`))));

  const [transition, setTransition] = useState<string | null>(null);
  const [draft, setDraft] = useDraft(`veylith:case-note:${id}`);
  const [visibility, setVisibility] = useState("internal");
  const [taskOpen, setTaskOpen] = useState<any | "new" | null>(null);
  const [doneTask, setDoneTask] = useState<any | null>(null);
  const [doneNotes, setDoneNotes] = useState("");
  const [evOpen, setEvOpen] = useState(false);
  const [verifyTask, setVerifyTask] = useState<any | null>(null);
  const [verifyNotes, setVerifyNotes] = useState("");
  const [verifyEvidence, setVerifyEvidence] = useState("");
  const [deleteEv, setDeleteEv] = useState<any | null>(null);
  const [integrity, setIntegrity] = useState<{ title: string; ok: boolean; missing: boolean } | null>(null);
  const [linking, setLinking] = useState(false);
  const { data: allAssessments } = useSWR<any>(linking ? "/assessments?limit=100" : null, get);
  const [err, setErr] = useState<unknown>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const [conflict, setConflict] = useState(false);

  if (error) return <ErrorBox error={error} />;
  if (!c) return <Loading rows={8} />;
  const memberName = (uid?: string) => members?.items.find((m: any) => m.user_id === uid)?.display_name || members?.items.find((m: any) => m.user_id === uid)?.email || "Unassigned";
  const refreshAll = () => { mutate(); mTl(); mTasks(); mEv(); mNotes(); mRep(); };

  async function guarded<T>(fn: () => Promise<T>) {
    setErr(null);
    try { return await fn(); } catch (e) {
      if (e instanceof ApiError && e.status === 409 && /changed by someone else/.test(e.detail)) setConflict(true);
      else setErr(e);
    }
  }

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "impact", label: "Impact", count: assessmentIds.length },
    { id: "tasks", label: "Tasks", count: tasks?.items.length },
    { id: "timeline", label: "Timeline" },
    { id: "evidence", label: "Evidence", count: evidence?.items.length },
    { id: "reports", label: "Reports", count: reports?.items.length },
  ];

  return (
    <>
      <PageHeader
        title={`${c.reference} · ${c.title}`}
        description={<span className="flex flex-wrap items-center gap-2"><Badge tone="info">{CASE_STATUS_LABEL[c.status]}</Badge><SeverityBadge value={c.severity} /><PriorityBadge value={c.priority} />{c.client && <span>Client: <strong>{c.client}</strong></span>}</span>}
        actions={can("analyst") && c.allowed_transitions.map((t: string) => <Button key={t} variant={t === "closed" ? "secondary" : "primary"} onClick={() => setTransition(t)}>{c.status === "closed" ? "Reopen" : t === "closed" ? "Close case" : `→ ${CASE_STATUS_LABEL[t]}`}</Button>)}
      />
      {conflict && (
        <div className="mb-4"><Notice tone="warn">This case was changed by someone else while you were working. <button className="font-medium underline" onClick={() => { setConflict(false); refreshAll(); }}>Reload the latest version</button> and try again — your draft note is kept.</Notice></div>
      )}
      <ErrorBox error={err} />
      <Tabs tabs={tabs} value={tab} onChange={setTab} />

      {tab === "overview" && (
        <div className="grid gap-5 lg:grid-cols-3">
          <Card title="Case details" className="lg:col-span-2">
            <Definition items={[
              ["Status", CASE_STATUS_LABEL[c.status]],
              ["Assigned analyst", can("analyst") ? (
                <Select key="a" aria-label="Assignee" value={c.assignee_id ?? ""} onChange={(e) => guarded(async () => { await patch(`/cases/${id}`, { version: c.version, assignee_id: e.target.value || undefined, unassign: !e.target.value }); refreshAll(); })}>
                  <option value="">Unassigned</option>{members?.items.map((m: any) => <option key={m.user_id} value={m.user_id}>{m.display_name || m.email}</option>)}
                </Select>) : memberName(c.assignee_id)],
              ["Priority", can("analyst") ? <Select key="pr" aria-label="Priority" value={c.priority} onChange={(e) => guarded(async () => { await patch(`/cases/${id}`, { version: c.version, priority: e.target.value }); refreshAll(); })}>{LEVELS.map((l) => <option key={l} value={l}>{humanize(l)}</option>)}</Select> : <PriorityBadge value={c.priority} />],
              ["Target date", can("analyst") ? <Input key="d" type="date" aria-label="Target date" value={c.due_date ?? ""} onChange={(e) => e.target.value && guarded(async () => { await patch(`/cases/${id}`, { version: c.version, due_date: e.target.value }); refreshAll(); })} /> : formatDate(c.due_date)],
              ["Severity", can("analyst") ? <Select key="sv" aria-label="Severity" value={c.severity ?? ""} onChange={(e) => e.target.value && guarded(async () => { await patch(`/cases/${id}`, { version: c.version, severity: e.target.value }); refreshAll(); })}>{!c.severity && <option value="">Not stated</option>}{LEVELS.map((l) => <option key={l} value={l}>{humanize(l)}</option>)}</Select> : <SeverityBadge value={c.severity} />],
              ["Advisory", c.advisory ?? "—"], ["Open tasks", `${c.open_tasks}${c.overdue_tasks ? ` (${c.overdue_tasks} overdue)` : ""}`], ["Created", formatDateTime(c.created_at)],
            ]} />
            {c.description && <p className="mt-4 whitespace-pre-wrap rounded bg-slate-50 p-3 text-sm">{c.description}</p>}
            {c.resolution_summary && <div className="mt-4"><p className="text-xs font-medium uppercase text-slate-500">Resolution summary{c.closure_reason ? ` · ${humanize(c.closure_reason)}` : ""}</p><p className="mt-1 whitespace-pre-wrap text-sm">{c.resolution_summary}</p></div>}
          </Card>
          <Card title="Notes">
            <div className="max-h-72 space-y-2 overflow-auto">
              {notes?.items.length === 0 && <p className="text-sm text-slate-500">No notes yet.</p>}
              {notes?.items.map((n: any) => (
                <div key={n.id} className="rounded border border-slate-200 p-2 text-sm">
                  <div className="mb-1 flex items-center justify-between text-xs text-slate-500"><Badge tone={n.visibility === "customer" ? "info" : "neutral"}>{n.visibility === "customer" ? "Customer-visible" : "Internal"}</Badge><span>{formatDateTime(n.created_at)}</span></div>
                  <p className="whitespace-pre-wrap break-words">{n.body}</p>
                </div>
              ))}
            </div>
            {can("analyst") && (
              <div className="mt-3 space-y-2">
                <Textarea aria-label="New note" rows={3} placeholder="Add a note…" value={draft} onChange={(e) => setDraft(e.target.value)} />
                <div className="flex items-center justify-between gap-2">
                  <Select aria-label="Visibility" className="max-w-[11rem]" value={visibility} onChange={(e) => setVisibility(e.target.value)}><option value="internal">Internal only</option><option value="customer">Customer-visible</option></Select>
                  <Button size="sm" disabled={!draft.trim()} onClick={() => guarded(async () => { await post(`/cases/${id}/notes`, { body: draft, visibility }); setDraft(""); mNotes(); mTl(); })}>Add note</Button>
                </div>
                {visibility === "customer" && <p className="text-xs text-amber-700">Customer-visible notes appear in client reports.</p>}
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === "impact" && (
        <div className="space-y-4">
          {can("analyst") && c.status !== "closed" && <div className="flex justify-end"><Button variant="secondary" onClick={() => setLinking(true)}>Link another assessment</Button></div>}
          {!assessments ? (assessmentIds.length ? <Loading /> : <Empty title="No assessments linked">This case was opened without an assessment.</Empty>) : assessments.map((a: any) => (
            <Card key={a.id} title={<Link className="hover:underline" href={`/assessments/${a.id}`}>{a.advisory} → {a.vendor} {a.product}</Link>} actions={<><StateBadge value={a.state} /><PriorityBadge value={a.priority} /></>}>
              <div className="grid gap-4 md:grid-cols-2">
                <div><p className="mb-1 text-xs font-medium uppercase text-slate-500">Path</p><ol className="list-decimal pl-5 text-sm">{a.evidence.path.map((s: any, i: number) => <li key={i}>{s.label}</li>)}</ol></div>
                <div><p className="mb-1 text-xs font-medium uppercase text-slate-500">Not yet established</p><ul className="list-disc pl-5 text-sm text-slate-700">{a.unknowns.slice(0, 4).map((u: string, i: number) => <li key={i}>{u}</li>)}</ul></div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {tab === "tasks" && (
        <>
          {can("analyst") && c.status !== "closed" && <div className="mb-3 flex justify-end"><Button onClick={() => setTaskOpen("new")}>Add task</Button></div>}
          <DataTable
            rows={tasks?.items ?? []}
            empty={<Empty title="No remediation tasks">Examples: verify the deployed version, contact the vendor, review integration permissions, check access logs, apply the vendor patch.</Empty>}
            columns={[
              { header: "Task", cell: (t: any) => <div><div className="font-medium">{t.title}</div>{t.completion_notes && <div className="text-xs text-slate-500">{t.completion_notes}</div>}</div> },
              { header: "Status", cell: (t: any) => <Badge tone={t.status === "done" ? "info" : t.status === "blocked" ? "high" : "neutral"}>{TASK_STATUS_LABEL[t.status] ?? humanize(t.status)}</Badge> },
              { header: "Verification", cell: (t: any) => t.status === "done" || t.verification_status !== "unverified" ? <div><Badge tone={t.verification_status === "verified" ? "low" : t.verification_status === "rejected" ? "critical" : "medium"}>{VERIFICATION_LABEL[t.verification_status]}</Badge>{t.verified_at && <div className="mt-1 text-xs text-slate-500">{memberName(t.verified_by)} · {formatDate(t.verified_at)}</div>}{t.verification_notes && <div className="mt-1 max-w-xs text-xs text-slate-600">{t.verification_notes}</div>}</div> : <span className="text-slate-400">—</span> },
              { header: "Priority", cell: (t: any) => <PriorityBadge value={t.priority} /> },
              { header: "Assignee", cell: (t: any) => memberName(t.assignee_id) },
              { header: "Due", cell: (t: any) => <span className={t.overdue ? "font-medium text-red-600" : ""}>{formatDate(t.due_date)}{t.overdue ? " · overdue" : ""}</span> },
              { header: "", cell: (t: any) => can("analyst") && (
                <div className="flex justify-end gap-1">
                  {t.status !== "done" && t.status !== "cancelled" && <>
                    {t.status === "open" && <Button size="sm" variant="secondary" onClick={() => guarded(async () => { await patch(`/tasks/${t.id}`, { status: "in_progress" }); mTasks(); })}>Start</Button>}
                    <Button size="sm" onClick={() => { setDoneTask(t); setDoneNotes(""); }}>Complete</Button>
                  </>}
                  {t.status === "done" && t.verification_status !== "verified" && <Button size="sm" onClick={() => { setVerifyTask(t); setVerifyNotes(""); setVerifyEvidence(t.verification_evidence_id ?? ""); }}>Verify</Button>}
                  <Button size="sm" variant="ghost" onClick={() => setTaskOpen(t)}>Edit</Button>
                </div>) },
            ]}
          />
        </>
      )}

      {tab === "timeline" && (
        <Card>
          <ol className="relative space-y-4 border-l border-slate-200 pl-5">
            {tl?.items.map((e: any) => (
              <li key={e.id} className="relative">
                <span className={`absolute -left-[1.6rem] top-1 h-2.5 w-2.5 rounded-full ${e.is_system ? "bg-slate-400" : "bg-brand"}`} />
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">{formatDateTime(e.occurred_at)}<Badge tone={e.is_system ? "neutral" : "info"}>{e.is_system ? "System" : e.actor}</Badge></div>
                <div className="text-sm">{e.summary}</div>
              </li>
            ))}
          </ol>
          {!tl && <Loading rows={3} />}
        </Card>
      )}

      {tab === "evidence" && (
        <>
          {can("analyst") && (
            <div className="mb-3 flex justify-end gap-2">
              <input ref={fileRef} type="file" hidden aria-label="Upload evidence file" onChange={(e) => { const f = e.target.files?.[0]; if (f) guarded(async () => { await upload(`/cases/${id}/evidence/files`, f, { assessment_id: assessmentIds[0] ?? "" }); mEv(); mTl(); }); e.target.value = ""; }} />
              <Button variant="secondary" onClick={() => fileRef.current?.click()}>Upload file</Button>
              <Button onClick={() => setEvOpen(true)}>Add source or note</Button>
            </div>
          )}
          {integrity && (
            <div className="mb-3" role="status"><Notice tone={integrity.ok ? "info" : "warn"}>
              {integrity.ok ? `“${integrity.title}” matches the SHA-256 recorded when it was stored. This shows it is unchanged since then, not that it was authentic when collected.` : integrity.missing ? `“${integrity.title}”: the stored file is missing.` : `“${integrity.title}” no longer matches its recorded SHA-256. Downloads are blocked; treat this evidence as compromised and tell an administrator.`}
              {" "}<button className="font-medium underline" onClick={() => setIntegrity(null)}>Dismiss</button>
            </Notice></div>
          )}
          <DataTable
            rows={evidence?.items ?? []}
            empty={<Empty title="No evidence yet">Attach vendor advisories, logs and observations. Files are stored privately with a SHA-256 hash.</Empty>}
            columns={[
              { header: "Evidence", cell: (e: any) => <div><div className="font-medium">{e.title}</div>{e.excerpt && <div className="line-clamp-2 max-w-md text-xs text-slate-500">{e.excerpt}</div>}</div> },
              { header: "Type", cell: (e: any) => humanize(e.kind) },
              { header: "Source", cell: (e: any) => <div className="text-xs">{e.source_name}{safeUrl(e.source_url) ? <a className="block break-all text-brand hover:underline" href={safeUrl(e.source_url)!} target="_blank" rel="noopener noreferrer">{e.source_url}</a> : e.source_url && <div className="break-all">{e.source_url}</div>}</div> },
              { header: "Collected", cell: (e: any) => <div className="text-xs"><div>{e.collected_at ? formatDateTime(e.collected_at) : "Not stated"}</div><div className="text-slate-500">recorded {formatDateTime(e.retrieved_at)}</div></div> },
              { header: "Integrity", cell: (e: any) => e.sha256 ? <div className="text-xs"><div>{formatBytes(e.size_bytes)}</div><code title={e.sha256}>{e.sha256.slice(0, 12)}…</code></div> : "—" },
              { header: "Status", cell: (e: any) => <Badge tone={e.verification_status === "verified" ? "low" : e.verification_status === "rejected" ? "high" : "medium"}>{humanize(e.verification_status)}</Badge> },
              { header: "", cell: (e: any) => (
                <div className="flex justify-end gap-1">
                  {e.kind === "file" && can("analyst") && <Button size="sm" variant="secondary" onClick={() => guarded(() => download(`/evidence/${e.id}/download`, e.original_filename || "evidence"))}>Download</Button>}
                  {e.kind === "file" && can("analyst") && <Button size="sm" variant="ghost" onClick={() => guarded(async () => { const r = await get(`/evidence/${e.id}/integrity`); setIntegrity({ title: e.title, ok: r.ok, missing: r.missing }); })}>Check integrity</Button>}
                  {can("analyst") && e.verification_status !== "verified" && <Button size="sm" variant="secondary" onClick={() => guarded(async () => { await post(`/evidence/${e.id}/verify`, { verification_status: "verified" }); mEv(); mTl(); })}>Verify</Button>}
                  {can("owner") && <Button size="sm" variant="ghost" onClick={() => setDeleteEv(e)}>Delete</Button>}
                </div>) },
            ]}
          />
        </>
      )}

      {tab === "reports" && (
        <>
          {can("analyst") && (
            <div className="mb-3 flex justify-end gap-2">
              <Button variant="secondary" onClick={() => guarded(async () => { await post(`/cases/${id}/reports`, { kind: "executive" }); mRep(); mTl(); })}>Generate executive report</Button>
              <Button onClick={() => guarded(async () => { await post(`/cases/${id}/reports`, { kind: "technical" }); mRep(); mTl(); })}>Generate technical report</Button>
            </div>
          )}
          <DataTable
            rows={reports?.items ?? []}
            empty={<Empty title="No reports yet">Reports are generated from this case&apos;s authorised records and never include internal notes.</Empty>}
            columns={[
              { header: "Report", cell: (r: any) => humanize(r.kind) },
              { header: "Status", cell: (r: any) => <Badge tone={r.status === "completed" ? "low" : r.status === "failed" ? "critical" : "info"}>{REPORT_STATUS_LABEL[r.status] ?? humanize(r.status)}</Badge> },
              { header: "Created", cell: (r: any) => formatDateTime(r.created_at) },
              { header: "Template", cell: (r: any) => `v${r.template_version}${r.attempts > 1 ? ` · ${r.attempts} attempts` : ""}` },
              { header: "Size", cell: (r: any) => (r.size_bytes ? formatBytes(r.size_bytes) : "—") },
              { header: "", cell: (r: any) => (<div className="flex justify-end">{r.status === "completed" && can("analyst") && <Button size="sm" onClick={() => guarded(() => download(`/reports/${r.id}/download`, "veylith-report.pdf"))}>Download PDF</Button>}{r.retryable && <div className="flex items-center gap-2">{r.error && <span className="max-w-xs text-right text-xs text-red-700">{r.error}</span>}{can("analyst") && <Button size="sm" variant="secondary" onClick={() => guarded(async () => { await post(`/reports/${r.id}/retry`); mRep(); mTl(); })}>Retry</Button>}</div>}</div>) },
            ]}
          />
        </>
      )}

      {transition && <TransitionDialog c={c} to={transition} open unverified={(tasks?.items ?? []).filter((t: any) => t.status === "done" && t.verification_status !== "verified").length} onClose={() => setTransition(null)} onDone={() => { refreshAll(); }} />}
      <FormModal
        open={!!taskOpen}
        title={taskOpen === "new" ? "Add task" : "Edit task"}
        fields={[
          { name: "title", label: "Title", required: true },
          { name: "description", label: "Description", type: "textarea" },
          { name: "assignee_id", label: "Assignee", type: "select", options: (members?.items ?? []).map((m: any) => ({ value: m.user_id, label: m.display_name || m.email })) },
          { name: "priority", label: "Priority", type: "select", options: LEVELS, required: true },
          { name: "due_date", label: "Due date", type: "date" },
        ]}
        initial={taskOpen === "new" ? { priority: "medium" } : taskOpen ?? undefined}
        onClose={() => setTaskOpen(null)}
        onSubmit={async (v) => { taskOpen === "new" ? await post(`/cases/${id}/tasks`, v) : await patch(`/tasks/${taskOpen.id}`, v); mTasks(); mTl(); }}
      />
      <Modal open={!!doneTask} title="Complete task" onClose={() => setDoneTask(null)}>
        <div className="space-y-3">
          <p className="text-sm font-medium">{doneTask?.title}</p>
          <Field label="Completion notes (required)" hint="What was done, and how it was verified."><Textarea rows={3} value={doneNotes} onChange={(e) => setDoneNotes(e.target.value)} /></Field>
          {evidence?.items.length > 0 && (
            <Field label="Verification evidence (optional)">
              <Select id="verif" defaultValue="" onChange={(e) => setDoneTask({ ...doneTask, evidence: e.target.value })}>
                <option value="">None</option>{evidence.items.map((e: any) => <option key={e.id} value={e.id}>{e.title}</option>)}
              </Select>
            </Field>
          )}
          <div className="flex justify-end gap-2"><Button variant="secondary" onClick={() => setDoneTask(null)}>Cancel</Button><Button disabled={!doneNotes.trim()} onClick={() => guarded(async () => { await patch(`/tasks/${doneTask.id}`, { status: "done", completion_notes: doneNotes, verification_evidence_id: doneTask.evidence || undefined }); setDoneTask(null); mTasks(); mTl(); mutate(); })}>Mark complete</Button></div>
        </div>
      </Modal>
      <Modal open={!!verifyTask} title="Verify remediation" onClose={() => setVerifyTask(null)}>
        <div className="space-y-3">
          <p className="text-sm font-medium">{verifyTask?.title}</p>
          <p className="rounded-sm bg-slate-100 p-2 text-sm text-slate-700"><span className="kicker block text-slate-500">Completion claim</span>{verifyTask?.completion_notes}</p>
          <Field label="What did you check?" hint="Verification is separate from completion: record how the fix was confirmed."><Textarea rows={3} value={verifyNotes} onChange={(e) => setVerifyNotes(e.target.value)} /></Field>
          {evidence?.items.length > 0 && (
            <Field label="Supporting evidence">
              <Select value={verifyEvidence} onChange={(e) => setVerifyEvidence(e.target.value)}>
                <option value="">None</option>{evidence.items.map((e: any) => <option key={e.id} value={e.id}>{e.title}</option>)}
              </Select>
            </Field>
          )}
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setVerifyTask(null)}>Cancel</Button>
            <Button variant="danger" disabled={!verifyNotes.trim()} onClick={() => guarded(async () => { await post(`/tasks/${verifyTask.id}/verify`, { verification_status: "rejected", notes: verifyNotes }); setVerifyTask(null); mTasks(); mTl(); mutate(); })}>Reject</Button>
            <Button disabled={!verifyNotes.trim() && !verifyEvidence} onClick={() => guarded(async () => { await post(`/tasks/${verifyTask.id}/verify`, { verification_status: "verified", notes: verifyNotes, evidence_id: verifyEvidence || undefined }); setVerifyTask(null); mTasks(); mTl(); mutate(); })}>Mark verified</Button>
          </div>
        </div>
      </Modal>
      <FormModal
        open={!!deleteEv}
        title="Delete evidence"
        submitLabel="Delete evidence"
        fields={[{ name: "reason", label: "Reason (recorded in the audit trail)", type: "textarea", required: true, hint: "The file is retained and hidden, not destroyed. Owners only." }]}
        onClose={() => setDeleteEv(null)}
        onSubmit={async (v) => { await del(`/evidence/${deleteEv.id}`, { reason: v.reason }); mEv(); mTl(); }}
      />
      <Modal open={linking} title="Link another assessment" onClose={() => setLinking(false)}>
        <div className="space-y-3">
          <p className="text-sm text-slate-600">Assessments are linked by reference; their evidence is not copied into the case.</p>
          <div className="max-h-72 space-y-1 overflow-auto">
            {!allAssessments ? <Loading rows={3} /> : allAssessments.items.filter((a: any) => !assessmentIds.includes(a.id)).map((a: any) => (
              <button key={a.id} className="block w-full rounded-sm border border-slate-300 px-3 py-2 text-left text-sm hover:bg-brand-soft" onClick={() => guarded(async () => { await post(`/cases/${id}/assessments`, { assessment_ids: [a.id] }); setLinking(false); refreshAll(); })}>
                <span className="font-medium">{a.advisory}</span> · {a.client} · {a.vendor} {a.product}
              </button>
            ))}
            {allAssessments && allAssessments.items.every((a: any) => assessmentIds.includes(a.id)) && <Empty title="Nothing left to link" />}
          </div>
        </div>
      </Modal>
      <FormModal
        open={evOpen}
        title="Add evidence"
        fields={[
          { name: "kind", label: "Type", type: "select", options: ["url", "note"], required: true },
          { name: "title", label: "Title", required: true },
          { name: "source_name", label: "Source name" },
          { name: "source_url", label: "Source URL", placeholder: "https://…", hint: "Stored as a reference only; Veylith never fetches it." },
          { name: "excerpt", label: "Relevant excerpt or observation", type: "textarea" },
          { name: "collected_at", label: "Collected on", type: "date", hint: "When the information was gathered, if different from today." },
        ]}
        initial={{ kind: "url", assessment_id: assessmentIds[0] }}
        onClose={() => setEvOpen(false)}
        onSubmit={async (v) => { await post(`/cases/${id}/evidence`, { ...v, collected_at: v.collected_at || undefined, assessment_id: assessmentIds[0] }); mEv(); mTl(); }}
      />
    </>
  );
}
