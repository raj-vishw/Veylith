"use client";
import { useState } from "react";
import useSWR from "swr";
import { FormModal } from "@/components/form";
import { SourceHealth } from "@/components/source-health";
import { useSession } from "@/components/session";
import { Badge, Button, Card, ConfirmDialog, DataTable, Empty, ErrorBox, Field, Input, Loading, Notice, PageHeader, Pagination, Select, Tabs } from "@/components/ui";
import { del, get, patch, post, qs } from "@/lib/api";
import { formatDateTime, humanize } from "@/lib/utils";

function Profile() {
  const { can, refresh } = useSession();
  const { data: org, mutate } = useSWR<any>("/organization", get);
  const [form, setForm] = useState<any>(null);
  const [msg, setMsg] = useState<string>("");
  const [err, setErr] = useState<unknown>(null);
  if (!org) return <Loading rows={3} />;
  const f = form ?? { name: org.name, slug: org.slug, timezone: org.timezone, retention_days: org.retention_days };
  async function save() {
    setErr(null);
    setMsg("");
    try {
      await patch("/organization", { ...f, retention_days: Number(f.retention_days) });
      setMsg("Saved");
      setForm(null);
      mutate();
      refresh();
    } catch (e) {
      setErr(e);
    }
  }
  return (
    <Card title="Organization profile" className="max-w-xl">
      <div className="space-y-3">
        <Field label="Name"><Input disabled={!can("owner")} value={f.name} onChange={(e) => setForm({ ...f, name: e.target.value })} /></Field>
        <Field label="URL slug" hint="Lowercase letters, numbers and hyphens."><Input disabled={!can("owner")} value={f.slug} onChange={(e) => setForm({ ...f, slug: e.target.value })} /></Field>
        <Field label="Timezone"><Input disabled={!can("owner")} value={f.timezone} onChange={(e) => setForm({ ...f, timezone: e.target.value })} /></Field>
        <Field label="Retention (days)" hint="How long records are intended to be kept. Enforcement of deletion is a manual operational task in this release."><Input type="number" min={30} max={3650} disabled={!can("owner")} value={f.retention_days} onChange={(e) => setForm({ ...f, retention_days: e.target.value })} /></Field>
        <ErrorBox error={err} />
        {msg && <p className="text-sm text-emerald-700">{msg}</p>}
        {can("owner") ? <Button onClick={save}>Save changes</Button> : <p className="text-xs text-slate-500">Only owners can change organization settings.</p>}
      </div>
    </Card>
  );
}

function Members() {
  const { can, me } = useSession();
  const { data, mutate } = useSWR<any>("/members", get);
  const [adding, setAdding] = useState(false);
  const [remove, setRemove] = useState<any>(null);
  const [err, setErr] = useState<unknown>(null);
  if (!data) return <Loading />;
  return (
    <>
      <ErrorBox error={err} />
      <div className="mb-3 flex items-center justify-between">
        <p className="text-sm text-slate-600">Owners manage the organization; analysts manage vendors and cases; viewers have read-only access.</p>
        {can("owner") && <Button onClick={() => setAdding(true)}>Add member</Button>}
      </div>
      <DataTable
        rows={data.items.map((m: any) => ({ ...m, id: m.user_id }))}
        columns={[
          { header: "Member", cell: (m: any) => <div><div className="font-medium">{m.display_name || m.email}</div><div className="text-xs text-slate-500">{m.email}</div></div> },
          { header: "Status", cell: (m: any) => <Badge tone={m.status === "active" ? "low" : "neutral"}>{humanize(m.status)}</Badge> },
          { header: "Role", cell: (m: any) => can("owner") && m.status === "active" ? (
            <Select aria-label={`Role for ${m.email}`} className="max-w-[9rem]" value={m.role} onChange={async (e) => { setErr(null); try { await patch(`/members/${m.user_id}`, { role: e.target.value }); mutate(); } catch (x) { setErr(x); } }}>
              {["owner", "analyst", "viewer"].map((r) => <option key={r} value={r}>{humanize(r)}</option>)}
            </Select>) : <Badge>{humanize(m.role)}</Badge> },
          { header: "Joined", cell: (m: any) => formatDateTime(m.joined_at) },
          { header: "", cell: (m: any) => can("owner") && m.status === "active" && m.user_id !== me.user.id && <Button size="sm" variant="ghost" onClick={() => setRemove(m)}>Revoke</Button> },
        ]}
      />
      <FormModal
        open={adding}
        title="Add member"
        fields={[
          { name: "email", label: "Email", required: true },
          { name: "display_name", label: "Name" },
          { name: "role", label: "Role", type: "select", options: ["analyst", "viewer", "owner"], required: true },
          { name: "password", label: "Initial password", hint: "Required for new accounts (min 12 characters). Share it securely; the member should change it." },
        ]}
        initial={{ role: "analyst" }}
        onClose={() => setAdding(false)}
        onSubmit={async (v) => { await post("/members", v); mutate(); }}
      />
      <ConfirmDialog open={!!remove} danger title="Revoke membership?" message={<>{remove?.email} loses access to this organization immediately and their sessions here are revoked. The membership record is kept for the audit history and can be re-admitted.</>} confirmLabel="Revoke" onClose={() => setRemove(null)} onConfirm={async () => { try { await del(`/members/${remove.user_id}`); mutate(); } catch (x) { setErr(x); } setRemove(null); }} />
    </>
  );
}

function Audit() {
  const [offset, setOffset] = useState(0);
  const [type, setType] = useState("");
  const { data, error } = useSWR<any>(`/audit-events${qs({ event_type: type, limit: 25, offset })}`, get);
  return (
    <>
      <div className="mb-3 flex items-center gap-3">
        <Select aria-label="Event category" className="max-w-[14rem]" value={type} onChange={(e) => { setType(e.target.value); setOffset(0); }}>
          <option value="">All events</option>
          {["auth", "member", "client", "vendor", "product", "asset", "relationship", "assessment", "case", "task", "evidence", "report", "ingestion", "correlation"].map((t) => <option key={t} value={t}>{humanize(t)}</option>)}
        </Select>
        <span className="text-xs text-slate-500">Append-only application log. It records who did what, but it is not a tamper-proof forensic record.</span>
      </div>
      <ErrorBox error={error} />
      {!data ? <Loading /> : (
        <>
          <DataTable
            rows={data.items}
            empty={<Empty title="No events" />}
            columns={[
              { header: "When", cell: (e: any) => <span className="whitespace-nowrap text-xs">{formatDateTime(e.occurred_at)}</span> },
              { header: "Actor", cell: (e: any) => e.actor },
              { header: "Event", cell: (e: any) => <code className="text-xs">{e.event_type}</code> },
              { header: "Object", cell: (e: any) => <span className="text-xs text-slate-500">{e.object_type} {e.object_id.slice(0, 8)}</span> },
              { header: "Details", cell: (e: any) => <code className="block max-w-sm break-all text-xs text-slate-600">{Object.keys(e.metadata).length ? JSON.stringify(e.metadata) : ""}</code> },
            ]}
          />
          <Pagination total={data.total} limit={25} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}

function Sources() {
  const { can } = useSession();
  const { data: health, mutate: mHealth } = useSWR<any>("/ingestion-health", get, { refreshInterval: 5000 });
  const { data: runs, mutate: mRuns } = useSWR<any>("/ingestion-runs?limit=10", get, { refreshInterval: 5000 });
  const { data: corr, mutate: mCorr } = useSWR<any>("/correlation-runs?limit=5", get, { refreshInterval: 5000 });
  const [err, setErr] = useState<unknown>(null);
  const [msg, setMsg] = useState("");
  const start = async (source: string) => {
    setErr(null);
    setMsg("");
    try {
      await post("/ingestion-runs", { source });
      setMsg(`${source.toUpperCase()} ingestion queued.`);
      mRuns();
      mHealth();
    } catch (e) {
      setErr(e);
    }
  };
  return (
    <div className="space-y-5">
      <Notice>NVD and CISA KEV provide vulnerability intelligence. They are not a feed of vendor breaches and cannot show that a particular customer was compromised.</Notice>
      <ErrorBox error={err} />
      {msg && <p className="text-sm text-emerald-700">{msg}</p>}
      <Card title="Sources" actions={can("owner") && <><Button size="sm" onClick={() => start("kev")}>Fetch CISA KEV</Button><Button size="sm" onClick={() => start("nvd")}>Fetch NVD (recent)</Button><Button size="sm" variant="secondary" onClick={() => start("fixture")}>Load synthetic demo advisories</Button></>}>
        <SourceHealth health={health} />
      </Card>
      <Card title="Recent ingestion runs">
        <DataTable rows={runs?.items ?? []} empty={<Empty title="No runs yet" />} columns={[
          { header: "Started", cell: (r: any) => formatDateTime(r.started_at) }, { header: "Source", cell: (r: any) => r.source.toUpperCase() },
          { header: "Status", cell: (r: any) => <Badge tone={r.status === "succeeded" ? "low" : r.status === "failed" ? "critical" : "info"}>{r.status}</Badge> },
          { header: "Seen / new / updated", cell: (r: any) => `${r.records_seen} / ${r.records_new} / ${r.records_updated}` }, { header: "Error", cell: (r: any) => <span className="text-xs text-red-700">{r.error}</span> },
        ]} />
      </Card>
      <Card title="Correlation runs" actions={can("analyst") && <Button size="sm" variant="secondary" onClick={async () => { setErr(null); try { await post("/correlation-runs"); setMsg("Correlation queued."); setTimeout(() => mCorr(), 1500); } catch (e) { setErr(e); } }}>Re-run correlation</Button>}>
        <DataTable rows={corr?.items ?? []} empty={<Empty title="No runs yet" />} columns={[
          { header: "Started", cell: (r: any) => formatDateTime(r.started_at) },
          { header: "Status", cell: (r: any) => <Badge tone={r.status === "succeeded" ? "low" : r.status === "failed" ? "critical" : "info"}>{r.status}</Badge> },
          { header: "Advisories", cell: (r: any) => r.advisories_considered }, { header: "Created / updated", cell: (r: any) => `${r.assessments_created} / ${r.assessments_updated}` },
          { header: "Error", cell: (r: any) => <span className="text-xs text-red-700">{r.error}</span> },
        ]} />
      </Card>
    </div>
  );
}

export default function SettingsPage() {
  const { can } = useSession();
  const [tab, setTab] = useState("profile");
  const tabs = [{ id: "profile", label: "Organization" }, { id: "members", label: "Team" }, { id: "sources", label: "Intelligence sources" }, ...(can("analyst") ? [{ id: "audit", label: "Audit trail" }] : [])];
  return (
    <>
      <PageHeader title="Settings" />
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      {tab === "profile" && <Profile />}
      {tab === "members" && <Members />}
      {tab === "sources" && <Sources />}
      {tab === "audit" && <Audit />}
    </>
  );
}
