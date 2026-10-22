"use client";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import useSWR from "swr";
import { useSession } from "@/components/session";
import { Badge, Button, Card, Confidence, ErrorBox, Field, Input, Loading, Modal, Notice, PageHeader, PriorityBadge, Select, StateBadge, Textarea } from "@/components/ui";
import { get, post } from "@/lib/api";
import { MATCH_LABEL, STATE_HELP, STATE_LABEL, VERSION_LABEL } from "@/lib/labels";
import { formatDateTime, humanize, safeUrl } from "@/lib/utils";

const STEP_ICON: Record<string, string> = { advisory: "📄", product: "📦", asset: "🗄️" };
const DIMENSIONS: { key: string; label: string; help: string }[] = [
  { key: "match_status", label: "Match", help: "Did the matcher find this product in the advisory? Set by the engine." },
  { key: "exposure_status", label: "Exposure", help: "Is the vulnerable configuration present and reachable? Set only by an analyst." },
  { key: "compromise_status", label: "Compromise", help: "Is there evidence of unauthorised access? Set only by an analyst; confirmation needs verified evidence." },
  { key: "remediation_status", label: "Remediation", help: "Progress of the fix. Tracked by analysts." },
];

function ReviewDialog({ a, open, onClose, onDone }: { a: any; open: boolean; onClose: () => void; onDone: () => void }) {
  const [reviewStatus, setReviewStatus] = useState("reviewed");
  const [exposure, setExposure] = useState("");
  const [compromise, setCompromise] = useState("");
  const [remediation, setRemediation] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<unknown>(null);
  const changing = (exposure && exposure !== a.exposure_status) || (compromise && compromise !== a.compromise_status);

  async function submit() {
    setError(null);
    try {
      await post(`/assessments/${a.id}/review`, {
        review_status: reviewStatus,
        exposure_status: exposure || undefined,
        compromise_status: compromise || undefined,
        remediation_status: remediation || undefined,
        note,
      });
      onDone();
      onClose();
    } catch (e) {
      setError(e);
    }
  }
  return (
    <Modal open={open} title="Review assessment" onClose={onClose}>
      <div className="space-y-3">
        <Field label="Review outcome">
          <Select value={reviewStatus} onChange={(e) => setReviewStatus(e.target.value)}>
            <option value="reviewed">Reviewed — keep tracking</option>
            <option value="dismissed">Dismissed — not relevant</option>
            <option value="unreviewed">Mark unreviewed</option>
          </Select>
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Exposure" hint="Set to verified only after checking the deployment.">
            <Select value={exposure} onChange={(e) => setExposure(e.target.value)}>
              <option value="">Keep “{humanize(a.exposure_status)}”</option>
              {["unverified", "verified", "not_applicable"].filter((s) => s !== a.exposure_status).map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
            </Select>
          </Field>
          <Field label="Compromise" hint="Confirmed requires verified evidence.">
            <Select value={compromise} onChange={(e) => setCompromise(e.target.value)}>
              <option value="">Keep “{humanize(a.compromise_status)}”</option>
              {["unknown", "suspected", "confirmed", "not_confirmed"].filter((s) => s !== a.compromise_status).map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
            </Select>
          </Field>
          <Field label="Remediation">
            <Select value={remediation} onChange={(e) => setRemediation(e.target.value)}>
              <option value="">Keep “{humanize(a.remediation_status)}”</option>
              {["not_started", "in_progress", "completed", "verified"].filter((s) => s !== a.remediation_status).map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
            </Select>
          </Field>
        </div>
        {compromise === "confirmed" && <Notice tone="warn">Confirming compromise requires <strong>verified</strong> evidence attached to this assessment (add it on the case, then mark it verified).</Notice>}
        <Field label={changing ? "Reason (required)" : "Note"}><Textarea rows={3} value={note} onChange={(e) => setNote(e.target.value)} /></Field>
        <ErrorBox error={error} />
        <div className="flex justify-end gap-2"><Button variant="secondary" onClick={onClose}>Cancel</Button><Button onClick={submit}>Save review</Button></div>
      </div>
    </Modal>
  );
}

function TextDialog({ title, label, open, minLength, confirm, danger, onClose, onSubmit }: { title: string; label: string; open: boolean; minLength: number; confirm: string; danger?: boolean; onClose: () => void; onSubmit: (text: string) => Promise<unknown> }) {
  const [text, setText] = useState("");
  const [error, setError] = useState<unknown>(null);
  return (
    <Modal open={open} title={title} onClose={onClose}>
      <div className="space-y-3">
        <Field label={label}><Textarea rows={3} value={text} onChange={(e) => setText(e.target.value)} /></Field>
        <ErrorBox error={error} />
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button variant={danger ? "danger" : "primary"} disabled={text.trim().length < minLength} onClick={async () => { setError(null); try { await onSubmit(text); setText(""); onClose(); } catch (e) { setError(e); } }}>{confirm}</Button>
        </div>
      </div>
    </Modal>
  );
}

export default function AssessmentDetail() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { can } = useSession();
  const { data: a, error, mutate } = useSWR<any>(`/assessments/${id}`, get);
  const [review, setReview] = useState(false);
  const [note, setNote] = useState(false);
  const [incorrect, setIncorrect] = useState(false);
  const [creating, setCreating] = useState(false);
  const [title, setTitle] = useState("");
  const [createErr, setCreateErr] = useState<unknown>(null);
  const [msg, setMsg] = useState("");

  if (error) return <ErrorBox error={error} />;
  if (!a) return <Loading rows={8} />;
  const ev = a.evidence;
  const total = a.priority_factors.reduce((s: number, f: any) => s + f.points, 0);
  const range = ev.match.affected_range ?? {};
  const rangeText = [range.exact && range.exact !== "?" ? `exactly ${range.exact}` : "", range.start_including && `from ${range.start_including}`, range.start_excluding && `after ${range.start_excluding}`, range.end_including && `up to ${range.end_including}`, range.end_excluding && `before ${range.end_excluding}`].filter(Boolean).join(", ") || "not specified by the advisory";
  const currentEvidence = a.evidence_items.filter((e: any) => !e.superseded_at);
  const history = a.evidence_items.filter((e: any) => e.superseded_at);
  const dismissed = a.review_status === "dismissed";

  async function createCase() {
    setCreateErr(null);
    try {
      const c = await post("/cases", { title, assessment_ids: [a.id] });
      router.push(`/cases/${c.id}`);
    } catch (e) {
      setCreateErr(e);
    }
  }

  return (
    <>
      <PageHeader
        title={`${a.advisory} → ${a.vendor} ${a.product}`}
        description={<>{a.advisory_title}</>}
        actions={can("analyst") && (
          <>
            <Button variant="secondary" onClick={() => setReview(true)}>Review</Button>
            <Button variant="secondary" onClick={() => setNote(true)}>Add note</Button>
            <Button variant="secondary" onClick={async () => { await post(`/assessments/${a.id}/re-evaluate`); setMsg("Re-evaluation requested. Refresh in a moment."); setTimeout(() => mutate(), 2500); }}>Re-evaluate</Button>
            {a.match && !dismissed && <Button variant="ghost" onClick={() => setIncorrect(true)}>Mark match incorrect</Button>}
            {a.case_ids.length === 0 ? <Button onClick={() => { setTitle(`${a.advisory}: ${a.vendor}${a.client ? ` — ${a.client}` : ""}`); setCreating(true); }}>Open case</Button> : <Link href={`/cases/${a.case_ids[0]}`}><Button>View case</Button></Link>}
          </>
        )}
      />
      {a.synthetic_notice && <div className="mb-4"><Notice tone="demo"><strong>Synthetic demonstration data.</strong> {a.synthetic_notice}</Notice></div>}
      {msg && <div className="mb-4"><Notice>{msg}</Notice></div>}
      {dismissed && a.match?.status === "incorrect" && <div className="mb-4"><Notice tone="warn"><strong>Match marked incorrect:</strong> {a.match.incorrect_reason}. The original evidence is kept below.</Notice></div>}

      <div className="mb-5 rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex flex-wrap items-center gap-2">
          <StateBadge value={a.state} /><PriorityBadge value={a.priority} />
          <Badge tone={a.review_status === "unreviewed" ? "medium" : "low"}>{humanize(a.review_status)}</Badge>
          {a.known_exploited && <Badge tone="critical">Known exploited</Badge>}
          <span className="text-sm text-slate-600">Client: <strong>{a.client ?? "not linked"}</strong></span>
        </div>
        <p className="mt-2 text-sm text-slate-700">{STATE_HELP[a.state]}</p>
        <dl className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4" aria-label="Status dimensions">
          {DIMENSIONS.map((d) => (
            <div key={d.key} title={d.help} className="rounded-md border border-slate-200 px-3 py-2">
              <dt className="text-xs text-slate-500">{d.label}</dt>
              <dd className="mt-0.5 text-sm font-medium">{humanize(a[d.key])}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="space-y-5 lg:col-span-2">
          <Card title="Why it matched">
            <ul className="space-y-1 text-sm">
              <li><strong>Method:</strong> {MATCH_LABEL[a.match_type]} {ev.match.detail && <span className="text-slate-600">({ev.match.detail})</span>}</li>
              <li><strong>Observed:</strong> {a.vendor} {ev.match.recorded_version ? `version ${ev.match.recorded_version}` : "(version not recorded)"} <span className="text-slate-500">· ecosystem {ev.match.ecosystem}</span></li>
              <li><strong>Affected range used:</strong> {rangeText}{range.fixed_version ? ` — first unaffected version ${range.fixed_version}` : ""}</li>
              <li><strong>Result:</strong> {VERSION_LABEL[a.version_status] ?? humanize(a.version_status)}</li>
              <li className="text-xs text-slate-500">Matcher {a.matcher_version || "n/a"} · last evaluated {formatDateTime(a.last_evaluated_at)}</li>
            </ul>
            <p className="mt-2 text-xs text-slate-500">Matching is deterministic: identifiers, then names and aliases, then version ranges. Ambiguous names or uninterpretable versions are flagged for review, never matched silently.</p>
          </Card>

          <Card title="Dependency path" actions={<Badge tone="info">Inferred from recorded relationships</Badge>}>
            <ol className="space-y-2">
              {ev.path.map((s: any, i: number) => (
                <li key={i} className="flex gap-3">
                  <span aria-hidden className="mt-0.5 text-lg">{STEP_ICON[s.step]}</span>
                  <div className="text-sm">
                    <div className="font-medium">{s.label}{s.hop > 1 && <span className="ml-2 text-xs font-normal text-slate-500">(hop {s.hop}: transitive)</span>}</div>
                    {s.step === "advisory" && safeUrl(s.url) && <a className="break-all text-xs text-brand hover:underline" href={safeUrl(s.url)!} target="_blank" rel="noopener noreferrer">{s.url}</a>}
                    {s.step === "product" && <div className="text-xs text-slate-500">{MATCH_LABEL[s.match]} · {VERSION_LABEL[s.version_status]}</div>}
                    {s.step === "asset" && <div className="text-xs text-slate-500">{humanize(s.criticality)} criticality</div>}
                  </div>
                </li>
              ))}
            </ol>
            {ev.relationships.length > 0 && (
              <div className="mt-4 border-t border-slate-100 pt-3">
                <p className="mb-1 text-xs font-medium uppercase text-slate-500">Recorded relationships on this path</p>
                <ul className="space-y-1 text-sm">
                  {ev.relationships.map((r: any) => (
                    <li key={r.id} className="flex flex-wrap items-center gap-2">{r.label}<Badge tone={r.verification_status === "verified" ? "low" : r.verification_status === "stale" ? "high" : "medium"}>{humanize(r.verification_status)}</Badge>{r.access_scope && <Badge>{r.access_scope}</Badge>}</li>
                  ))}
                </ul>
              </div>
            )}
          </Card>

          <div className="grid gap-5 md:grid-cols-2">
            <Card title="Facts (from sources and inventory)" actions={<Badge tone="low">Recorded</Badge>}><ul className="list-disc space-y-1 pl-5 text-sm">{ev.known.map((k: string, i: number) => <li key={i}>{k}</li>)}</ul></Card>
            <Card title="Not established" actions={<Badge tone="medium">Unknown</Badge>}><ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">{a.unknowns.map((u: string, i: number) => <li key={i}>{u}</li>)}</ul></Card>
          </div>

          <Card title="Analyst conclusions" actions={<Badge tone="info">Human decisions</Badge>}>
            {a.events.filter((e: any) => ["reviewed", "note", "match_marked_incorrect", "re_evaluation_requested"].includes(e.event_type)).length === 0 ? (
              <p className="text-sm text-slate-500">No analyst decisions yet. Everything above is engine output.</p>
            ) : (
              <ul className="space-y-2 text-sm">
                {a.events.filter((e: any) => ["reviewed", "note", "match_marked_incorrect", "re_evaluation_requested"].includes(e.event_type)).map((e: any, i: number) => (
                  <li key={i} className="flex gap-3"><span className="w-40 shrink-0 text-xs text-slate-500">{formatDateTime(e.occurred_at)}</span><span>{humanize(e.event_type)}{e.note ? <> — {e.note}</> : null}</span></li>
                ))}
              </ul>
            )}
          </Card>

          <Card title="Recommended verification steps">
            <ol className="list-decimal space-y-1 pl-5 text-sm">{a.recommended_steps.map((s: string, i: number) => <li key={i}>{s}</li>)}</ol>
          </Card>

          <Card title="Supporting evidence (preserved snapshots)">
            <ul className="space-y-2 text-sm">
              {currentEvidence.map((e: any) => (
                <li key={e.id} className="rounded border border-slate-200 p-2"><Badge>{humanize(e.kind)}</Badge> <span className="ml-1">{e.summary}</span><div className="text-xs text-slate-500">Recorded {formatDateTime(e.created_at)}</div></li>
              ))}
            </ul>
            {history.length > 0 && (
              <details className="mt-3 text-sm">
                <summary className="cursor-pointer text-slate-600">{history.length} superseded snapshot(s) from earlier evaluations</summary>
                <ul className="mt-2 space-y-1 text-xs text-slate-600">
                  {history.map((e: any) => <li key={e.id}><Badge>{humanize(e.kind)}</Badge> {e.summary} <span className="text-slate-400">(recorded {formatDateTime(e.created_at)}, superseded {formatDateTime(e.superseded_at)})</span></li>)}
                </ul>
              </details>
            )}
          </Card>

          <Card title="History">
            <ul className="space-y-2 text-sm">
              {a.events.map((e: any, i: number) => (
                <li key={i} className="flex gap-3"><span className="w-40 shrink-0 text-xs text-slate-500">{formatDateTime(e.occurred_at)}</span><span>{humanize(e.event_type)}{e.to_state && e.to_state !== e.from_state ? <> · {e.from_state ? `${STATE_LABEL[e.from_state]} → ` : ""}{STATE_LABEL[e.to_state]}</> : null}{e.note ? <> — {e.note}</> : null}</span></li>
              ))}
            </ul>
          </Card>
        </div>

        <div className="space-y-5">
          <Card title="Confidence (kept separate)">
            <div className="grid grid-cols-2 gap-2">
              <Confidence label="Source" value={a.source_confidence} /><Confidence label="Match" value={a.match_confidence} />
              <Confidence label="Relationship" value={a.relationship_confidence} /><Confidence label="Impact" value={a.impact_confidence} />
            </div>
            <p className="mt-2 text-xs text-slate-500">A confident product match does not mean confident impact or compromise.</p>
          </Card>

          <Card title={`Why priority is ${a.priority}`}>
            <table className="w-full text-sm">
              <tbody>
                {a.priority_factors.map((f: any, i: number) => (
                  <tr key={i} className="border-b border-slate-100 last:border-0">
                    <td className="py-1.5 pr-2"><div className="font-medium">{f.factor}</div><div className="text-xs text-slate-500">{f.detail}</div></td>
                    <td className={`py-1.5 text-right font-mono ${f.points < 0 ? "text-emerald-700" : ""}`}>{f.points > 0 ? `+${f.points}` : f.points}</td>
                  </tr>
                ))}
                <tr><td className="pt-2 font-semibold">Total</td><td className="pt-2 text-right font-mono font-semibold">{total}</td></tr>
              </tbody>
            </table>
            <p className="mt-2 text-xs text-slate-500">These are contributing factors, not a probability of compromise. There is no hidden score.</p>
          </Card>

          <Card title="Source">
            <dl className="space-y-2 text-sm">
              <div><dt className="text-xs text-slate-500">Advisory</dt><dd><Link className="text-brand hover:underline" href={`/advisories/${a.advisory_id}`}>{a.advisory}</Link></dd></div>
              <div><dt className="text-xs text-slate-500">Published by source</dt><dd>{formatDateTime(ev.advisory.published_at)}</dd></div>
              <div><dt className="text-xs text-slate-500">Last modified by source</dt><dd>{formatDateTime(ev.advisory.modified_at)}</dd></div>
              <div><dt className="text-xs text-slate-500">Assessment created / updated</dt><dd>{formatDateTime(a.created_at)} / {formatDateTime(a.updated_at)}</dd></div>
              <div><Link className="text-brand hover:underline" href={`/graph?focus=product-${a.product_id}`}>Open the product in the exposure graph →</Link></div>
            </dl>
          </Card>
        </div>
      </div>

      <ReviewDialog a={a} open={review} onClose={() => setReview(false)} onDone={() => mutate()} />
      <TextDialog open={note} title="Add analyst note" label="Note" minLength={1} confirm="Add note" onClose={() => setNote(false)} onSubmit={async (t) => { await post(`/assessments/${a.id}/notes`, { body: t }); mutate(); }} />
      <TextDialog open={incorrect} title="Mark match as incorrect" label="Why is this match wrong? (required, kept with the match)" minLength={5} confirm="Mark incorrect" danger onClose={() => setIncorrect(false)} onSubmit={async (t) => { await post(`/matches/${a.match_id}/incorrect`, { reason: t }); mutate(); }} />
      <Modal open={creating} title="Open investigation case" onClose={() => setCreating(false)}>
        <div className="space-y-3">
          <Field label="Case title"><Input value={title} onChange={(e) => setTitle(e.target.value)} /></Field>
          <ErrorBox error={createErr} />
          <div className="flex justify-end gap-2"><Button variant="secondary" onClick={() => setCreating(false)}>Cancel</Button><Button disabled={title.length < 3} onClick={createCase}>Open case</Button></div>
        </div>
      </Modal>
    </>
  );
}
