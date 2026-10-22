"use client";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { useState } from "react";
import useSWR from "swr";
import { FormModal } from "@/components/form";
import { useSession } from "@/components/session";
import { Badge, Button, Card, ConfirmDialog, DataTable, Definition, Empty, ErrorBox, Loading, Modal, PageHeader, PriorityBadge, Field, Select, Input, Textarea, Notice } from "@/components/ui";
import { PRODUCT_FIELDS, VENDOR_FIELDS } from "@/lib/fields";
import { del, get, patch, post } from "@/lib/api";
import { REL_LABEL, REL_TYPES, REL_RULES, VERIFICATION_METHODS } from "@/lib/labels";
import { formatDate, humanize } from "@/lib/utils";

function RelationshipDialog({ vendorId, open, onClose, onDone }: { vendorId: string; open: boolean; onClose: () => void; onDone: () => void }) {
  const { data: clients } = useSWR<any>(open ? "/clients?limit=100" : null, get);
  const { data: assets } = useSWR<any>(open ? "/assets?limit=100" : null, get);
  const { data: vendors } = useSWR<any>(open ? "/vendors?limit=100" : null, get);
  const [relType, setRelType] = useState("USES_VENDOR");
  const [direction, setDirection] = useState<"out" | "in">("in");
  const [other, setOther] = useState("");
  const [extra, setExtra] = useState({ access_scope: "", evidence: "", confidence: "medium", verification_status: "unverified", verification_method: "" });
  const [error, setError] = useState<unknown>(null);

  // Offer only the entity types the backend would accept for this relationship and direction.
  const candidates = REL_RULES[relType].filter(([s, t]) => (direction === "out" ? s === "vendor" : t === "vendor")).map(([s, t]) => (direction === "out" ? t : s));
  const options: { id: string; label: string }[] = [];
  for (const kind of new Set(candidates)) {
    const src = kind === "client" ? clients : kind === "asset" ? assets : kind === "vendor" ? vendors : null;
    for (const e of src?.items ?? []) if (!(kind === "vendor" && e.id === vendorId)) options.push({ id: `${kind}:${e.id}`, label: `${humanize(kind)} · ${e.name}` });
  }
  const valid = REL_RULES[relType].some(([s, t]) => (direction === "out" ? s === "vendor" : t === "vendor"));

  async function submit() {
    setError(null);
    const [kind, id] = other.split(":");
    const body = direction === "out"
      ? { source_type: "vendor", source_id: vendorId, target_type: kind, target_id: id, rel_type: relType, ...extra }
      : { source_type: kind, source_id: id, target_type: "vendor", target_id: vendorId, rel_type: relType, ...extra };
    try {
      await post("/relationships", body);
      onDone();
      onClose();
    } catch (e) {
      setError(e);
    }
  }

  return (
    <Modal open={open} title="Record a relationship" onClose={onClose}>
      <div className="space-y-3">
        <Notice>A vendor being used by a client does not mean it can reach all of that client&apos;s systems. Record access explicitly.</Notice>
        <Field label="Relationship">
          <Select value={relType} onChange={(e) => { setRelType(e.target.value); setOther(""); }}>
            {REL_TYPES.map((t) => <option key={t} value={t}>{t} — {REL_LABEL[t]}</option>)}
          </Select>
        </Field>
        <Field label="This vendor is the…">
          <Select value={direction} onChange={(e) => { setDirection(e.target.value as any); setOther(""); }}>
            <option value="in">target (something points at this vendor)</option>
            <option value="out">source (this vendor points at something)</option>
          </Select>
        </Field>
        {!valid ? (
          <p className="text-sm text-amber-700">{relType} cannot connect a vendor in this direction.</p>
        ) : (
          <Field label="Other end">
            <Select value={other} onChange={(e) => setOther(e.target.value)}>
              <option value="">Select…</option>
              {options.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
            </Select>
          </Field>
        )}
        <Field label="Access scope / permissions"><Input value={extra.access_scope} onChange={(e) => setExtra({ ...extra, access_scope: e.target.value })} placeholder="read: repository contents" /></Field>
        <Field label="Evidence or source"><Textarea rows={2} value={extra.evidence} onChange={(e) => setExtra({ ...extra, evidence: e.target.value })} /></Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Confidence"><Select value={extra.confidence} onChange={(e) => setExtra({ ...extra, confidence: e.target.value })}>{["low", "medium", "high"].map((c) => <option key={c}>{c}</option>)}</Select></Field>
          <Field label="Verification"><Select value={extra.verification_status} onChange={(e) => setExtra({ ...extra, verification_status: e.target.value })}>{["unverified", "verified", "disputed", "stale"].map((c) => <option key={c}>{c}</option>)}</Select></Field>
        </div>
        {extra.verification_status === "verified" && (
          <Field label="Verification method (required)" hint="How was this relationship verified?">
            <Select value={extra.verification_method} onChange={(e) => setExtra({ ...extra, verification_method: e.target.value })}>
              <option value="">Select…</option>
              {VERIFICATION_METHODS.map((m) => <option key={m} value={m}>{humanize(m)}</option>)}
            </Select>
          </Field>
        )}
        <ErrorBox error={error} />
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button disabled={!other || !valid || (extra.verification_status === "verified" && !extra.verification_method)} onClick={submit}>Add relationship</Button>
        </div>
      </div>
    </Modal>
  );
}

export default function VendorDetail() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { can } = useSession();
  const { data: v, error, mutate } = useSWR<any>(`/vendors/${id}`, get);
  const { data: rels, mutate: mutateRels } = useSWR<any>(`/relationships?entity_id=${id}&limit=100`, get);
  const { data: blast } = useSWR<any>(`/vendors/${id}/blast-radius`, get);
  const { data: graph } = useSWR<any>(`/graph?focus=vendor-${id}&depth=2`, get);
  const [editing, setEditing] = useState(false);
  const [product, setProduct] = useState<any | "new" | null>(null);
  const [relOpen, setRelOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [removeRel, setRemoveRel] = useState<any | null>(null);

  if (error) return <ErrorBox error={error} />;
  if (!v) return <Loading rows={6} />;
  const label = (nodeId: string) => graph?.nodes.find((n: any) => n.id === nodeId)?.label ?? nodeId.slice(0, 14);

  return (
    <>
      <PageHeader
        title={v.name}
        description={v.description || "No description recorded."}
        actions={can("analyst") && (<><Button variant="secondary" onClick={() => setEditing(true)}>Edit</Button><Button variant="ghost" onClick={() => setConfirmDelete(true)}>Delete</Button></>)}
      />
      <div className="grid gap-5 lg:grid-cols-3">
        <Card title="Details" className="lg:col-span-2">
          <Definition items={[
            ["Website", v.domain || "—"], ["Category", v.category || "—"], ["Criticality", <PriorityBadge key="c" value={v.criticality} />],
            ["Access granted", <Badge key="a" tone={["write", "admin"].includes(v.access_level) ? "high" : "neutral"}>{humanize(v.access_level)}</Badge>],
            ["Integration", v.integration_type || "—"], ["Internal owner", v.owner || "—"], ["Review status", humanize(v.review_status)], ["Last reviewed", formatDate(v.last_reviewed_at)],
            ["Source of facts", v.source], ["Confidence", humanize(v.confidence)],
          ]} />
          {v.notes && <p className="mt-4 whitespace-pre-wrap rounded bg-slate-50 p-3 text-sm">{v.notes}</p>}
        </Card>

        <Card title="Blast radius">
          {!blast ? <Loading rows={2} /> : blast.clients.length === 0 ? (
            <p className="text-sm text-slate-500">No client is connected to this vendor yet.</p>
          ) : (
            <div className="space-y-2 text-sm">
              <p><strong>{blast.summary.clients_with_recorded_dependency}</strong> client(s) with a recorded dependency</p>
              <p><strong>{blast.summary.clients_with_sensitive_access}</strong> with sensitive access relationships</p>
              <p><strong>{blast.summary.clients_needing_more_information}</strong> need more information</p>
              <p className="text-xs text-slate-500">A recorded dependency is not a compromise. Verify each client before drawing conclusions.</p>
            </div>
          )}
        </Card>

        <Card title="Products and versions" className="lg:col-span-3" actions={can("analyst") && <Button size="sm" onClick={() => setProduct("new")}>Add product</Button>}>
          <DataTable
            rows={v.products}
            empty={<Empty title="No products recorded">Advisories are matched against products. Add the product and version this vendor supplies.</Empty>}
            columns={[
              { header: "Product", cell: (p: any) => <span className="font-medium">{p.name}</span> },
              { header: "Version", cell: (p: any) => p.version || <Badge tone="medium">Unknown</Badge> },
              { header: "CPE", cell: (p: any) => <code className="text-xs">{p.cpe || "—"}</code> },
              { header: "Confidence", cell: (p: any) => humanize(p.confidence) },
              { header: "", cell: (p: any) => can("analyst") && (<div className="flex justify-end gap-1"><Button size="sm" variant="secondary" onClick={() => setProduct(p)}>Edit</Button><Button size="sm" variant="ghost" onClick={async () => { await del(`/products/${p.id}`); mutate(); }}>Remove</Button></div>) },
            ]}
          />
        </Card>

        <Card title="Relationships" className="lg:col-span-3" actions={can("analyst") && <Button size="sm" onClick={() => setRelOpen(true)}>Add relationship</Button>}>
          <DataTable
            rows={rels?.items ?? []}
            empty={<Empty title="No relationships yet">Connect this vendor to the clients and assets that use it.</Empty>}
            columns={[
              { header: "From", cell: (r: any) => label(`${r.source_type}-${r.source_id}`) },
              { header: "Relationship", cell: (r: any) => <Badge tone="info">{REL_LABEL[r.rel_type]}</Badge> },
              { header: "To", cell: (r: any) => label(`${r.target_type}-${r.target_id}`) },
              { header: "Scope", cell: (r: any) => r.access_scope || "—" },
              { header: "Verification", cell: (r: any) => <Badge tone={r.verification_status === "verified" ? "low" : r.verification_status === "unverified" ? "medium" : "high"}>{humanize(r.verification_status)}</Badge> },
              {
                header: "",
                cell: (r: any) => can("analyst") && (
                  <div className="flex justify-end gap-1">
                    {r.verification_status !== "verified" && <Button size="sm" variant="secondary" onClick={async () => { await patch(`/relationships/${r.id}`, { verification_status: "verified", verification_method: "manual_review" }); mutateRels(); }}>Mark verified</Button>}
                    <Button size="sm" variant="ghost" onClick={() => setRemoveRel(r)}>Remove</Button>
                  </div>
                ),
              },
            ]}
          />
          <p className="mt-3 text-xs text-slate-500">See the whole picture in the <Link className="text-brand underline" href={`/graph?focus=vendor-${id}`}>exposure graph</Link>.</p>
        </Card>
      </div>

      <FormModal open={editing} title="Edit vendor" fields={VENDOR_FIELDS} initial={v} onClose={() => setEditing(false)} onSubmit={async (vals) => { await patch(`/vendors/${id}`, vals); mutate(); }} />
      <FormModal open={!!product} title={product === "new" ? "Add product" : "Edit product"} fields={PRODUCT_FIELDS} initial={product === "new" ? { confidence: "medium", ecosystem: "generic" } : (product ?? undefined)} onClose={() => setProduct(null)}
        onSubmit={async (vals) => { product === "new" ? await post("/products", { ...vals, vendor_id: id }) : await patch(`/products/${product.id}`, vals); mutate(); }} />
      <RelationshipDialog vendorId={id} open={relOpen} onClose={() => setRelOpen(false)} onDone={() => { mutateRels(); mutate(); }} />
      <ConfirmDialog open={confirmDelete} danger title="Delete vendor?" message="The vendor is hidden everywhere. Existing assessments and the audit trail keep their references." confirmLabel="Delete" onClose={() => setConfirmDelete(false)} onConfirm={async () => { await del(`/vendors/${id}`); router.push("/vendors"); }} />
      <ConfirmDialog open={!!removeRel} danger title="Remove relationship?" message="This changes the impact paths of related assessments after the next correlation run." confirmLabel="Remove" onClose={() => setRemoveRel(null)} onConfirm={async () => { await del(`/relationships/${removeRel.id}`); setRemoveRel(null); mutateRels(); }} />
    </>
  );
}
