"use client";
import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { FormModal } from "@/components/form";
import { VENDOR_FIELDS } from "@/lib/fields";
import { useSession } from "@/components/session";
import { Badge, Button, DataTable, Empty, ErrorBox, Input, Loading, Modal, PageHeader, Pagination, PriorityBadge, Select } from "@/components/ui";
import { get, post, qs, upload } from "@/lib/api";
import { LEVELS } from "@/lib/labels";
import { humanize } from "@/lib/utils";

const LIMIT = 25;

function ImportDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<any>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  async function run(dry: boolean) {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const r = await upload(`/vendors/import?dry_run=${dry}`, file);
      setPreview(r);
      if (!dry) {
        onDone();
        close();
      }
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  function close() {
    setFile(null);
    setPreview(null);
    setError(null);
    onClose();
  }

  return (
    <Modal open={open} title="Import vendors from CSV" onClose={close} wide>
      <div className="space-y-4 text-sm">
        <p className="text-slate-600">
          Columns: <code>name</code> (required), <code>website</code>, <code>category</code>, <code>criticality</code>, <code>owner</code>, <code>integration_type</code>, <code>access_level</code>, <code>description</code>. You will see a preview before anything is saved.
        </p>
        <input ref={input} type="file" accept=".csv,text/csv" aria-label="CSV file" onChange={(e) => { setFile(e.target.files?.[0] ?? null); setPreview(null); }} />
        <ErrorBox error={error} />
        {preview && (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <Badge tone="low">{preview.accepted.length} will be created</Badge>
              <Badge tone="medium">{preview.duplicates.length} duplicates skipped</Badge>
              <Badge tone="critical">{preview.rejected.length} rejected</Badge>
            </div>
            {preview.accepted.length > 0 && (
              <ul className="max-h-40 overflow-auto rounded border border-slate-200 p-2">
                {preview.accepted.map((a: any) => (
                  <li key={a.name}>{a.name} <span className="text-slate-500">{a.domain}</span></li>
                ))}
              </ul>
            )}
            {preview.rejected.length > 0 && (
              <div>
                <p className="font-medium text-red-700">Rejected rows</p>
                <ul className="max-h-32 overflow-auto rounded border border-red-200 bg-red-50 p-2">
                  {preview.rejected.map((r: any) => (
                    <li key={r.row}>Row {r.row}: {r.errors.join("; ")}</li>
                  ))}
                </ul>
              </div>
            )}
            {preview.duplicates.length > 0 && (
              <p className="text-slate-600">Duplicates (already in the inventory or repeated in the file): {preview.duplicates.map((d: any) => `row ${d.row} ${d.name}`).join(", ")}</p>
            )}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={close}>Cancel</Button>
          <Button variant="secondary" disabled={!file || busy} onClick={() => run(true)}>Preview</Button>
          <Button disabled={!file || busy || !preview || preview.accepted.length === 0} onClick={() => run(false)}>
            Import {preview?.accepted.length ?? 0} vendor(s)
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export default function VendorsPage() {
  const { can } = useSession();
  const router = useRouter();
  const [q, setQ] = useState("");
  const [criticality, setCriticality] = useState("");
  const [reviewStatus, setReviewStatus] = useState("");
  const [sort, setSort] = useState("name");
  const [offset, setOffset] = useState(0);
  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState(false);
  const { data, error, mutate } = useSWR<any>(`/vendors${qs({ q, criticality, review_status: reviewStatus, sort, limit: LIMIT, offset })}`, get);

  return (
    <>
      <PageHeader
        title="Vendors"
        description="Third parties your clients depend on, with the access they were granted. Every fact records its source and your confidence in it."
        actions={
          can("analyst") && (
            <>
              <Button variant="secondary" onClick={() => setImporting(true)}>Import CSV</Button>
              <Button onClick={() => setCreating(true)}>Add vendor</Button>
            </>
          )
        }
      />
      <div className="mb-3 flex flex-wrap gap-3">
        <Input aria-label="Search vendors" className="max-w-xs" placeholder="Search name, domain, category…" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
        <Select aria-label="Filter by criticality" className="max-w-[11rem]" value={criticality} onChange={(e) => { setCriticality(e.target.value); setOffset(0); }}>
          <option value="">All criticalities</option>
          {LEVELS.map((l) => <option key={l} value={l}>{humanize(l)}</option>)}
        </Select>
        <Select aria-label="Filter by review status" className="max-w-[12rem]" value={reviewStatus} onChange={(e) => { setReviewStatus(e.target.value); setOffset(0); }}>
          <option value="">Any review status</option>
          {["unreviewed", "in_review", "reviewed"].map((l) => <option key={l} value={l}>{humanize(l)}</option>)}
        </Select>
        <Select aria-label="Sort vendors" className="max-w-[12rem]" value={sort} onChange={(e) => { setSort(e.target.value); setOffset(0); }}>
          <option value="name">Name A–Z</option>
          <option value="-name">Name Z–A</option>
          <option value="updated">Recently modified</option>
          <option value="-updated">Least recently modified</option>
        </Select>
      </div>
      <ErrorBox error={error} />
      {!data ? (
        <Loading />
      ) : (
        <>
          <DataTable
            rows={data.items}
            onRowClick={(v: any) => router.push(`/vendors/${v.id}`)}
            empty={<Empty title={q || criticality ? "No vendors match these filters" : "No vendors yet"}>Add a vendor or import a CSV to start building the dependency picture.</Empty>}
            columns={[
              { header: "Vendor", cell: (v: any) => <span className="font-medium text-slate-900">{v.name}</span> },
              { header: "Domain", cell: (v: any) => v.domain || "—" },
              { header: "Category", cell: (v: any) => v.category || "—" },
              { header: "Criticality", cell: (v: any) => <PriorityBadge value={v.criticality} /> },
              { header: "Access", cell: (v: any) => <Badge tone={v.access_level === "admin" || v.access_level === "write" ? "high" : "neutral"}>{humanize(v.access_level)}</Badge> },
              { header: "Review", cell: (v: any) => humanize(v.review_status) },
            ]}
          />
          <Pagination total={data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
      <FormModal open={creating} title="Add vendor" fields={VENDOR_FIELDS} initial={{ criticality: "medium", access_level: "none", review_status: "unreviewed", confidence: "medium", source: "manual" }} onClose={() => setCreating(false)} onSubmit={async (v) => { const r = await post("/vendors", v); router.push(`/vendors/${r.id}`); }} />
      <ImportDialog open={importing} onClose={() => setImporting(false)} onDone={() => mutate()} />
    </>
  );
}
