"use client";
import Link from "next/link";
import { useState } from "react";
import useSWR from "swr";
import { useSession } from "@/components/session";
import { Badge, Button, DataTable, Empty, ErrorBox, Loading, PageHeader, Pagination } from "@/components/ui";
import { download, get, qs } from "@/lib/api";
import { formatBytes, formatDateTime, humanize } from "@/lib/utils";

const LIMIT = 25;

export default function ReportsPage() {
  const { can } = useSession();
  const [offset, setOffset] = useState(0);
  const [err, setErr] = useState<unknown>(null);
  const { data, error } = useSWR<any>(`/reports${qs({ limit: LIMIT, offset })}`, get, { refreshInterval: 5000 });

  return (
    <>
      <PageHeader title="Reports" description="PDF investigation reports generated from case records. Every generation and download is recorded in the audit trail." />
      <ErrorBox error={error ?? err} />
      {!data ? <Loading /> : (
        <>
          <DataTable
            rows={data.items}
            empty={<Empty title="No reports yet">Open a case and choose Reports → Generate.</Empty>}
            columns={[
              { header: "Case", cell: (r: any) => <Link className="font-medium text-brand hover:underline" href={`/cases/${r.case_id}`}>{r.case_reference} · {r.case_title}</Link> },
              { header: "Type", cell: (r: any) => humanize(r.kind) },
              { header: "Status", cell: (r: any) => <Badge tone={r.status === "completed" ? "low" : r.status === "failed" ? "critical" : "info"}>{r.status === "pending" ? "Generating…" : humanize(r.status)}</Badge> },
              { header: "Generated", cell: (r: any) => formatDateTime(r.completed_at ?? r.created_at) },
              { header: "Size", cell: (r: any) => (r.size_bytes ? formatBytes(r.size_bytes) : "—") },
              { header: "", cell: (r: any) => (r.status === "completed" && can("analyst") ? <Button size="sm" onClick={() => download(`/reports/${r.id}/download`, "veylith-report.pdf").catch(setErr)}>Download</Button> : r.status === "failed" ? <span className="text-xs text-red-700">{r.error}</span> : null) },
            ]}
          />
          <Pagination total={data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}
