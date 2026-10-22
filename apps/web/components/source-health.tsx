"use client";
import { Badge, Loading } from "@/components/ui";
import { formatDateTime } from "@/lib/utils";

const TONE: Record<string, string> = { healthy: "low", stale: "medium", failing: "critical", never_run: "neutral" };
const LABEL: Record<string, string> = { healthy: "Healthy", stale: "Stale", failing: "Failing", never_run: "Never run" };
const NAME: Record<string, string> = { nvd: "NIST National Vulnerability Database", kev: "CISA Known Exploited Vulnerabilities" };

/** Shows whether each source could actually be checked, so an empty advisory list is never mistaken for "all clear". */
export function SourceHealth({ health }: { health?: { sources: any[]; any_problem: boolean } }) {
  if (!health) return <Loading rows={2} />;
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {health.sources.map((s) => (
        <div key={s.source} className="rounded-md border border-slate-200 p-3 text-sm" data-testid={`source-${s.source}`}>
          <div className="flex items-center justify-between gap-2">
            <span className="font-medium">{NAME[s.source] ?? s.source}</span>
            <Badge tone={TONE[s.status]}>{LABEL[s.status]}</Badge>
          </div>
          <p className={`mt-1 text-xs ${s.status === "healthy" ? "text-slate-500" : "text-amber-800"}`}>{s.message}</p>
          <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-xs text-slate-600">
            <dt>Last successful check</dt>
            <dd>{s.last_success_at ? formatDateTime(s.last_success_at) : "never"}</dd>
            {s.latest && (
              <>
                <dt>Latest attempt</dt>
                <dd>
                  {formatDateTime(s.latest.started_at)} · {s.latest.status}
                  {s.latest.attempts > 1 ? ` (${s.latest.attempts} attempts)` : ""}
                </dd>
                <dt>Fetched / new / updated</dt>
                <dd>
                  {s.latest.records_seen} / {s.latest.records_new} / {s.latest.records_updated}
                </dd>
                <dt>Rejected records</dt>
                <dd className={s.latest.records_rejected ? "font-medium text-red-700" : ""}>{s.latest.records_rejected}</dd>
                {s.latest.catalog_version && (
                  <>
                    <dt>Catalogue version</dt>
                    <dd>{s.latest.catalog_version}</dd>
                  </>
                )}
              </>
            )}
          </dl>
        </div>
      ))}
    </div>
  );
}
