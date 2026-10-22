"use client";
// Small design-system primitives (shadcn/ui style: Tailwind classes + composition), kept dependency-free.
import { ReactNode, useEffect, useRef, ButtonHTMLAttributes, InputHTMLAttributes, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";
import { cn, humanize } from "@/lib/utils";
import { STATE_LABEL } from "@/lib/labels";

// ---- buttons & inputs -------------------------------------------------------------------
type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "ghost"; size?: "sm" | "md" };
export function Button({ variant = "primary", size = "md", className, ...props }: ButtonProps) {
  const styles = {
    primary: "bg-ink-900 text-slate-50 hover:bg-brand disabled:bg-slate-300",
    secondary: "border border-slate-800 bg-transparent text-slate-900 hover:bg-slate-900 hover:text-slate-50 disabled:border-slate-300 disabled:text-slate-400 disabled:hover:bg-transparent",
    danger: "bg-red-600 text-slate-50 hover:bg-red-700 disabled:bg-slate-300",
    ghost: "text-slate-700 hover:bg-slate-100",
  }[variant];
  return (
    <button
      {...props}
      className={cn("inline-flex items-center justify-center gap-1.5 rounded-sm font-medium tracking-wide transition-colors disabled:cursor-not-allowed", size === "sm" ? "px-2.5 py-1 text-xs" : "px-3.5 py-2 text-sm", styles, className)}
    />
  );
}

const fieldBase = "w-full rounded-sm border border-slate-400 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 disabled:bg-slate-100";
export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cn(fieldBase, props.className)} />;
}
export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea rows={4} {...props} className={cn(fieldBase, props.className)} />;
}
export function Select({ children, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select {...props} className={cn(fieldBase, props.className)}>
      {children}
    </select>
  );
}
export function Field({ label, hint, error, children }: { label: string; hint?: string; error?: string; children: ReactNode }) {
  return (
    <label className="block space-y-1">
      <span className="kicker block text-slate-600">{label}</span>
      {children}
      {hint && !error && <span className="block text-xs text-slate-500">{hint}</span>}
      {error && <span className="block text-xs text-red-600">{error}</span>}
    </label>
  );
}

// ---- layout ----------------------------------------------------------------------------
export function Card({ title, actions, children, className }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn("rounded-sm border border-slate-300 border-t-2 border-t-slate-900 bg-white", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-slate-200 px-4 py-2.5">
          <h2 className="kicker text-slate-800">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3 border-b border-slate-300 pb-4">
      <div>
        <h1 className="text-3xl leading-tight text-slate-900">{title}</h1>
        {description && <p className="mt-1.5 max-w-3xl text-sm text-slate-600">{description}</p>}
      </div>
      <div className="flex items-center gap-2">{actions}</div>
    </div>
  );
}

export function Modal({ open, title, onClose, children, wide }: { open: boolean; title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    ref.current?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-ink-950/60 p-4 pt-16" onMouseDown={onClose}>
      <div
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(e) => e.stopPropagation()}
        className={cn("w-full rounded-sm border border-slate-800 bg-white shadow-xl", wide ? "max-w-3xl" : "max-w-lg")}
      >
        <header className="flex items-center justify-between border-b border-slate-200 px-5 py-3">
          <h2 className="display text-lg">{title}</h2>
          <button aria-label="Close" onClick={onClose} className="rounded p-1 text-slate-500 hover:bg-slate-100">
            ✕
          </button>
        </header>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function ConfirmDialog({ open, title, message, confirmLabel = "Confirm", danger, onConfirm, onClose }: { open: boolean; title: string; message: ReactNode; confirmLabel?: string; danger?: boolean; onConfirm: () => void; onClose: () => void }) {
  return (
    <Modal open={open} title={title} onClose={onClose}>
      <div className="space-y-4">
        <div className="text-sm text-slate-700">{message}</div>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant={danger ? "danger" : "primary"} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

// ---- feedback --------------------------------------------------------------------------
export function Loading({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="skeleton h-9 w-full" />
      ))}
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="rounded-sm border border-l-4 border-red-200 border-l-red-600 bg-red-50 px-3 py-2 text-sm text-red-800">
      {message}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-sm border border-dashed border-slate-400 px-6 py-10 text-center">
      <p className="display text-base text-slate-800">{title}</p>
      {children && <div className="mt-1 text-sm text-slate-500">{children}</div>}
    </div>
  );
}

export function Notice({ tone = "info", children }: { tone?: "info" | "warn" | "demo"; children: ReactNode }) {
  const styles = { info: "border-sky-200 bg-sky-50 text-sky-900", warn: "border-amber-300 bg-amber-50 text-amber-900", demo: "border-fuchsia-300 bg-fuchsia-50 text-fuchsia-900" }[tone];
  return <div className={cn("rounded-sm border border-l-4 px-3 py-2 text-sm", styles)}>{children}</div>;
}

// ---- badges ----------------------------------------------------------------------------
const TONES: Record<string, string> = {
  critical: "bg-red-100 text-red-800 border-red-200",
  high: "bg-orange-100 text-orange-800 border-orange-200",
  medium: "bg-amber-100 text-amber-800 border-amber-200",
  low: "bg-emerald-100 text-emerald-800 border-emerald-200",
  neutral: "bg-slate-100 text-slate-700 border-slate-200",
  info: "bg-sky-100 text-sky-800 border-sky-200",
  purple: "bg-violet-100 text-violet-800 border-violet-200",
};
export function Badge({ tone = "neutral", children, title }: { tone?: string; children: ReactNode; title?: string }) {
  return (
    <span title={title} className={cn("kicker inline-flex items-center rounded-sm border px-1.5 py-0.5 !text-[10px]", TONES[tone] ?? TONES.neutral)}>
      {children}
    </span>
  );
}
// Severity carries a shape as well as a tone and a word, so it never depends on colour alone.
const SEVERITY_GLYPH: Record<string, string> = { critical: "▲▲▲", high: "▲▲", medium: "▲", low: "▽" };
export const SeverityBadge = ({ value }: { value?: string | null }) =>
  value ? (
    <Badge tone={value} title={`Severity: ${humanize(value)}`}>
      <span aria-hidden="true" className="mr-1 tracking-tighter">{SEVERITY_GLYPH[value] ?? ""}</span>
      {humanize(value)}
    </Badge>
  ) : (
    <span className="text-slate-400" title="The sources do not state a severity">—</span>
  );
export const PriorityBadge = ({ value }: { value?: string | null }) => (value ? <Badge tone={value}>{humanize(value)}</Badge> : null);

const STATE_TONE: Record<string, string> = {
  potential_impact: "medium",
  insufficient_data: "neutral",
  confirmed_dependency: "info",
  exposure_verified: "high",
  compromise_confirmed: "critical",
  no_match_found: "low",
};
export const StateBadge = ({ value }: { value: string }) => <Badge tone={STATE_TONE[value] ?? "neutral"}>{STATE_LABEL[value] ?? humanize(value)}</Badge>;

const CONF_TONE: Record<string, string> = { high: "low", medium: "medium", low: "high" };
export function Confidence({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-sm border border-slate-300 px-3 py-2">
      <div className="kicker text-slate-500">{label}</div>
      <div className="mt-0.5">
        <Badge tone={CONF_TONE[value] ?? "neutral"}>{humanize(value)}</Badge>
      </div>
    </div>
  );
}

// ---- table & pagination ----------------------------------------------------------------
export interface Column<T> {
  header: string;
  cell: (row: T) => ReactNode;
  className?: string;
}
export function DataTable<T extends { id?: string }>({ columns, rows, onRowClick, empty }: { columns: Column<T>[]; rows: T[]; onRowClick?: (row: T) => void; empty?: ReactNode }) {
  if (!rows.length) return <>{empty ?? <Empty title="Nothing here yet" />}</>;
  return (
    <div className="overflow-x-auto rounded-sm border border-slate-300 border-t-2 border-t-slate-900 bg-white">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead className="bg-slate-100">
          <tr>
            {columns.map((c) => (
              <th key={c.header} scope="col" className={cn("kicker px-3 py-2 text-left text-slate-600", c.className)}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rows.map((row, i) => (
            <tr
              key={row.id ?? i}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              onKeyDown={onRowClick ? (e) => e.key === "Enter" && onRowClick(row) : undefined}
              tabIndex={onRowClick ? 0 : undefined}
              className={cn(onRowClick && "cursor-pointer hover:bg-brand-soft")}
            >
              {columns.map((c) => (
                <td key={c.header} className={cn("px-3 py-2 align-top", c.className)}>
                  {c.cell(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Pagination({ total, limit, offset, onChange }: { total: number; limit: number; offset: number; onChange: (offset: number) => void }) {
  if (total <= limit) return null;
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.ceil(total / limit);
  return (
    <div className="mt-3 flex items-center justify-between text-sm text-slate-600">
      <span>
        {offset + 1}–{Math.min(offset + limit, total)} of {total}
      </span>
      <div className="flex items-center gap-2">
        <Button size="sm" variant="secondary" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>
          Previous
        </Button>
        <span>
          Page {page} / {pages}
        </span>
        <Button size="sm" variant="secondary" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>
          Next
        </Button>
      </div>
    </div>
  );
}

export function Tabs({ tabs, value, onChange }: { tabs: { id: string; label: string; count?: number }[]; value: string; onChange: (id: string) => void }) {
  return (
    <div role="tablist" className="mb-4 flex gap-1 border-b border-slate-200">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={cn("kicker -mb-px border-b-2 px-3 py-2.5", value === t.id ? "border-brand text-brand" : "border-transparent text-slate-600 hover:text-slate-900")}
        >
          {t.label}
          {t.count !== undefined && <span className="ml-1.5 rounded-sm bg-slate-200 px-1.5 text-[10px] text-slate-700">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Definition({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
      {items.map(([k, v]) => (
        <div key={k}>
          <dt className="kicker text-slate-500">{k}</dt>
          <dd className="mt-0.5 text-sm text-slate-900">{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}
