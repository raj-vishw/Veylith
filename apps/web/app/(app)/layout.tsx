"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ReactNode } from "react";
import { SessionProvider, useSession } from "@/components/session";
import { Notice } from "@/components/ui";
import { post } from "@/lib/api";
import { cn } from "@/lib/utils";

const GROUPS = [
  { name: "Signals", items: [
    { href: "/", label: "Overview" },
    { href: "/intelligence", label: "Intelligence" },
    { href: "/assessments", label: "Assessments" },
    { href: "/advisories", label: "Advisories" },
  ] },
  { name: "Estate", items: [
    { href: "/graph", label: "Exposure graph" },
    { href: "/vendors", label: "Vendors" },
    { href: "/clients", label: "Clients" },
    { href: "/assets", label: "Assets" },
  ] },
  { name: "Response", items: [
    { href: "/cases", label: "Cases" },
    { href: "/reports", label: "Reports" },
    { href: "/settings", label: "Settings" },
  ] },
];
const NAV = GROUPS.flatMap((g) => g.items);

function Shell({ children }: { children: ReactNode }) {
  const { me, isDemo, refresh } = useSession();
  const pathname = usePathname();
  const router = useRouter();

  async function logout() {
    await post("/auth/logout");
    window.location.assign("/login");
  }
  async function createOrg() {
    const name = window.prompt("Name for the new workspace");
    if (!name || name.trim().length < 2) return;
    const org = await post("/organizations", { name: name.trim() });
    await post("/auth/switch-org", { organization_id: org.id });
    window.location.assign("/");
  }
  async function switchOrg(id: string) {
    await post("/auth/switch-org", { organization_id: id });
    refresh();
    router.refresh();
    window.location.assign("/");
  }

  const crumbs = pathname.split("/").filter(Boolean);

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col overflow-y-auto bg-ink-950 text-slate-200 md:flex">
        <div className="flex items-center gap-3 border-b border-ink-700 px-5 py-5">
          <svg width="28" height="28" viewBox="0 0 28 28" fill="none" aria-hidden="true">
            <path d="M4 5 14 23 24 5" stroke="#fbf9f3" strokeWidth="2" />
            <circle cx="14" cy="23" r="3" fill="#e8512a" />
            <circle cx="4" cy="5" r="2" fill="#fbf9f3" />
            <circle cx="24" cy="5" r="2" fill="#fbf9f3" />
          </svg>
          <div>
            <div className="display font-serif text-xl leading-none text-slate-50">Veylith</div>
            <div className="kicker mt-1.5 !text-[9px] text-slate-400">Impact intelligence</div>
          </div>
        </div>
        <nav aria-label="Primary" className="flex-1 space-y-5 px-3 py-5">
          {GROUPS.map((g) => (
            <div key={g.name}>
              <div className="kicker mb-1.5 px-2 !text-[9px] text-slate-500">{g.name}</div>
              {g.items.map((item) => {
                const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
                return (
                  <Link key={item.href} href={item.href} aria-current={active ? "page" : undefined} className={cn("block border-l-2 px-3 py-1.5 text-sm", active ? "border-signal bg-ink-800 text-white" : "border-transparent text-slate-400 hover:border-ink-700 hover:text-slate-100")}>
                    {item.label}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="space-y-2 border-t border-ink-800 p-3 text-xs">
          <button onClick={createOrg} className="kicker w-full rounded-sm border border-ink-700 px-2 py-1.5 text-left !text-[10px] text-slate-200 hover:bg-ink-800">
            + New workspace
          </button>
          {me.organizations.length > 1 && (
            <select aria-label="Switch organization" value={me.organization.id} onChange={(e) => switchOrg(e.target.value)} className="w-full rounded bg-ink-800 px-2 py-1.5 text-slate-100">
              {me.organizations.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </select>
          )}
          <div className="truncate text-slate-300">{me.organization.name}</div>
          <div className="truncate text-slate-400">
            {me.user.email} · {me.role}
          </div>
          <button onClick={logout} className="kicker w-full rounded-sm border border-ink-700 px-2 py-1.5 text-left !text-[10px] text-slate-200 hover:bg-ink-800">
            Sign out
          </button>
        </div>
      </aside>
      <div className="min-w-0 flex-1">
        <nav aria-label="Mobile" className="flex gap-1 overflow-x-auto bg-ink-950 px-2 py-2 md:hidden">
          {NAV.map((item) => (
            <Link key={item.href} href={item.href} className="whitespace-nowrap rounded px-2.5 py-1.5 text-xs text-slate-200 hover:bg-ink-800">
              {item.label}
            </Link>
          ))}
        </nav>
        {isDemo && (
          <div className="px-6 pt-4">
            <Notice tone="demo">
              <strong>Demonstration workspace.</strong> All clients, vendors, assets and advisories here are synthetic and not real intelligence about any real organization.
            </Notice>
          </div>
        )}
        <div className="kicker px-6 pt-4 text-slate-500" aria-label="Breadcrumb">
          <Link href="/" className="hover:underline">
            Home
          </Link>
          {crumbs.map((c, i) => (
            <span key={i}>
              {" / "}
              <span className="capitalize">{/^[0-9a-f-]{20,}$/.test(c) ? "detail" : c}</span>
            </span>
          ))}
        </div>
        <main className="mx-auto max-w-[1400px] px-6 pb-12 pt-3">{children}</main>
      </div>
    </div>
  );
}

export default function AppLayout({ children }: { children: ReactNode }) {
  return (
    <SessionProvider>
      <Shell>{children}</Shell>
    </SessionProvider>
  );
}
