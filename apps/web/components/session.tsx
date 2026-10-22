"use client";
import { createContext, useContext, useEffect, useMemo, ReactNode } from "react";
import useSWR from "swr";
import { get, setCsrfToken } from "@/lib/api";

export type Role = "owner" | "analyst" | "viewer";
const RANK: Record<Role, number> = { viewer: 1, analyst: 2, owner: 3 };

export interface Me {
  user: { id: string; email: string; display_name: string };
  organization: { id: string; name: string };
  role: Role;
  organizations: { id: string; name: string; role: Role }[];
  csrf_token: string;
}

interface SessionValue {
  me: Me;
  isDemo: boolean;
  can: (role: Role) => boolean;
  refresh: () => void;
}

const Ctx = createContext<SessionValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const { data: me, mutate } = useSWR<Me>("/auth/me", get, { revalidateOnFocus: true, shouldRetryOnError: false });
  const { data: org } = useSWR<{ is_demo: boolean }>(me ? "/organization" : null, get);
  useEffect(() => {
    if (me) setCsrfToken(me.csrf_token);
  }, [me]);
  const value = useMemo<SessionValue | null>(
    () => (me ? { me, isDemo: !!org?.is_demo, can: (r: Role) => RANK[me.role] >= RANK[r], refresh: () => void mutate() } : null),
    [me, org, mutate],
  );
  if (!value) {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-slate-500" aria-busy="true">
        Loading workspace…
      </div>
    );
  }
  // setCsrfToken runs in an effect; make sure it is set before any child issues a write.
  setCsrfToken(value.me.csrf_token);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSession outside SessionProvider");
  return v;
}
