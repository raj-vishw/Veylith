import { ReactNode } from "react";

// Split-screen frame for sign-in / register: ink panel with a constellation of dependencies, paper panel with the form.
const NODES: [number, number, number][] = [[60, 80, 5], [180, 40, 3], [300, 110, 4], [120, 190, 3], [260, 230, 6], [380, 190, 3], [90, 320, 4], [220, 350, 3], [350, 330, 5]];
const EDGES: [number, number][] = [[0, 1], [1, 2], [0, 3], [3, 4], [2, 4], [4, 5], [3, 6], [4, 7], [7, 8], [5, 8], [6, 7]];

export function AuthFrame({ children }: { children: ReactNode }) {
  return (
    <main className="grid min-h-screen md:grid-cols-[1.1fr_1fr]">
      <section className="relative hidden flex-col justify-between overflow-hidden bg-ink-950 p-10 text-slate-100 md:flex">
        <svg viewBox="0 0 440 400" className="absolute inset-0 h-full w-full opacity-70" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
          {EDGES.map(([a, b], i) => (
            <line key={i} x1={NODES[a][0]} y1={NODES[a][1]} x2={NODES[b][0]} y2={NODES[b][1]} stroke="#2a3731" strokeWidth="1" strokeDasharray={i % 3 === 0 ? "3 4" : undefined} />
          ))}
          {NODES.map(([x, y, r], i) => (
            <circle key={i} cx={x} cy={y} r={r} fill={i === 4 ? "#e8512a" : "none"} stroke={i === 4 ? "#e8512a" : "#6f6958"} strokeWidth="1.5" />
          ))}
        </svg>
        <div className="kicker relative text-slate-400">Veylith / dossier 001</div>
        <div className="relative max-w-md">
          <p className="display font-serif text-4xl leading-tight">From an outside event to the client who has to act.</p>
          <p className="mt-4 text-sm text-slate-400">Trace a vendor incident through dependencies, with the evidence and the uncertainty kept in view.</p>
        </div>
        <div className="kicker relative text-slate-500">Potential impact, never presumed compromise</div>
      </section>
      <section className="flex items-center justify-center p-6">
        <div className="w-full max-w-sm">{children}</div>
      </section>
    </main>
  );
}
