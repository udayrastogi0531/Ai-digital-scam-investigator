"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Activity, History, LayoutDashboard, Menu, Plus, X } from "lucide-react";
import { getHealth } from "@/lib/api";
import type { HealthInfo } from "@/lib/types";
import { Logo } from "@/components/ui";

const NAV = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/investigate", label: "Investigate", icon: Plus },
  { href: "/history", label: "History", icon: History },
];

function useHealth() {
  const [health, setHealth] = useState<HealthInfo | null>(null);
  useEffect(() => {
    let cancelled = false;
    getHealth()
      .then((h) => {
        if (!cancelled) setHealth(h);
      })
      .catch(() => {
        /* shell degrades gracefully when API is down */
      });
    return () => {
      cancelled = true;
    };
  }, []);
  return health;
}

function SystemPill({ health }: { health: HealthInfo | null }) {
  if (!health) {
    return (
      <span className="chip border-base-600/60 bg-base-800/50 text-slate-500">
        <Activity className="h-3 w-3" aria-hidden /> Checking…
      </span>
    );
  }
  const demo = health.providers.llm.is_mock && health.providers.threat_intel.uses_mock;
  return (
    <span
      className={`chip border-base-600/60 bg-base-800/50 ${
        demo ? "text-amber-300/90" : "text-emerald-300/90"
      }`}
      title={demo ? "Demo mode — no external APIs configured" : "Live providers configured"}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${demo ? "bg-amber-400" : "bg-emerald-400"}`} aria-hidden />
      {demo ? "Demo mode" : "Live mode"}
    </span>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const health = useHealth();
  const [open, setOpen] = useState(false);

  // close the mobile menu on navigation
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-40 border-b border-base-700/60 bg-base-950/85 backdrop-blur-md">
        <div className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between gap-4 px-4 sm:px-6">
          <Link href="/" className="flex shrink-0 items-center gap-3" aria-label="ScamIntelligence home">
            <Logo size={32} />
            <span className="hidden font-mono text-sm font-bold tracking-tight text-slate-100 sm:block">
              Scam<span className="text-accent">Intelligence</span>
            </span>
          </Link>

          <nav className="hidden items-center gap-1 md:flex" aria-label="Primary">
            {NAV.map((n) => {
              const active = pathname === n.href || (n.href !== "/dashboard" && pathname.startsWith(n.href));
              return (
                <Link key={n.href} href={n.href} className={`nav-link ${active ? "nav-link-active" : ""}`}>
                  <n.icon className="h-4 w-4" aria-hidden />
                  {n.label}
                </Link>
              );
            })}
          </nav>

          <div className="hidden items-center gap-3 md:flex">
            <SystemPill health={health} />
            <Link href="/investigate" className="btn-primary btn-sm">
              <Plus className="h-3.5 w-3.5" aria-hidden /> New
            </Link>
          </div>

          <button
            type="button"
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-base-600/70 text-slate-300 md:hidden"
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            aria-label={open ? "Close menu" : "Open menu"}
          >
            {open ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>

        {open && (
          <nav className="border-t border-base-700/60 bg-base-950/95 px-4 py-3 md:hidden" aria-label="Mobile">
            <div className="flex flex-col gap-1">
              {NAV.map((n) => {
                const active = pathname === n.href || (n.href !== "/dashboard" && pathname.startsWith(n.href));
                return (
                  <Link key={n.href} href={n.href} className={`nav-link ${active ? "nav-link-active" : ""}`}>
                    <n.icon className="h-4 w-4" aria-hidden />
                    {n.label}
                  </Link>
                );
              })}
              <Link href="/investigate" className="btn-primary mt-2">
                <Plus className="h-4 w-4" aria-hidden /> New investigation
              </Link>
            </div>
          </nav>
        )}
      </header>

      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 sm:py-8">{children}</main>

      <footer className="border-t border-base-700/40">
        <div className="mx-auto flex w-full max-w-7xl flex-col items-start justify-between gap-2 px-4 py-5 text-[11px] text-slate-600 sm:flex-row sm:items-center sm:px-6">
          <span>Decision-support tool — findings are probabilistic, not conclusive.</span>
          <span className="font-mono">Submitted content stays on your own deployment.</span>
        </div>
      </footer>
    </div>
  );
}