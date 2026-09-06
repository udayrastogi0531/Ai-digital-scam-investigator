"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  FileSearch,
  FlaskConical,
  Gauge,
  Plus,
  Radar,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import { EmptyState, ErrorBanner, RiskBadge, SectionHeader, Skeleton, Spinner } from "@/components/ui";
import { Reveal } from "@/components/reveal";
import { getHealth, listDemoCases, listInvestigations, runDemoCase } from "@/lib/api";
import type { HealthInfo, InvestigationListItem } from "@/lib/types";
import { categoryLabel, formatDate, healthRows, riskMeta } from "@/lib/types";

const LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

function ProviderStrip({ health }: { health: HealthInfo | null }) {
  if (!health) {
    return (
      <div className="panel p-4">
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <Spinner label="Checking system status…" />
        </div>
      </div>
    );
  }
  const rows = healthRows(health);
  return (
    <div className="panel divide-y divide-base-700/50 overflow-hidden">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-1 px-4 py-2.5 text-[11px] text-slate-500">
        <span className="flex items-center gap-1.5 font-semibold text-slate-300">
          <Activity className="h-3.5 w-3.5 text-accent" aria-hidden /> SYSTEM STATUS
        </span>
        <span>API {health.status === "ok" ? "Online" : health.status}</span>
        <span>DB {health.database ?? "Connected"}</span>
        <span>ML {health.providers.ml.available ? "Active" : "Unavailable"}</span>
      </div>
      <div className="grid grid-cols-2 divide-x divide-y divide-base-700/50 sm:grid-cols-3 lg:grid-cols-6">
        {rows.map((r) => (
          <div key={r.label} className="flex items-start gap-2.5 px-4 py-3">
            <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${r.ok ? "bg-emerald-400" : "bg-amber-400"}`} aria-hidden />
            <div className="min-w-0">
              <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-600">{r.label}</div>
              <div className="truncate text-xs font-medium text-slate-300" title={r.detail}>
                {r.detail}
              </div>
              {r.mock && <div className="text-[10px] text-amber-400/80">demo / mock</div>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const [recent, setRecent] = useState<InvestigationListItem[] | null>(null);
  const [demos, setDemos] = useState<Array<{ slug: string; title: string }>>([]);
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [runningDemo, setRunningDemo] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function refresh() {
    try {
      const [list, demoList, h] = await Promise.all([
        listInvestigations({ page_size: 100 }),
        listDemoCases(),
        getHealth(),
      ]);
      setRecent(list.items);
      setDemos(demoList);
      setHealth(h);
      setErr(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function startDemo(slug: string) {
    setRunningDemo(slug);
    setErr(null);
    try {
      const inv = await runDemoCase(slug);
      window.location.href = `/results/${inv.investigation_id}`;
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setRunningDemo(null);
    }
  }

  const total = recent?.length ?? 0;
  const highRisk = recent?.filter((i) => i.risk_level === "HIGH" || i.risk_level === "CRITICAL").length ?? 0;
  const scored = recent?.filter((i) => typeof i.risk_score === "number") ?? [];
  const avgRisk = scored.length ? Math.round(scored.reduce((a, i) => a + (i.risk_score ?? 0), 0) / scored.length) : null;

  const dist = (recent ?? []).reduce<Record<string, number>>((acc, i) => {
    const lvl = i.risk_level ?? "—";
    acc[lvl] = (acc[lvl] ?? 0) + 1;
    return acc;
  }, {});
  const byType = (recent ?? []).reduce<Record<string, number>>((acc, i) => {
    const t = i.scam_type ?? "unclassified";
    acc[t] = (acc[t] ?? 0) + 1;
    return acc;
  }, {});
  const topTypes = Object.entries(byType)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  const maxLevelCount = Math.max(1, ...LEVEL_ORDER.map((l) => dist[l] ?? 0));
  const maxTypeCount = Math.max(1, ...topTypes.map(([, c]) => c));
  const demoMode = health?.providers.llm.is_mock ?? true;

  if (err && recent === null) {
    return (
      <div className="mx-auto max-w-3xl space-y-4">
        <SectionHeader title="Investigation Center" sub="Monitor and analyze suspicious digital activity." />
        <ErrorBanner message={`${err} — start the API server (uvicorn app.main:app) and reload.`} onRetry={refresh} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Investigation Center"
        sub="Monitor and analyze suspicious digital activity."
        action={
          <Link href="/investigate" className="btn-primary">
            <Plus className="h-4 w-4" aria-hidden /> New investigation
          </Link>
        }
      />

      <ProviderStrip health={health} />

      {err && <ErrorBanner message={err} onRetry={refresh} />}

      {/* KPI cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Reveal>
          <div className="panel panel-hover h-full p-4">
            <div className="panel-title flex items-center justify-between">
              Investigations
              <FileSearch className="h-3.5 w-3.5 text-accent/70" aria-hidden />
            </div>
            <div className="mono-tabular mt-2 font-mono text-3xl font-bold text-slate-100">
              {recent === null ? <Skeleton className="h-8 w-14" /> : total}
            </div>
            <div className="mt-1 text-xs text-slate-500">total analyzed</div>
          </div>
        </Reveal>
        <Reveal delay={60}>
          <div className="panel panel-hover h-full p-4">
            <div className="panel-title flex items-center justify-between">
              High / critical
              <ShieldAlert className="h-3.5 w-3.5 text-red-400/70" aria-hidden />
            </div>
            <div className={`mono-tabular mt-2 font-mono text-3xl font-bold ${highRisk ? "text-red-300" : "text-emerald-300"}`}>
              {recent === null ? <Skeleton className="h-8 w-14" /> : highRisk}
            </div>
            <div className="mt-1 text-xs text-slate-500">need attention</div>
          </div>
        </Reveal>
        <Reveal delay={120}>
          <div className="panel panel-hover h-full p-4">
            <div className="panel-title flex items-center justify-between">
              Avg risk
              <Gauge className="h-3.5 w-3.5 text-amber-400/70" aria-hidden />
            </div>
            <div className="mono-tabular mt-2 font-mono text-3xl font-bold text-slate-100">
              {recent === null ? <Skeleton className="h-8 w-14" /> : avgRisk ?? "—"}
            </div>
            <div className="mt-1 text-xs text-slate-500">{avgRisk === null ? "no scored cases" : "across scored cases"}</div>
          </div>
        </Reveal>
        <Reveal delay={180}>
          <div className="panel panel-hover h-full p-4">
            <div className="panel-title flex items-center justify-between">
              System
              <Radar className="h-3.5 w-3.5 text-emerald-400/70" aria-hidden />
            </div>
            <div className={`mono-tabular mt-2 font-mono text-3xl font-bold ${demoMode ? "text-amber-300" : "text-emerald-300"}`}>
              {health === null ? <Skeleton className="h-8 w-14" /> : demoMode ? "Demo" : "Live"}
            </div>
            <div className="mt-1 text-xs text-slate-500">{health ? (demoMode ? "no paid APIs configured" : "live providers") : "checking…"}</div>
          </div>
        </Reveal>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* risk distribution */}
        <Reveal>
          <section className="panel h-full p-5">
            <h2 className="panel-title">Risk distribution</h2>
            <div className="mt-4 space-y-3.5">
              {LEVEL_ORDER.map((l, idx) => {
                const count = dist[l] ?? 0;
                const pct = total ? Math.round((count / total) * 100) : 0;
                const meta = riskMeta(l);
                return (
                  <div key={l} className="flex items-center gap-3">
                    <span className={`w-20 text-[11px] font-bold uppercase tracking-wide ${meta.text}`}>{l}</span>
                    <div className="h-3 flex-1 overflow-hidden rounded-full bg-base-800">
                      <div
                        className="h-full origin-left animate-bar-grow rounded-full"
                        style={{
                          width: `${(count / maxLevelCount) * 100}%`,
                          background: `linear-gradient(90deg, ${meta.hex}55, ${meta.hex})`,
                          animationDelay: `${idx * 90}ms`,
                        }}
                      />
                    </div>
                    <span className="mono-tabular w-16 text-right font-mono text-[11px] text-slate-400">
                      {count} · {pct}%
                    </span>
                  </div>
                );
              })}
            </div>

            <h2 className="panel-title mt-7">Top categories</h2>
            <div className="mt-3 space-y-2.5">
              {topTypes.length === 0 && <p className="text-sm text-slate-600">No investigations yet.</p>}
              {topTypes.map(([type, count]) => (
                <div key={type} className="flex items-center gap-3">
                  <span className="w-48 truncate text-xs text-slate-300">{categoryLabel(type)}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-base-800">
                    <div
                      className="h-full origin-left animate-bar-grow rounded-full bg-gradient-to-r from-cyan-500/70 to-accent"
                      style={{ width: `${(count / maxTypeCount) * 100}%` }}
                    />
                  </div>
                  <span className="mono-tabular w-6 text-right font-mono text-[11px] text-slate-400">{count}</span>
                </div>
              ))}
            </div>
          </section>
        </Reveal>

        {/* demo cases */}
        <Reveal delay={100}>
          <section className="panel h-full p-5">
            <div className="flex items-center justify-between">
              <h2 className="panel-title">Try a sample investigation</h2>
              <FlaskConical className="h-4 w-4 text-accent/70" aria-hidden />
            </div>
            <p className="mt-2 text-xs leading-relaxed text-slate-500">
              Fictional cases run through the full pipeline — handy when you have nothing to paste yet.
            </p>
            <div className="mt-4 grid gap-2 sm:grid-cols-2">
              {demos.length === 0 && (
                <div className="sm:col-span-2"><Skeleton className="h-9 w-full" /></div>
              )}
              {demos.map((d) => (
                <button
                  key={d.slug}
                  onClick={() => startDemo(d.slug)}
                  disabled={runningDemo !== null}
                  className="group flex items-center justify-between gap-2 rounded-lg border border-base-600/70 bg-base-900/50 px-3 py-2.5 text-left text-[13px] text-slate-300 transition-all hover:border-accent/50 hover:bg-base-800/60 hover:text-accent disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <span className="truncate">{d.title.replace("Demo: ", "")}</span>
                  {runningDemo === d.slug ? (
                    <Spinner />
                  ) : (
                    <ArrowRight className="h-3.5 w-3.5 shrink-0 text-slate-600 transition group-hover:text-accent" aria-hidden />
                  )}
                </button>
              ))}
            </div>
            {demos.length > 0 && (
              <p className="mt-3 text-[10px] text-slate-600">
                Runs a deterministic demo case server-side — results are real pipeline output, not mockups.
              </p>
            )}
          </section>
        </Reveal>
      </div>

      {/* quick CTA */}
      <Reveal>
        <div className="panel relative overflow-hidden p-6 sm:p-8">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_60%_100%_at_100%_0%,rgba(34,211,238,0.08),transparent_60%)]" />
          <div className="relative flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                <Sparkles className="h-4 w-4 text-accent" aria-hidden /> Analyze something suspicious?
              </div>
              <p className="mt-1 max-w-lg text-[13px] leading-relaxed text-slate-500">
                Paste a message, add a URL or upload a screenshot. The investigation engine extracts
                evidence, correlates signals and produces an explainable risk report.
              </p>
            </div>
            <Link href="/investigate" className="btn-primary px-6 py-3">
              Start investigation <ArrowRight className="h-4 w-4" aria-hidden />
            </Link>
          </div>
        </div>
      </Reveal>

      {/* recent */}
      <section className="panel overflow-hidden">
        <div className="flex items-center justify-between px-5 pt-4 pb-2">
          <h2 className="panel-title">Recent investigations</h2>
          <Link href="/history" className="text-xs font-medium text-accent transition hover:underline">
            View all →
          </Link>
        </div>
        {recent === null ? (
          <div className="space-y-3 p-5">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : recent.length === 0 ? (
          <div className="p-6">
            <EmptyState
              icon={<CheckCircle2 className="h-6 w-6" aria-hidden />}
              title="No investigations yet"
              hint="Submit your first suspicious message, URL or screenshot — or run a sample investigation above."
              action={
                <Link href="/investigate" className="btn-primary">
                  <Plus className="h-4 w-4" aria-hidden /> Start investigation
                </Link>
              }
            />
          </div>
        ) : (
          <div className="scroll-slim overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead>
                <tr className="border-y border-base-700/60 bg-base-900/60 text-[10px] uppercase tracking-[0.12em] text-slate-600">
                  <th className="px-5 py-2.5 font-semibold">Investigation</th>
                  <th className="px-3 py-2.5 font-semibold">Type</th>
                  <th className="px-3 py-2.5 font-semibold">Input</th>
                  <th className="px-3 py-2.5 font-semibold">Risk</th>
                  <th className="px-5 py-2.5 text-right font-semibold">Opened</th>
                </tr>
              </thead>
              <tbody>
                {recent.slice(0, 8).map((i, idx) => (
                  <tr
                    key={i.id}
                    className="border-b border-base-800/50 transition-colors last:border-0 hover:bg-base-800/30"
                    style={{ animation: `fade-in 0.4s ease-out ${idx * 40}ms both` }}
                  >
                    <td className="px-5 py-3">
                      <Link href={`/results/${i.id}`} className="font-medium text-slate-200 transition hover:text-accent">
                        {i.title}
                      </Link>
                      <div className="mt-0.5 font-mono text-[10px] uppercase tracking-wide text-slate-600">
                        {i.status}
                      </div>
                    </td>
                    <td className="px-3 py-3 text-xs text-slate-400">
                      {i.scam_type ? categoryLabel(i.scam_type) : "—"}
                    </td>
                    <td className="px-3 py-3">
                      <span className="chip border-base-600/50 bg-base-800/50 font-mono text-[10px] uppercase text-slate-400">
                        {i.input_types.map((t) => t.toUpperCase()).join(" + ") || "—"}
                      </span>
                    </td>
                    <td className="px-3 py-3"><RiskBadge level={i.risk_level} score={i.risk_score} /></td>
                    <td className="px-5 py-3 text-right font-mono text-[11px] text-slate-500">
                      {formatDate(i.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}