"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { RiskBadge, Spinner, StatCard } from "@/components/ui";
import { EmptyState } from "@/components/ui";
import { getHealth, listDemoCases, listInvestigations, runDemoCase } from "@/lib/api";
import type { HealthInfo, InvestigationListItem } from "@/lib/types";
import { categoryLabel } from "@/lib/types";

const LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

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

  if (err && recent === null) {
    return <EmptyState title="Backend not reachable" hint={`${err} — start the API server (uvicorn app.main:app) and reload.`} />;
  }

  const total = recent?.length ?? 0;
  const highRisk = recent?.filter((i) => i.risk_level === "HIGH" || i.risk_level === "CRITICAL").length ?? 0;
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

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Investigation dashboard</h1>
          <p className="mt-1 text-sm text-slate-400">
            Agentic pipeline: evidence extraction → LangGraph analysis → deterministic risk → report.
          </p>
        </div>
        <Link href="/investigate" className="btn-primary">
          ＋ New investigation
        </Link>
      </div>

      {health && (
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1 rounded-md border border-base-700 bg-base-850/60 px-4 py-2 text-xs text-slate-400">
          <span>LLM: <b className={health.providers.llm.is_mock ? "text-amber-300" : "text-emerald-300"}>
            {health.providers.llm.is_mock ? "demo (deterministic)" : health.providers.llm.model}
          </b></span>
          <span>ML: <b className={health.providers.ml.available ? "text-emerald-300" : "text-amber-300"}>
            {health.providers.ml.model}
          </b></span>
          <span>Threat intel: <b className={health.providers.threat_intel.uses_mock ? "text-amber-300" : "text-emerald-300"}>
            {health.providers.threat_intel.uses_mock ? "demo (mock)" : health.providers.threat_intel.active.join(", ")}
          </b></span>
          <span>OCR: <b className={health.providers.ocr.is_mock ? "text-amber-300" : "text-emerald-300"}>
            {health.providers.ocr.provider}
          </b></span>
        </div>
      )}

      {err && <div className="panel border-red-500/40 bg-red-500/5 p-3 text-sm text-red-200">{err}</div>}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Investigations" value={total} sub="total analysed" />
        <StatCard label="High / critical" value={highRisk} tone={highRisk ? "danger" : "ok"} sub="need attention" />
        <StatCard label="Scam signals" value="Multi-source" sub="rules + ML + intel + LLM" />
        <StatCard label="Mode" value={health?.providers.llm.is_mock ? "Demo" : "Live"} tone={health?.providers.llm.is_mock ? "warn" : "ok"} sub="runs without paid APIs" />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* risk distribution */}
        <section className="panel p-5">
          <h2 className="panel-title">Risk distribution</h2>
          <div className="mt-4 space-y-3">
            {LEVEL_ORDER.map((l) => (
              <div key={l} className="flex items-center gap-3">
                <span className="w-20 text-xs font-semibold text-slate-300">{l}</span>
                <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-base-800">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      l === "CRITICAL" ? "bg-red-400" : l === "HIGH" ? "bg-orange-400" : l === "MEDIUM" ? "bg-amber-400" : "bg-emerald-400"
                    }`}
                    style={{ width: `${((dist[l] ?? 0) / maxLevelCount) * 100}%` }}
                  />
                </div>
                <span className="w-6 text-right font-mono text-xs text-slate-400">{dist[l] ?? 0}</span>
              </div>
            ))}
          </div>
          <h2 className="panel-title mt-6">Top categories</h2>
          <div className="mt-3 space-y-2">
            {topTypes.length === 0 && <p className="text-sm text-slate-500">No investigations yet.</p>}
            {topTypes.map(([type, count]) => (
              <div key={type} className="flex items-center gap-3">
                <span className="w-44 truncate text-xs text-slate-300">{categoryLabel(type)}</span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-base-800">
                  <div className="h-full rounded-full bg-accent/80" style={{ width: `${(count / maxTypeCount) * 100}%` }} />
                </div>
                <span className="w-6 text-right font-mono text-xs text-slate-400">{count}</span>
              </div>
            ))}
          </div>
        </section>

        {/* demo cases */}
        <section className="panel p-5">
          <h2 className="panel-title">Try a sample investigation</h2>
          <p className="mt-2 text-xs text-slate-500">
            Fictional cases run through the full pipeline — handy when you have nothing to paste yet.
          </p>
          <div className="mt-4 grid gap-2 sm:grid-cols-2">
            {demos.map((d) => (
              <button
                key={d.slug}
                onClick={() => startDemo(d.slug)}
                disabled={runningDemo !== null}
                className="group rounded-md border border-base-600 px-3 py-2 text-left text-sm text-slate-300 transition hover:border-accent/60 hover:text-accent disabled:opacity-50"
              >
                {runningDemo === d.slug ? <Spinner label="Running…" /> : <span>{d.title.replace("Demo: ", "")}</span>}
              </button>
            ))}
          </div>
        </section>
      </div>

      {/* recent */}
      <section className="panel overflow-hidden">
        <div className="flex items-center justify-between px-5 pt-4">
          <h2 className="panel-title">Recent investigations</h2>
          <Link href="/history" className="text-xs text-accent hover:underline">View all →</Link>
        </div>
        {recent === null ? (
          <div className="p-6"><Spinner /></div>
        ) : recent.length === 0 ? (
          <div className="p-6"><EmptyState title="Nothing investigated yet" hint="Submit your first suspicious message, URL or screenshot." /></div>
        ) : (
          <table className="mt-3 w-full text-left text-sm">
            <thead>
              <tr className="border-y border-base-700 text-xs uppercase tracking-wider text-slate-500">
                <th className="px-5 py-2 font-medium">Case</th>
                <th className="px-3 py-2 font-medium">Type</th>
                <th className="px-3 py-2 font-medium">Risk</th>
                <th className="px-5 py-2 text-right font-medium">Opened</th>
              </tr>
            </thead>
            <tbody>
              {recent.slice(0, 8).map((i) => (
                <tr key={i.id} className="border-b border-base-800/70 last:border-0 hover:bg-base-800/40">
                  <td className="px-5 py-2.5">
                    <Link href={`/results/${i.id}`} className="font-medium text-slate-200 hover:text-accent">
                      {i.title}
                    </Link>
                    <div className="font-mono text-[10px] text-slate-600">{i.input_types.join(" + ")}</div>
                  </td>
                  <td className="px-3 py-2.5 text-xs text-slate-400">{i.scam_type ? categoryLabel(i.scam_type) : "—"}</td>
                  <td className="px-3 py-2.5"><RiskBadge level={i.risk_level} score={i.risk_score} /></td>
                  <td className="px-5 py-2.5 text-right font-mono text-[11px] text-slate-500">
                    {i.created_at ? new Date(i.created_at).toLocaleString() : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
