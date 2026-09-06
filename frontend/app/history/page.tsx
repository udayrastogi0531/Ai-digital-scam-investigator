"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { RiskBadge, Spinner, EmptyState } from "@/components/ui";
import { deleteInvestigation, listInvestigations } from "@/lib/api";
import type { PaginatedInvestigations } from "@/lib/types";
import { categoryLabel } from "@/lib/types";

const RISK_FILTERS = ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const PAGE_SIZE = 15;

export default function HistoryPage() {
  const [data, setData] = useState<PaginatedInvestigations | null>(null);
  const [search, setSearch] = useState("");
  const [risk, setRisk] = useState("");
  const [type, setType] = useState("");
  const [page, setPage] = useState(1);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const result = await listInvestigations({
        page,
        page_size: PAGE_SIZE,
        search: search || undefined,
        risk_level: risk || undefined,
        scam_type: type || undefined,
      });
      setData(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [search, risk, type, page]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  async function remove(id: string) {
    if (!window.confirm("Delete this investigation and its evidence?")) return;
    try {
      await deleteInvestigation(id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Investigation history</h1>
          <p className="mt-1 text-sm text-slate-400">
            {data ? `${data.total} saved investigation${data.total === 1 ? "" : "s"}` : "Loading…"}
          </p>
        </div>
        <Link href="/investigate" className="btn-primary">＋ New investigation</Link>
      </div>

      <div className="panel grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-slate-500">Search</label>
          <input
            className="input"
            placeholder="Title or text fragment…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-slate-500">Risk level</label>
          <select className="input" value={risk} onChange={(e) => { setRisk(e.target.value); setPage(1); }}>
            {RISK_FILTERS.map((r) => (
              <option key={r} value={r}>{r === "" ? "All levels" : r}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-slate-500">Scam type</label>
          <input
            className="input"
            placeholder="e.g. banking_scam, phishing"
            value={type}
            onChange={(e) => {
              setType(e.target.value);
              setPage(1);
            }}
          />
        </div>
      </div>

      {error && <div className="panel border-red-500/40 bg-red-500/5 p-3 text-sm text-red-200">{error}</div>}

      {!data ? (
        <div className="p-10"><Spinner label="Loading history…" /></div>
      ) : data.items.length === 0 ? (
        <EmptyState title="No investigations match" hint="Adjust filters, or start a new investigation from the dashboard." />
      ) : (
        <div className="panel overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead>
              <tr className="border-b border-base-700 text-xs uppercase tracking-wider text-slate-500">
                <th className="px-4 py-2.5 font-medium">Investigation</th>
                <th className="px-3 py-2.5 font-medium">Scam type</th>
                <th className="px-3 py-2.5 font-medium">Input</th>
                <th className="px-3 py-2.5 font-medium">Risk</th>
                <th className="px-3 py-2.5 font-medium">Date</th>
                <th className="px-3 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {data.items.map((i) => (
                <tr key={i.id} className="border-b border-base-800/70 transition hover:bg-base-800/40">
                  <td className="px-4 py-2.5">
                    <Link href={`/results/${i.id}`} className="font-medium text-slate-200 hover:text-accent">
                      {i.title}
                    </Link>
                    <span className={`ml-2 font-mono text-[10px] uppercase ${i.status === "completed" ? "text-emerald-400" : i.status === "failed" ? "text-red-400" : "text-amber-400"}`}>
                      {i.status}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 text-xs text-slate-400">
                    {i.scam_type ? categoryLabel(i.scam_type) : "—"}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-[10px] text-slate-500">
                    {i.input_types.map((t) => t.toUpperCase()).join("+") || "—"}
                  </td>
                  <td className="px-3 py-2.5"><RiskBadge level={i.risk_level} score={i.risk_score} /></td>
                  <td className="px-3 py-2.5 font-mono text-[11px] text-slate-500">
                    {i.created_at ? new Date(i.created_at).toLocaleDateString() : "—"}
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <button
                      className="text-xs text-slate-500 transition hover:text-red-300"
                      onClick={() => remove(i.id)}
                      title="Delete investigation"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="flex items-center justify-between border-t border-base-700 px-4 py-3">
            <button
              className="btn-ghost px-3 py-1 text-xs disabled:opacity-40"
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
            >
              ← Prev
            </button>
            <span className="font-mono text-xs text-slate-500">Page {page} / {totalPages}</span>
            <button
              className="btn-ghost px-3 py-1 text-xs disabled:opacity-40"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
