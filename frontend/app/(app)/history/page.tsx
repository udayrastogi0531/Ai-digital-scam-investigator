"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { Archive, ChevronLeft, ChevronRight, Plus, Search, Trash2 } from "lucide-react";
import { EmptyState, ErrorBanner, RiskBadge, SectionHeader, Skeleton } from "@/components/ui";
import { deleteInvestigation, listInvestigations } from "@/lib/api";
import type { PaginatedInvestigations } from "@/lib/types";
import { categoryLabel, formatDay } from "@/lib/types";

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
      if (data && data.items.length === 1 && page > 1) setPage((p) => p - 1);
      else load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Investigation history"
        sub={data ? `${data.total} saved investigation${data.total === 1 ? "" : "s"} analyzed` : "Loading saved investigations…"}
        action={
          <Link href="/investigate" className="btn-primary">
            <Plus className="h-4 w-4" aria-hidden /> New investigation
          </Link>
        }
      />

      {/* filters */}
      <div className="panel grid gap-4 p-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="sm:col-span-2">
          <label htmlFor="search" className="field-label">Search</label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-600" aria-hidden />
            <input
              id="search"
              className="input pl-9"
              placeholder="Title or text fragment…"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
            />
          </div>
        </div>
        <div>
          <label htmlFor="risk-filter" className="field-label">Risk level</label>
          <select
            id="risk-filter"
            className="input"
            value={risk}
            onChange={(e) => {
              setRisk(e.target.value);
              setPage(1);
            }}
          >
            {RISK_FILTERS.map((r) => (
              <option key={r} value={r}>
                {r === "" ? "All levels" : r}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="type-filter" className="field-label">Scam type</label>
          <input
            id="type-filter"
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

      {error && <ErrorBanner message={error} onRetry={load} />}

      {!data ? (
        <div className="space-y-3">
          {[0, 1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : data.items.length === 0 ? (
        <EmptyState
          icon={<Archive className="h-6 w-6" aria-hidden />}
          title={search || risk || type ? "No investigations match" : "No investigations yet"}
          hint={
            search || risk || type
              ? "Adjust the search or filters, or clear them to see everything."
              : "Start your first investigation to analyze a suspicious message, URL or screenshot."
          }
          action={
            !(search || risk || type) ? (
              <Link href="/investigate" className="btn-primary">
                <Plus className="h-4 w-4" aria-hidden /> Start investigation
              </Link>
            ) : undefined
          }
        />
      ) : (
        <div className="panel overflow-hidden">
          <div className="scroll-slim overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead>
                <tr className="border-b border-base-700/60 bg-base-900/60 text-[10px] uppercase tracking-[0.12em] text-slate-600">
                  <th className="px-4 py-3 font-semibold">Investigation</th>
                  <th className="px-3 py-3 font-semibold">Scam type</th>
                  <th className="px-3 py-3 font-semibold">Input</th>
                  <th className="px-3 py-3 font-semibold">Risk</th>
                  <th className="px-3 py-3 font-semibold">Date</th>
                  <th className="px-3 py-3" />
                </tr>
              </thead>
              <tbody>
                {data.items.map((i) => (
                  <tr key={i.id} className="group border-b border-base-800/50 transition-colors last:border-0 hover:bg-base-800/30">
                    <td className="px-4 py-3">
                      <Link href={`/results/${i.id}`} className="font-medium text-slate-200 transition hover:text-accent">
                        {i.title}
                      </Link>
                      <div className="mt-0.5 flex items-center gap-2">
                        <span
                          className={`font-mono text-[10px] uppercase tracking-wide ${
                            i.status === "completed"
                              ? "text-emerald-400"
                              : i.status === "failed"
                                ? "text-red-400"
                                : "text-amber-400"
                          }`}
                        >
                          {i.status}
                        </span>
                        <span className="font-mono text-[10px] text-slate-600">{i.id.slice(0, 8)}</span>
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
                    <td className="px-3 py-3 font-mono text-[11px] text-slate-500">{formatDay(i.created_at)}</td>
                    <td className="px-3 py-3 text-right">
                      <button
                        className="rounded-md p-1.5 text-slate-600 opacity-0 transition hover:bg-red-500/10 hover:text-red-300 group-hover:opacity-100"
                        onClick={() => remove(i.id)}
                        title="Delete investigation"
                        aria-label={`Delete ${i.title}`}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* pagination */}
          <div className="flex items-center justify-between border-t border-base-700/60 px-4 py-3">
            <button
              className="btn-ghost btn-sm disabled:opacity-40"
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
            >
              <ChevronLeft className="h-3.5 w-3.5" aria-hidden /> Prev
            </button>
            <span className="mono-tabular font-mono text-xs text-slate-500">
              Page {page} / {totalPages} · {data.total} total
            </span>
            <button
              className="btn-ghost btn-sm disabled:opacity-40"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              Next <ChevronRight className="h-3.5 w-3.5" aria-hidden />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}