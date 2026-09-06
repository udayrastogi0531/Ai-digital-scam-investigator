"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { EntityChips, EvidenceCard, ScamTypePill, Timeline } from "@/components/investigation";
import { ErrorBanner, RiskBadge, RiskGauge, Spinner } from "@/components/ui";
import { getInvestigation } from "@/lib/api";
import type { InvestigationView } from "@/lib/types";
import { categoryLabel } from "@/lib/types";

function SufficiencyBadge({ value }: { value?: string | null }) {
  const map: Record<string, { label: string; cls: string }> = {
    INSUFFICIENT: { label: "Insufficient evidence", cls: "text-slate-300 border-slate-500/50 bg-slate-500/10" },
    PARTIAL: { label: "Partial evidence", cls: "text-amber-300 border-amber-500/40 bg-amber-500/10" },
    SUFFICIENT: { label: "Sufficient", cls: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10" },
  };
  const m = (value && map[value]) || { label: "—", cls: "text-slate-500 border-base-600 bg-base-900" };
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${m.cls}`}>
      {m.label}
    </span>
  );
}

function ThreatIntelView({ inv }: { inv: InvestigationView }) {
  const signals = inv.evidence.filter((e) => e.source === "threat_intelligence");
  const mock = signals.some((s) => s.detail?.is_mock === true || (s.description ?? "").includes("[DEMO]"));
  if (signals.length === 0) return null;

  const statusStyle: Record<string, string> = {
    ok: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
    unavailable: "text-orange-300 border-orange-500/40 bg-orange-500/10",
    rate_limited: "text-amber-300 border-amber-500/40 bg-amber-500/10",
    error: "text-red-300 border-red-500/40 bg-red-500/10",
  };
  const statusLabel: Record<string, string> = {
    ok: "ok",
    unavailable: "unavailable",
    rate_limited: "rate-limited",
    error: "error",
  };

  return (
    <section className="panel p-5">
      <div className="flex items-center justify-between gap-2">
        <h2 className="panel-title">Threat intelligence</h2>
        {mock && (
          <span className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-amber-300">
            Demo / mock
          </span>
        )}
      </div>
      <ul className="mt-3 space-y-3">
        {signals.map((s, i) => {
          const d = s.detail as Record<string, unknown>;
          const status = String(d.status ?? "ok");
          const verdict = String(d.verdict ?? "unknown");
          const providers = Array.isArray(d.providers) ? (d.providers as Array<Record<string, unknown>>) : null;
          return (
            <li key={i} className="text-sm text-slate-300">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase ${statusStyle[status] ?? statusStyle.error}`}
                >
                  {statusLabel[status] ?? status}
                </span>
                <span className="font-mono text-xs text-accent">{verdict}</span>
                <span className="font-mono text-[10px] text-slate-500">{String(d.provider ?? "")}</span>
                {typeof d.checked_at === "string" && (
                  <span className="font-mono text-[10px] text-slate-600">
                    {new Date(d.checked_at).toLocaleString()}
                  </span>
                )}
              </div>
              {d.reputation ? (
                <div className="mt-0.5 text-xs text-slate-400">{String(d.reputation)}</div>
              ) : null}
              {d.error ? <div className="mt-0.5 text-xs text-red-300/80">{String(d.error)}</div> : null}
              {providers && providers.length > 1 && (
                <ul className="mt-1.5 space-y-1 border-l border-base-700 pl-2.5">
                  {providers.map((p, j) => {
                    const pStatus = String(p.status ?? "ok");
                    const pVerdict = String(p.verdict ?? "unknown");
                    const failed = pStatus !== "ok";
                    return (
                      <li key={j} className="flex flex-wrap items-center gap-x-2 text-[11px] text-slate-400">
                        <span className="font-mono text-accent/80">{String(p.provider ?? "")}</span>
                        <span>{pVerdict}</span>
                        {failed && <span className="text-amber-300">({pStatus})</span>}
                        {p.is_mock === true && <span className="text-amber-300/80">[demo]</span>}
                        {p.error ? <span className="text-red-300/70">{String(p.error)}</span> : null}
                      </li>
                    );
                  })}
                </ul>
              )}
            </li>
          );
        })}
      </ul>
      {mock && (
        <p className="mt-3 text-[11px] text-amber-200/70">
          No real threat-intelligence API is configured — these results come from a local demo provider
          and are not external verification.
        </p>
      )}
    </section>
  );
}

export default function ResultPage({ params }: { params: Promise<{ id: string }> }) {
  const [id, setId] = useState<string | null>(null);
  const [inv, setInv] = useState<InvestigationView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    params.then((p) => setId(p.id));
  }, [params]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    getInvestigation(id)
      .then((data) => {
        if (!cancelled) setInv(data);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (error) {
    return (
      <div className="mx-auto max-w-3xl space-y-4">
        <ErrorBanner message={error} />
        <Link href="/history" className="text-sm text-accent hover:underline">← Back to history</Link>
      </div>
    );
  }

  if (!inv) {
    return (
      <div className="mx-auto max-w-3xl p-10">
        <Spinner label="Loading investigation…" />
      </div>
    );
  }

  const risk = inv.risk;
  const demoMode =
    inv.warnings.some((w) => /demo|mock/i.test(w)) ||
    String(inv.processing_metadata?.provider_mode ?? "").includes("mock");

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <Link href="/history" className="text-xs text-accent hover:underline">← History</Link>
          <h1 className="mt-1 text-lg font-bold text-slate-100">{inv.title}</h1>
          <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-slate-500">
            <span className="font-mono">{inv.investigation_id}</span>
            <span>{inv.input_types.map((t) => t.toUpperCase()).join(" + ")}</span>
            {inv.created_at && <span>{new Date(inv.created_at).toLocaleString()}</span>}
            <RiskBadge level={risk?.level} score={risk?.score} />
          </div>
        </div>
        <Link href="/investigate" className="btn-ghost text-sm">＋ New</Link>
      </div>

      {inv.warnings.length > 0 && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-sm text-amber-200">
          <div className="mb-1 font-semibold">⚠️ Provider / pipeline notices</div>
          <ul className="list-inside list-disc space-y-0.5">
            {inv.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      {demoMode && (
        <div className="rounded-md border border-accent/30 bg-accent/5 px-3 py-2 text-xs text-cyan-200">
          Demo mode: running without paid APIs — explanations are deterministic and threat-intel/OCR results are
          local mocks. Enable real providers via environment variables for production use.
        </div>
      )}

      {risk ? (
        <div className="panel flex flex-wrap items-center justify-between gap-6 p-5">
          <div>
            <RiskGauge score={risk.score} level={risk.level} confidence={risk.confidence} />
            <div className="mt-3 flex items-center gap-2">
              <span className="text-xs text-slate-400">Evidence sufficiency:</span>
              <SufficiencyBadge value={risk.evidence_sufficiency} />
            </div>
            {risk.level === "LOW" &&
              (risk.evidence_sufficiency === "INSUFFICIENT" || risk.evidence_sufficiency === "PARTIAL") && (
                <div className="mt-2 max-w-xs text-[11px] leading-relaxed text-slate-400">
                  <span className="font-semibold text-slate-300">
                    Low risk based on available evidence
                  </span>{" "}
                  — the submission contained {risk.evidence_sufficiency === "INSUFFICIENT" ? "too little" : "only limited"}{" "}
                  evidence for a confident assessment. This is{" "}
                  <span className="font-semibold text-amber-300">not a verified safe result</span>.
                </div>
              )}
          </div>
          <div className="min-w-[260px] flex-1">
            <div className="panel-title mb-2">Main contributing factors</div>
            <ul className="space-y-1.5">
              {risk.contributors.slice(0, 6).map((c) => (
                <li key={c.name} className="flex items-center gap-2 text-sm">
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-accent" />
                  <span className="text-slate-300">{c.name}</span>
                  <span className="ml-auto font-mono text-[10px] text-slate-500">
                    {c.impact > 0 ? "pushes risk up" : c.impact < 0 ? "lowers risk" : "neutral"}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : (
        <div className="panel p-5 text-sm text-slate-400">No risk assessment available.</div>
      )}

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="space-y-6 lg:col-span-3">
          <section className="panel p-5">
            <h2 className="panel-title mb-3">Assessment</h2>
            {inv.scam_type && <ScamTypePill primary={inv.scam_type.primary} confidence={inv.scam_type.confidence} />}
            {inv.scam_type && inv.scam_type.alternatives.length > 0 && (
              <p className="mt-2 text-xs text-slate-500">
                Alternatives: {inv.scam_type.alternatives.map(categoryLabel).join(", ")}
              </p>
            )}
            {inv.report?.summary && <p className="mt-3 text-sm leading-relaxed text-slate-300">{inv.report.summary}</p>}
            {inv.report?.likely_objective && (
              <p className="mt-2 text-sm text-slate-400">
                Likely objective: <span className="font-medium text-slate-200">{inv.report.likely_objective}</span>
                <span className="ml-2 rounded bg-base-700 px-1.5 py-0.5 font-mono text-[10px] uppercase text-slate-400">
                  {inv.report.objective_confidence} confidence
                </span>
              </p>
            )}
            {inv.report?.limitations && (
              <p className="mt-3 border-t border-base-700 pt-3 text-xs italic leading-relaxed text-slate-500">
                {inv.report.limitations}
              </p>
            )}
          </section>

          <section className="panel p-5">
            <h2 className="panel-title mb-3">Evidence</h2>
            <div className="scroll-slim max-h-[480px] space-y-2 overflow-y-auto pr-1">
              {inv.evidence.length === 0 && <p className="text-sm text-slate-500">No evidence captured.</p>}
              {inv.evidence.map((e, i) => (
                <EvidenceCard key={`${e.source}-${e.signal}-${i}`} e={e} />
              ))}
            </div>
          </section>

          {inv.ml && (
            <section className="panel p-5">
              <h2 className="panel-title mb-2">Machine learning assessment</h2>
              <div className="flex items-center gap-4">
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-base-800">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-fuchsia-500"
                    style={{ width: `${Math.round(inv.ml.probability_scam * 100)}%` }}
                  />
                </div>
                <span className="font-mono text-sm font-bold text-slate-200">
                  Scam probability {(inv.ml.probability_scam * 100).toFixed(0)}%
                </span>
              </div>
              <div className="mt-1 text-xs text-slate-500">
                Model <span className="font-mono">{inv.ml.model}</span> · label{" "}
                <span className="font-mono">{inv.ml.label}</span>
                {inv.ml.is_mock && (
                  <span className="ml-2 text-amber-300">(heuristic fallback — no trained model)</span>
                )}
              </div>
              <p className="mt-2 text-[11px] text-slate-600">
                The ML prediction is one input signal — the final verdict comes from the deterministic
                evidence and risk engine, not from the model.
              </p>
            </section>
          )}
        </div>

        <div className="space-y-6 lg:col-span-2">
          <ThreatIntelView inv={inv} />
          <section className="panel p-5">
            <h2 className="panel-title mb-3">Investigation timeline</h2>
            <Timeline entries={inv.timeline} />
          </section>

          <section className="panel p-5">
            <h2 className="panel-title mb-3">Recommended actions</h2>
            <ul className="space-y-2">
              {(inv.report?.recommendations ?? []).map((r, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                  <span className="mt-0.5 text-accent">▸</span>
                  <span>{r}</span>
                </li>
              ))}
              {(inv.report?.recommendations ?? []).length === 0 && (
                <li className="text-sm text-slate-500">No specific actions generated.</li>
              )}
            </ul>
          </section>

          {inv.report && inv.report.suspicious_indicators.length > 0 && (
            <section className="panel p-5">
              <h2 className="panel-title mb-3">Suspicious indicators</h2>
              <ul className="space-y-1.5">
                {inv.report.suspicious_indicators.map((ind, i) => (
                  <li key={i} className="text-sm text-slate-300">
                    ⚑ {String(typeof ind === "string" ? ind : (ind.label ?? ind))}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {inv.entities && (
            <section className="panel p-5">
              <h2 className="panel-title mb-3">Extracted entities</h2>
              <EntityChips entities={inv.entities as unknown as Record<string, Array<{ value: string; entity_type: string }>>} />
            </section>
          )}

          {inv.report && inv.report.sections.length > 0 && (
            <section className="panel p-5">
              <h2 className="panel-title mb-3">Full report</h2>
              {inv.report.sections.map((s) => (
                <div key={s.title} className="mb-3">
                  <div className="text-sm font-semibold text-slate-200">{s.title}</div>
                  <p className="mt-0.5 whitespace-pre-line text-xs leading-relaxed text-slate-400">{s.content}</p>
                </div>
              ))}
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
