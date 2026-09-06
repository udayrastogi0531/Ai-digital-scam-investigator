"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  AlertOctagon,
  ArrowRight,
  Brain,
  FileText,
  Fingerprint,
  Globe,
  ImageIcon,
  Layers,
  MessageSquareText,
  Radar,
  ScanSearch,
  ShieldCheck,
  ShieldQuestion,
} from "lucide-react";
import { EvidenceGroup, EntityChips, ScamTypePill, Timeline } from "@/components/investigation";
import { ErrorBanner, RiskBadge, RiskGauge, SectionHeader, Skeleton, Spinner } from "@/components/ui";
import { getInvestigation } from "@/lib/api";
import type { InvestigationView, RiskLevel } from "@/lib/types";
import { categoryLabel, formatDate, riskMeta } from "@/lib/types";

function SufficiencyBadge({ value }: { value?: string | null }) {
  const map: Record<string, { label: string; cls: string; icon: React.ReactNode }> = {
    INSUFFICIENT: {
      label: "Insufficient evidence",
      cls: "border-slate-500/40 bg-slate-500/10 text-slate-300",
      icon: <ShieldQuestion className="h-3.5 w-3.5" aria-hidden />,
    },
    PARTIAL: {
      label: "Partial evidence",
      cls: "border-amber-500/40 bg-amber-500/10 text-amber-300",
      icon: <ShieldQuestion className="h-3.5 w-3.5" aria-hidden />,
    },
    SUFFICIENT: {
      label: "Sufficient",
      cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
      icon: <ShieldCheck className="h-3.5 w-3.5" aria-hidden />,
    },
  };
  const m = (value && map[value]) || {
    label: "—",
    cls: "border-base-600/60 bg-base-900 text-slate-500",
    icon: null,
  };
  return (
    <span className={`chip ${m.cls}`}>
      {m.icon}
      {m.label}
    </span>
  );
}

function ThreatIntelView({ inv }: { inv: InvestigationView }) {
  const signals = inv.evidence.filter((e) => e.source === "threat_intelligence");
  const mock = signals.some((s) => s.detail?.is_mock === true || (s.description ?? "").includes("[DEMO]"));
  if (signals.length === 0) return null;

  const statusStyle: Record<string, string> = {
    ok: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
    unavailable: "border-orange-500/40 bg-orange-500/10 text-orange-300",
    rate_limited: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    error: "border-red-500/40 bg-red-500/10 text-red-300",
  };

  return (
    <section className="panel p-5">
      <div className="flex items-center justify-between gap-2">
        <h2 className="panel-title">Threat intelligence</h2>
        {mock && (
          <span className="chip border-amber-400/30 bg-amber-400/10 text-[10px] uppercase tracking-wide text-amber-300">
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
                <span className={`chip px-2 py-0.5 font-mono text-[10px] uppercase ${statusStyle[status] ?? statusStyle.error}`}>
                  {status}
                </span>
                <span className="font-mono text-xs font-semibold text-accent">{verdict}</span>
                <span className="font-mono text-[10px] text-slate-500">{String(d.provider ?? "")}</span>
                {typeof d.checked_at === "string" && (
                  <span className="font-mono text-[10px] text-slate-600">{formatDate(d.checked_at)}</span>
                )}
              </div>
              {d.reputation ? <div className="mt-0.5 text-xs text-slate-400">{String(d.reputation)}</div> : null}
              {d.error ? <div className="mt-0.5 text-xs text-red-300/80">{String(d.error)}</div> : null}
              {providers && providers.length > 1 && (
                <ul className="mt-1.5 space-y-1 border-l border-base-700 pl-2.5">
                  {providers.map((p, j) => {
                    const pStatus = String(p.status ?? "ok");
                    const failed = pStatus !== "ok";
                    return (
                      <li key={j} className="flex flex-wrap items-center gap-x-2 text-[11px] text-slate-400">
                        <span className="font-mono text-accent/80">{String(p.provider ?? "")}</span>
                        <span>{String(p.verdict ?? "unknown")}</span>
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
        <p className="mt-3 text-[11px] leading-relaxed text-amber-200/70">
          No real threat-intelligence API is configured — these results come from a local demo provider
          and are not external verification.
        </p>
      )}
    </section>
  );
}

const SOURCE_GROUPS: Array<{
  key: string;
  title: string;
  icon: React.ReactNode;
  sources: string[];
}> = [
  { key: "url", title: "URL evidence", icon: <Globe className="h-4 w-4" aria-hidden />, sources: ["url_analysis"] },
  { key: "text", title: "Text signals", icon: <MessageSquareText className="h-4 w-4" aria-hidden />, sources: ["text_analysis"] },
  { key: "pattern", title: "Pattern matches", icon: <Fingerprint className="h-4 w-4" aria-hidden />, sources: ["scam_pattern"] },
  { key: "ml", title: "ML assessment", icon: <Brain className="h-4 w-4" aria-hidden />, sources: ["ml_classifier"] },
  { key: "intel", title: "Threat intelligence", icon: <Radar className="h-4 w-4" aria-hidden />, sources: ["threat_intelligence"] },
  { key: "entity", title: "Entity evidence", icon: <ScanSearch className="h-4 w-4" aria-hidden />, sources: ["entity_analysis"] },
  { key: "ocr", title: "Input & OCR", icon: <ImageIcon className="h-4 w-4" aria-hidden />, sources: ["input_parser", "ocr"] },
];

export default function ResultPage({ params }: { params: Promise<{ id: string }> }) {
  const [id, setId] = useState<string | null>(null);
  const [inv, setInv] = useState<InvestigationView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retryKey, setRetryKey] = useState(0);

  useEffect(() => {
    params.then((p) => setId(p.id));
  }, [params]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    setInv(null);
    setError(null);
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
  }, [id, retryKey]);

  if (error) {
    return (
      <div className="mx-auto max-w-3xl space-y-4">
        <ErrorBanner message={error} onRetry={() => setRetryKey((k) => k + 1)} />
        <Link href="/history" className="inline-flex items-center gap-1.5 text-sm text-accent hover:underline">
          ← Back to history
        </Link>
      </div>
    );
  }

  if (!inv) {
    return (
      <div className="mx-auto max-w-3xl space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-56 w-full" />
        <div className="grid gap-4 sm:grid-cols-2">
          <Skeleton className="h-40 w-full" />
          <Skeleton className="h-40 w-full" />
        </div>
      </div>
    );
  }

  const risk = inv.risk;
  const demoMode =
    inv.warnings.some((w) => /demo|mock/i.test(w)) ||
    String(inv.processing_metadata?.provider_mode ?? "").includes("mock");

  const flagged = inv.evidence.filter((e) => e.severity === "high" || e.severity === "critical").slice(0, 8);

  return (
    <div className="space-y-6">
      {/* header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <Link href="/history" className="inline-flex items-center gap-1.5 text-xs text-accent hover:underline">
            ← History
          </Link>
          <h1 className="mt-1 text-xl font-bold tracking-tight text-slate-100">{inv.title}</h1>
          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-slate-500">
            <span>{inv.investigation_id}</span>
            <span className="uppercase">{inv.input_types.map((t) => t.toUpperCase()).join(" + ")}</span>
            <span>{formatDate(inv.created_at)}</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <RiskBadge level={risk?.level} score={risk?.score} />
          <Link href="/investigate" className="btn-ghost btn-sm">＋ New</Link>
        </div>
      </div>

      {/* warnings + demo notice */}
      {inv.warnings.length > 0 && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/[0.06] p-4 text-sm text-amber-200">
          <div className="mb-1 flex items-center gap-2 font-semibold">
            <AlertOctagon className="h-4 w-4" aria-hidden /> Provider / pipeline notices
          </div>
          <ul className="list-inside list-disc space-y-0.5 text-amber-200/80">
            {inv.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}
      {demoMode && (
        <div className="rounded-xl border border-accent/25 bg-accent/[0.05] px-4 py-2.5 text-xs text-cyan-200">
          Demo mode: running without paid APIs — explanations are deterministic and threat-intel / OCR
          results are local mocks. Enable real providers via backend environment variables.
        </div>
      )}

      {/* risk hero */}
      {risk ? (
        <div className="panel relative overflow-hidden p-6 sm:p-8">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_60%_90%_at_15%_0%,rgba(34,211,238,0.06),transparent_60%)]" />
          <div className="relative grid gap-8 lg:grid-cols-[auto_1fr] lg:items-center">
            <div className="flex flex-col items-center gap-4 lg:flex-row lg:gap-8">
              <RiskGauge score={risk.score} level={risk.level} confidence={risk.confidence} />
              <div className="text-center lg:text-left">
                <div className={`text-2xl font-extrabold tracking-tight ${riskMeta(risk.level).text}`}>
                  {riskMeta(risk.level).label.toUpperCase()}
                </div>
                <div className="mt-2 flex flex-wrap items-center justify-center gap-2 lg:justify-start">
                  <SufficiencyBadge value={risk.evidence_sufficiency} />
                </div>
                <div className="mt-3 text-xs text-slate-500">
                  Confidence{" "}
                  <span className="mono-tabular font-mono font-semibold text-slate-200">
                    {Math.round(risk.confidence * 100)}%
                  </span>
                  {" · "}
                  method <span className="font-mono text-slate-400">{risk.method}</span>
                </div>
              </div>
            </div>

            {/* why this score */}
            <div className="rounded-xl border border-base-700/60 bg-base-925/70 p-5">
              <h2 className="panel-title">Why this score?</h2>
              {risk.contributors.length === 0 ? (
                <p className="mt-3 text-sm text-slate-500">No contributing factors were recorded.</p>
              ) : (
                <ul className="mt-3 space-y-2">
                  {risk.contributors.slice(0, 8).map((c) => (
                    <li key={c.name} className="flex items-center gap-3 text-sm">
                      <span
                        className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                          c.impact > 0 ? "bg-red-400" : c.impact < 0 ? "bg-emerald-400" : "bg-slate-500"
                        }`}
                        aria-hidden
                      />
                      <span className="min-w-0 flex-1 truncate text-slate-300" title={c.name}>
                        {c.name}
                      </span>
                      <span
                        className={`mono-tabular shrink-0 font-mono text-xs ${
                          c.impact > 0 ? "text-red-300" : c.impact < 0 ? "text-emerald-300" : "text-slate-500"
                        }`}
                      >
                        {c.impact > 0 ? `+${Math.round(c.impact)}` : Math.round(c.impact)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          {risk.level === "LOW" &&
            (risk.evidence_sufficiency === "INSUFFICIENT" || risk.evidence_sufficiency === "PARTIAL") && (
              <div className="relative mt-6 max-w-2xl rounded-lg border border-base-600/60 bg-base-925/70 px-4 py-3 text-xs leading-relaxed text-slate-400">
                <span className="font-semibold text-slate-200">Low risk based on available evidence</span> — the
                submission contained{" "}
                {risk.evidence_sufficiency === "INSUFFICIENT" ? "too little" : "only limited"} evidence for a
                confident assessment. This is <span className="font-semibold text-amber-300">not a verified safe
                result</span>.
              </div>
            )}
        </div>
      ) : (
        <div className="panel p-5 text-sm text-slate-400">No risk assessment available.</div>
      )}

      {/* why flagged */}
      {flagged.length > 0 && (
        <section className="panel p-5">
          <div className="flex items-center gap-2">
            <AlertOctagon className="h-4 w-4 text-red-400" aria-hidden />
            <h2 className="panel-title">Why this was flagged</h2>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {flagged.map((e, i) => (
              <span
                key={`${e.source}-${e.signal}-${i}`}
                className="chip border-red-500/25 bg-red-500/[0.07] text-[12px] text-red-200"
              >
                {e.description || `${e.source} · ${e.signal}`}
              </span>
            ))}
          </div>
        </section>
      )}

      {/* assessment summary */}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <section className="panel p-5">
            <div className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-accent" aria-hidden />
              <h2 className="panel-title">Assessment</h2>
            </div>
            <div className="mt-3">
              {inv.scam_type && <ScamTypePill primary={inv.scam_type.primary} confidence={inv.scam_type.confidence} />}
            </div>
            {inv.scam_type && inv.scam_type.alternatives.length > 0 && (
              <p className="mt-2 text-xs text-slate-500">
                Alternatives: {inv.scam_type.alternatives.map(categoryLabel).join(", ")}
              </p>
            )}
            {inv.report?.summary && (
              <p className="mt-3 text-sm leading-relaxed text-slate-300">{inv.report.summary}</p>
            )}
            {inv.report?.likely_objective && (
              <p className="mt-2 text-sm text-slate-400">
                Likely objective: <span className="font-medium text-slate-200">{inv.report.likely_objective}</span>
                <span className="ml-2 rounded bg-base-700/80 px-1.5 py-0.5 font-mono text-[10px] uppercase text-slate-400">
                  {inv.report.objective_confidence} confidence
                </span>
              </p>
            )}
            {inv.report?.limitations && (
              <p className="mt-3 border-t border-base-700/60 pt-3 text-xs italic leading-relaxed text-slate-500">
                {inv.report.limitations}
              </p>
            )}
          </section>

          {/* evidence by group */}
          {SOURCE_GROUPS.map((g) => (
            <EvidenceGroup
              key={g.key}
              title={g.title}
              icon={g.icon}
              items={inv.evidence.filter((e) => g.sources.includes(e.source))}
            />
          ))}

          {inv.ml && (
            <section className="panel p-5">
              <div className="flex items-center gap-2">
                <Brain className="h-4 w-4 text-accent" aria-hidden />
                <h2 className="panel-title">Machine learning assessment</h2>
              </div>
              <div className="mt-4 flex items-center gap-4">
                <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-base-800">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-fuchsia-500 transition-all duration-700"
                    style={{ width: `${Math.round(inv.ml.probability_scam * 100)}%` }}
                  />
                </div>
                <span className="mono-tabular shrink-0 font-mono text-sm font-bold text-slate-200">
                  Scam probability {(inv.ml.probability_scam * 100).toFixed(0)}%
                </span>
              </div>
              <div className="mt-2 text-xs text-slate-500">
                Model <span className="font-mono">{inv.ml.model}</span> · label{" "}
                <span className="font-mono">{inv.ml.label}</span>
                {inv.ml.is_mock && (
                  <span className="ml-2 text-amber-300">(heuristic fallback — no trained model)</span>
                )}
              </div>
              <p className="mt-2 text-[11px] leading-relaxed text-slate-600">
                The ML prediction is one input signal — the final verdict comes from the deterministic
                evidence and risk engine, not from the model.
              </p>
            </section>
          )}
        </div>

        <div className="space-y-6">
          <ThreatIntelView inv={inv} />

          <section className="panel p-5">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-accent" aria-hidden />
              <h2 className="panel-title">Investigation timeline</h2>
            </div>
            <div className="mt-4 scroll-slim max-h-[420px] overflow-y-auto pr-1">
              <Timeline entries={inv.timeline} />
            </div>
          </section>

          <section className="panel p-5">
            <h2 className="panel-title">Recommended actions</h2>
            <ul className="mt-3 space-y-2.5">
              {(inv.report?.recommendations ?? []).map((r, i) => (
                <li key={i} className="flex items-start gap-2.5 text-sm text-slate-300">
                  <ArrowRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" aria-hidden />
                  <span className="leading-relaxed">{r}</span>
                </li>
              ))}
              {(inv.report?.recommendations ?? []).length === 0 && (
                <li className="text-sm text-slate-500">No specific actions generated.</li>
              )}
            </ul>
          </section>

          {inv.report && inv.report.suspicious_indicators.length > 0 && (
            <section className="panel p-5">
              <h2 className="panel-title">Suspicious indicators</h2>
              <ul className="mt-3 space-y-1.5">
                {inv.report.suspicious_indicators.map((ind, i) => {
                const r = ind as Record<string, unknown>;
                const text =
                  typeof ind === "string" ? ind : String(r.indicator ?? r.label ?? r.text ?? ind);
                return (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                    <span className="mt-0.5 shrink-0 text-red-400" aria-hidden>⚑</span>
                    <span className="leading-relaxed">{text}</span>
                  </li>
                );
              })}
              </ul>
            </section>
          )}

          {inv.entities && (
            <section className="panel p-5">
              <h2 className="panel-title">Extracted entities</h2>
              <div className="mt-3">
                <EntityChips entities={inv.entities as unknown as Record<string, Array<{ value: string; entity_type: string }>>} />
              </div>
            </section>
          )}

          {inv.report && inv.report.sections.length > 0 && (
            <section className="panel p-5">
              <h2 className="panel-title">Full report</h2>
              {inv.report.sections.map((s) => (
                <div key={s.title} className="mb-3 last:mb-0">
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