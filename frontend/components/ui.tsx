"use client";

import type { RiskLevel, Severity } from "@/lib/types";
import { RISK_COLORS } from "@/lib/types";

export function RiskBadge({ level, score }: { level: RiskLevel | null | undefined; score?: number | null }) {
  if (!level) return <span className="text-xs text-slate-500">—</span>;
  const c = RISK_COLORS[level];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-bold ring-1 ${c.bg} ${c.text} ${c.ring}`}
    >
      {level}
      {typeof score === "number" && <span className="font-mono font-normal opacity-80">{Math.round(score)}</span>}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: Severity }) {
  const color =
    severity === "critical"
      ? "bg-red-400"
      : severity === "high"
        ? "bg-orange-400"
        : severity === "medium"
          ? "bg-amber-400"
          : severity === "low"
            ? "bg-emerald-400"
            : "bg-slate-500";
  return <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${color}`} />;
}

export function RiskGauge({ score, level, confidence }: { score: number; level: RiskLevel; confidence: number }) {
  const c = RISK_COLORS[level];
  const R = 56;
  const CIRC = 2 * Math.PI * R;
  const filled = Math.max(0, Math.min(100, score)) / 100;

  return (
    <div className="flex items-center gap-5">
      <div className="relative h-36 w-36">
        <svg viewBox="0 0 140 140" className="h-full w-full -rotate-90">
          <circle cx="70" cy="70" r={R} fill="none" stroke="#1e293b" strokeWidth="12" />
          <circle
            cx="70"
            cy="70"
            r={R}
            fill="none"
            stroke={c.hex}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={CIRC}
            strokeDashoffset={CIRC * (1 - filled)}
            className="transition-all duration-700"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-3xl font-bold text-slate-100">{Math.round(score)}</span>
          <span className="text-[10px] uppercase tracking-widest text-slate-500">/ 100</span>
        </div>
      </div>
      <div>
        <div className={`text-2xl font-extrabold ${c.text}`}>{level}</div>
        <div className="mt-1 text-sm text-slate-400">
          Confidence{" "}
          <span className="font-mono font-semibold text-slate-200">{Math.round(confidence * 100)}%</span>
        </div>
      </div>
    </div>
  );
}

export function StatCard({
  label,
  value,
  tone = "default",
  sub,
}: {
  label: string;
  value: string | number;
  tone?: "default" | "danger" | "warn" | "ok";
  sub?: string;
}) {
  const toneCls =
    tone === "danger"
      ? "text-red-300"
      : tone === "warn"
        ? "text-amber-300"
        : tone === "ok"
          ? "text-emerald-300"
          : "text-slate-100";
  return (
    <div className="panel p-4">
      <div className="panel-title">{label}</div>
      <div className={`mt-2 font-mono text-2xl font-bold ${toneCls}`}>{value}</div>
      {sub && <div className="mt-1 text-xs text-slate-500">{sub}</div>}
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-slate-400">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-accent border-t-transparent" />
      <span className="text-sm">{label ?? "Loading…"}</span>
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="panel border-red-500/40 bg-red-500/5 p-4 text-sm text-red-200">
      <span className="font-semibold">Error:</span> {message}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="panel flex flex-col items-center justify-center gap-2 p-10 text-center">
      <span className="text-2xl">🛰️</span>
      <div className="font-medium text-slate-300">{title}</div>
      {hint && <div className="max-w-md text-sm text-slate-500">{hint}</div>}
    </div>
  );
}
