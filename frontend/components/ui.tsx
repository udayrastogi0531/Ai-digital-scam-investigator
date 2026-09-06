"use client";

import { AlertTriangle, ScanSearch, ShieldAlert, ShieldCheck, Sparkles } from "lucide-react";
import type { RiskLevel, Severity } from "@/lib/types";
import { RISK_COLORS, riskMeta } from "@/lib/types";

export function RiskBadge({ level, score }: { level: RiskLevel | null | undefined; score?: number | null }) {
  if (!level) return <span className="text-xs text-slate-600">—</span>;
  const c = RISK_COLORS[level];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-bold tracking-wide ring-1 ${c.bg} ${c.text} ${c.ring}`}
    >
      {level}
      {typeof score === "number" && (
        <span className="mono-tabular font-mono text-[10px] font-normal opacity-90">{Math.round(score)}</span>
      )}
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
            : "bg-slate-600";
  return <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${color}`} aria-hidden />;
}

/** Animated circular risk gauge. */
export function RiskGauge({ score, level, confidence }: { score: number; level: RiskLevel; confidence: number }) {
  const c = RISK_COLORS[level];
  const R = 62;
  const CIRC = 2 * Math.PI * R;
  const filled = Math.max(0, Math.min(100, score)) / 100;

  return (
    <div className="relative h-44 w-44">
      <svg viewBox="0 0 150 150" className="h-full w-full -rotate-90">
        <defs>
          <linearGradient id={`gauge-${level}`} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={c.hex} stopOpacity="0.55" />
            <stop offset="100%" stopColor={c.hex} />
          </linearGradient>
        </defs>
        <circle cx="75" cy="75" r={R} fill="none" stroke="#1c2847" strokeWidth="11" />
        <circle
          cx="75"
          cy="75"
          r={R}
          fill="none"
          stroke={`url(#gauge-${level})`}
          strokeWidth="11"
          strokeLinecap="round"
          strokeDasharray={CIRC}
          strokeDashoffset={CIRC * (1 - filled)}
          className="transition-all duration-1000 ease-out"
          style={{ filter: `drop-shadow(0 0 6px ${c.hex}55)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="mono-tabular font-mono text-5xl font-bold tracking-tight text-slate-100">
          {Math.round(score)}
        </span>
        <span className="mt-0.5 font-mono text-[10px] uppercase tracking-[0.2em] text-slate-500">/ 100</span>
      </div>
    </div>
  );
}

export function StatCard({
  label,
  value,
  tone = "default",
  sub,
  icon,
}: {
  label: string;
  value: string | number;
  tone?: "default" | "danger" | "warn" | "ok";
  sub?: string;
  icon?: React.ReactNode;
}) {
  const toneCls =
    tone === "danger"
      ? "text-red-300"
      : tone === "warn"
        ? "text-amber-300"
        : tone === "ok"
          ? "text-emerald-300"
          : "text-slate-100";
  const iconCls =
    tone === "danger"
      ? "text-red-400/80"
      : tone === "warn"
        ? "text-amber-400/80"
        : tone === "ok"
          ? "text-emerald-400/80"
          : "text-accent/80";
  return (
    <div className="panel panel-hover relative overflow-hidden p-4">
      <div className="flex items-center justify-between">
        <div className="panel-title">{label}</div>
        {icon && <span className={iconCls}>{icon}</span>}
      </div>
      <div className={`mono-tabular mt-2 font-mono text-3xl font-bold ${toneCls}`}>{value}</div>
      {sub && <div className="mt-1 text-xs text-slate-500">{sub}</div>}
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-slate-400" role="status">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-accent border-t-transparent" />
      <span className="text-sm">{label ?? "Loading…"}</span>
    </div>
  );
}

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-red-500/30 bg-red-500/[0.06] px-4 py-3 text-sm text-red-200">
      <div className="flex items-start gap-2.5">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" aria-hidden />
        <div>
          <div className="font-semibold">Request failed</div>
          <div className="mt-0.5 break-words font-mono text-xs text-red-300/80">{message}</div>
        </div>
      </div>
      {onRetry && (
        <button type="button" onClick={onRetry} className="btn-danger btn-sm">
          Try again
        </button>
      )}
    </div>
  );
}

export function EmptyState({
  title,
  hint,
  action,
  icon,
}: {
  title: string;
  hint?: string;
  action?: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <div className="panel flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-base-600/60 bg-base-800/60 text-slate-500">
        {icon ?? <ShieldSearchIcon />}
      </div>
      <div className="text-base font-semibold text-slate-200">{title}</div>
      {hint && <div className="max-w-md text-sm leading-relaxed text-slate-500">{hint}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

function ShieldSearchIcon() {
  return <ScanSearch className="h-6 w-6" aria-hidden />;
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={`skeleton ${className ?? "h-4 w-full"}`} aria-hidden />;
}

export function SectionHeader({ title, sub, action }: { title: string; sub?: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">{title}</h1>
        {sub && <p className="mt-1 text-sm text-slate-500">{sub}</p>}
      </div>
      {action}
    </div>
  );
}

export function ModeBadge({ mock, liveLabel, mockLabel }: { mock: boolean; liveLabel: string; mockLabel: string }) {
  return mock ? (
    <span className="chip border-amber-400/30 bg-amber-400/10 text-amber-300">
      <span className="h-1.5 w-1.5 rounded-full bg-amber-400" /> {mockLabel}
    </span>
  ) : (
    <span className="chip border-emerald-400/30 bg-emerald-400/10 text-emerald-300">
      <ShieldCheck className="h-3 w-3" aria-hidden /> {liveLabel}
    </span>
  );
}

export function Spacer() {
  return <span className="h-px flex-1 bg-base-700/60" aria-hidden />;
}

export function Logo({ size = 34 }: { size?: number }) {
  return (
    <span
      className="relative flex items-center justify-center rounded-lg border border-accent/30 bg-gradient-to-br from-accent/20 to-blue-500/10 text-accent"
      style={{ width: size, height: size }}
    >
      <ShieldAlert className="h-[55%] w-[55%]" strokeWidth={2.2} aria-hidden />
      <span className="absolute -right-0.5 -top-0.5 h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.9)]" />
    </span>
  );
}

export function Pill({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={`chip border-base-600/70 bg-base-800/60 text-slate-300 ${className ?? ""}`}>{children}</span>
  );
}

export function SparklineDot() {
  return <Sparkles className="h-3 w-3 text-accent" aria-hidden />;
}