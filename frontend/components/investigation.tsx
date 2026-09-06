"use client";

import { AlertOctagon, AlertTriangle, CheckCircle2, Info, ShieldAlert } from "lucide-react";
import { SeverityDot } from "@/components/ui";
import type { EvidenceSignal, TimelineEntry } from "@/lib/types";
import { SEVERITY_STYLE, categoryLabel } from "@/lib/types";

const SEVERITY_ICON: Record<string, React.ReactNode> = {
  critical: <AlertOctagon className="h-4 w-4 text-red-400" aria-hidden />,
  high: <ShieldAlert className="h-4 w-4 text-orange-400" aria-hidden />,
  medium: <AlertTriangle className="h-4 w-4 text-amber-400" aria-hidden />,
  low: <CheckCircle2 className="h-4 w-4 text-emerald-400" aria-hidden />,
  info: <Info className="h-4 w-4 text-slate-400" aria-hidden />,
};

export function EvidenceCard({ e }: { e: EvidenceSignal }) {
  const border = SEVERITY_STYLE[e.severity];
  return (
    <div className={`rounded-xl border border-l-2 bg-base-900/70 p-3.5 ${border}`}>
      <div className="flex items-start gap-2.5">
        <span className="mt-0.5">{SEVERITY_ICON[e.severity] ?? SEVERITY_ICON.info}</span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="font-mono text-xs font-bold text-accent">{e.source}</span>
            <span className="font-mono text-[10px] uppercase tracking-wide text-slate-500">{e.signal}</span>
            <span className="rounded border border-base-600/60 bg-base-800/70 px-1.5 py-0.5 font-mono text-[10px] uppercase text-slate-400">
              {e.severity}
            </span>
            <span className="font-mono text-[10px] text-slate-600">conf {(e.confidence * 100).toFixed(0)}%</span>
          </div>
          {e.description && <p className="mt-1 text-sm leading-relaxed text-slate-300">{e.description}</p>}
        </div>
      </div>
    </div>
  );
}

export function EvidenceGroup({
  title,
  icon,
  items,
}: {
  title: string;
  icon: React.ReactNode;
  items: EvidenceSignal[];
}) {
  if (items.length === 0) return null;
  return (
    <section className="panel p-5">
      <div className="flex items-center gap-2">
        <span className="text-accent">{icon}</span>
        <h2 className="panel-title">{title}</h2>
        <span className="ml-auto rounded-full border border-base-600/60 bg-base-800/60 px-2 py-0.5 font-mono text-[10px] text-slate-400">
          {items.length}
        </span>
      </div>
      <div className="mt-3 space-y-2">
        {items.map((e, i) => (
          <EvidenceCard key={`${e.source}-${e.signal}-${i}`} e={e} />
        ))}
      </div>
    </section>
  );
}

export function Timeline({ entries }: { entries: TimelineEntry[] }) {
  const icons: Record<string, React.ReactNode> = {
    parse: "◈", ocr: "▣", analyze: "◉", url_analysis: "◎", entity_analysis: "◇",
    threat_intel: "◭", ml: "◆", correlate: "◈", risk: "▲", explain: "◇", report: "▣",
  };
  return (
    <ol className="relative space-y-0 border-l border-base-600/50 pl-5">
      {entries.map((t) => (
        <li key={t.stage} className="relative pb-4 last:pb-0">
          <span className="absolute -left-[27px] top-0 flex h-4 w-4 items-center justify-center rounded-full border border-base-500/60 bg-base-900">
            <span className="h-1.5 w-1.5 rounded-full bg-accent/80" />
          </span>
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-sm font-medium text-slate-200">
              <span className="mr-1 text-accent">{icons[t.stage] ?? "·"}</span>
              {t.label}
            </span>
            {typeof t.duration_ms === "number" && (
              <span className="mono-tabular font-mono text-[10px] text-slate-500">{t.duration_ms} ms</span>
            )}
          </div>
          <div className="font-mono text-[10px] uppercase tracking-wide text-slate-600">{t.stage}</div>
        </li>
      ))}
    </ol>
  );
}

export function EntityChips({ entities }: { entities: Record<string, Array<{ value: string; entity_type: string }>> }) {
  const groups: Array<[string, string]> = [
    ["urls", "🔗"], ["emails", "✉"], ["phones", "☎"], ["amounts", "₹"],
    ["companies", "🏢"], ["banks", "🏦"], ["organizations", "🏛"], ["dates", "📅"], ["other", "…"],
  ];
  return (
    <div className="space-y-2.5">
      {groups.map(([key, icon]) => {
        const list = entities[key] ?? [];
        if (!list.length) return null;
        return (
          <div key={key} className="flex flex-wrap items-center gap-1.5">
            <span className="w-24 shrink-0 font-mono text-[10px] uppercase tracking-wider text-slate-500">
              {icon} {key}
            </span>
            <div className="flex flex-wrap gap-1.5">
              {list.map((e, i) => (
                <span
                  key={`${key}-${i}`}
                  className="max-w-full truncate rounded border border-base-600/60 bg-base-800/70 px-2 py-0.5 font-mono text-[11px] text-slate-300"
                  title={e.value}
                >
                  {e.value}
                </span>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function ScamTypePill({ primary, confidence }: { primary: string; confidence: number }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/[0.08] px-3 py-1.5">
      <span className="text-sm font-bold text-accent">{categoryLabel(primary)}</span>
      <span className="font-mono text-[10px] text-slate-400">{(confidence * 100).toFixed(0)}% confidence</span>
    </span>
  );
}