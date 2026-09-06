"use client";

import { SeverityDot } from "@/components/ui";
import type { EvidenceSignal, TimelineEntry } from "@/lib/types";
import { SEVERITY_STYLE, categoryLabel } from "@/lib/types";

export function EvidenceCard({ e }: { e: EvidenceSignal }) {
  const border = SEVERITY_STYLE[e.severity];
  const tag = e.severity === "info" ? "info" : e.severity;
  return (
    <div className={`panel border-l-2 p-3 ${border}`}>
      <div className="flex items-start gap-2.5">
        <SeverityDot severity={e.severity} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs font-semibold text-accent">{e.source}</span>
            <span className="font-mono text-[10px] uppercase tracking-wide text-slate-500">{e.signal}</span>
            <span className="rounded bg-base-700/80 px-1.5 py-0.5 font-mono text-[10px] uppercase text-slate-300">
              {tag}
            </span>
            <span className="font-mono text-[10px] text-slate-500">
              conf {(e.confidence * 100).toFixed(0)}%
            </span>
          </div>
          {e.description && <p className="mt-1 text-sm text-slate-300">{e.description}</p>}
        </div>
      </div>
    </div>
  );
}

export function Timeline({ entries }: { entries: TimelineEntry[] }) {
  const icons: Record<string, string> = {
    parse: "📥", ocr: "🖼️", analyze: "🔎", url_analysis: "🔗", entity_analysis: "🏷️",
    threat_intel: "🛰️", ml: "🤖", correlate: "🧩", risk: "⚠️", explain: "💬", report: "📄",
  };
  return (
    <ol className="relative space-y-0 border-l border-base-600 pl-5">
      {entries.map((t) => (
        <li key={t.stage} className="relative pb-4 last:pb-0">
          <span className="absolute -left-[27px] top-0 flex h-4 w-4 items-center justify-center rounded-full border border-base-500 bg-base-900" />
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-sm font-semibold text-slate-200">
              {icons[t.stage] ?? "·"} {t.label}
            </span>
            {typeof t.duration_ms === "number" && (
              <span className="font-mono text-[10px] text-slate-500">{t.duration_ms} ms</span>
            )}
          </div>
          <div className="font-mono text-[10px] uppercase tracking-wide text-slate-600">{t.stage}</div>
        </li>
      ))}
    </ol>
  );
}

export function IndicatorRow({ icon, label }: { icon: string; label: string }) {
  return (
    <div className="flex items-start gap-2.5 text-sm text-slate-300">
      <span className="mt-0.5">{icon}</span>
      <span>{label}</span>
    </div>
  );
}

export function EntityChips({ entities }: { entities: Record<string, Array<{ value: string; entity_type: string }>> }) {
  const groups: Array<[string, string]> = [
    ["urls", "🔗"], ["emails", "✉️"], ["phones", "📞"], ["amounts", "💰"],
    ["companies", "🏢"], ["banks", "🏦"], ["organizations", "🏛️"], ["dates", "📅"], ["other", "…"],
  ];
  return (
    <div className="space-y-2">
      {groups.map(([key, icon]) => {
        const list = entities[key] ?? [];
        if (!list.length) return null;
        return (
          <div key={key} className="flex flex-wrap items-center gap-1.5">
            <span className="w-24 font-mono text-[10px] uppercase tracking-wider text-slate-500">
              {icon} {key}
            </span>
            {list.map((e, i) => (
              <span
                key={`${key}-${i}`}
                className="max-w-full truncate rounded border border-base-600 bg-base-900 px-2 py-0.5 font-mono text-[11px] text-slate-300"
                title={e.value}
              >
                {e.value}
              </span>
            ))}
          </div>
        );
      })}
    </div>
  );
}

export function ScamTypePill({ primary, confidence }: { primary: string; confidence: number }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-md border border-accent/40 bg-accent/10 px-3 py-1.5">
      <span className="text-sm font-bold text-accent">{categoryLabel(primary)}</span>
      <span className="font-mono text-[10px] text-slate-400">
        {(confidence * 100).toFixed(0)}% confidence
      </span>
    </span>
  );
}
