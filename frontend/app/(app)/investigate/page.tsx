"use client";

import { useCallback, useRef, useState } from "react";
import {
  CheckCircle2,
  FileSearch,
  Globe,
  ImagePlus,
  Layers,
  Loader2,
  MessageSquareText,
  Radar,
  Scan,
  Sparkles,
  X,
} from "lucide-react";
import { ErrorBanner, SectionHeader } from "@/components/ui";
import { submitInvestigation } from "@/lib/api";

const SOURCE_OPTIONS = [
  { value: "email", label: "Email" },
  { value: "sms", label: "SMS" },
  { value: "whatsapp", label: "WhatsApp" },
  { value: "social", label: "Social message" },
  { value: "job_offer", label: "Job offer" },
  { value: "payment", label: "Payment request" },
  { value: "other", label: "Other" },
];

const PROCESS_STAGES = [
  { icon: FileSearch, label: "Input received" },
  { icon: Scan, label: "Extracting evidence" },
  { icon: Globe, label: "Analyzing signals" },
  { icon: Layers, label: "Correlating evidence" },
  { icon: Radar, label: "Calculating risk" },
  { icon: Sparkles, label: "Generating report" },
];

function ProcessingOverlay({ done }: { done: boolean }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-base-950/85 p-4 backdrop-blur-sm">
      <div className="panel w-full max-w-md scale-in p-7 text-center">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-accent/30 bg-accent/10 text-accent">
          {done ? <CheckCircle2 className="h-6 w-6 text-emerald-400" aria-hidden /> : <Loader2 className="h-6 w-6 animate-spin" aria-hidden />}
        </div>
        <h2 className="mt-4 text-lg font-bold text-slate-100">
          {done ? "Investigation complete" : "Investigation in progress"}
        </h2>
        <p className="mt-1 text-xs leading-relaxed text-slate-500">
          The agentic pipeline is running server-side — extracting evidence, correlating signals and
          scoring risk.
        </p>

        <div className="mt-6 space-y-2 text-left">
          {PROCESS_STAGES.map((s, i) => {
            const active = !done && i === PROCESS_STAGES.length - 1 && false;
            void active;
            const finished = done || i < Math.max(1, PROCESS_STAGES.length - 1);
            return (
              <div
                key={s.label}
                className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors duration-300 ${
                  finished ? "text-slate-200" : "text-slate-600"
                }`}
              >
                {finished ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden />
                ) : (
                  <span className="flex h-4 w-4 shrink-0 items-center justify-center">
                    <span className="h-2.5 w-2.5 animate-ping rounded-full bg-accent/60" />
                  </span>
                )}
                <s.icon className="h-4 w-4 shrink-0 opacity-70" aria-hidden />
                {s.label}
              </div>
            );
          })}
        </div>

        <p className="mt-5 text-[10px] leading-relaxed text-slate-600">
          Stages shown for guidance — the engine reports real node completion in the investigation
          timeline on the result page.
        </p>
      </div>
    </div>
  );
}

export default function InvestigatePage() {
  const [title, setTitle] = useState("");
  const [sourceLabel, setSourceLabel] = useState("email");
  const [text, setText] = useState("");
  const [urlInput, setUrlInput] = useState("");
  const [urls, setUrls] = useState<string[]>([]);
  const [image, setImage] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  function addUrl() {
    const trimmed = urlInput.trim();
    if (!trimmed) return;
    const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
    if (!urls.includes(withScheme)) setUrls((u) => [...u, withScheme]);
    setUrlInput("");
  }

  const handleFile = useCallback((f: File | null) => {
    if (!f) return;
    if (!f.type.startsWith("image/")) {
      setError("Only image files are accepted (screenshot upload).");
      return;
    }
    if (f.size > 10 * 1024 * 1024) {
      setError("Image is larger than the 10 MB limit.");
      return;
    }
    setImage(f);
    setImagePreview(URL.createObjectURL(f));
    setError(null);
  }, []);

  async function submit() {
    setError(null);
    if (!text.trim() && urls.length === 0 && !image) {
      setError("Add a message, at least one URL, or a screenshot before investigating.");
      return;
    }
    setBusy(true);
    setDone(false);
    try {
      const inv = await submitInvestigation({
        text: text.trim() || undefined,
        urls,
        title: title.trim() || undefined,
        source_label: sourceLabel,
        image,
      });
      setDone(true);
      // brief pause so the completed state is visible, then open the report
      setTimeout(() => {
        window.location.href = `/results/${inv.investigation_id}`;
      }, 700);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  const canSubmit = (text.trim() || urls.length > 0 || image) && !busy;

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <SectionHeader
        title="New investigation"
        sub="Paste a suspicious email, SMS, WhatsApp or social message — optionally add a URL or a screenshot."
      />

      {error && <ErrorBanner message={error} />}

      <div className="panel space-y-6 p-5 sm:p-6">
        {/* source + title */}
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="source" className="field-label">Input source</label>
            <select id="source" className="input" value={sourceLabel} onChange={(e) => setSourceLabel(e.target.value)}>
              {SOURCE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="title" className="field-label">Title (optional)</label>
            <input
              id="title"
              className="input"
              placeholder="e.g. Suspicious PayPal email"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              maxLength={255}
            />
          </div>
        </div>

        {/* message */}
        <div>
          <label htmlFor="message" className="field-label">Message content</label>
          <div className="relative">
            <MessageSquareText className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-slate-600" aria-hidden />
            <textarea
              id="message"
              className="input min-h-[190px] resize-y pl-9 font-mono text-[13px] leading-relaxed"
              placeholder={"Paste the suspicious message here…\n\nExample: \"Your account has been suspended. Verify within 24 hours at http://… or it will be closed.\""}
              value={text}
              onChange={(e) => setText(e.target.value)}
              maxLength={50000}
            />
          </div>
          <div className="mt-1 text-right font-mono text-[10px] text-slate-600">{text.length} / 50000</div>
        </div>

        {/* URLs */}
        <div>
          <label htmlFor="url-input" className="field-label">Explicit URLs (optional)</label>
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Globe className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-600" aria-hidden />
              <input
                id="url-input"
                className="input pl-9 font-mono"
                placeholder="https://example.com/suspicious-link"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addUrl();
                  }
                }}
              />
            </div>
            <button type="button" className="btn-ghost whitespace-nowrap" onClick={addUrl}>
              Add
            </button>
          </div>
          {urls.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {urls.map((u) => (
                <span
                  key={u}
                  className="inline-flex max-w-full items-center gap-1.5 rounded-md border border-base-600/70 bg-base-900/80 px-2 py-1 font-mono text-[11px] text-slate-300"
                >
                  <span className="truncate">{u}</span>
                  <button
                    aria-label={`Remove ${u}`}
                    className="shrink-0 text-slate-500 transition hover:text-red-300"
                    onClick={() => setUrls((list) => list.filter((x) => x !== u))}
                  >
                    <X className="h-3 w-3" />
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>

        {/* screenshot upload */}
        <div>
          <label className="field-label">Screenshot (optional)</label>
          {imagePreview ? (
            <div className="flex flex-wrap items-start gap-4">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={imagePreview}
                alt="screenshot preview"
                className="max-h-44 rounded-lg border border-base-600/70"
              />
              <div className="flex flex-col gap-2">
                <button type="button" className="btn-ghost btn-sm" onClick={() => fileRef.current?.click()}>
                  Replace
                </button>
                <button
                  type="button"
                  className="btn-danger btn-sm"
                  onClick={() => {
                    setImage(null);
                    setImagePreview(null);
                  }}
                >
                  Remove
                </button>
              </div>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => fileRef.current?.click()}
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragOver(false);
                handleFile(e.dataTransfer.files?.[0] ?? null);
              }}
              className={`flex w-full flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-4 py-10 text-sm transition-all ${
                dragOver
                  ? "border-accent/70 bg-accent/[0.06] text-slate-200"
                  : "border-base-600/70 bg-base-900/40 text-slate-500 hover:border-accent/50 hover:text-slate-300"
              }`}
            >
              <ImagePlus className={`h-7 w-7 ${dragOver ? "text-accent" : "text-slate-600"}`} aria-hidden />
              <span>{dragOver ? "Drop the screenshot to attach it" : "Drag & drop a screenshot, or click to browse"}</span>
              <span className="text-[10px] text-slate-600">PNG / JPG, up to 10 MB — OCR runs locally, the image stays on your server</span>
            </button>
          )}
          <input
            ref={fileRef}
            type="file"
            accept="image/*"
            className="hidden"
            onChange={(e) => handleFile(e.target.files?.[0] ?? null)}
          />
        </div>

        <div className="flex flex-wrap items-center justify-end gap-3 border-t border-base-700/60 pt-5">
          <span className="mr-auto hidden text-[11px] text-slate-600 sm:block">
            Everything runs through the deterministic evidence pipeline.
          </span>
          <button type="button" className="btn-primary min-w-[220px]" onClick={submit} disabled={!canSubmit}>
            {busy ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> Investigating…
              </>
            ) : (
              <>
                <Scan className="h-4 w-4" aria-hidden /> Start investigation
              </>
            )}
          </button>
        </div>
      </div>

      {busy && <ProcessingOverlay done={done} />}
    </div>
  );
}