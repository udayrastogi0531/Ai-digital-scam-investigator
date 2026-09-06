"use client";

import { useRef, useState } from "react";
import { ErrorBanner, Spinner } from "@/components/ui";
import { submitInvestigation } from "@/lib/api";

const SOURCE_OPTIONS = [
  { value: "email", label: "📧 Email" },
  { value: "sms", label: "💬 SMS" },
  { value: "whatsapp", label: "🟢 WhatsApp" },
  { value: "social", label: "🧵 Social message" },
  { value: "job_offer", label: "💼 Job offer" },
  { value: "payment", label: "💳 Payment request" },
  { value: "other", label: "❔ Other" },
];

export default function InvestigatePage() {
  const [title, setTitle] = useState("");
  const [sourceLabel, setSourceLabel] = useState("email");
  const [text, setText] = useState("");
  const [urlInput, setUrlInput] = useState("");
  const [urls, setUrls] = useState<string[]>([]);
  const [image, setImage] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  function addUrl() {
    const trimmed = urlInput.trim();
    if (!trimmed) return;
    const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
    if (!urls.includes(withScheme)) setUrls((u) => [...u, withScheme]);
    setUrlInput("");
  }

  function handleFile(f: File | null) {
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
  }

  async function submit() {
    setError(null);
    if (!text.trim() && urls.length === 0 && !image) {
      setError("Add a message, at least one URL, or a screenshot before investigating.");
      return;
    }
    setBusy(true);
    try {
      const inv = await submitInvestigation({
        text: text.trim() || undefined,
        urls,
        title: title.trim() || undefined,
        source_label: sourceLabel,
        image,
      });
      window.location.href = `/results/${inv.investigation_id}`;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  const canSubmit = (text.trim() || urls.length > 0 || image) && !busy;

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">New investigation</h1>
        <p className="mt-1 text-sm text-slate-400">
          Paste a suspicious email, SMS, WhatsApp or social message — optionally add a URL or a screenshot.
          The pipeline extracts evidence and runs a full investigation.
        </p>
      </div>

      {error && <ErrorBanner message={error} />}

      <div className="panel space-y-5 p-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-slate-400">
              Where does it come from?
            </label>
            <select
              className="input"
              value={sourceLabel}
              onChange={(e) => setSourceLabel(e.target.value)}
            >
              {SOURCE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-slate-400">
              Title (optional)
            </label>
            <input
              className="input"
              placeholder="e.g. Suspicious PayPal email"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              maxLength={255}
            />
          </div>
        </div>

        <div>
          <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-slate-400">
            Message content
          </label>
          <textarea
            className="input min-h-[180px] resize-y font-mono text-[13px] leading-relaxed"
            placeholder={"Paste the suspicious message here…\n\nExample: \"Your account has been suspended. Verify within 24 hours at http://… or it will be closed.\""}
            value={text}
            onChange={(e) => setText(e.target.value)}
            maxLength={50000}
          />
          <div className="mt-1 text-right font-mono text-[10px] text-slate-600">{text.length} / 50000</div>
        </div>

        <div>
          <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-slate-400">
            Explicit URLs (optional)
          </label>
          <div className="flex gap-2">
            <input
              className="input font-mono"
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
            <button type="button" className="btn-ghost whitespace-nowrap" onClick={addUrl}>
              Add
            </button>
          </div>
          {urls.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {urls.map((u) => (
                <span
                  key={u}
                  className="inline-flex items-center gap-1.5 rounded border border-base-600 bg-base-900 px-2 py-1 font-mono text-[11px] text-slate-300"
                >
                  {u}
                  <button
                    aria-label="remove"
                    className="text-slate-500 hover:text-red-300"
                    onClick={() => setUrls((list) => list.filter((x) => x !== u))}
                  >
                    ✕
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>

        <div>
          <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-slate-400">
            Screenshot (optional)
          </label>
          {imagePreview ? (
            <div className="flex items-start gap-3">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={imagePreview}
                alt="screenshot preview"
                className="max-h-44 rounded border border-base-600"
              />
              <div className="space-x-2">
                <button type="button" className="btn-ghost text-xs" onClick={() => fileRef.current?.click()}>
                  Replace
                </button>
                <button
                  type="button"
                  className="btn-ghost text-xs"
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
              className="flex w-full flex-col items-center justify-center gap-1 rounded-md border border-dashed border-base-600 bg-base-900/50 px-4 py-8 text-sm text-slate-500 transition hover:border-accent/60 hover:text-slate-300"
            >
              <span className="text-xl">📸</span>
              Click to upload a screenshot (PNG/JPG, ≤10 MB)
              <span className="text-[10px] text-slate-600">OCR runs locally — no image leaves your server</span>
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

        <div className="flex items-center justify-end gap-3 border-t border-base-700 pt-4">
          <button type="button" className="btn-primary min-w-[220px]" onClick={submit} disabled={!canSubmit}>
            {busy ? <Spinner label="Investigating…" /> : "🔬 Start investigation"}
          </button>
        </div>
      </div>
    </div>
  );
}
