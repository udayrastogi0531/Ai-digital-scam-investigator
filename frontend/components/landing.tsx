"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  ArrowRight,
  Brain,
  CheckCircle2,
  ChevronRight,
  CircleDashed,
  Cpu,
  Database,
  FileSearch,
  FileText,
  GitBranch,
  Globe,
  Layers,
  Lock,
  Network,
  Radar,
  Scale,
  Scan,
  ShieldCheck,
  Sparkles,
  Zap,
} from "lucide-react";
import { Reveal } from "@/components/reveal";

/* ------------------------------------------------------------------ */
/* Hero background: animated investigation network                     */
/* ------------------------------------------------------------------ */

function HeroNetwork() {
  return (
    <div
      className="pointer-events-none absolute inset-0 overflow-hidden"
      aria-hidden
    >
      {/* grid + radial washes */}
      <div className="grid-bg animate-grid-drift absolute inset-0 opacity-60" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_70%_55%_at_50%_-5%,rgba(34,211,238,0.12),transparent_60%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_55%_45%_at_85%_20%,rgba(129,140,248,0.08),transparent_60%)]" />

      {/* network diagram */}
      <svg
        className="absolute left-1/2 top-1/2 h-[620px] w-[900px] max-w-none -translate-x-1/2 -translate-y-1/2 opacity-[0.55]"
        viewBox="0 0 900 620"
        fill="none"
      >
        <defs>
          <linearGradient id="lg-flow" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="#22d3ee" stopOpacity="0" />
            <stop offset="0.5" stopColor="#22d3ee" stopOpacity="0.7" />
            <stop offset="1" stopColor="#38bdf8" stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* edges */}
        <g stroke="#22d3ee" strokeWidth="1.2" opacity="0.5">
          <path d="M450 60 L450 150" strokeDasharray="6 6" className="animate-flow-x" />
          <path d="M450 150 L230 250" strokeDasharray="6 6" className="animate-flow-x" style={{ animationDelay: "0.2s" }} />
          <path d="M450 150 L450 250" strokeDasharray="6 6" className="animate-flow-x" style={{ animationDelay: "0.4s" }} />
          <path d="M450 150 L670 250" strokeDasharray="6 6" className="animate-flow-x" style={{ animationDelay: "0.6s" }} />
          <path d="M230 250 L450 360" strokeDasharray="6 6" className="animate-flow-x" style={{ animationDelay: "0.8s" }} />
          <path d="M450 250 L450 360" strokeDasharray="6 6" className="animate-flow-x" style={{ animationDelay: "1s" }} />
          <path d="M670 250 L450 360" strokeDasharray="6 6" className="animate-flow-x" style={{ animationDelay: "1.2s" }} />
          <path d="M450 360 L450 460" strokeDasharray="6 6" className="animate-flow-x" style={{ animationDelay: "1.4s" }} />
          <path d="M450 460 L450 550" strokeDasharray="6 6" className="animate-flow-x" style={{ animationDelay: "1.6s" }} />
        </g>

        {/* input node */}
        <g className="animate-float">
          <circle cx="450" cy="60" r="26" fill="#0d1426" stroke="#22d3ee" strokeOpacity="0.7" />
          <text x="450" y="66" textAnchor="middle" fill="#a5f3fc" fontSize="13" fontFamily="monospace">IN</text>
        </g>

        {/* analysis hub */}
        <circle cx="450" cy="150" r="34" fill="#0d1426" stroke="#38bdf8" strokeOpacity="0.8">
          <animate attributeName="r" values="34;38;34" dur="3s" repeatCount="indefinite" />
        </circle>
        <text x="450" y="156" textAnchor="middle" fill="#bae6fd" fontSize="12" fontFamily="monospace">ANALYZE</text>

        {/* branches */}
        {[
          { x: 230, y: 250, label: "URL" },
          { x: 450, y: 250, label: "TEXT" },
          { x: 670, y: 250, label: "OCR" },
        ].map((n, i) => (
          <g key={n.label}>
            <circle cx={n.x} cy={n.y} r="24" fill="#0d1426" stroke="#818cf8" strokeOpacity="0.7">
              <animate attributeName="opacity" values="0.75;1;0.75" dur={`${2.2 + i * 0.3}s`} repeatCount="indefinite" />
            </circle>
            <text x={n.x} y={n.y + 5} textAnchor="middle" fill="#c7d2fe" fontSize="11" fontFamily="monospace">{n.label}</text>
          </g>
        ))}

        {/* correlate */}
        <circle cx="450" cy="360" r="30" fill="#0d1426" stroke="#22d3ee" strokeOpacity="0.8">
          <animate attributeName="r" values="30;34;30" dur="3.4s" repeatCount="indefinite" />
        </circle>
        <text x="450" y="366" textAnchor="middle" fill="#a5f3fc" fontSize="11" fontFamily="monospace">CORRELATE</text>

        {/* risk */}
        <circle cx="450" cy="460" r="28" fill="rgba(251,146,60,0.08)" stroke="#fb923c" strokeOpacity="0.75" />
        <text x="450" y="466" textAnchor="middle" fill="#fed7aa" fontSize="11" fontFamily="monospace">RISK</text>

        {/* report */}
        <circle cx="450" cy="550" r="26" fill="#0d1426" stroke="#34d399" strokeOpacity="0.8" />
        <text x="450" y="556" textAnchor="middle" fill="#a7f3d0" fontSize="11" fontFamily="monospace">REPORT</text>

        {/* drifting particles */}
        {[
          { cx: 180, cy: 90, d: "3s", o: 0.5 },
          { cx: 700, cy: 120, d: "4s", o: 0.4 },
          { cx: 320, cy: 320, d: "3.6s", o: 0.45 },
          { cx: 590, cy: 330, d: "4.4s", o: 0.4 },
          { cx: 260, cy: 480, d: "3.2s", o: 0.5 },
        ].map((p, i) => (
          <circle key={i} cx={p.cx} cy={p.cy} r="2" fill="#22d3ee" opacity={p.o}>
            <animate
              attributeName="cy"
              values={`${p.cy};${p.cy - 22};${p.cy}`}
              dur={p.d}
              repeatCount="indefinite"
            />
            <animate attributeName="opacity" values={`${p.o};0.1;${p.o}`} dur={p.d} repeatCount="indefinite" />
          </circle>
        ))}
      </svg>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Hero preview card: illustrative animated investigation              */
/* ------------------------------------------------------------------ */

const PREVIEW_STAGES = [
  "Evidence extracted",
  "URL analyzed",
  "Scam patterns detected",
  "Evidence correlated",
];

function LivePreviewCard() {
  const [stage, setStage] = useState(0);
  const [risk, setRisk] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setStage((s) => (s + 1) % (PREVIEW_STAGES.length + 1));
      setRisk((r) => Math.min(87, r + 21));
    }, 900);
    return () => clearInterval(interval);
  }, []);

  const running = stage < PREVIEW_STAGES.length;

  return (
    <div className="panel relative overflow-hidden shadow-glow-accent">
      <div className="flex items-center justify-between border-b border-base-700/60 px-5 py-3">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
          <Scan className="h-4 w-4 text-accent" aria-hidden />
          Live investigation
        </div>
        <span className="chip border-base-600/60 bg-base-800/50 text-[10px] text-slate-500">
          Illustrative preview
        </span>
      </div>

      <div className="space-y-4 px-5 py-5">
        <p className="rounded-lg border border-base-700/60 bg-base-925 px-3.5 py-3 font-mono text-[13px] leading-relaxed text-slate-300">
          “Your bank account will be suspended. Verify immediately using the attached link.”
        </p>

        <div className="space-y-2">
          {PREVIEW_STAGES.map((s, i) => {
            const done = i < stage;
            const active = i === stage && running;
            return (
              <div
                key={s}
                className={`flex items-center gap-2.5 text-sm transition-colors duration-300 ${
                  done ? "text-emerald-300" : active ? "text-slate-200" : "text-slate-600"
                }`}
              >
                {done ? (
                  <CheckCircle2 className="h-4 w-4" aria-hidden />
                ) : active ? (
                  <CircleDashed className="h-4 w-4 animate-spin text-accent" aria-hidden />
                ) : (
                  <CircleDashed className="h-4 w-4" aria-hidden />
                )}
                {s}
              </div>
            );
          })}
        </div>

        <div className="rounded-lg border border-base-700/60 bg-base-925 px-4 py-3.5">
          <div className="flex items-baseline justify-between">
            <span className="text-[11px] uppercase tracking-[0.14em] text-slate-500">Risk score</span>
            <span className="mono-tabular font-mono text-2xl font-bold text-orange-300">{risk}</span>
          </div>
          <div className="mt-2 h-2 overflow-hidden rounded-full bg-base-800">
            <div
              className="h-full rounded-full bg-gradient-to-r from-amber-400 to-orange-500 transition-all duration-700 ease-out"
              style={{ width: `${risk}%` }}
            />
          </div>
          <div className="mt-1.5 flex items-center justify-between text-[10px] text-slate-600">
            <span>0 — 100</span>
            <span className="font-semibold uppercase tracking-wide text-orange-300/80">HIGH</span>
          </div>
        </div>

        <Link
          href="/investigate"
          className="btn-primary w-full"
          onClick={(e) => e.stopPropagation()}
        >
          Start a real investigation <ArrowRight className="h-4 w-4" aria-hidden />
        </Link>
        <p className="text-center text-[10px] leading-relaxed text-slate-600">
          Animated product preview. Run a real case through the full engine on the dashboard.
        </p>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Sections                                                            */
/* ------------------------------------------------------------------ */

const FEATURES = [
  {
    icon: FileSearch,
    title: "Evidence extraction",
    body: "Pulls URLs, entities, amounts, OTPs, brand mentions and linguistic indicators out of raw messages.",
  },
  {
    icon: GitBranch,
    title: "Agentic investigation",
    body: "LangGraph orchestrates specialised branches — URL, text, OCR, entity and ML — as one typed workflow.",
  },
  {
    icon: Globe,
    title: "URL intelligence",
    body: "Detects lookalike domains, punycode and homoglyph impersonation, dangerous schemes and credential paths.",
  },
  {
    icon: Brain,
    title: "Machine learning",
    body: "A trained classifier contributes a probability signal — never the final verdict on its own.",
  },
  {
    icon: Layers,
    title: "Evidence correlation",
    body: "Independent indicators are correlated before scoring, so a strong signal isn't diluted by silent channels.",
  },
  {
    icon: Scale,
    title: "Deterministic risk",
    body: "A transparent 0–100 risk engine with per-signal contributors you can audit in the report.",
  },
  {
    icon: Radar,
    title: "Evidence sufficiency",
    body: "Distinguishes low risk from insufficient evidence — sparse input is never presented as verified safe.",
  },
  {
    icon: FileText,
    title: "Explainable reports",
    body: "Every verdict comes with the evidence, contributors, recommended actions and honest limitations.",
  },
];

const STAGES = [
  { icon: FileSearch, title: "Input", body: "Message, URLs and screenshots are captured and sanitised." },
  { icon: Scan, title: "Extract", body: "URLs, entities, signals and indicators are pulled from each source." },
  { icon: Cpu, title: "Analyze", body: "Parallel branches inspect URL structure, text language, entities and OCR text." },
  { icon: Network, title: "Correlate", body: "Evidence is weighted and cross-checked; failures never read as clean." },
  { icon: Zap, title: "Score", body: "The deterministic engine produces a 0–100 risk with per-signal impact." },
  { icon: Sparkles, title: "Explain", body: "A grounded explanation ties the verdict to the actual evidence found." },
  { icon: ShieldCheck, title: "Report", body: "An actionable, machine-readable investigation report is generated." },
];

const STACK_LAYERS = [
  {
    icon: Scale,
    title: "Deterministic risk engine",
    body: "Rules and weighted correlation produce the final 0–100 score. No black box.",
  },
  {
    icon: GitBranch,
    title: "LangGraph orchestration",
    body: "Typed state, conditional routing and parallel branches keep every step auditable.",
  },
  {
    icon: Brain,
    title: "Machine learning",
    body: "Feature-extracted classification adds a probability signal to the evidence pool.",
  },
  {
    icon: Radar,
    title: "Threat intelligence",
    body: "Normalised provider results (Google Safe Browsing, VirusTotal, or demo) merge into evidence.",
  },
  {
    icon: Layers,
    title: "Evidence correlation",
    body: "Signals are combined with quality weighting — one strong signal isn't drowned by silence.",
  },
  {
    icon: Sparkles,
    title: "Grounded LLM explanation",
    body: "An LLM (or deterministic fallback) writes reports from structured evidence only — it never decides risk.",
  },
];

const SECURITY_POINTS = [
  { icon: Lock, text: "No secrets in the frontend — API keys live server-side only." },
  { icon: Globe, text: "No arbitrary URL fetching — the engine analyzes structure, not remote content." },
  { icon: ShieldCheck, text: "Uploads are sniffed, size-capped and stored under random names." },
  { icon: Database, text: "Submitted content stays on your own deployment." },
];

const TECH_STACK = ["Python", "FastAPI", "LangGraph", "Next.js", "TypeScript", "scikit-learn", "PostgreSQL", "SQLite"];

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

export function LandingPage() {
  return (
    <div className="animate-fade-in">
      {/* HERO */}
      <section className="relative overflow-hidden">
        <HeroNetwork />
        <div className="relative mx-auto grid w-full max-w-7xl gap-12 px-4 pb-20 pt-16 sm:px-6 lg:grid-cols-[1.15fr_0.85fr] lg:items-center lg:pt-24">
          <div>
            <Reveal>
              <div className="inline-flex items-center gap-2 rounded-full border border-accent/25 bg-accent/[0.06] px-3.5 py-1.5 text-xs font-medium text-cyan-200">
                <ShieldCheck className="h-3.5 w-3.5 text-accent" aria-hidden />
                AI-POWERED CYBERSECURITY INVESTIGATION
              </div>
            </Reveal>
            <Reveal delay={80}>
              <h1 className="mt-5 text-4xl font-extrabold leading-[1.08] tracking-tight text-slate-50 sm:text-5xl lg:text-[3.4rem]">
                Investigate digital scams <span className="text-gradient">before they cost you.</span>
              </h1>
            </Reveal>
            <Reveal delay={160}>
              <p className="mt-5 max-w-xl text-base leading-relaxed text-slate-400 sm:text-lg">
                Detect phishing, impersonation, malicious URLs and suspicious communications with an
                evidence-driven AI investigation engine — not a chatbot with opinions.
              </p>
            </Reveal>
            <Reveal delay={240}>
              <div className="mt-8 flex flex-wrap items-center gap-3">
                <Link href="/investigate" className="btn-primary px-6 py-3 text-base">
                  <Scan className="h-4 w-4" aria-hidden /> Start investigation
                </Link>
                <Link href="#how-it-works" className="btn-ghost px-6 py-3 text-base">
                  View how it works <ChevronRight className="h-4 w-4" aria-hidden />
                </Link>
              </div>
            </Reveal>
            <Reveal delay={320}>
              <ul className="mt-8 flex flex-wrap gap-x-6 gap-y-2 text-xs text-slate-500">
                {["Evidence-based", "Deterministic risk", "AI-assisted", "No paid APIs required for demo mode"].map(
                  (t) => (
                    <li key={t} className="flex items-center gap-1.5">
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400/80" aria-hidden /> {t}
                    </li>
                  )
                )}
              </ul>
            </Reveal>
          </div>

          <Reveal delay={200} className="lg:justify-self-end lg:w-[420px]">
            <LivePreviewCard />
          </Reveal>
        </div>
      </section>

      {/* TRUST / CAPABILITIES */}
      <section className="relative border-t border-base-700/40">
        <div className="mx-auto w-full max-w-7xl px-4 py-20 sm:px-6">
          <Reveal>
            <div className="mx-auto max-w-2xl text-center">
              <div className="panel-title">Capabilities</div>
              <h2 className="mt-3 text-3xl font-bold tracking-tight text-slate-100 sm:text-4xl">
                Built for real investigations
              </h2>
              <p className="mt-4 text-sm leading-relaxed text-slate-400">
                Every capability feeds structured evidence into one deterministic risk engine — so the
                final verdict is always explainable.
              </p>
            </div>
          </Reveal>
          <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {FEATURES.map((f, i) => (
              <Reveal key={f.title} delay={i * 50}>
                <div className="panel panel-hover group h-full p-5">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-accent/25 bg-accent/[0.07] text-accent transition-colors group-hover:bg-accent/15">
                    <f.icon className="h-5 w-5" aria-hidden />
                  </div>
                  <div className="mt-4 font-mono text-[10px] uppercase tracking-[0.16em] text-slate-600">
                    0{i + 1}
                  </div>
                  <h3 className="mt-1 text-sm font-semibold text-slate-100">{f.title}</h3>
                  <p className="mt-2 text-[13px] leading-relaxed text-slate-500">{f.body}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section id="how-it-works" className="relative border-t border-base-700/40 bg-base-925/50">
        <div className="mx-auto w-full max-w-7xl px-4 py-20 sm:px-6">
          <Reveal>
            <div className="mx-auto max-w-2xl text-center">
              <div className="panel-title">Pipeline</div>
              <h2 className="mt-3 text-3xl font-bold tracking-tight text-slate-100 sm:text-4xl">
                How the investigation works
              </h2>
            </div>
          </Reveal>
          <div className="mt-12 grid gap-3 md:grid-cols-4 lg:grid-cols-7">
            {STAGES.map((s, i) => (
              <Reveal key={s.title} delay={i * 60}>
                <div className="panel panel-hover group relative h-full p-4 text-center">
                  <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-full border border-accent/25 bg-accent/[0.07] text-accent transition-transform group-hover:scale-110">
                    <s.icon className="h-5 w-5" aria-hidden />
                  </div>
                  <div className="mt-3 font-mono text-[10px] text-slate-600">STEP 0{i + 1}</div>
                  <h3 className="mt-0.5 text-sm font-semibold text-slate-100">{s.title}</h3>
                  <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">{s.body}</p>
                </div>
              </Reveal>
            ))}
          </div>
          <Reveal delay={200}>
            <p className="mt-8 text-center text-xs text-slate-600">
              Stages run server-side as one orchestrated LangGraph workflow — the frontend reflects real results, never staged claims.
            </p>
          </Reveal>
        </div>
      </section>

      {/* ENGINEERING / ARCHITECTURE */}
      <section className="relative border-t border-base-700/40">
        <div className="mx-auto w-full max-w-7xl px-4 py-20 sm:px-6">
          <Reveal>
            <div className="mx-auto max-w-2xl text-center">
              <div className="panel-title">Engineering</div>
              <h2 className="mt-3 text-3xl font-bold tracking-tight text-slate-100 sm:text-4xl">
                Built as an investigation system, not a chatbot
              </h2>
              <p className="mt-4 text-sm leading-relaxed text-slate-400">
                A layered stack where each stage is auditable and no single component decides the outcome.
              </p>
            </div>
          </Reveal>
          <div className="mt-12 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {STACK_LAYERS.map((l, i) => (
              <Reveal key={l.title} delay={i * 60}>
                <div className="panel panel-hover h-full p-5">
                  <div className="flex items-center gap-3">
                    <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-base-600/70 bg-base-800/60 text-accent">
                      <l.icon className="h-4.5 w-4.5" aria-hidden />
                    </span>
                    <h3 className="text-sm font-semibold text-slate-100">{l.title}</h3>
                  </div>
                  <p className="mt-3 text-[13px] leading-relaxed text-slate-500">{l.body}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* SECURITY */}
      <section className="relative border-t border-base-700/40 bg-base-925/50">
        <div className="mx-auto w-full max-w-7xl px-4 py-20 sm:px-6">
          <div className="grid gap-10 lg:grid-cols-[0.9fr_1.1fr] lg:items-center">
            <Reveal>
              <div className="panel-title">Security posture</div>
              <h2 className="mt-3 text-3xl font-bold tracking-tight text-slate-100">
                Defensive by default
              </h2>
              <p className="mt-4 max-w-md text-sm leading-relaxed text-slate-400">
                The tool is designed to investigate threats without introducing new ones — no secret
                leakage, no SSRF surface, no unsafe fetching.
              </p>
              <div className="mt-6 flex h-10 w-10 items-center justify-center rounded-full border border-emerald-400/30 bg-emerald-400/10 text-emerald-300">
                <Lock className="h-5 w-5" aria-hidden />
              </div>
            </Reveal>
            <div className="space-y-3">
              {SECURITY_POINTS.map((s, i) => (
                <Reveal key={s.text} delay={i * 70}>
                  <div className="flex items-start gap-3 rounded-xl border border-base-700/60 bg-base-900/70 px-4 py-3.5">
                    <s.icon className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400/90" aria-hidden />
                    <span className="text-sm text-slate-300">{s.text}</span>
                  </div>
                </Reveal>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* TECH STACK */}
      <section className="relative border-t border-base-700/40">
        <div className="mx-auto w-full max-w-7xl px-4 py-16 sm:px-6">
          <Reveal>
            <div className="flex flex-wrap items-center justify-between gap-6">
              <div>
                <div className="panel-title">Tech stack</div>
                <h2 className="mt-2 text-xl font-bold text-slate-100">Built on proven infrastructure</h2>
              </div>
              <div className="flex flex-wrap gap-2">
                {TECH_STACK.map((t) => (
                  <span
                    key={t}
                    className="rounded-lg border border-base-600/60 bg-base-900/60 px-3 py-1.5 font-mono text-xs text-slate-400"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* CTA */}
      <section className="relative border-t border-base-700/40">
        <div className="mx-auto w-full max-w-7xl px-4 py-20 sm:px-6">
          <Reveal>
            <div className="panel relative overflow-hidden p-10 text-center sm:p-14">
              <div className="absolute inset-0 bg-[radial-gradient(ellipse_60%_80%_at_50%_0%,rgba(34,211,238,0.1),transparent_70%)]" />
              <div className="relative">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-accent/30 bg-accent/10 text-accent">
                  <ShieldCheck className="h-6 w-6" aria-hidden />
                </div>
                <h2 className="mx-auto mt-5 max-w-xl text-3xl font-bold tracking-tight text-slate-100">
                  Ready to investigate something suspicious?
                </h2>
                <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-slate-400">
                  Analyze a message, URL or screenshot with the AI Digital Scam Investigator.
                </p>
                <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
                  <Link href="/investigate" className="btn-primary px-6 py-3 text-base">
                    <Scan className="h-4 w-4" aria-hidden /> Start investigation
                  </Link>
                  <Link href="/dashboard" className="btn-ghost px-6 py-3 text-base">
                    Open dashboard
                  </Link>
                </div>
              </div>
            </div>
          </Reveal>
        </div>
      </section>
    </div>
  );
}