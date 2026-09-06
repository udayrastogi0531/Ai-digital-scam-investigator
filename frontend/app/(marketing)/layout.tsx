import Link from "next/link";
import { BookOpen, FileJson, Scan, ShieldCheck } from "lucide-react";

function GithubIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="currentColor" aria-hidden>
      <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.55v-2.15c-3.2.7-3.87-1.36-3.87-1.36-.52-1.33-1.28-1.68-1.28-1.68-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.19 1.76 1.19 1.03 1.75 2.69 1.25 3.34.95.1-.74.4-1.25.72-1.53-2.55-.29-5.23-1.28-5.23-5.68 0-1.25.45-2.28 1.19-3.08-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11.1 11.1 0 0 1 5.78 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.8 1.19 1.83 1.19 3.08 0 4.41-2.69 5.38-5.25 5.67.41.35.77 1.04.77 2.1v3.12c0 .3.21.66.8.55A11.5 11.5 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5z" />
    </svg>
  );
}
import { Logo } from "@/components/ui";

export default function MarketingLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="relative z-50 border-b border-base-700/30 bg-base-950/60 backdrop-blur-md">
        <div className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between gap-4 px-4 sm:px-6">
          <Link href="/" className="flex items-center gap-3" aria-label="ScamIntelligence home">
            <Logo size={32} />
            <span className="font-mono text-sm font-bold tracking-tight text-slate-100">
              Scam<span className="text-accent">Intelligence</span>
            </span>
          </Link>
          <nav className="hidden items-center gap-1 md:flex" aria-label="Primary">
            <Link href="/dashboard" className="nav-link">Dashboard</Link>
            <Link href="/investigate" className="nav-link">Investigate</Link>
            <Link href="/history" className="nav-link">History</Link>
          </nav>
          <div className="hidden md:block">
            <Link href="/investigate" className="btn-primary btn-sm">
              <Scan className="h-3.5 w-3.5" aria-hidden /> Start investigation
            </Link>
          </div>
        </div>
      </header>

      <main className="flex-1">{children}</main>

      <footer className="border-t border-base-700/40 bg-base-925/60">
        <div className="mx-auto w-full max-w-7xl px-4 py-10 sm:px-6">
          <div className="grid gap-8 md:grid-cols-3">
            <div>
              <div className="flex items-center gap-2.5">
                <Logo size={28} />
                <span className="font-mono text-sm font-bold text-slate-100">
                  Scam<span className="text-accent">Intelligence</span>
                </span>
              </div>
              <p className="mt-3 max-w-xs text-xs leading-relaxed text-slate-500">
                Agentic cybersecurity investigation platform for phishing, impersonation and malicious URLs.
              </p>
            </div>
            <div>
              <div className="panel-title">Product</div>
              <ul className="mt-3 space-y-2 text-sm">
                <li><Link href="/dashboard" className="text-slate-400 transition hover:text-accent">Dashboard</Link></li>
                <li><Link href="/investigate" className="text-slate-400 transition hover:text-accent">New investigation</Link></li>
                <li><Link href="/history" className="text-slate-400 transition hover:text-accent">History</Link></li>
              </ul>
            </div>
            <div>
              <div className="panel-title">Resources</div>
              <ul className="mt-3 space-y-2 text-sm">
                <li>
                  <a href="https://github.com/udayrastogi0531/Ai-digital-scam-investigator" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-slate-400 transition hover:text-accent">
                    <GithubIcon /> GitHub
                  </a>
                </li>
                <li>
                  <a href="https://github.com/udayrastogi0531/Ai-digital-scam-investigator#readme" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-slate-400 transition hover:text-accent">
                    <BookOpen className="h-3.5 w-3.5" aria-hidden /> Documentation
                  </a>
                </li>
                <li>
                  <a href="http://localhost:8000/docs" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-slate-400 transition hover:text-accent">
                    <FileJson className="h-3.5 w-3.5" aria-hidden /> API
                  </a>
                </li>
              </ul>
            </div>
          </div>
          <div className="mt-8 flex flex-col items-start justify-between gap-2 border-t border-base-700/40 pt-5 text-[11px] text-slate-600 sm:flex-row sm:items-center">
            <span className="flex items-center gap-1.5">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-400/70" aria-hidden />
              Built with Python · FastAPI · LangGraph · Next.js · TypeScript · scikit-learn · PostgreSQL
            </span>
            <span>Decision-support tool — findings are probabilistic, not conclusive.</span>
          </div>
        </div>
      </footer>
    </div>
  );
}