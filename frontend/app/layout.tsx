import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "AI Digital Scam Investigator",
  description:
    "Agentic investigation engine for suspicious emails, messages, URLs and screenshots.",
};

function NavLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      className="rounded-md px-3 py-1.5 text-sm font-medium text-slate-300 transition hover:bg-base-800 hover:text-accent"
    >
      {children}
    </Link>
  );
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <header className="sticky top-0 z-20 border-b border-base-700/80 bg-base-950/90 backdrop-blur">
          <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4">
            <Link href="/" className="flex items-center gap-2.5">
              <span className="flex h-7 w-7 items-center justify-center rounded border border-accent/40 bg-accent/10 text-accent">
                <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z" />
                  <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </span>
              <span className="font-mono text-sm font-bold tracking-tight text-slate-100">
                Scam<span className="text-accent">Intelligence</span>
              </span>
            </Link>
            <nav className="flex items-center gap-1">
              <NavLink href="/">Dashboard</NavLink>
              <NavLink href="/investigate">New investigation</NavLink>
              <NavLink href="/history">History</NavLink>
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-4 py-6">{children}</main>
        <footer className="mx-auto max-w-6xl px-4 pb-8 pt-4 text-xs text-slate-600">
          Decision-support tool — findings are probabilistic, not conclusive. Submitted content stays on your
          own deployment.
        </footer>
      </body>
    </html>
  );
}
