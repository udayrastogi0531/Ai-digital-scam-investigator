import Link from "next/link";
import { Logo } from "@/components/ui";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col bg-base-950">
      <header className="border-b border-base-700/40">
        <div className="mx-auto flex h-16 w-full max-w-7xl items-center px-4 sm:px-6">
          <Link href="/" className="flex items-center gap-3" aria-label="ScamIntelligence home">
            <Logo size={32} />
            <span className="font-mono text-sm font-bold tracking-tight text-slate-100">
              Scam<span className="text-accent">Intelligence</span>
            </span>
          </Link>
        </div>
      </header>
      <main className="flex flex-1 items-center justify-center px-4 py-12 sm:px-6">{children}</main>
      <footer className="border-t border-base-700/40">
        <div className="mx-auto w-full max-w-7xl px-4 py-5 text-[11px] text-slate-600 sm:px-6">
          Decision-support tool — findings are probabilistic, not conclusive.
        </div>
      </footer>
    </div>
  );
}
