"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Loader2, UserPlus } from "lucide-react";
import { ErrorBanner } from "@/components/ui";
import { register } from "@/lib/api";

export default function RegisterPage() {
  const router = useRouter();
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    setBusy(true);
    try {
      await register({
        email,
        password,
        display_name: displayName.trim() || undefined,
      });
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(false);
    }
  }

  return (
    <div className="panel w-full max-w-md p-6 sm:p-8">
      <h1 className="text-xl font-bold tracking-tight text-slate-100">Create an account</h1>
      <p className="mt-1 text-sm text-slate-500">
        Investigations you create are visible only to you.
      </p>

      {error && (
        <div className="mt-5">
          <ErrorBanner message={error} />
        </div>
      )}

      <form onSubmit={submit} className="mt-6 space-y-4">
        <div>
          <label htmlFor="display-name" className="field-label">
            Name (optional)
          </label>
          <input
            id="display-name"
            className="input"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Analyst name"
            maxLength={120}
          />
        </div>
        <div>
          <label htmlFor="email" className="field-label">
            Email
          </label>
          <input
            id="email"
            type="email"
            autoComplete="email"
            required
            className="input"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
          />
        </div>
        <div>
          <label htmlFor="password" className="field-label">
            Password
          </label>
          <input
            id="password"
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            className="input"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="At least 8 characters"
          />
          <p className="mt-1 text-[11px] text-slate-600">
            Minimum 8 characters. Stored only as a salted hash server-side.
          </p>
        </div>

        <button type="submit" className="btn-primary w-full" disabled={busy}>
          {busy ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> Creating account…
            </>
          ) : (
            <>
              <UserPlus className="h-4 w-4" aria-hidden /> Create account
            </>
          )}
        </button>
      </form>

      <p className="mt-6 text-center text-sm text-slate-500">
        Already registered?{" "}
        <Link href="/login" className="font-medium text-accent hover:underline">
          Sign in
        </Link>
      </p>
    </div>
  );
}
