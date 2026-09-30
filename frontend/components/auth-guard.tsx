"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { isAuthenticated } from "@/lib/auth";
import { Skeleton } from "@/components/ui";

/**
 * Client-side gate for the authenticated application shell.
 *
 * The backend is the real authority — every data request is rejected with a
 * 401 without a valid token — this guard only avoids rendering an empty shell
 * and bounces visitors to the login page.  A 401 from any API call also routes
 * here (see `lib/api.ts`), so an expired session lands on /login automatically.
 */
export function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!isAuthenticated()) {
      router.replace("/login");
      return;
    }
    setReady(true);
  }, [router]);

  if (!ready) {
    return (
      <div className="mx-auto max-w-3xl space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-44 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
    );
  }

  return <>{children}</>;
}
