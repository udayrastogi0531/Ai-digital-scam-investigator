// Client-side session storage for the access token.
//
// The backend issues a stateless JWT; the browser keeps it and sends it as a
// bearer token.  No secret ever reaches the browser — `NEXT_PUBLIC_*` is not
// used for anything sensitive, and the API origin is proxied same-origin so
// there is no CORS/credential sprawl.

export const TOKEN_KEY = "scamintel.access_token";
export const USER_KEY = "scamintel.user";

export interface StoredUser {
  id: string;
  email: string;
  display_name?: string | null;
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function getStoredUser(): StoredUser | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(USER_KEY);
    return raw ? (JSON.parse(raw) as StoredUser) : null;
  } catch {
    return null;
  }
}

export function setSession(token: string, user: StoredUser): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(TOKEN_KEY, token);
  window.localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearSession(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(USER_KEY);
}

export function isAuthenticated(): boolean {
  return Boolean(getToken());
}
