import { clearSession, getToken, setSession } from "./auth";
import type {
  AuthUser,
  DemoCase,
  HealthInfo,
  InvestigationSummary,
  InvestigationView,
  PaginatedInvestigations,
  TokenResponse,
} from "./types";

const BASE = "/api";

/** Thrown when the backend rejects a request because the session is missing or expired. */
export class UnauthorizedError extends Error {
  constructor(message = "Your session has expired. Please sign in again.") {
    super(message);
    this.name = "UnauthorizedError";
  }
}

function authHeaders(extra?: HeadersInit): Record<string, string> {
  const headers: Record<string, string> = {};
  if (extra) {
    new Headers(extra).forEach((value, key) => {
      headers[key] = value;
    });
  }
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

/**
 * A 401 means the stored session is no longer valid: drop it and send the user
 * to the login page.  Skipped for the auth endpoints themselves, where a 401
 * is an ordinary "wrong credentials" result.
 */
function handleUnauthorized(): never {
  clearSession();
  if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
    window.location.href = "/login";
  }
  throw new UnauthorizedError();
}

async function errorMessage(res: Response, fallback: string): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) {
      // FastAPI validation errors
      return body.detail.map((d: { msg?: string }) => d.msg ?? "invalid input").join("; ");
    }
    return JSON.stringify(body.detail ?? body);
  } catch {
    return fallback;
  }
}

async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: authHeaders(init.headers),
  });
  if (res.status === 401) handleUnauthorized();
  return res;
}

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(path, init);
  if (!res.ok) {
    throw new Error(await errorMessage(res, `Request failed (${res.status})`));
  }
  return (await res.json()) as T;
}

// --- auth -------------------------------------------------------------------

async function tokenFetch(path: string, body: unknown): Promise<TokenResponse> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(await errorMessage(res, `Request failed (${res.status})`));
  }
  const data = (await res.json()) as TokenResponse;
  setSession(data.access_token, data.user);
  return data;
}

export function register(input: {
  email: string;
  password: string;
  display_name?: string;
}): Promise<TokenResponse> {
  return tokenFetch("/auth/register", input);
}

export function login(input: { email: string; password: string }): Promise<TokenResponse> {
  return tokenFetch("/auth/login", input);
}

export async function getMe(): Promise<AuthUser> {
  return jsonFetch<AuthUser>("/auth/me");
}

export async function logout(): Promise<void> {
  try {
    await apiFetch("/auth/logout", { method: "POST" });
  } catch {
    // Best-effort: tokens are stateless, so a failed call must not block the
    // client from discarding its session locally.
  } finally {
    clearSession();
  }
}

// --- app data ---------------------------------------------------------------

export async function getHealth(): Promise<HealthInfo> {
  return jsonFetch<HealthInfo>("/health");
}

export async function listInvestigations(params: {
  page?: number;
  page_size?: number;
  search?: string;
  risk_level?: string;
  scam_type?: string;
  input_type?: string;
}): Promise<PaginatedInvestigations> {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return jsonFetch<PaginatedInvestigations>(`/investigations${suffix}`);
}

export async function getInvestigation(id: string): Promise<InvestigationView> {
  return jsonFetch<InvestigationView>(`/investigations/${id}`);
}

export async function deleteInvestigation(id: string): Promise<void> {
  const res = await apiFetch(`/investigations/${id}`, { method: "DELETE" });
  if (!res.ok && res.status !== 404) {
    throw new Error(await errorMessage(res, `Delete failed (${res.status})`));
  }
}

export interface SubmissionFields {
  text?: string;
  urls?: string[];
  title?: string;
  source_label?: string;
  image?: File | null;
}

/** Submit combined evidence (multipart) — returns the finished summary. */
export async function submitInvestigation(fields: SubmissionFields): Promise<InvestigationSummary> {
  const form = new FormData();
  if (fields.text) form.set("text", fields.text);
  if (fields.title) form.set("title", fields.title);
  if (fields.source_label) form.set("source_label", fields.source_label);
  for (const u of fields.urls ?? []) form.append("urls", u);
  if (fields.image) form.set("image", fields.image, fields.image.name);

  const res = await apiFetch("/investigations", { method: "POST", body: form });
  if (!res.ok) {
    throw new Error(await errorMessage(res, `Submission failed (${res.status})`));
  }
  return (await res.json()) as InvestigationSummary;
}

export async function runDemoCase(slug: string): Promise<InvestigationSummary> {
  const res = await apiFetch(`/demo/${slug}`, { method: "POST" });
  if (!res.ok) {
    throw new Error(await errorMessage(res, `Demo case failed (${res.status})`));
  }
  return (await res.json()) as InvestigationSummary;
}

export async function listDemoCases(): Promise<DemoCase[]> {
  const data = await jsonFetch<{ demo_mode: boolean; cases: DemoCase[] }>("/demo");
  return data.cases;
}
