import type {
  DemoCase,
  HealthInfo,
  InvestigationSummary,
  InvestigationView,
  PaginatedInvestigations,
} from "./types";

const BASE = "/api";

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init);
  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      message = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      /* non-JSON error body */
    }
    throw new Error(message);
  }
  return (await res.json()) as T;
}

export async function getHealth(): Promise<HealthInfo> {
  return jsonFetch<HealthInfo>("/health");
}

export async function listInvestigations(params: {
  page?: number;
  page_size?: number;
  search?: string;
  risk_level?: string;
  scam_type?: string;
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
  const res = await fetch(`${BASE}/investigations/${id}`, { method: "DELETE" });
  if (!res.ok && res.status !== 404) {
    throw new Error(`Delete failed (${res.status})`);
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

  const res = await fetch(`${BASE}/investigations`, { method: "POST", body: form });
  if (!res.ok) {
    let message = `Submission failed (${res.status})`;
    try {
      const body = await res.json();
      message = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* ignore */
    }
    throw new Error(message);
  }
  return (await res.json()) as InvestigationSummary;
}

export async function runDemoCase(slug: string): Promise<InvestigationSummary> {
  const res = await fetch(`${BASE}/demo/${slug}`, { method: "POST" });
  if (!res.ok) {
    throw new Error(`Demo case failed (${res.status})`);
  }
  return (await res.json()) as InvestigationSummary;
}

export async function listDemoCases(): Promise<DemoCase[]> {
  const data = await jsonFetch<{ demo_mode: boolean; cases: DemoCase[] }>("/demo");
  return data.cases;
}
