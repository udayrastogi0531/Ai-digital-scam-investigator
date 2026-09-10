// Mirrors of the backend Pydantic schemas (app/schemas/*.py).

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Severity = "low" | "medium" | "high" | "critical" | "info";

export interface RiskContributor {
  name: string;
  impact: number;
  detail?: string | null;
  evidence_sources: string[];
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  confidence: number;
  contributors: RiskContributor[];
  weights: Record<string, number>;
  method: string;
  evidence_sufficiency?: string | null; // INSUFFICIENT | PARTIAL | SUFFICIENT
}

export interface ScamClassification {
  primary: string;
  alternatives: string[];
  confidence: number;
  method: string;
  rationale?: string | null;
}

export interface EvidenceSignal {
  source: string;
  signal: string;
  severity: Severity;
  confidence: number;
  description?: string | null;
  detail: Record<string, unknown>;
}

export interface ExtractedEntity {
  entity_type: string;
  value: string;
  context?: string | null;
  metadata: Record<string, unknown>;
}

export interface ExtractedEntities {
  urls: ExtractedEntity[];
  emails: ExtractedEntity[];
  phones: ExtractedEntity[];
  companies: ExtractedEntity[];
  banks: ExtractedEntity[];
  organizations: ExtractedEntity[];
  amounts: ExtractedEntity[];
  dates: ExtractedEntity[];
  other: ExtractedEntity[];
}

export interface ReportSection {
  title: string;
  content: string;
  kind: string;
}

export interface InvestigationReport {
  summary: string;
  likely_objective?: string | null;
  objective_confidence?: string;
  recommendations: string[];
  suspicious_indicators: Array<Record<string, unknown>>;
  limitations?: string | null;
  sections: ReportSection[];
  provider: string;
  model?: string | null;
}

export interface MLPrediction {
  probability_scam: number;
  label: string;
  model: string;
  is_mock: boolean;
}

export interface TimelineEntry {
  stage: string;
  label: string;
  duration_ms?: number;
  at?: string | null;
}

export interface InvestigationSummary {
  investigation_id: string;
  title: string;
  status: string;
  input_types: string[];
  risk: RiskAssessment | null;
  scam_type: ScamClassification | null;
  entities: ExtractedEntities | null;
  evidence: EvidenceSignal[];
  report: InvestigationReport | null;
  ml?: MLPrediction | null;
  timeline: TimelineEntry[];
  created_at?: string | null;
  warnings: string[];
}

export interface InvestigationView extends InvestigationSummary {
  processing_metadata: Record<string, unknown>;
  analyses: Array<Record<string, unknown>>;
}

export interface InvestigationListItem {
  id: string;
  title: string;
  status: string;
  risk_score?: number | null;
  risk_level?: RiskLevel | null;
  scam_type?: string | null;
  input_types: string[];
  evidence_sufficiency?: string | null; // INSUFFICIENT | PARTIAL | SUFFICIENT
  created_at?: string | null;
}

export interface PaginatedInvestigations {
  items: InvestigationListItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface DemoCase {
  slug: string;
  title: string;
}

export interface HealthInfo {
  status: string;
  app?: string;
  version?: string;
  database?: string;
  providers: {
    llm: { name: string; is_mock: boolean; model: string | null };
    threat_intel: { active: string[]; uses_mock: boolean };
    ml: { available: boolean; model: string };
    ocr: { provider: string; is_mock: boolean };
  };
}

export interface ProviderStatusRow {
  label: string;
  detail: string;
  /** Hollow vs filled status dot — filled = operational/connected. */
  ok: boolean;
  /** Whether the component is an optional external provider that is not configured. */
  mock: boolean;
  /** Extra sub-detail (e.g. model name, provider names). */
  sub?: string | null;
}

/**
 * Map a health payload to the status rows shown across the app shell /
 * dashboard.  Status is per-component and never hardcoded: it is derived
 * from the live `/api/health` response.  Optional providers that are not
 * configured are shown as “Not configured” — never as live, and never as
 * a product-wide “demo mode”.
 */
export function healthRows(h: HealthInfo): ProviderStatusRow[] {
  const ti = h.providers.threat_intel;
  return [
    {
      label: "API",
      detail: h.status === "ok" ? "Operational" : h.status,
      ok: h.status === "ok",
      mock: false,
      sub: "API layer",
    },
    {
      label: "Database",
      detail: h.database ?? "Connected",
      ok: h.status === "ok",
      mock: false,
      sub: "Investigation store",
    },
    {
      label: "ML Engine",
      detail: h.providers.ml.available ? "Active" : "Not loaded",
      ok: h.providers.ml.available,
      mock: false,
      sub: h.providers.ml.available ? h.providers.ml.model : null,
    },
    {
      label: "Rule Engine",
      detail: "Active",
      ok: true,
      mock: false,
      sub: "Deterministic patterns",
    },
    {
      label: "OCR",
      detail: h.providers.ocr.is_mock ? "Not configured" : "Local",
      ok: !h.providers.ocr.is_mock,
      mock: h.providers.ocr.is_mock,
      sub: h.providers.ocr.is_mock ? "Local engine required" : h.providers.ocr.provider,
    },
    {
      label: "LLM",
      detail: h.providers.llm.is_mock ? "Not configured" : "Connected",
      ok: !h.providers.llm.is_mock,
      mock: h.providers.llm.is_mock,
      sub: h.providers.llm.is_mock ? "Deterministic engine active" : h.providers.llm.model,
    },
    {
      label: "Threat Intelligence",
      detail: ti.uses_mock || ti.active.length === 0 ? "Not configured" : "Connected",
      ok: !ti.uses_mock && ti.active.length > 0,
      mock: ti.uses_mock,
      sub: ti.uses_mock || ti.active.length === 0 ? "External lookup optional" : ti.active.join(", "),
    },
  ];
}

/** Overall system state used by the shell pill: core services are API + DB. */
export function systemState(h: HealthInfo | null): { label: string; ok: boolean; detail: string } {
  if (!h) return { label: "Offline", ok: false, detail: "API unreachable" };
  if (h.status === "ok") return { label: "Operational", ok: true, detail: h.database ?? "Connected" };
  return { label: "Degraded", ok: false, detail: h.status };
}

export const RISK_META: Record<RiskLevel, { hex: string; soft: string; text: string; ring: string; label: string }> = {
  LOW: {
    hex: "#34d399",
    soft: "bg-emerald-500/10",
    text: "text-emerald-300",
    ring: "ring-emerald-400/30",
    label: "Low risk",
  },
  MEDIUM: {
    hex: "#fbbf24",
    soft: "bg-amber-500/10",
    text: "text-amber-300",
    ring: "ring-amber-400/30",
    label: "Medium risk",
  },
  HIGH: {
    hex: "#fb923c",
    soft: "bg-orange-500/10",
    text: "text-orange-300",
    ring: "ring-orange-400/30",
    label: "High risk",
  },
  CRITICAL: {
    hex: "#f87171",
    soft: "bg-red-500/10",
    text: "text-red-300",
    ring: "ring-red-400/40",
    label: "Critical risk",
  },
};

export function riskMeta(level: RiskLevel | null | undefined) {
  if (level && RISK_META[level]) return RISK_META[level];
  return { hex: "#475569", soft: "bg-slate-500/10", text: "text-slate-400", ring: "ring-slate-500/30", label: "Unknown" };
}

export function formatDate(iso?: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

export function formatDay(iso?: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString();
}

export const CATEGORY_LABELS: Record<string, string> = {
  banking_scam: "Banking scam",
  phishing: "Phishing",
  job_scam: "Job scam",
  investment_scam: "Investment scam",
  payment_scam: "Payment scam",
  romance_scam: "Romance scam",
  tech_support: "Tech-support scam",
  impersonation: "Impersonation",
  delivery_scam: "Delivery / package scam",
  lottery_scam: "Lottery / prize scam",
  account_takeover: "Account takeover",
  identity_theft: "Identity theft",
  advance_fee: "Advance-fee scam",
  crypto_scam: "Cryptocurrency scam",
  unknown: "Unclear / no pattern",
  other: "Other",
};

export function categoryLabel(key: string): string {
  return CATEGORY_LABELS[key] ?? key.replace(/_/g, " ");
}

export const RISK_COLORS: Record<RiskLevel, { text: string; bg: string; ring: string; hex: string }> = {
  LOW: { text: "text-emerald-300", bg: "bg-emerald-500/10", ring: "ring-emerald-400/30", hex: "#34d399" },
  MEDIUM: { text: "text-amber-300", bg: "bg-amber-500/10", ring: "ring-amber-400/30", hex: "#fbbf24" },
  HIGH: { text: "text-orange-300", bg: "bg-orange-500/10", ring: "ring-orange-400/30", hex: "#fb923c" },
  CRITICAL: { text: "text-red-300", bg: "bg-red-500/10", ring: "ring-red-400/40", hex: "#f87171" },
};

export const SEVERITY_STYLE: Record<Severity, string> = {
  info: "border-slate-600/50",
  low: "border-emerald-500/40",
  medium: "border-amber-500/40",
  high: "border-orange-500/50",
  critical: "border-red-500/60",
};
