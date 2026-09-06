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
  providers: {
    llm: { name: string; is_mock: boolean; model: string | null };
    threat_intel: { active: string[]; uses_mock: boolean };
    ml: { available: boolean; model: string };
    ocr: { provider: string; is_mock: boolean };
  };
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
