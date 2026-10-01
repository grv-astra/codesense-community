export type Edition = 'community' | 'pro' | 'enterprise';

export interface EditionFeatures {
  llm_analysis: boolean; sbom_signing: boolean; license_compliance: boolean;
  api_access: boolean; incremental_scan: boolean; github_scan: boolean;
  sso: boolean; audit_log: boolean;
}
export interface EditionLimits {
  projects: number | null; code_scans_per_window: number | null;
  sbom_scans_per_window: number | null; window_days: number;
  max_codebase_mb: number | null; seats: number | null;
}
export interface EditionUsage {
  projects: number; code_scans_in_window: number;
  sbom_scans_in_window: number; seats: number;
}
export interface EditionStatus {
  edition: Edition; label: string; source: string; customer: string;
  issued_at: string; expires_at: string | null; model_tier: 'low' | 'mid' | 'high';
  features: EditionFeatures; limits: EditionLimits; usage: EditionUsage;
  warnings: string[];
}

// --- /api/editions/ : the full catalog for the /plans comparison page ---

export interface EditionCatalogEntry {
  edition: Edition;
  label: string;
  model_tier: 'low' | 'mid' | 'high';
  features: EditionFeatures;
  limits: EditionLimits;
}

export interface EditionsCatalogActive {
  edition: Edition;
  source: string;
  customer: string;
  expires_at: string | null;
  warnings: string[];
  usage: Partial<EditionUsage>;
}

export interface EditionsCatalog {
  feature_keys: (keyof EditionFeatures)[];
  limit_keys: (keyof EditionLimits)[];
  editions: EditionCatalogEntry[];
  active: EditionsCatalogActive;
}
