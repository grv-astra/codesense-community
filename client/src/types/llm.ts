// Bring-your-own LLM (AI verification) — mirrors server/scanner/byo_llm/settings_service.py.
// The API key is write-only: it is sent on save but never present in any response.

export type LlmProviderId = 'openai_compatible' | 'azure_openai' | 'anthropic';

export interface LlmProviderInfo {
  id: LlmProviderId;
  label: string;
  needs_key: boolean;
  needs_api_version: boolean;
  default_api_version?: string;
}

export interface LlmSettings {
  enabled: boolean;
  provider: LlmProviderId;
  base_url: string;
  model: string;
  api_version: string;
  timeout_s: number;
  max_concurrency: number;
  key_set: boolean;
  /** Also have the LLM write mitigation advice (a second call per finding). */
  enrich_reports: boolean;
  /** `reports` = the consent also covers the mitigation data (rule name + analyzer message). */
  consent: { given: boolean; reports: boolean; host: string; at: string | null; by: string };
  last_test: { at: string | null; ok: boolean | null; error: string };
  updated_at: string | null;
  providers: LlmProviderInfo[];
  limits: { timeout_s: [number, number]; max_concurrency: [number, number] };
  disclosure: {
    sent: string[];
    /** Sent in addition, only while "Also write mitigation advice" is on. */
    sent_for_mitigation: string[];
    not_sent: string[];
    key_note: string;
    false_positive_min_confidence: number;
  };
}

export interface LlmSettingsUpdate {
  provider?: LlmProviderId;
  base_url?: string;
  model?: string;
  api_version?: string;
  timeout_s?: number;
  max_concurrency?: number;
  /** Only sent when the admin typed a new key; "" / absent keeps the saved one. */
  api_key?: string;
  clear_api_key?: boolean;
  enrich_reports?: boolean;
  enabled?: boolean;
  consent?: boolean;
}

export interface LlmTestResult {
  ok: boolean;
  latency_ms: number;
  error: string;
}

export type LlmState =
  | 'not_configured'
  | 'disabled'
  | 'needs_consent'
  | 'untested'
  | 'connected'
  | 'failing'
  | 'bundled';

export interface LlmStatus {
  state: LlmState;
  source: 'byo' | 'bundled' | 'none';
  provider: string;
  model: string;
  host: string;
  last_check_at: string | null;
  error: string;
}

/** `metrics.llm` as stored on a scan (see lsast_scanner / ByoBackend.metrics). */
export interface LlmScanMetrics {
  available: boolean;
  detail?: string;
  backend?: 'byo';
  provider?: string;
  model?: string;
  host?: string;
  calls?: number;
  failures?: number;
  retries?: number;
  verified?: number;
  unverified?: number;
  tokens_in?: number;
  tokens_out?: number;
  breaker_open?: boolean;
  breaker_reason?: string;
  /** Mitigation advice (step 7). Absent on scans from before it existed. */
  enrich_reports?: boolean;
  report_calls?: number;
  report_failures?: number;
  reports_written?: number;
  reports_skipped?: number;
  report_breaker_open?: boolean;
}
