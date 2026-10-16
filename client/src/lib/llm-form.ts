import { detectPreset } from '@/lib/llm-presets';
import type { LlmProviderId, LlmSettings, LlmSettingsUpdate } from '@/types/llm';

export interface AiFormState {
  presetId: string;
  provider: LlmProviderId;
  base_url: string;
  model: string;
  api_version: string;
  timeout_s: string;
  max_concurrency: string;
  enrich_reports: boolean;
  api_key: string;     // write-only: only ever holds what the admin just typed
}

export function formFromSettings(s: LlmSettings): AiFormState {
  return {
    presetId: detectPreset(s.provider, s.base_url).id,
    provider: s.provider,
    base_url: s.base_url,
    model: s.model,
    api_version: s.api_version,
    timeout_s: String(s.timeout_s),
    max_concurrency: String(s.max_concurrency),
    enrich_reports: s.enrich_reports,
    api_key: '',
  };
}

/** The request body for save / test. The key is included only if one was typed. */
export function buildUpdate(f: AiFormState): LlmSettingsUpdate {
  const body: LlmSettingsUpdate = {
    provider: f.provider,
    base_url: f.base_url.trim(),
    model: f.model.trim(),
    timeout_s: Number(f.timeout_s),
    max_concurrency: Number(f.max_concurrency),
    enrich_reports: f.enrich_reports,
  };
  if (f.provider === 'azure_openai') body.api_version = f.api_version.trim();
  if (f.api_key.trim()) body.api_key = f.api_key.trim();
  return body;
}

export function hostOf(url: string): string {
  try {
    const u = new URL(url);
    return u.port ? `${u.hostname}:${u.port}` : u.hostname;
  } catch {
    return '';
  }
}

function hostChanged(s: LlmSettings, f: AiFormState): boolean {
  const saved = hostOf(s.base_url);
  return !!saved && hostOf(f.base_url) !== saved;
}

/** Turning verification ON must show the consent dialog first when nothing is confirmed for
 * this host yet, the host was edited, or mitigation advice is on but its extra data (rule name
 * + analyzer message) is not covered by the consent already given. */
export function needsConsent(s: LlmSettings, f: AiFormState, wantEnabled: boolean): boolean {
  if (!wantEnabled) return false;
  if (!s.consent.given || hostChanged(s, f)) return true;
  return f.enrich_reports && !s.consent.reports;
}

/** An enabled connection whose existing consent predates (or excluded) mitigation advice that the
 * form now has switched on: scans keep verifying but write no advice until the admin confirms. */
export function reportsUnconfirmed(s: LlmSettings, f: AiFormState): boolean {
  return s.enabled && s.consent.given && !hostChanged(s, f) && f.enrich_reports && !s.consent.reports;
}
