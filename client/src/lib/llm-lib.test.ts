import { describe, expect, it } from 'vitest';
import { LLM_PRESETS, detectPreset, isLoopbackUrl } from './llm-presets';
import { buildUpdate, formFromSettings, hostOf, needsConsent, reportsUnconfirmed } from './llm-form';
import { describeLlmStatus } from './llm-status';
import type { LlmSettings, LlmStatus } from '@/types/llm';

const settings = (over: Partial<LlmSettings> = {}): LlmSettings => ({
  enabled: false, provider: 'openai_compatible', base_url: 'https://api.openai.com/v1', model: 'gpt-4o-mini',
  api_version: '', timeout_s: 60, max_concurrency: 2, key_set: true,
  enrich_reports: true,
  consent: { given: false, reports: false, host: '', at: null, by: '' },
  last_test: { at: null, ok: null, error: '' }, updated_at: null,
  providers: [], limits: { timeout_s: [10, 300], max_concurrency: [1, 8] },
  disclosure: { sent: [], sent_for_mitigation: [], not_sent: [], key_note: '', false_positive_min_confidence: 0.8 },
  ...over,
});

describe('presets', () => {
  it('detects a preset from provider + url, ignoring case and trailing slashes', () => {
    expect(detectPreset('openai_compatible', 'https://API.openai.com/v1/').id).toBe('openai');
    expect(detectPreset('anthropic', 'https://api.anthropic.com').id).toBe('anthropic');
    expect(detectPreset('openai_compatible', 'http://localhost:11434/v1').id).toBe('ollama');
  });

  it('falls back to custom for anything else, and the same URL under another provider', () => {
    expect(detectPreset('openai_compatible', 'https://llm.corp.example/v1').id).toBe('custom');
    expect(detectPreset('azure_openai', 'https://api.openai.com/v1').id).toBe('custom');
    expect(detectPreset('openai_compatible', '').id).toBe('custom');
  });

  it('has unique ids and a custom entry', () => {
    const ids = LLM_PRESETS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toContain('custom');
  });

  it('knows which URLs stay on this machine', () => {
    for (const u of ['http://localhost:11434/v1', 'http://127.0.0.1:8000', 'http://[::1]:1234/v1']) {
      expect(isLoopbackUrl(u)).toBe(true);
    }
    for (const u of ['https://api.openai.com/v1', 'http://192.168.1.5:8000', 'not a url', '']) {
      expect(isLoopbackUrl(u)).toBe(false);
    }
  });
});

describe('form <-> request', () => {
  it('never puts a key into the form from saved settings', () => {
    const f = formFromSettings(settings());
    expect(f.api_key).toBe('');
    expect(JSON.stringify(f)).not.toMatch(/sk-/);
  });

  it('omits api_key unless one was typed, and trims', () => {
    const f = formFromSettings(settings());
    expect(buildUpdate(f)).not.toHaveProperty('api_key');
    expect(buildUpdate({ ...f, api_key: '  sk-new  ' }).api_key).toBe('sk-new');
    expect(buildUpdate({ ...f, api_key: '   ' })).not.toHaveProperty('api_key');
  });

  it('sends numbers as numbers and api_version only for Azure', () => {
    const f = formFromSettings(settings({ timeout_s: 90, max_concurrency: 3 }));
    expect(buildUpdate(f)).toMatchObject({ timeout_s: 90, max_concurrency: 3 });
    expect(buildUpdate(f)).not.toHaveProperty('api_version');
    expect(buildUpdate({ ...f, provider: 'azure_openai', api_version: ' 2024-10-21 ' }).api_version).toBe('2024-10-21');
  });

  it('always sends the mitigation-advice switch, defaulting to what is saved', () => {
    expect(buildUpdate(formFromSettings(settings())).enrich_reports).toBe(true);
    expect(buildUpdate(formFromSettings(settings({ enrich_reports: false }))).enrich_reports).toBe(false);
  });

  it('extracts host[:port]', () => {
    expect(hostOf('https://api.openai.com/v1')).toBe('api.openai.com');
    expect(hostOf('http://localhost:11434/v1')).toBe('localhost:11434');
    expect(hostOf('nope')).toBe('');
  });
});

describe('consent rules', () => {
  const given = { given: true, reports: true, host: 'api.openai.com', at: null, by: 'admin' };
  const form = (s: LlmSettings, over: object = {}) => ({ ...formFromSettings(s), ...over });

  it('turning off never needs consent', () => {
    const s = settings();
    expect(needsConsent(s, form(s), false)).toBe(false);
  });

  it('turning on needs consent when nothing is confirmed', () => {
    const s = settings();
    expect(needsConsent(s, form(s), true)).toBe(true);
  });

  it('turning on needs no consent when verification and advice are both covered', () => {
    const s = settings({ consent: given });
    expect(needsConsent(s, form(s), true)).toBe(false);
  });

  it('turning on needs consent again when the host was edited', () => {
    const s = settings({ consent: given });
    expect(needsConsent(s, form(s, { base_url: 'https://llm.other.example/v1' }), true)).toBe(true);
  });

  it('advice on but not covered needs consent; advice off does not', () => {
    const s = settings({ consent: { ...given, reports: false } });
    expect(needsConsent(s, form(s), true)).toBe(true);
    expect(needsConsent(s, form(s, { enrich_reports: false }), true)).toBe(false);
  });

  it('flags an enabled connection whose consent predates the advice switch', () => {
    const s = settings({ enabled: true, consent: { ...given, reports: false } });
    expect(reportsUnconfirmed(s, form(s))).toBe(true);
    expect(reportsUnconfirmed(s, form(s, { enrich_reports: false }))).toBe(false);
    expect(reportsUnconfirmed(s, form(s, { base_url: 'https://llm.other.example/v1' }))).toBe(false); // host change turns it off instead
  });

  it('does not flag a covered, a disabled, or an unconsented connection', () => {
    const covered = settings({ enabled: true, consent: given });
    expect(reportsUnconfirmed(covered, form(covered))).toBe(false);
    const off = settings({ enabled: false, consent: { ...given, reports: false } });
    expect(reportsUnconfirmed(off, form(off))).toBe(false);
    const none = settings({ enabled: true });
    expect(reportsUnconfirmed(none, form(none))).toBe(false);
  });
});

describe('describeLlmStatus', () => {
  const st = (over: Partial<LlmStatus>): LlmStatus => ({
    state: 'not_configured', source: 'none', provider: '', model: '', host: '', last_check_at: null, error: '', ...over,
  });

  it('says every state in words, not just colour', () => {
    const labels = (['not_configured', 'disabled', 'needs_consent', 'untested', 'connected', 'failing', 'bundled'] as const)
      .map((state) => describeLlmStatus(st({ state })).label);
    expect(new Set(labels).size).toBe(7);
    labels.forEach((l) => expect(l).toMatch(/^AI verification: /));
  });

  it('maps tones', () => {
    expect(describeLlmStatus(st({ state: 'connected' })).tone).toBe('good');
    expect(describeLlmStatus(st({ state: 'failing', error: 'bad key' })).tone).toBe('bad');
    expect(describeLlmStatus(st({ state: 'untested' })).tone).toBe('warn');
    expect(describeLlmStatus(st({ state: 'not_configured' })).tone).toBe('neutral');
  });

  it('puts the target and the error in the hint', () => {
    const v = describeLlmStatus(st({ state: 'failing', model: 'gpt-4o-mini', host: 'api.openai.com', error: 'rejected the API key' }));
    expect(v.hint).toContain('gpt-4o-mini @ api.openai.com');
    expect(v.hint).toContain('rejected the API key');
  });
});
