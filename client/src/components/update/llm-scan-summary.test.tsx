import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import LlmScanSummary from './llm-scan-summary';

const text = () => screen.getByTestId('llm-scan-summary').textContent;

describe('LlmScanSummary', () => {
  it('reports who verified, counts, and usage for the user\'s own LLM', () => {
    render(<LlmScanSummary llm={{
      available: true, backend: 'byo', model: 'gpt-4o-mini', host: 'api.openai.com',
      verified: 7, unverified: 2, calls: 9, tokens_in: 1000, tokens_out: 200,
    }} />);
    expect(text()).toContain('Verified by gpt-4o-mini @ api.openai.com');
    expect(text()).toContain('7 verified, 2 unverified');
    expect(text()).toContain('9 model calls');
    expect(text()).toContain('1,200 tokens');
  });

  it('uses the singular for one call and omits tokens when none were reported', () => {
    render(<LlmScanSummary llm={{ available: true, backend: 'byo', model: 'm', host: 'h', verified: 1, unverified: 0, calls: 1 }} />);
    expect(text()).toContain('1 model call.');
    expect(text()).not.toContain('tokens');
  });

  it('counts mitigation calls and reports how many findings got advice', () => {
    render(<LlmScanSummary llm={{
      available: true, backend: 'byo', model: 'm', host: 'h', verified: 4, unverified: 0,
      calls: 4, enrich_reports: true, report_calls: 4, reports_written: 3, reports_skipped: 1,
      tokens_in: 3000, tokens_out: 900,
    }} />);
    expect(text()).toContain('Mitigation advice written for 3 findings; 1 kept the standard text.');
    expect(text()).toContain('8 model calls');             // verification + mitigation
    expect(text()).toContain('3,900 tokens');
  });

  it('is brief when every finding got advice, and handles a single one', () => {
    render(<LlmScanSummary llm={{
      available: true, backend: 'byo', model: 'm', host: 'h', verified: 1, unverified: 0,
      calls: 1, enrich_reports: true, report_calls: 1, reports_written: 1, reports_skipped: 0,
    }} />);
    expect(text()).toContain('Mitigation advice written for 1 finding.');
    expect(text()).not.toContain('standard text');
  });

  it('notes when mitigation writing stopped early', () => {
    render(<LlmScanSummary llm={{
      available: true, backend: 'byo', model: 'm', host: 'h', verified: 6, unverified: 0, calls: 6,
      enrich_reports: true, report_calls: 5, reports_written: 0, reports_skipped: 5, report_breaker_open: true,
    }} />);
    expect(text()).toContain('Mitigation writing stopped early');
  });

  it('says nothing about mitigation when it was off, or on scans from before it existed', () => {
    const { rerender } = render(<LlmScanSummary llm={{
      available: true, backend: 'byo', model: 'm', host: 'h', verified: 1, unverified: 0, calls: 1, enrich_reports: false,
    }} />);
    expect(text()).not.toContain('Mitigation');
    rerender(<LlmScanSummary llm={{ available: true, backend: 'byo', model: 'm', host: 'h', verified: 1, unverified: 0, calls: 1 }} />);
    expect(text()).not.toContain('Mitigation');
  });

  it('says so when the connection died mid-scan', () => {
    render(<LlmScanSummary llm={{
      available: true, backend: 'byo', model: 'm', host: 'h', verified: 1, unverified: 5,
      breaker_open: true, breaker_reason: 'The LLM rejected the API key (HTTP 401).',
    }} />);
    expect(text()).toContain('stopped working during the scan');
    expect(text()).toContain('kept unverified');
  });

  it('explains why AI was not used', () => {
    render(<LlmScanSummary llm={{ available: false, detail: 'Your LLM connection is not working: timed out.' }} />);
    expect(text()).toContain('was not used');
    expect(text()).toContain('timed out');
  });

  it('handles the bundled model and an empty reason', () => {
    const { rerender } = render(<LlmScanSummary llm={{ available: true, detail: 'ok' }} />);
    expect(text()).toBe('Verified by the bundled local model.');
    rerender(<LlmScanSummary llm={{ available: false }} />);
    expect(text()).toBe('AI verification was not used for this scan.');
  });
});
