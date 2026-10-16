import type { LlmScanMetrics } from '@/types/llm';

/** One-paragraph account of how this scan's findings were (or were not) AI-verified. */
export default function LlmScanSummary({ llm }: { llm: LlmScanMetrics }) {
  let body: string;
  if (!llm.available) {
    body = llm.detail
      ? `AI verification was not used for this scan: ${llm.detail}`
      : 'AI verification was not used for this scan.';
  } else if (llm.backend === 'byo') {
    const target = [llm.model, llm.host && `@ ${llm.host}`].filter(Boolean).join(' ');
    const verified = llm.verified ?? 0;
    const unverified = llm.unverified ?? 0;
    body = `Verified by ${target}: ${verified} verified, ${unverified} unverified (kept for your review).`;
    if (llm.enrich_reports) {
      const written = llm.reports_written ?? 0;
      const standard = llm.reports_skipped ?? 0;      // failed or unusable replies: finding keeps the standard text
      body += ` Mitigation advice written for ${written} finding${written === 1 ? '' : 's'}`;
      body += standard ? `; ${standard} kept the standard text.` : '.';
      if (llm.report_breaker_open) body += ' Mitigation writing stopped early after repeated errors.';
    }
    if (llm.calls !== undefined) {
      const total = llm.calls + (llm.report_calls ?? 0);
      const tokens = (llm.tokens_in ?? 0) + (llm.tokens_out ?? 0);
      body += ` ${total} model call${total === 1 ? '' : 's'}${tokens ? `, about ${tokens.toLocaleString()} tokens` : ''}.`;
    }
    if (llm.breaker_open) {
      body += ` The connection stopped working during the scan${llm.breaker_reason ? ` (${llm.breaker_reason})` : ''}, so the remaining findings were kept unverified.`;
    }
  } else {
    body = 'Verified by the bundled local model.';
  }

  return (
    <p className="mt-3 text-sm text-gray-600 dark:text-gray-400" data-testid="llm-scan-summary">
      {body}
    </p>
  );
}
