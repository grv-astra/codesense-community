/** One observed sample of verification progress, taken each poll. */
export interface EtaSample {
  timestamp: number; // ms since epoch (Date.now())
  processed: number; // metrics.findings_progress.processed at that moment
}

export interface EtaResult {
  ready: boolean;
  label: string;
  ratePerMinute: number | null;
}

const MAX_SAMPLES = 8;
const MIN_SAMPLES_FOR_ESTIMATE = 3;

/**
 * Appends a sample, keeping only the most recent MAX_SAMPLES -- a rolling
 * window so the rate self-corrects to current throughput instead of drifting
 * stale over a long scan. See design doc decision 2 for why this isn't a
 * fixed constant or a whole-scan cumulative average.
 */
export function pushEtaSample(samples: EtaSample[], sample: EtaSample): EtaSample[] {
  const next = [...samples, sample];
  return next.length > MAX_SAMPLES ? next.slice(next.length - MAX_SAMPLES) : next;
}

/**
 * Rolling-rate ETA: average throughput (findings/ms) across the current
 * sample window, projected against what's left.
 */
export function computeEta(samples: EtaSample[], total: number): EtaResult {
  if (samples.length < MIN_SAMPLES_FOR_ESTIMATE || total <= 0) {
    return { ready: false, label: 'Estimating…', ratePerMinute: null };
  }
  const first = samples[0];
  const last = samples[samples.length - 1];
  const elapsedMs = last.timestamp - first.timestamp;
  const processedDelta = last.processed - first.processed;
  if (elapsedMs <= 0 || processedDelta <= 0) {
    return { ready: false, label: 'Estimating…', ratePerMinute: null };
  }
  const ratePerMs = processedDelta / elapsedMs;
  const ratePerMinute = ratePerMs * 60000;
  const remaining = Math.max(0, total - last.processed);
  const remainingMinutes = Math.round(remaining / ratePerMs / 60000);
  const label = remainingMinutes < 1
    ? `<1 min left · ${ratePerMinute.toFixed(1)}/min avg`
    : `~${remainingMinutes} min left · ${ratePerMinute.toFixed(1)}/min avg`;
  return { ready: true, label, ratePerMinute };
}
