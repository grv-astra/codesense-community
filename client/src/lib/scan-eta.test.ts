import { describe, test, expect } from 'vitest';
import { pushEtaSample, computeEta, type EtaSample } from './scan-eta';

describe('pushEtaSample', () => {
  test('keeps only the most recent 8 samples', () => {
    let samples: EtaSample[] = [];
    for (let i = 0; i < 12; i++) {
      samples = pushEtaSample(samples, { timestamp: i * 1000, processed: i });
    }
    expect(samples).toHaveLength(8);
    expect(samples[0].processed).toBe(4);
    expect(samples[7].processed).toBe(11);
  });
});

describe('computeEta', () => {
  test('is not ready with fewer than 3 samples', () => {
    const samples: EtaSample[] = [
      { timestamp: 0, processed: 1 },
      { timestamp: 2500, processed: 2 },
    ];
    const result = computeEta(samples, 100);
    expect(result.ready).toBe(false);
    expect(result.label).toBe('Estimating…');
  });

  test('is not ready when total is zero', () => {
    const samples: EtaSample[] = [
      { timestamp: 0, processed: 1 },
      { timestamp: 2500, processed: 2 },
      { timestamp: 5000, processed: 3 },
    ];
    expect(computeEta(samples, 0).ready).toBe(false);
  });

  test('computes a rate and remaining-time label from the sample window', () => {
    const samples: EtaSample[] = [
      { timestamp: 0, processed: 10 },
      { timestamp: 15000, processed: 11 },
      { timestamp: 30000, processed: 13 },
    ];
    const result = computeEta(samples, 43);
    expect(result.ready).toBe(true);
    expect(result.ratePerMinute).toBeCloseTo(6, 1);
    expect(result.label).toBe('~5 min left · 6.0/min avg');
  });

  test('converges toward a new (slower) rate within the window after a mid-scan slowdown', () => {
    let samples: EtaSample[] = [];
    for (let i = 1; i <= 5; i++) {
      samples = pushEtaSample(samples, { timestamp: i * 1000, processed: i });
    }
    for (let i = 1; i <= 4; i++) {
      samples = pushEtaSample(samples, { timestamp: 5000 + i * 20000, processed: 5 + i });
    }
    const result = computeEta(samples, 20);
    expect(result.ratePerMinute).toBeLessThan(10);
  });

  test('stays not-ready when processed has not moved since the first sample', () => {
    const samples: EtaSample[] = [
      { timestamp: 0, processed: 5 },
      { timestamp: 2500, processed: 5 },
      { timestamp: 5000, processed: 5 },
    ];
    expect(computeEta(samples, 20).ready).toBe(false);
  });
});
