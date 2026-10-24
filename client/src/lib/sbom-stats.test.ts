import { describe, expect, it } from 'vitest';

import { sbomDependencyStats, sbomSigningSummary } from './sbom-stats';

describe('sbomSigningSummary', () => {
  const when = (iso: string) => `T(${iso})`;
  const signed = { signed: true, verified: true, verified_at: '2026-10-22T10:00:00+00:00', skipped_reason: null };

  it('says a verified signature was verified, and when', () => {
    expect(sbomSigningSummary(signed, when)).toBe('Signed and verified (cosign) on T(2026-10-22T10:00:00+00:00)');
  });

  it('does not claim verification that did not happen', () => {
    expect(sbomSigningSummary({ ...signed, verified: false }, when)).toMatch(/could not be verified/);
  });

  it('explains an edition without signing', () => {
    const skipped = { signed: false, verified: false, verified_at: null, skipped_reason: 'edition' };
    expect(sbomSigningSummary(skipped, when)).toBe('Not signed (not included in this edition)');
  });

  it('shows nothing for scans that have no signing record', () => {
    expect(sbomSigningSummary(null, when)).toBeNull();
    expect(sbomSigningSummary(undefined, when)).toBeNull();
  });
});

describe('sbomDependencyStats', () => {
  // Regression: 3 packages with 11 CVEs rendered "-8 clean packages" and "366.7% affected".
  it('uses distinct affected packages, not the CVE count', () => {
    const s = sbomDependencyStats({ dependencies_scanned: 3, vulnerabilities: 11, affected_dependencies: 3 });
    expect(s).toEqual({ affected: 3, clean: 0, affectedPercent: '100.0', cleanPercent: '0.0' });
  });

  it('reports clean packages when only some are affected', () => {
    const s = sbomDependencyStats({ dependencies_scanned: 10, vulnerabilities: 40, affected_dependencies: 4 });
    expect(s.clean).toBe(6);
    expect(s.affectedPercent).toBe('40.0');
    expect(s.cleanPercent).toBe('60.0');
  });

  it('never goes negative or above 100% when the server lacks affected_dependencies', () => {
    const s = sbomDependencyStats({ dependencies_scanned: 3, vulnerabilities: 11 });
    expect(s.clean).toBe(0);
    expect(s.affectedPercent).toBe('100.0');
  });

  it('handles an empty SBOM without NaN', () => {
    const s = sbomDependencyStats({ dependencies_scanned: 0, vulnerabilities: 0, affected_dependencies: 0 });
    expect(s).toEqual({ affected: 0, clean: 0, affectedPercent: '0.0', cleanPercent: '0.0' });
  });
});
