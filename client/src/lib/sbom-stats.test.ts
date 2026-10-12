import { describe, expect, it } from 'vitest';

import { sbomDependencyStats } from './sbom-stats';

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
