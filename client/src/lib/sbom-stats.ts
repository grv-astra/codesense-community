export interface SbomDependencyStats {
  affected: number;
  clean: number;
  affectedPercent: string;
  cleanPercent: string;
}

/**
 * Package-level summary for an SBOM scan.
 *
 * `vulnerabilities` counts CVEs, and one package can carry several, so it must not be
 * subtracted from the package count (that produced "-8 clean packages" and ">100%
 * affected"). The server sends `affected_dependencies` (distinct vulnerable packages);
 * for an older server without it we fall back to the CVE count, clamped to the package
 * count so the numbers stay sane.
 */
export function sbomDependencyStats(scan: {
  dependencies_scanned: number;
  vulnerabilities: number;
  affected_dependencies?: number;
}): SbomDependencyStats {
  const total = Math.max(0, scan.dependencies_scanned || 0);
  const reported = scan.affected_dependencies ?? scan.vulnerabilities ?? 0;
  const affected = Math.min(Math.max(0, reported), total);
  const clean = total - affected;
  const pct = (n: number) => (total === 0 ? '0.0' : ((n / total) * 100).toFixed(1));
  return { affected, clean, affectedPercent: pct(affected), cleanPercent: pct(clean) };
}
