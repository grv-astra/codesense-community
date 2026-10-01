import type { StatCountDetails, TopCountsTrend } from '@/types/dashboard';
import { Link } from '@tanstack/react-router';

const formatTrend = (pct: number) => `${pct >= 0 ? '+' : ''}${pct}%`;

const formatCount = (count: number) =>
  count >= 1000 ? `${(count / 1000).toFixed(1)}k` : count.toLocaleString();

/**
 * Demoted KPI strip — Users / Projects / scan and finding totals. These are
 * orientation, not the story, so they sit as one thin row below the fold
 * rather than six full-weight cards up top. Each still deep-links to its page.
 */
const DashboardCards = ({
  data,
  trend,
}: {
  data: StatCountDetails | undefined;
  trend: TopCountsTrend | undefined;
}) => {
  const stats = [
    { label: 'Users', count: data?.users ?? 0, href: '/users/list' as const, trend: trend?.users },
    { label: 'Projects', count: data?.projects ?? 0, href: '/project/list' as const, trend: trend?.projects },
    { label: 'Code scans', count: data?.scans ?? 0, href: '/scan/start' as const, trend: trend?.scans },
    { label: 'SBOM scans', count: data?.sbom_scans ?? 0, href: '/scan/start' as const, trend: trend?.sbom_scans },
    { label: 'Findings', count: data?.findings ?? 0, href: '/scan/start' as const },
    { label: 'SBOM findings', count: data?.sbom_findings ?? 0, href: '/scan/start' as const },
  ];

  return (
    <div className="grid grid-cols-2 divide-x divide-y divide-border overflow-hidden rounded-lg border border-border bg-card sm:grid-cols-3 sm:divide-y-0 lg:grid-cols-6">
      {stats.map((s) => (
        <Link key={s.label} to={s.href} className="flex flex-col gap-1 px-4 py-3 transition-colors hover:bg-muted">
          <span className="text-xs text-muted-foreground">{s.label}</span>
          <span className="text-xl font-semibold tabular-nums text-foreground">{formatCount(s.count)}</span>
          {s.trend && (
            <span
              className={
                'text-xs font-medium tabular-nums ' +
                (s.trend.pct >= 0 ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground')
              }
            >
              {formatTrend(s.trend.pct)} {s.trend.period}
            </span>
          )}
        </Link>
      ))}
    </div>
  );
};

export default DashboardCards;
