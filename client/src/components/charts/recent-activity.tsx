import { StateBadge } from '@/components/atomic/enum-badge';
import type { RecentScanItem } from '@/types/dashboard';
import { Link } from '@tanstack/react-router';
import { FileSearch, ScanLine } from 'lucide-react';
import { ChartCard, ChartEmpty } from './_chart-card';

const timeAgo = (iso: string) => {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
};

const RecentActivity = ({ data = [] }: { data?: RecentScanItem[] }) => {
  return (
    <ChartCard
      title="Recent scans"
      subtitle="Latest code and SBOM scans across all projects"
    >
      {data.length === 0 ? (
        <ChartEmpty
          message="No scans yet."
          action={
            <Link
              to="/scan/start"
              className="text-xs font-medium text-foreground underline underline-offset-4 hover:no-underline"
            >
              Start a scan
            </Link>
          }
        />
      ) : (
        <ul className="divide-y divide-border">
          {data.map((scan) => {
            const Icon = scan.type === 'sbom' ? FileSearch : ScanLine;
            const linkProps =
              scan.type === 'sbom'
                ? { to: '/scan/sbom/$sbomscanId/updates' as const, params: { sbomscanId: scan.id } }
                : { to: '/scan/$scanId/updates' as const, params: { scanId: scan.id } };

            return (
              <li key={scan.id}>
                <Link
                  {...linkProps}
                  className="-mx-1 flex items-center gap-3 rounded-md px-1 py-2 transition-colors hover:bg-muted"
                >
                  <span className="shrink-0 rounded-md bg-muted p-1.5 text-muted-foreground">
                    <Icon size={14} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center justify-between gap-2">
                      <span className="truncate text-sm font-medium text-foreground">{scan.project}</span>
                      <StateBadge state={scan.status} size="xs" />
                    </span>
                    <span className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
                      <span className="truncate">{scan.scan_name}</span>
                      <span className="shrink-0 tabular-nums">
                        {scan.findings} findings · {timeAgo(scan.created_at)}
                      </span>
                    </span>
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </ChartCard>
  );
};

export default RecentActivity;
