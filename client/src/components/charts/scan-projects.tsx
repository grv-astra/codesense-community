import type { ScansByProjectItem } from '@/types/dashboard';
import { ChartCard, ChartEmpty } from './_chart-card';

function ScanProjects({ data = [] }: { data?: ScansByProjectItem[] }) {
  const rows = data.slice(0, 8);

  return (
    <ChartCard
      title="Top scanned projects"
      subtitle="Highest scan and finding activity"
      footnote="Live from the scan store"
    >
      {rows.length === 0 ? (
        <ChartEmpty message="No project activity yet." />
      ) : (
        <ul className="divide-y divide-border">
          {rows.map((proj) => (
            <li key={proj.project} className="py-2 first:pt-0 last:pb-0">
              <div className="flex items-start justify-between gap-3">
                <p className="truncate text-sm font-medium text-foreground">{proj.project}</p>
                <span className="shrink-0 text-xs font-semibold tabular-nums text-sev-critical">
                  {proj.critical} critical
                </span>
              </div>
              <div className="mt-0.5 flex justify-between text-xs text-muted-foreground">
                <span className="tabular-nums">{proj.scans} scans</span>
                <span className="tabular-nums">{proj.findings} findings</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </ChartCard>
  );
}

export default ScanProjects;
