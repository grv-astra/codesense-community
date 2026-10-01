import { SEVERITY_ORDER } from '@/types/scan';
import type { ScanDetails } from '@/types/scan';
import type { FindingDetails } from '@/types/finding';
import type { EtaResult } from '@/lib/scan-eta';
import { SecurityBadge } from '@/components/atomic/enum-badge';
import { LiveFindingFeed } from './LiveFindingFeed';

interface VerifyingPanelProps {
  scan: ScanDetails;
  elapsedLabel: string;
  eta: EtaResult;
  recentFindings: FindingDetails[];
  newFindingIds: Set<string>;
}

export function VerifyingPanel({ scan, elapsedLabel, eta, recentFindings, newFindingIds }: VerifyingPanelProps) {
  const fp = scan.metrics?.findings_progress;
  const processed = fp?.processed ?? 0;
  const total = fp?.total ?? 0;
  const percent = total > 0 ? Math.min(100, Math.round((processed / total) * 100)) : 0;
  const severityCounts = scan.severity_counts;

  return (
    <div>
      <div className="flex justify-end mb-3">
        <span className="text-xs text-gray-500 dark:text-gray-400 font-mono">⏱ {elapsedLabel}</span>
      </div>

      <div className="flex justify-between items-baseline mb-2">
        <span className="text-sm font-semibold text-[#2d2d2d] dark:text-white">
          {processed} of {total} verified
        </span>
        <span
          className="text-xs text-gray-500 dark:text-gray-400"
          title="Rolling average over the last few poll intervals"
        >
          {eta.label}
        </span>
      </div>
      <div
        className="h-2 bg-[#e5e5e5] dark:bg-[#404040] rounded-full overflow-hidden mb-4"
        role="progressbar"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Verification progress"
      >
        <div
          className="h-full bg-[#bf0000] rounded-full transition-all duration-500 ease-out"
          style={{ width: `${percent}%` }}
        />
      </div>

      {severityCounts && (
        <div className="flex flex-wrap gap-2 mb-4">
          {SEVERITY_ORDER.filter((sev) => (severityCounts[sev] ?? 0) > 0).map((sev) => (
            <span key={sev} className="flex items-center gap-1">
              <SecurityBadge severity={sev} size="sm" />
              <span className="text-xs font-semibold">{severityCounts[sev]}</span>
            </span>
          ))}
        </div>
      )}

      <div className="text-[11px] uppercase tracking-wide text-gray-400 dark:text-gray-500 font-bold mb-2">
        Live — findings as they're verified
      </div>
      <LiveFindingFeed findings={recentFindings} newFindingIds={newFindingIds} />
    </div>
  );
}
