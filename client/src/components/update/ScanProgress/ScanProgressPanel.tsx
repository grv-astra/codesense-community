import type { ScanDetails } from '@/types/scan';
import { formatDuration } from '@/utils/timestampFormater';
import { useScanProgress } from '@/hooks/use-scan-progress';
import { PhaseStepper } from './PhaseStepper';
import { AnalyzingPanel } from './AnalyzingPanel';
import { VerifyingPanel } from './VerifyingPanel';

interface ScanProgressPanelProps {
  scan: ScanDetails;
  isCancelling: boolean;
}

export function ScanProgressPanel({ scan, isCancelling }: ScanProgressPanelProps) {
  const { eta, recentFindings, newFindingIds } = useScanProgress(scan);
  const verifying = scan.status === 'in_progress' && scan.metrics?.findings_progress !== undefined;
  const elapsedLabel = formatDuration(scan);

  return (
    <div className="rounded-2xl shadow-lg border border-[#e5e5e5] dark:border-[#404040] p-8">
      <h2 className="text-lg font-semibold text-[#2d2d2d] dark:text-white mb-6">Scan Progress</h2>
      <PhaseStepper subPhase={verifying ? 'verifying' : 'analyzing'} isCancelling={isCancelling} />
      {verifying ? (
        <VerifyingPanel
          scan={scan}
          elapsedLabel={elapsedLabel}
          eta={eta}
          recentFindings={recentFindings}
          newFindingIds={newFindingIds}
        />
      ) : (
        <AnalyzingPanel scan={scan} elapsedLabel={elapsedLabel} />
      )}
    </div>
  );
}
