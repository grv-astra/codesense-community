import { Recycle } from 'lucide-react';
import type { ScanDetails } from '@/types/scan';

interface AnalyzingPanelProps {
  scan: ScanDetails;
  elapsedLabel: string;
}

export function AnalyzingPanel({ scan, elapsedLabel }: AnalyzingPanelProps) {
  const fileCount = scan.total_files;
  const languages = scan.metrics?.languages ?? [];
  const incremental = scan.incremental_info;
  const statusLabel = fileCount > 0 ? `Scanning ${fileCount} files` : 'Analyzing source…';

  return (
    <div>
      <div className="flex justify-end mb-3">
        <span className="text-xs text-gray-500 dark:text-gray-400 font-mono">⏱ {elapsedLabel}</span>
      </div>

      <div className="border border-dashed border-[#e5e5e5] dark:border-[#404040] bg-[#e5e5e5]/30 dark:bg-[#2d2d2d]/30 rounded-xl p-6 text-center mb-4" aria-live="polite" role="status">
        <div aria-hidden="true" className="w-6 h-6 mx-auto mb-3 rounded-full border-2 border-[#e5e5e5] dark:border-[#404040] border-t-[#bf0000] animate-spin" />
        <div className="text-sm font-semibold text-[#2d2d2d] dark:text-white">
          {statusLabel}
        </div>
        {languages.length > 0 && (
          <div className="text-xs text-gray-500 dark:text-gray-400 mt-1 capitalize">
            {languages.join(' · ')}
          </div>
        )}
      </div>

      {incremental?.is_incremental && (
        <div className="rounded-lg bg-[#bf0000]/10 text-[#bf0000] px-3 py-2 text-xs flex items-center gap-2">
          <Recycle className="w-4 h-4 shrink-0" />
          <span>
            <strong>Incremental scan</strong> — {incremental.unchanged} files unchanged, reused from the last scan · {incremental.changed} being re-analyzed
          </span>
        </div>
      )}

      <p className="text-[11px] text-gray-400 dark:text-gray-500 mt-4 leading-relaxed">
        No progress bar here — detection runs as one pass with no per-file signal to report, so this shows real scope instead of a fake percentage.
      </p>
    </div>
  );
}
