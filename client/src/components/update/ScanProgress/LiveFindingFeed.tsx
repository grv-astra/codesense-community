import { useState } from 'react';
import type { FindingDetails } from '@/types/finding';
import { SecurityBadge } from '@/components/atomic/enum-badge';

interface LiveFindingFeedProps {
  findings: FindingDetails[];
  newFindingIds: Set<string>;
}

const COLLAPSED_COUNT = 5;
const FLAGGED_SEVERITIES = new Set(['critical', 'high']);

export function LiveFindingFeed({ findings, newFindingIds }: LiveFindingFeedProps) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? findings : findings.slice(0, COLLAPSED_COUNT);
  const hiddenCount = findings.length - visible.length;

  if (findings.length === 0) {
    return (
      <p className="text-xs text-gray-400 dark:text-gray-500 italic">
        Waiting for the first finding to be verified…
      </p>
    );
  }

  return (
    <div>
      <div className="flex flex-col gap-2" role="list" aria-live="polite" aria-label="Verified findings">
        {visible.map((finding) => {
          const isFlagged = newFindingIds.has(finding.id) && FLAGGED_SEVERITIES.has(finding.severity);
          return (
            <div
              key={finding.id}
              role="listitem"
              className={
                'flex items-center gap-3 px-3 py-2.5 rounded-lg border text-sm ' +
                (isFlagged ? 'bg-[#bf0000]/5 border-[#bf0000]/30' : 'border-[#e5e5e5] dark:border-[#404040]')
              }
            >
              <SecurityBadge severity={finding.severity} size="sm" />
              <div className="min-w-0 flex-1">
                <div className="font-medium text-[#2d2d2d] dark:text-white truncate" title={finding.title}>
                  {finding.title}
                  {isFlagged && (
                    <span className="ml-2 text-[10px] font-bold text-[#bf0000] uppercase">
                      New {finding.severity}
                    </span>
                  )}
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400 truncate" title={finding.file_path}>{finding.file_path}</div>
              </div>
            </div>
          );
        })}
      </div>

      {hiddenCount > 0 && (
        <button
          type="button"
          onClick={() => setExpanded(true)}
          className="w-full mt-2 text-xs font-semibold text-[#bf0000] hover:underline py-1"
        >
          Show all {findings.length} loaded
        </button>
      )}
    </div>
  );
}
