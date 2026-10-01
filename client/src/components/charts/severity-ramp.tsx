import type { SeverityData } from '@/types/dashboard';
import { DASHBOARD_SEVERITY_ORDER } from '@/lib/chart-tokens';
import { cn } from '@/lib/utils';

const SEV_BG: Record<string, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
};

/**
 * The dashboard hero's centrepiece: open findings drawn *as* the severity
 * distribution. One horizontal stacked bar in the shared severity ramp, with a
 * labelled count under each segment. This is the app's answer to "how much
 * risk is open, and where" — the number alone can't show the shape.
 */
export function SeverityRamp({ data, className }: { data?: SeverityData; className?: string }) {
  const counts = data ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const total = DASHBOARD_SEVERITY_ORDER.reduce((sum, k) => sum + (counts[k] || 0), 0);

  return (
    <div className={cn('w-full', className)}>
      <div
        className="flex h-3 w-full overflow-hidden rounded-full bg-muted"
        role="img"
        aria-label={
          total === 0
            ? 'No open findings'
            : DASHBOARD_SEVERITY_ORDER.map((k) => `${counts[k] || 0} ${k}`).join(', ')
        }
      >
        {total > 0 &&
          DASHBOARD_SEVERITY_ORDER.map((k) => {
            const value = counts[k] || 0;
            if (value === 0) return null;
            return (
              <div
                key={k}
                className={SEV_BG[k]}
                style={{ flexBasis: `${(value / total) * 100}%` }}
              />
            );
          })}
      </div>

      <dl className="mt-3 flex flex-wrap gap-x-6 gap-y-2">
        {DASHBOARD_SEVERITY_ORDER.map((k) => (
          <div key={k} className="flex items-center gap-2">
            <span className={cn('size-2 rounded-[2px]', SEV_BG[k])} aria-hidden="true" />
            <dt className="text-xs capitalize text-muted-foreground">{k}</dt>
            <dd className="text-xs font-semibold tabular-nums text-foreground">
              {(counts[k] || 0).toLocaleString()}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
