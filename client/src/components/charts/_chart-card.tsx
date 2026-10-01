import { Skeleton } from '@/components/atomic/skeleton';
import { cn } from '@/lib/utils';

/**
 * The one card shell every dashboard chart sits in. Replaces the bespoke
 * `rounded-xl bg-white dark:bg-[#2d2d2d] … transition-colors duration-300`
 * chrome each chart used to repeat. Flat by design — a single `bg-card`
 * surface with a hairline border, no nested inner panel, no drop shadow — so
 * the dashboard reads as one instrument, not a tray of detached widgets.
 */
type ChartCardProps = {
  title: string;
  subtitle?: string;
  /** right-aligned header slot — e.g. a 7/30/90 range toggle */
  action?: React.ReactNode;
  /** muted line under the body — e.g. data provenance */
  footnote?: string;
  className?: string;
  bodyClassName?: string;
  children: React.ReactNode;
};

export function ChartCard({
  title,
  subtitle,
  action,
  footnote,
  className,
  bodyClassName,
  children,
}: ChartCardProps) {
  return (
    <section className={cn('flex min-h-0 flex-col rounded-lg border border-border bg-card', className)}>
      <header className="flex items-start justify-between gap-3 px-4 pt-4 pb-3">
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold text-foreground">{title}</h3>
          {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </header>
      <div className={cn('min-h-0 flex-1 px-4 pb-4', bodyClassName)}>{children}</div>
      {footnote && (
        <p className="border-t border-border px-4 py-2 text-[11px] text-muted-foreground">{footnote}</p>
      )}
    </section>
  );
}

/**
 * Skeleton with the same footprint as a `<ChartCard>` — header lines plus a
 * body block of `height` px. Used as the per-card Suspense fallback so the
 * lazy chart chunk streaming in causes no layout shift.
 */
export function ChartCardSkeleton({ height = 240 }: { height?: number }) {
  return (
    <section className="flex flex-col rounded-lg border border-border bg-card">
      <header className="space-y-2 px-4 pt-4 pb-3">
        <Skeleton className="h-4 w-40" />
        <Skeleton className="h-3 w-56" />
      </header>
      <div className="px-4 pb-4">
        <Skeleton className="w-full" style={{ height }} />
      </div>
    </section>
  );
}

/**
 * Empty state for a chart/list with no data. `message` says what's missing;
 * `action` is an optional call to action (usually a `<Link to="/scan/start">`).
 */
export function ChartEmpty({
  message,
  action,
}: {
  message: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex h-full min-h-[8rem] flex-col items-center justify-center gap-2 py-8 text-center">
      <p className="max-w-[28ch] text-sm text-muted-foreground">{message}</p>
      {action}
    </div>
  );
}
