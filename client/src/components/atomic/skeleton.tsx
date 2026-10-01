import { cn } from '@/lib/utils';

/**
 * Loading placeholder. Give it the size/shape of the content it stands in for
 * so nothing shifts when the real content arrives. The pulse is paused under
 * `prefers-reduced-motion` by the global rule in index.css.
 */
export function Skeleton({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="skeleton"
      aria-hidden="true"
      className={cn('animate-pulse rounded-md bg-muted', className)}
      {...props}
    />
  );
}
