import { useEditionStatus } from '@/hooks/use-edition';
import { cn } from '@/lib/utils';

export function EditionBadge() {
  const { data, isLoading } = useEditionStatus();
  if (isLoading || !data) return null;

  const tone =
    data.edition === 'enterprise'
      ? 'bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-200'
      : data.edition === 'pro'
        ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200'
        : 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300';

  return (
    <span className="inline-flex items-center gap-1 text-xs font-medium">
      <span className={cn('rounded px-1.5 py-0.5', tone)}>{data.label}</span>
      {data.warnings.length > 0 && (
        <span role="img" aria-label="warning" title={data.warnings.join('\n')}>
          ⚠️
        </span>
      )}
    </span>
  );
}
