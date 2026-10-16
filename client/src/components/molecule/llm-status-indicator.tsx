import { Link } from '@tanstack/react-router';
import { useLlmStatus } from '@/hooks/use-llm';
import { TONE_CLASSES, describeLlmStatus } from '@/lib/llm-status';
import { cn } from '@/lib/utils';

export function LlmStatusIndicator() {
  const { data, isLoading } = useLlmStatus();
  if (isLoading || !data) return null;

  const view = describeLlmStatus(data);
  const tone = TONE_CLASSES[view.tone];
  return (
    <Link
      to="/settings"
      title={view.hint}
      className={cn('inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-xs font-medium', tone.chip)}
    >
      <span aria-hidden="true" className={cn('inline-block size-2 rounded-full', tone.dot)} />
      {view.label}
    </Link>
  );
}
