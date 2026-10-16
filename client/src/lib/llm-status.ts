import type { LlmStatus } from '@/types/llm';

export type Tone = 'good' | 'bad' | 'warn' | 'neutral' | 'info';

export interface LlmStatusView {
  label: string;
  tone: Tone;
  hint: string;
}

/** Text + colour for each state. The label always says it in words, so colour is never the only cue. */
export function describeLlmStatus(s: LlmStatus): LlmStatusView {
  const target = [s.model, s.host && `@ ${s.host}`].filter(Boolean).join(' ');
  switch (s.state) {
    case 'connected':
      return { label: 'AI verification: connected', tone: 'good', hint: target };
    case 'failing':
      return {
        label: 'AI verification: not working',
        tone: 'bad',
        hint: [target, s.error].filter(Boolean).join(' — ') || 'The last check failed.',
      };
    case 'untested':
      return { label: 'AI verification: not tested yet', tone: 'warn', hint: `${target} — use "Test connection" in Settings.` };
    case 'needs_consent':
      return { label: 'AI verification: needs consent', tone: 'warn', hint: 'Confirm what is sent to the LLM host in Settings.' };
    case 'bundled':
      return { label: 'AI verification: bundled model', tone: 'info', hint: 'Using the bundled local model.' };
    case 'disabled':
      return { label: 'AI verification: off', tone: 'neutral', hint: 'Your LLM connection is saved but switched off.' };
    default:
      return { label: 'AI verification: not set up', tone: 'neutral', hint: 'Connect your own LLM in Settings to verify findings.' };
  }
}

export const TONE_CLASSES: Record<Tone, { chip: string; dot: string }> = {
  good: { chip: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-200', dot: 'bg-green-600 dark:bg-green-400' },
  bad: { chip: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200', dot: 'bg-red-600 dark:bg-red-400' },
  warn: { chip: 'bg-amber-100 text-amber-900 dark:bg-amber-900/40 dark:text-amber-200', dot: 'bg-amber-600 dark:bg-amber-400' },
  neutral: { chip: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300', dot: 'bg-gray-500 dark:bg-gray-400' },
  info: { chip: 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200', dot: 'bg-blue-600 dark:bg-blue-400' },
};
