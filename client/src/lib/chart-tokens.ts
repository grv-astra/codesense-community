import { useMemo } from 'react';
import { useTheme } from '@/contexts/use-theme';

/**
 * Single source for chart colours. The palette lives in `index.css` as CSS
 * custom properties (`--sev-*`, `--data-*`, `--chart-*`) that flip with the
 * `.dark` class; recharts needs concrete strings, so `useChartTokens()` reads
 * the computed values. It re-reads whenever the theme toggles (the `isDarkMode`
 * dependency), which is the only time these change.
 *
 * No chart should hardcode a hex value — import from here instead.
 */

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

// Order the dashboard severity chart/ramp actually receives (the API's
// `count_by_severity` has no `info` bucket).
export const DASHBOARD_SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;

type ChartTokens = {
  severity: Record<Severity, string>;
  /** neutral graphite ramp for non-severity series, darkest first */
  data: [string, string, string, string];
  axis: string;
  grid: string;
  tooltipBg: string;
  tooltipBorder: string;
};

// SSR / jsdom fallback — matches the light palette in index.css so tests and a
// non-DOM first render get sane values instead of empty strings.
const FALLBACK: ChartTokens = {
  severity: {
    critical: '#7f1d1d',
    high: '#dc2626',
    medium: '#ea7317',
    low: '#a16207',
    info: '#6b7280',
  },
  data: ['#374151', '#6b7280', '#9ca3af', '#d1d5db'],
  axis: '#6b7280',
  grid: '#e5e7eb',
  tooltipBg: '#ffffff',
  tooltipBorder: '#e5e7eb',
};

function readVars(): ChartTokens {
  if (typeof window === 'undefined' || !document?.documentElement) return FALLBACK;
  const s = getComputedStyle(document.documentElement);
  const v = (name: string, fallback: string) => s.getPropertyValue(name).trim() || fallback;
  return {
    severity: {
      critical: v('--sev-critical', FALLBACK.severity.critical),
      high: v('--sev-high', FALLBACK.severity.high),
      medium: v('--sev-medium', FALLBACK.severity.medium),
      low: v('--sev-low', FALLBACK.severity.low),
      info: v('--sev-info', FALLBACK.severity.info),
    },
    data: [
      v('--data-1', FALLBACK.data[0]),
      v('--data-2', FALLBACK.data[1]),
      v('--data-3', FALLBACK.data[2]),
      v('--data-4', FALLBACK.data[3]),
    ],
    axis: v('--chart-axis', FALLBACK.axis),
    grid: v('--chart-grid', FALLBACK.grid),
    tooltipBg: v('--chart-tooltip-bg', FALLBACK.tooltipBg),
    tooltipBorder: v('--chart-tooltip-border', FALLBACK.tooltipBorder),
  };
}

export function useChartTokens(): ChartTokens {
  const { isDarkMode } = useTheme();
  // isDarkMode is the dependency: the `.dark` class (and thus every var above)
  // changes only when it does.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  return useMemo(readVars, [isDarkMode]);
}
