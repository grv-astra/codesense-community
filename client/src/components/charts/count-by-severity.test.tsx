import { render, screen } from '@testing-library/react';
import { describe, expect, test } from 'vitest';
import { ThemeProvider } from '@/contexts/use-theme';
import SeverityBreakdown from './count-by-severity';

const wrap = (ui: React.ReactElement) => render(<ThemeProvider>{ui}</ThemeProvider>);

describe('SeverityBreakdown (count-by-severity)', () => {
  test('renders inside the shared ChartCard shell', () => {
    wrap(<SeverityBreakdown data={{ critical: 1, high: 2, medium: 3, low: 4 }} />);
    expect(screen.getByRole('heading', { name: 'Severity breakdown' })).toBeInTheDocument();
    expect(screen.getByText('Open findings by severity, all projects')).toBeInTheDocument();
  });

  test('shows an explicit empty state when every bucket is zero', () => {
    wrap(<SeverityBreakdown data={{ critical: 0, high: 0, medium: 0, low: 0 }} />);
    expect(screen.getByText(/No findings yet/i)).toBeInTheDocument();
  });
});
