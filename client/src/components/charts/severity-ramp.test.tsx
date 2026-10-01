import { render, screen } from '@testing-library/react';
import { describe, expect, test } from 'vitest';
import { SeverityRamp } from './severity-ramp';

describe('SeverityRamp (dashboard hero)', () => {
  test('renders a labelled count for every severity in fixed order', () => {
    render(<SeverityRamp data={{ critical: 3, high: 480, medium: 121, low: 22 }} />);

    for (const label of ['critical', 'high', 'medium', 'low']) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
    expect(screen.getByText('480')).toBeInTheDocument();
    expect(screen.getByText('121')).toBeInTheDocument();

    // the bar carries an accessible summary of the distribution
    expect(
      screen.getByRole('img', { name: /3 critical, 480 high, 121 medium, 22 low/i }),
    ).toBeInTheDocument();
  });

  test('degrades to an empty label when there are no findings', () => {
    render(<SeverityRamp data={{ critical: 0, high: 0, medium: 0, low: 0 }} />);
    expect(screen.getByRole('img', { name: /no open findings/i })).toBeInTheDocument();
  });

  test('does not crash when data is undefined', () => {
    render(<SeverityRamp />);
    expect(screen.getByRole('img', { name: /no open findings/i })).toBeInTheDocument();
  });
});
