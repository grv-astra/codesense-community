import { render, screen } from '@testing-library/react';
import { describe, expect, test } from 'vitest';
import { ChartCard, ChartCardSkeleton, ChartEmpty } from './_chart-card';

describe('ChartCard', () => {
  test('renders title, subtitle, footnote, action slot and children', () => {
    render(
      <ChartCard
        title="Severity breakdown"
        subtitle="Open findings by severity"
        footnote="Live from the findings store"
        action={<button type="button">7d</button>}
      >
        <div>chart body</div>
      </ChartCard>,
    );

    expect(screen.getByRole('heading', { name: 'Severity breakdown' })).toBeInTheDocument();
    expect(screen.getByText('Open findings by severity')).toBeInTheDocument();
    expect(screen.getByText('Live from the findings store')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '7d' })).toBeInTheDocument();
    expect(screen.getByText('chart body')).toBeInTheDocument();
  });

  test('omits the footnote row when no footnote is given', () => {
    render(
      <ChartCard title="By language">
        <div>body</div>
      </ChartCard>,
    );
    expect(screen.queryByText(/Live from/i)).not.toBeInTheDocument();
  });
});

describe('ChartEmpty', () => {
  test('renders the message and an optional action', () => {
    render(
      <ChartEmpty message="No scans yet." action={<a href="/scan/start">Start a scan</a>} />,
    );
    expect(screen.getByText('No scans yet.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Start a scan' })).toBeInTheDocument();
  });
});

describe('ChartCardSkeleton', () => {
  test('renders a placeholder body at the requested height', () => {
    const { container } = render(<ChartCardSkeleton height={200} />);
    const block = container.querySelector('[data-slot="skeleton"][style*="height"]') as HTMLElement;
    expect(block).toBeTruthy();
    expect(block.style.height).toBe('200px');
  });
});
