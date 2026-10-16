import { render, screen } from '@testing-library/react';
import { afterEach, describe, test, expect, vi } from 'vitest';
import { FirstRunSetup } from './FirstRunSetup';

describe('FirstRunSetup in a build without a bundled model (Community installer)', () => {
  afterEach(() => vi.unstubAllEnvs());

  test('the vulnerability database alone drives the bar to 100%, and the text does not mention an AI model', () => {
    vi.stubEnv('VITE_BUNDLES_MODEL', '0');
    render(
      <FirstRunSetup
        state={{ status: 'pending', progress: { 'grype-db': { bytes: 100, total: 100 } }, retry: vi.fn() }}
      />,
    );
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '100');
    expect(screen.getByText(/Preparing the vulnerability database/)).toBeInTheDocument();
    expect(screen.queryByText(/AI model/)).not.toBeInTheDocument();
  });

  test('halfway through the database is 50%, not 25%', () => {
    vi.stubEnv('VITE_BUNDLES_MODEL', '0');
    render(
      <FirstRunSetup
        state={{ status: 'pending', progress: { 'grype-db': { bytes: 50, total: 100 } }, retry: vi.fn() }}
      />,
    );
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '50');
  });

  test('the default (model bundled) build is unchanged: database alone is only half the bar', () => {
    render(
      <FirstRunSetup
        state={{ status: 'pending', progress: { 'grype-db': { bytes: 100, total: 100 } }, retry: vi.fn() }}
      />,
    );
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '50');
    expect(screen.getByText(/Preparing the AI model and vulnerability database/)).toBeInTheDocument();
  });
});

describe('FirstRunSetup', () => {
  test('shows progress percentage while pending', () => {
    render(
      <FirstRunSetup
        state={{
          status: 'pending',
          // model is weighted at 50% of the overall bar and is itself 50%
          // done, so the fixed 50/50 weighting yields 25% overall.
          progress: { model: { bytes: 50, total: 100 } },
          retry: vi.fn(),
        }}
      />,
    );
    expect(screen.getByText(/25%/)).toBeInTheDocument();
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '25');
  });

  test('percent is monotonically non-decreasing when grype-db tracking begins after model completes', () => {
    const { rerender } = render(
      <FirstRunSetup
        state={{
          status: 'pending',
          progress: { model: { bytes: 100, total: 100 } },
          retry: vi.fn(),
        }}
      />,
    );
    expect(screen.getByText(/50%/)).toBeInTheDocument();
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '50');

    rerender(
      <FirstRunSetup
        state={{
          status: 'pending',
          progress: {
            model: { bytes: 100, total: 100 },
            'grype-db': { bytes: 1, total: 1000 },
          },
          retry: vi.fn(),
        }}
      />,
    );
    const percentAfter = Number(screen.getByRole('progressbar').getAttribute('aria-valuenow'));
    expect(percentAfter).toBeGreaterThanOrEqual(50);
  });

  test('shows the failure reason and calls retry on click', () => {
    const retry = vi.fn();
    render(
      <FirstRunSetup state={{ status: 'failed', asset: 'grype-db', reason: 'disk full', retry }} />,
    );
    expect(screen.getByText(/disk full/)).toBeInTheDocument();
    screen.getByRole('button', { name: /retry/i }).click();
    expect(retry).toHaveBeenCalledTimes(1);
  });
});
