import { render, screen } from '@testing-library/react';
import { describe, test, expect } from 'vitest';
import { PhaseStepper } from './PhaseStepper';

describe('PhaseStepper', () => {
  test('marks Uploaded done and Analyzing current when subPhase is analyzing', () => {
    render(<PhaseStepper subPhase="analyzing" isCancelling={false} />);
    expect(screen.getByText('✓ Uploaded')).toBeInTheDocument();
    expect(screen.getByText('Analyzing')).toBeInTheDocument();
  });

  test('marks Uploaded and Analyzing done when subPhase is verifying', () => {
    render(<PhaseStepper subPhase="verifying" isCancelling={false} />);
    expect(screen.getByText('✓ Uploaded')).toBeInTheDocument();
    expect(screen.getByText('✓ Analyzing')).toBeInTheDocument();
    expect(screen.getByText('Verifying findings')).toBeInTheDocument();
  });

  test('shows "Cancelling…" on the current step when isCancelling is true', () => {
    render(<PhaseStepper subPhase="verifying" isCancelling={true} />);
    expect(screen.getByText('Cancelling…')).toBeInTheDocument();
  });

  test('sets aria-current="step" only on the current step', () => {
    render(<PhaseStepper subPhase="analyzing" isCancelling={false} />);
    const current = screen.getByText('Analyzing');
    expect(current).toHaveAttribute('aria-current', 'step');
    const done = screen.getByText('✓ Uploaded');
    expect(done).not.toHaveAttribute('aria-current');
  });
});
