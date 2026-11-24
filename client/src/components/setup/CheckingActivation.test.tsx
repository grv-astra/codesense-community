import { render, screen } from '@testing-library/react';
import { describe, test, expect } from 'vitest';
import { CheckingActivation } from './CheckingActivation';

describe('CheckingActivation', () => {
  test('shows only the short message while starting', () => {
    render(<CheckingActivation />);
    expect(screen.getByText('Starting Code Sense…')).toBeTruthy();
    expect(screen.queryByText(/taking longer than usual/i)).toBeNull();
  });

  test('adds the "taking longer" note when slow, without asking for a password', () => {
    render(<CheckingActivation slow />);
    expect(screen.getByText('Starting Code Sense…')).toBeTruthy();
    expect(screen.getByText(/taking longer than usual/i)).toBeTruthy();
    expect(screen.queryByText(/password/i)).toBeNull();
  });
});
