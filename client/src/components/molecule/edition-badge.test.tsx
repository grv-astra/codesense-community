import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { EditionBadge } from './edition-badge';
import * as useEdition from '@/hooks/use-edition';
import type { EditionStatus } from '@/types/edition';

function status(over: Partial<EditionStatus> = {}): EditionStatus {
  return {
    edition: 'pro', label: 'Pro', source: 'signed', customer: 'Acme',
    issued_at: '', expires_at: null, model_tier: 'mid', warnings: [],
    features: {} as EditionStatus['features'], limits: {} as EditionStatus['limits'],
    usage: {} as EditionStatus['usage'], ...over,
  };
}

describe('EditionBadge', () => {
  it('shows the edition label', () => {
    vi.spyOn(useEdition, 'useEditionStatus').mockReturnValue(
      { data: status(), isLoading: false } as ReturnType<typeof useEdition.useEditionStatus>);
    render(<EditionBadge />);
    expect(screen.getByText('Pro')).toBeInTheDocument();
  });

  it('shows a warning chip when warnings present', () => {
    vi.spyOn(useEdition, 'useEditionStatus').mockReturnValue(
      { data: status({ warnings: ['entitlements expired on 2026-01-01; defaulting to Community'] }),
        isLoading: false } as ReturnType<typeof useEdition.useEditionStatus>);
    render(<EditionBadge />);
    expect(screen.getByRole('img', { name: /warning/i })).toBeInTheDocument();
  });

  it('renders nothing while loading', () => {
    vi.spyOn(useEdition, 'useEditionStatus').mockReturnValue(
      { data: undefined, isLoading: true } as ReturnType<typeof useEdition.useEditionStatus>);
    const { container } = render(<EditionBadge />);
    expect(container).toBeEmptyDOMElement();
  });
});
