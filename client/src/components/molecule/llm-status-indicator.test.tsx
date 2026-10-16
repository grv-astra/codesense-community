import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { LlmStatusIndicator } from './llm-status-indicator';
import * as useLlm from '@/hooks/use-llm';
import type { LlmStatus } from '@/types/llm';

vi.mock('@tanstack/react-router', () => ({
  Link: ({ to, children, ...rest }: { to: string; children: React.ReactNode }) => <a href={to} {...rest}>{children}</a>,
}));

const status = (over: Partial<LlmStatus>): LlmStatus => ({
  state: 'connected', source: 'byo', provider: 'openai_compatible', model: 'gpt-4o-mini',
  host: 'api.openai.com', last_check_at: null, error: '', ...over,
});

const mockStatus = (data: LlmStatus | undefined, isLoading = false) =>
  vi.spyOn(useLlm, 'useLlmStatus').mockReturnValue({ data, isLoading } as ReturnType<typeof useLlm.useLlmStatus>);

describe('LlmStatusIndicator', () => {
  it('shows the connected state with the target in its tooltip and links to settings', () => {
    mockStatus(status({}));
    render(<LlmStatusIndicator />);
    const link = screen.getByRole('link', { name: /AI verification: connected/ });
    expect(link).toHaveAttribute('href', '/settings');
    expect(link).toHaveAttribute('title', 'gpt-4o-mini @ api.openai.com');
  });

  it('shows failing with the reason', () => {
    mockStatus(status({ state: 'failing', error: 'The LLM rejected the API key (HTTP 401).' }));
    render(<LlmStatusIndicator />);
    expect(screen.getByRole('link', { name: /not working/ }).getAttribute('title')).toContain('rejected the API key');
  });

  it('shows the neutral not-set-up state', () => {
    mockStatus(status({ state: 'not_configured', source: 'none', model: '', host: '' }));
    render(<LlmStatusIndicator />);
    expect(screen.getByText('AI verification: not set up')).toBeInTheDocument();
  });

  it('renders nothing while loading or when the status cannot be fetched', () => {
    mockStatus(undefined, true);
    expect(render(<LlmStatusIndicator />).container).toBeEmptyDOMElement();
    mockStatus(undefined, false);
    expect(render(<LlmStatusIndicator />).container).toBeEmptyDOMElement();
  });
});
