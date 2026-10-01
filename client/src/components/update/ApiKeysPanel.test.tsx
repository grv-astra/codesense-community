import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import { ApiKeysPanel } from './ApiKeysPanel';

vi.mock('@/services/apikey.service', () => ({
  apiKeyService: {
    listApiKeys: vi.fn(),
    createApiKey: vi.fn(),
    revokeApiKey: vi.fn(),
  },
}));

vi.mock('@/hooks/use-edition', async (importActual) => {
  const actual = await importActual<typeof import('@/hooks/use-edition')>();
  return { ...actual, useEditionStatus: vi.fn() };
});

import { apiKeyService } from '@/services/apikey.service';
import { useEditionStatus } from '@/hooks/use-edition';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const editionWith = (apiAccess: boolean) =>
  ({ data: { features: { api_access: apiAccess } }, isLoading: false }) as any;

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>);
}

describe('ApiKeysPanel', () => {
  beforeEach(() => {
    vi.mocked(apiKeyService.listApiKeys).mockReset();
    vi.mocked(apiKeyService.createApiKey).mockReset();
    vi.mocked(apiKeyService.revokeApiKey).mockReset();
    vi.mocked(useEditionStatus).mockReturnValue(editionWith(true));
  });

  test('gates key generation behind the api_access feature', async () => {
    vi.mocked(useEditionStatus).mockReturnValue(editionWith(false));
    vi.mocked(apiKeyService.listApiKeys).mockResolvedValue([]);
    renderWithClient(<ApiKeysPanel projectId="proj1" />);

    expect(await screen.findByText(/CodeSense Pro feature/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /generate new key/i })).toBeDisabled();
  });

  test('does not flash the upsell while the edition query is still loading', async () => {
    vi.mocked(useEditionStatus).mockReturnValue({ data: undefined, isLoading: true } as any);
    vi.mocked(apiKeyService.listApiKeys).mockResolvedValue([]);
    renderWithClient(<ApiKeysPanel projectId="proj1" />);

    expect(await screen.findByText(/no api keys yet/i)).toBeInTheDocument();
    expect(screen.queryByText(/CodeSense Pro feature/i)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /generate new key/i })).not.toBeDisabled();
  });

  test('shows empty state when there are no keys', async () => {
    vi.mocked(apiKeyService.listApiKeys).mockResolvedValue([]);
    renderWithClient(<ApiKeysPanel projectId="proj1" />);
    expect(await screen.findByText(/no api keys yet/i)).toBeInTheDocument();
  });

  test('lists existing keys', async () => {
    vi.mocked(apiKeyService.listApiKeys).mockResolvedValue([
      {
        id: 'k1',
        name: 'azure-devops-prod',
        key_prefix: 'csk_ab12',
        created_at: '2026-08-11T00:00:00Z',
        last_used_at: null,
        revoked_at: null,
      },
    ]);
    renderWithClient(<ApiKeysPanel projectId="proj1" />);
    expect(await screen.findByText('azure-devops-prod')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
  });

  test('generating a key shows the plaintext once', async () => {
    vi.mocked(apiKeyService.listApiKeys).mockResolvedValue([]);
    vi.mocked(apiKeyService.createApiKey).mockResolvedValue({
      id: 'k2',
      name: 'new-key',
      key_prefix: 'csk_zz99',
      created_at: '2026-08-11T00:00:00Z',
      last_used_at: null,
      revoked_at: null,
      key: 'csk_zz99fullsecretvalue',
    });
    renderWithClient(<ApiKeysPanel projectId="proj1" />);

    fireEvent.click(await screen.findByRole('button', { name: /generate new key/i }));
    fireEvent.change(screen.getByLabelText(/key name/i), { target: { value: 'new-key' } });
    fireEvent.click(screen.getByRole('button', { name: /^generate$/i }));

    expect(await screen.findByDisplayValue('csk_zz99fullsecretvalue')).toBeInTheDocument();
    expect(apiKeyService.createApiKey).toHaveBeenCalledWith('proj1', { name: 'new-key' });
  });

  test('revoking a key calls the service', async () => {
    vi.mocked(apiKeyService.listApiKeys).mockResolvedValue([
      {
        id: 'k1',
        name: 'azure-devops-prod',
        key_prefix: 'csk_ab12',
        created_at: '2026-08-11T00:00:00Z',
        last_used_at: null,
        revoked_at: null,
      },
    ]);
    vi.mocked(apiKeyService.revokeApiKey).mockResolvedValue({
      id: 'k1',
      name: 'azure-devops-prod',
      key_prefix: 'csk_ab12',
      created_at: '2026-08-11T00:00:00Z',
      last_used_at: null,
      revoked_at: '2026-08-11T01:00:00Z',
    });
    renderWithClient(<ApiKeysPanel projectId="proj1" />);

    fireEvent.click(await screen.findByRole('button', { name: /revoke/i }));
    await waitFor(() => expect(apiKeyService.revokeApiKey).toHaveBeenCalledWith('proj1', 'k1'));
  });

  test('closing the dialog while creating does not leave the Generate button stuck disabled', async () => {
    vi.mocked(apiKeyService.listApiKeys).mockResolvedValue([]);
    let resolveCreate: (key: string) => void = () => {};
    vi.mocked(apiKeyService.createApiKey).mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveCreate = (key: string) =>
            resolve({
              id: 'k3',
              name: 'in-flight-key',
              key_prefix: 'csk_ff33',
              created_at: '2026-08-11T00:00:00Z',
              last_used_at: null,
              revoked_at: null,
              key,
            });
        })
    );
    renderWithClient(<ApiKeysPanel projectId="proj1" />);

    fireEvent.click(await screen.findByRole('button', { name: /generate new key/i }));
    fireEvent.change(screen.getByLabelText(/key name/i), { target: { value: 'in-flight-key' } });
    fireEvent.click(screen.getByRole('button', { name: /^generate$/i }));

    // Wait for the create request to actually be in flight (React Query invokes
    // the mutation function asynchronously) before closing the dialog.
    await waitFor(() => expect(apiKeyService.createApiKey).toHaveBeenCalled());

    // Close the dialog while the create request is still in flight.
    fireEvent.click(screen.getByRole('button', { name: /close/i }));
    expect(screen.queryByRole('button', { name: /^generate$/i })).not.toBeInTheDocument();

    // Let the request resolve now that the dialog is closed.
    resolveCreate('csk_ff33fullsecretvalue');

    // Reopen the dialog and provide a name so disabled-ness reflects only `submitting`.
    fireEvent.click(await screen.findByRole('button', { name: /generate new key/i }));
    fireEvent.change(screen.getByLabelText(/key name/i), { target: { value: 'second-attempt' } });

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^generate$/i })).not.toBeDisabled()
    );
  });
});
