import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { hasFeature, limitReached, useEditionStatus } from './use-edition';
import { editionService } from '@/services/edition.service';
import type { EditionStatus } from '@/types/edition';

vi.mock('@/services/edition.service', () => ({
  editionService: { getStatus: vi.fn() },
}));

const base: EditionStatus = {
  edition: 'community', label: 'Community', source: 'default', customer: '',
  issued_at: '', expires_at: null, model_tier: 'low', warnings: [],
  features: { llm_analysis: false, sbom_signing: false, license_compliance: false,
    api_access: false, incremental_scan: false, github_scan: true, sso: false, audit_log: false },
  limits: { projects: 1, code_scans_per_window: 25, sbom_scans_per_window: 25,
    window_days: 30, max_codebase_mb: 250, seats: 3 },
  usage: { projects: 1, code_scans_in_window: 0, sbom_scans_in_window: 0, seats: 1 },
};

describe('use-edition helpers', () => {
  it('hasFeature reads the flag', () => {
    expect(hasFeature(base, 'llm_analysis')).toBe(false);
    expect(hasFeature(base, 'github_scan')).toBe(true);
    expect(hasFeature(undefined, 'llm_analysis')).toBe(false);
  });

  it('limitReached compares usage to limit, unlimited never reached', () => {
    expect(limitReached(base, 'projects')).toBe(true);           // 1/1
    expect(limitReached({ ...base, usage: { ...base.usage, projects: 0 } }, 'projects')).toBe(false);
    const ent = { ...base, limits: { ...base.limits, projects: null as unknown as number } };
    expect(limitReached(ent, 'projects')).toBe(false);
  });
});

// Mirrors the QueryClientProvider wrapper setup used by the component tests
// (see components/molecule/license-status-card.test.tsx) + the renderHook
// pattern from use-activation.test.tsx.
function createWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
}

describe('useEditionStatus', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fetches edition status through editionService.getStatus', async () => {
    vi.mocked(editionService.getStatus).mockResolvedValue(base);

    const { result } = renderHook(() => useEditionStatus(), { wrapper: createWrapper() });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(result.current.data).toEqual(base);
    expect(editionService.getStatus).toHaveBeenCalled();
  });
});
