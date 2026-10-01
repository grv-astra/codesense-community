import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, test, expect, vi } from 'vitest';
import { ScanProgressPanel } from './ScanProgressPanel';
import type { ScanDetails } from '@/types/scan';

vi.mock('@/services/finding.service', () => ({
  findingService: {
    getFindingsByScan: vi.fn().mockResolvedValue({
      findings: [], pagination: { total: 0, page: 1, limit: 8, pages: 0 },
    }),
  },
}));

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>);
}

const base: ScanDetails = {
  id: 's1', project_id: 'p1', scan_name: 'S', status: 'in_progress',
  findings: 0, total_files: 50, files_scanned: 0,
  created_at: new Date().toISOString(), end_time: null, triggered_by: 'u',
  metrics: { total_loc: 0, total_functions: 0, languages: ['python'] },
};

describe('ScanProgressPanel', () => {
  test('shows the Analyzing panel before findings_progress exists', () => {
    renderWithClient(<ScanProgressPanel scan={base} isCancelling={false} />);
    expect(screen.getByText('Scanning 50 files')).toBeInTheDocument();
    expect(screen.queryByText(/verified/)).not.toBeInTheDocument();
  });

  test('shows the Verifying panel once findings_progress exists', () => {
    const scan: ScanDetails = {
      ...base,
      metrics: { ...base.metrics, findings_progress: { processed: 3, total: 10 } },
    };
    renderWithClient(<ScanProgressPanel scan={scan} isCancelling={false} />);
    expect(screen.getByText('3 of 10 verified')).toBeInTheDocument();
  });
});
