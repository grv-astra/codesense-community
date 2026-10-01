import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import ScanUpdate from './Scanupdate';
import type { ScanDetails } from '@/types/scan';

// The cancel/resume mutations go through scanService -- mock it so no real
// network call happens; these tests only care about how ScanUpdate renders
// for a given scan shape, not the mutation round-trip itself.
vi.mock('@/services/scan.service', () => ({
  scanService: {
    cancelScan: vi.fn(),
    resumeScan: vi.fn(),
  },
}));

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>);
}

const base: ScanDetails = {
  id: 'scan1',
  project_id: 'proj1',
  scan_name: 'Test Scan',
  status: 'in_progress',
  findings: 3,
  total_files: 10,
  files_scanned: 5,
  created_at: '2026-08-20T00:00:00.000Z',
  end_time: null,
  triggered_by: 'user1',
  metrics: { total_loc: 0, total_functions: 0, languages: [] },
};

describe('ScanUpdate cancel UX', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('a plain in_progress scan shows a live, enabled Cancel Scan button', () => {
    renderWithClient(<ScanUpdate scan={{ ...base, cancel_requested: false }} />);

    expect(screen.getByRole('button', { name: 'Cancel Scan' })).toBeEnabled();
    // The status badge reads the real status, not a synthetic "cancelling" one.
    expect(screen.getByText('in progress')).toBeInTheDocument();
  });

  test('cancel_requested=true on an in_progress scan shows "Cancelling…" instead of reverting to Cancel Scan', () => {
    renderWithClient(<ScanUpdate scan={{ ...base, cancel_requested: true }} />);

    const button = screen.getByRole('button', { name: 'Cancelling…' });
    expect(button).toBeDisabled();
    // Two "Cancelling" occurrences expected: the status badge and the phase
    // label under the progress circle -- getAllByText covers both.
    expect(screen.getAllByText(/Cancelling/).length).toBeGreaterThanOrEqual(2);
  });

  test('cancel_requested=true has no special-cased effect once the scan is actually terminal', () => {
    // A stale cancel_requested flag on an already-cancelled scan must not
    // relabel the (absent, since canCancel is false) button or confuse the
    // real "Scan Cancelled" status display.
    renderWithClient(<ScanUpdate scan={{ ...base, status: 'cancelled', cancel_requested: true }} />);

    expect(screen.queryByRole('button', { name: /Cancel/ })).not.toBeInTheDocument();
    expect(screen.getByText('cancelled')).toBeInTheDocument();
  });
});
