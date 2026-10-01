import { render, screen } from '@testing-library/react';
import { describe, test, expect } from 'vitest';
import { VerifyingPanel } from './VerifyingPanel';
import type { ScanDetails } from '@/types/scan';

const base: ScanDetails = {
  id: 's1', project_id: 'p1', scan_name: 'S', status: 'in_progress',
  findings: 2, total_files: 10, files_scanned: 10,
  created_at: '2026-08-25T00:00:00.000Z', end_time: null, triggered_by: 'u',
  metrics: { total_loc: 0, total_functions: 0, languages: [], findings_progress: { processed: 38, total: 112 } },
  severity_counts: { critical: 2, high: 5, medium: 12, low: 3 },
};

describe('VerifyingPanel', () => {
  test('renders the processed/total count, ETA label, and severity tally', () => {
    render(
      <VerifyingPanel
        scan={base}
        elapsedLabel="9m 04s"
        eta={{ ready: true, label: '~24 min left · 1.4/min avg', ratePerMinute: 1.4 }}
        recentFindings={[]}
        newFindingIds={new Set()}
      />
    );
    expect(screen.getByText('38 of 112 verified')).toBeInTheDocument();
    expect(screen.getByText('~24 min left · 1.4/min avg')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
  });
});
