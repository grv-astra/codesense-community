import { render, screen } from '@testing-library/react';
import { describe, test, expect } from 'vitest';
import { AnalyzingPanel } from './AnalyzingPanel';
import type { ScanDetails } from '@/types/scan';

const base: ScanDetails = {
  id: 's1', project_id: 'p1', scan_name: 'S', status: 'in_progress',
  findings: 0, total_files: 247, files_scanned: 0,
  created_at: '2026-08-25T00:00:00.000Z', end_time: null, triggered_by: 'u',
  metrics: { total_loc: 0, total_functions: 0, languages: ['python', 'ruby'] },
};

describe('AnalyzingPanel', () => {
  test('shows file count and languages, no incremental banner by default', () => {
    render(<AnalyzingPanel scan={base} elapsedLabel="0m 41s" />);
    expect(screen.getByText('Scanning 247 files')).toBeInTheDocument();
    expect(screen.getByText('python · ruby')).toBeInTheDocument();
    expect(screen.queryByText(/Incremental scan/)).not.toBeInTheDocument();
  });

  test('shows the incremental-scan banner when incremental_info says so', () => {
    render(
      <AnalyzingPanel
        scan={{ ...base, incremental_info: { is_incremental: true, unchanged: 142, changed: 12 } }}
        elapsedLabel="0m 41s"
      />
    );
    expect(screen.getByText(/Incremental scan/)).toBeInTheDocument();
    expect(screen.getByText(/142 files unchanged/)).toBeInTheDocument();
    expect(screen.getByText(/12 being re-analyzed/)).toBeInTheDocument();
  });

  test('falls back to a generic label when total_files is not yet known', () => {
    render(<AnalyzingPanel scan={{ ...base, total_files: 0 }} elapsedLabel="0m 05s" />);
    expect(screen.getByText('Analyzing source…')).toBeInTheDocument();
  });
});
