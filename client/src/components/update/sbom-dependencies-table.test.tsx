import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { SbomDependenciesResponse } from '@/types/finding';

const { useSbomDependencies } = vi.hoisted(() => ({ useSbomDependencies: vi.fn() }));
vi.mock('@/hooks/use-finding', () => ({ useSbomDependencies }));

import { SbomDependenciesTable } from './sbom-dependencies-table';

const response = (overrides: Partial<SbomDependenciesResponse> = {}): SbomDependenciesResponse => ({
  dependencies: [
    { id: 's:0', package_name: 'lodash', dependence_version: '4.17.15', package_type: 'npm',
      risk_rating: 'critical', risk_summary: '2 vulnerabilities (1 critical, 1 high)', vulnerabilities: 2,
      licenses: ['MIT', 'ISC'] },
    { id: 's:1', package_name: 'express', dependence_version: '4.18.2', package_type: 'npm',
      risk_rating: 'none', risk_summary: 'No known vulnerabilities.', vulnerabilities: 0, licenses: [] },
  ],
  pagination: { total: 2, page: 1, limit: 10, pages: 1 },
  inventory_complete: true,
  ...overrides,
});

const props = { scanId: 's', page: 1, search: '', onPageChange: vi.fn(), onSearchChange: vi.fn() };

describe('SbomDependenciesTable', () => {
  beforeEach(() => vi.clearAllMocks());

  it('asks the server for this scan, page and search', () => {
    useSbomDependencies.mockReturnValue({ data: response(), isLoading: false, error: null });
    render(<SbomDependenciesTable {...props} page={3} search="lod" />);
    expect(useSbomDependencies).toHaveBeenCalledWith('s', { page: 3, limit: 10, search: 'lod' });
  });

  it("renders the scan's real packages, not sample data", () => {
    useSbomDependencies.mockReturnValue({ data: response(), isLoading: false, error: null });
    render(<SbomDependenciesTable {...props} />);
    expect(screen.getByText('lodash')).toBeInTheDocument();
    expect(screen.getByText('2 vulnerabilities (1 critical, 1 high)')).toBeInTheDocument();
    expect(screen.getByText('MIT, ISC')).toBeInTheDocument();
    expect(screen.getByText('express')).toBeInTheDocument();
    expect(screen.getByText('No known vulnerabilities.')).toBeInTheDocument();
    expect(screen.queryByText('jsonwebtoken')).not.toBeInTheDocument();
    expect(screen.queryByText(/no longer available/i)).not.toBeInTheDocument();
  });

  it('says so when only packages with findings could be listed', () => {
    useSbomDependencies.mockReturnValue({ data: response({ inventory_complete: false }), isLoading: false, error: null });
    render(<SbomDependenciesTable {...props} />);
    expect(screen.getByText(/SBOM file for this scan is no longer available/i)).toBeInTheDocument();
  });

  it('shows the empty message when the scan has no packages', () => {
    useSbomDependencies.mockReturnValue({
      data: response({ dependencies: [], pagination: { total: 0, page: 1, limit: 10, pages: 0 } }),
      isLoading: false, error: null,
    });
    render(<SbomDependenciesTable {...props} />);
    expect(screen.getByText('No dependencies found')).toBeInTheDocument();
  });
});
