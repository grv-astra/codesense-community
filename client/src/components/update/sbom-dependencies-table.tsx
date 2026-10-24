import { SecurityBadge } from '@/components/atomic/enum-badge';
import { GenericTable, type TableColumn } from '@/components/molecule/generic-table';
import { useSbomDependencies } from '@/hooks/use-finding';
import type { SbomDependency } from '@/types/finding';

const PAGE_SIZE = 10;

interface Props {
  scanId: string;
  page: number;
  search: string;
  onPageChange: (page: number) => void;
  onSearchChange: (query: string) => void;
}

/** Every package of an SBOM scan, riskiest first, with its worst vulnerability and licenses. */
export function SbomDependenciesTable({ scanId, page, search, onPageChange, onSearchChange }: Props) {
  const { data, isLoading, error } = useSbomDependencies(scanId, { page, limit: PAGE_SIZE, search });

  const columns: TableColumn<SbomDependency>[] = [
    {
      key: 'srNo',
      header: 'Sr No.',
      render: (_, index: number) => (page - 1) * PAGE_SIZE + index + 1,
      width: '80px',
    },
    { key: 'package_name', header: 'Package Name' },
    { key: 'dependence_version', header: 'Version' },
    { key: 'package_type', header: 'Type' },
    {
      key: 'risk_rating',
      header: 'Risk Rating',
      render: (dep) =>
        dep.risk_rating === 'none' ? (
          <span className="text-xs text-muted-foreground">None</span>
        ) : (
          <SecurityBadge severity={dep.risk_rating} />
        ),
    },
    { key: 'risk_summary', header: 'Risk Summary' },
    {
      key: 'licenses',
      header: 'Licenses',
      render: (dep) => (dep.licenses.length ? dep.licenses.join(', ') : '—'),
    },
  ];

  return (
    <div className="space-y-3">
      {data && !data.inventory_complete && (
        <p className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200">
          The SBOM file for this scan is no longer available, so only packages that have a finding are
          listed here.
        </p>
      )}
      <GenericTable
        data={data?.dependencies ?? []}
        columns={columns}
        title="Dependencies List"
        loading={isLoading}
        error={error?.message}
        pagination={{ enabled: true, pageSize: PAGE_SIZE, showInfo: true, showPageNumbers: true }}
        totalItems={data?.pagination.total ?? 0}
        currentPage={page}
        onPageChange={onPageChange}
        emptyMessage="No dependencies found"
        rowClassName={() => 'hover:bg-gray-50 hover:dark:bg-gray-300/10'}
        enableColumnFilter
        filterButtonVariant="outline"
        onSearchChange={onSearchChange}
        searchPlaceholder="Search packages..."
        initialQuery={search}
      />
    </div>
  );
}
