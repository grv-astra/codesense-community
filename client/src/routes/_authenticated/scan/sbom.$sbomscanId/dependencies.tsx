import { createFileRoute, useParams } from '@tanstack/react-router';
import { SbomDependenciesTable } from '@/components/update/sbom-dependencies-table';
import { useTableQueryState } from '@/hooks/use-table-query-state';

export const Route = createFileRoute(
  '/_authenticated/scan/sbom/$sbomscanId/dependencies',
)({
  component: RouteComponent,
})

function RouteComponent() {
  const { sbomscanId } = useParams({ from: '/_authenticated/scan/sbom/$sbomscanId/dependencies' });
  const { page, search, setPage, setSearch } = useTableQueryState();

  return (
    <SbomDependenciesTable
      scanId={sbomscanId}
      page={page}
      search={search}
      onPageChange={setPage}
      onSearchChange={setSearch}
    />
  );
}
