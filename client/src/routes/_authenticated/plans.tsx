import { createFileRoute } from '@tanstack/react-router';
import { useEditionsCatalog } from '@/hooks/use-edition';
import { PlansComparison } from '@/components/molecule/plans-comparison';
import { DotsLoader } from '@/components/atomic/loader';

export const Route = createFileRoute('/_authenticated/plans')({
  component: PlansPage,
});

function PlansPage() {
  const { data, isLoading, isError, refetch } = useEditionsCatalog();

  return (
    <div className="mx-auto max-w-5xl">
      <div className="mb-4">
        <h1 className="text-xl font-semibold text-foreground">Plans</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {data
            ? `You're on the ${data.active.edition.charAt(0).toUpperCase()}${data.active.edition.slice(1)} plan.`
            : 'Compare Community, Pro and Enterprise.'}{' '}
          The plan is set at deployment time — contact your CodeSense administrator to change it.
        </p>
      </div>

      {isLoading && (
        <div className="flex justify-center py-16">
          <DotsLoader />
        </div>
      )}

      {isError && !isLoading && (
        <div className="rounded-md border border-border bg-card p-6 text-center text-sm text-muted-foreground">
          Couldn&apos;t load plan information.{' '}
          <button className="text-brand-red underline" onClick={() => refetch()}>
            Retry
          </button>
        </div>
      )}

      {data && !isLoading && <PlansComparison catalog={data} />}
    </div>
  );
}
