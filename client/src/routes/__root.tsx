import { createRootRoute, Outlet } from '@tanstack/react-router'
import { QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from "@/components/atomic/sonner"
import { queryClient } from '@/lib/query-client';
import { useAssetSetup } from '@/hooks/use-asset-setup';
import { useActivation } from '@/hooks/use-activation';
import { FirstRunSetup } from '@/components/setup/FirstRunSetup';
import { ActivationGate } from '@/components/setup/ActivationGate';
import { CheckingActivation } from '@/components/setup/CheckingActivation';
import { RouteError } from '@/components/molecule/route-error';

function RootComponent() {
  const assetSetup = useAssetSetup();
  const activation = useActivation(assetSetup.status === 'ready');

  let body: React.ReactNode;
  if (assetSetup.status !== 'ready') {
    body = <FirstRunSetup state={assetSetup} />;
  } else if (activation.state.status === 'locked') {
    body = <ActivationGate error={activation.error} submitting={activation.submitting} onSubmit={activation.submit} />;
  } else if (activation.state.status === 'checking') {
    body = <CheckingActivation />; // loading state, not a login-page flash
  } else {
    body = <Outlet />;
  }

  return (
    <QueryClientProvider client={queryClient}>
      {body}
      <Toaster />
    </QueryClientProvider>
  );
}

export const Route = createRootRoute({
  component: RootComponent,
  errorComponent: RouteError,
})
