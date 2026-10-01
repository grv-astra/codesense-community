import { useRouter, type ErrorComponentProps } from '@tanstack/react-router';
import { RefreshCw } from 'lucide-react';
import { Button } from '@/components/atomic/button';
import { Card, CardContent, CardHeader } from '@/components/atomic/card';

// Shared fallback for route `errorComponent`s (and the root). A thrown loader or
// a render error lands here instead of a blank screen; "Try again" invalidates
// the router so the loader re-runs, then resets the error boundary.
export function RouteError({ error, reset }: ErrorComponentProps) {
  const router = useRouter();

  const message =
    error instanceof Error && error.message
      ? error.message
      : 'Something went wrong while loading this page.';

  return (
    <div className="flex min-h-[60vh] items-center justify-center p-4">
      <Card className="w-full max-w-md text-center">
        <CardHeader>
          <div className="mx-auto flex size-12 items-center justify-center rounded-full bg-secondary">
            <RefreshCw className="size-5 text-muted-foreground" />
          </div>
          <h1 className="mt-3 text-lg font-semibold">Couldn't load this page</h1>
        </CardHeader>
        <CardContent>
          <p className="mb-5 text-sm text-muted-foreground break-words">{message}</p>
          <div className="flex justify-center gap-3">
            <Button
              variant="outline"
              onClick={() => {
                void router.invalidate();
                reset();
              }}
            >
              <RefreshCw className="size-4" />
              Try again
            </Button>
            <Button onClick={() => router.navigate({ to: '/' })}>Go to dashboard</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
