import { QueryCache, QueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';

// Single app-wide client. Exported (rather than created inline in __root) so
// route `loader`s can call `queryClient.ensureQueryData(...)` to start a fetch
// on navigation intent instead of after the component mounts.
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60_000, // 1 min — served from cache without a refetch
      gcTime: 5 * 60_000, // keep unused data 5 min before eviction
      retry: 1,
      // Desktop app in a Tauri webview: refetching every time the window
      // regains focus is pure noise. Reconnect refetch stays on for the
      // LAN-served case.
      refetchOnWindowFocus: false,
      refetchOnReconnect: true,
    },
  },
  // One place to surface unexpected fetch failures. Only fires a toast when the
  // query already had data on screen (a background refetch failed) — cold-load
  // failures are the route `errorComponent`'s job, not a toast's.
  queryCache: new QueryCache({
    onError: (error, query) => {
      if (query.state.data !== undefined) {
        const status =
          typeof error === 'object' && error !== null && 'response' in error
            ? (error as { response?: { status?: number } }).response?.status
            : undefined;
        if (status !== 401) {
          toast.error("Couldn't refresh — showing the last loaded data.");
        }
      }
    },
  }),
});
