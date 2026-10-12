import { AxiosError } from 'axios';
import { toast } from 'sonner';

/** Best human-readable message for a failed API call: the server's `error` / `detail` /
 * `message` when it sent one (e.g. "Project limit reached for this edition (1)..."),
 * else `fallback`. */
export function apiErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof AxiosError && error.response) {
    const data = error.response.data as { error?: unknown; detail?: unknown; message?: unknown } | undefined;
    for (const v of [data?.error, data?.detail, data?.message]) {
      if (typeof v === 'string' && v.trim()) return v;
    }
  }
  return fallback;
}

/** Log and surface a failed form action. Forms used to only `console.error`, so a
 * rejected request (edition limit, validation, server error) looked like a dead button. */
export function toastApiError(title: string, error: unknown, fallback = 'An unexpected error occurred.'): void {
  console.error(title, error);
  toast.error(title, { description: apiErrorMessage(error, fallback) });
}
