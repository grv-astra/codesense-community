import { useQuery } from '@tanstack/react-query';
import { editionService } from '@/services/edition.service';
import type { EditionStatus, EditionFeatures } from '@/types/edition';

export function useEditionStatus() {
  return useQuery({
    queryKey: ['edition'],
    queryFn: () => editionService.getStatus(),
    staleTime: 60 * 1000,
  });
}

export function useEditionsCatalog() {
  return useQuery({
    queryKey: ['editions-catalog'],
    queryFn: () => editionService.getCatalog(),
    staleTime: 5 * 60 * 1000,   // catalog is static; active/usage moves slowly
  });
}

export function hasFeature(s: EditionStatus | undefined, key: keyof EditionFeatures): boolean {
  return !!s?.features?.[key];
}

// Limit keys that have a matching entry in EditionStatus['usage']. window_days and
// max_codebase_mb are limits too, but there's nothing in `usage` to compare them
// against, so limitReached only accepts the ones that can actually be "reached".
export type QuotaLimitKey =
  | 'projects'
  | 'code_scans_per_window'
  | 'sbom_scans_per_window'
  | 'seats';

const USAGE_KEY: Record<QuotaLimitKey, keyof EditionStatus['usage']> = {
  projects: 'projects',
  code_scans_per_window: 'code_scans_in_window',
  sbom_scans_per_window: 'sbom_scans_in_window',
  seats: 'seats',
};

export function limitReached(s: EditionStatus | undefined, key: QuotaLimitKey): boolean {
  if (!s) return false;
  const lim = s.limits[key];
  if (lim === null || lim === undefined) return false;      // unlimited
  const uKey = USAGE_KEY[key];
  return s.usage[uKey] >= (lim as number);
}
