import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { findingService } from '@/services/finding.service';
import type { ScanDetails } from '@/types/scan';
import type { FindingDetails } from '@/types/finding';
import { computeEta, pushEtaSample, type EtaResult, type EtaSample } from '@/lib/scan-eta';

const FEED_POLL_MS = 2500;
const FEED_LIMIT = 8;

export interface ScanProgressState {
  eta: EtaResult;
  recentFindings: FindingDetails[];
  newFindingIds: Set<string>;
}

/**
 * Drives the live-verification UI: a rolling-rate ETA off
 * metrics.findings_progress, and a polled feed of the newest persisted
 * findings for this scan. The findings poll only runs once verification has
 * actually begun (findings_progress present) -- detection has no per-file
 * signal to poll for (see design doc), so there's nothing useful to fetch
 * before then.
 */
export function useScanProgress(scan: ScanDetails): ScanProgressState {
  const processed = scan.metrics?.findings_progress?.processed;
  const total = scan.metrics?.findings_progress?.total ?? 0;
  const verifying = scan.status === 'in_progress' && processed !== undefined;

  const [samples, setSamples] = useState<EtaSample[]>([]);
  const lastProcessedRef = useRef<number | undefined>(undefined);
  const seenIdsRef = useRef<Set<string>>(new Set());
  const [newFindingIds, setNewFindingIds] = useState<Set<string>>(new Set());

  // Reset accumulated state when switching to a different scan, so navigating
  // between two scan pages doesn't carry stale samples/ids over.
  useEffect(() => {
    setSamples([]);
    lastProcessedRef.current = undefined;
    seenIdsRef.current = new Set();
    setNewFindingIds(new Set());
  }, [scan.id]);

  useEffect(() => {
    if (!verifying || processed === undefined) return;
    if (lastProcessedRef.current === processed) return; // same poll, nothing new
    lastProcessedRef.current = processed;
    setSamples((prev) => pushEtaSample(prev, { timestamp: Date.now(), processed }));
  }, [verifying, processed]);

  const { data } = useQuery({
    queryKey: ['findings', 'recent', scan.id],
    queryFn: () => findingService.getFindingsByScan(scan.id, { limit: FEED_LIMIT, sort: '-created_at' }),
    enabled: verifying,
    refetchInterval: verifying ? FEED_POLL_MS : false,
    refetchIntervalInBackground: true,
  });

  const recentFindings = data?.findings ?? [];

  useEffect(() => {
    if (recentFindings.length === 0) return;
    const freshIds = new Set(
      recentFindings.map((f) => f.id).filter((id) => !seenIdsRef.current.has(id))
    );
    if (freshIds.size === 0) return;
    freshIds.forEach((id) => seenIdsRef.current.add(id));
    setNewFindingIds(freshIds);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recentFindings]);

  const eta = computeEta(samples, total);

  return { eta, recentFindings, newFindingIds };
}
