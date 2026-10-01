/**
 * Converts an ISO timestamp with microseconds to a human-readable IST format.
 *
 * @param isoTimestamp - A timestamp like "2025-07-27T14:51:36.689000"
 * @param options - Optional Intl.DateTimeFormat options (only affects month/day/year formatting)
 * @returns A readable date string in IST, e.g., "July 27, 2025, 8:21:36 PM IST"
 */
export function formatTimestamp(
  isoTimestamp: string | undefined | null,
  options: Intl.DateTimeFormatOptions = {}
): string {
  if (!isoTimestamp || typeof isoTimestamp !== 'string') return '';

  // The backend emits ISO 8601 with microseconds AND a timezone offset, e.g.
  // "2026-06-04T11:48:55.332702+00:00". Trim sub-millisecond digits (JS Date
  // only handles milliseconds) WITHOUT touching the trailing offset, so the
  // value still parses. A bare timestamp with no offset is parsed as-is.
  const normalized = isoTimestamp.replace(/(\.\d{3})\d+/, '$1');
  const date = new Date(normalized);

  if (isNaN(date.getTime())) return '';

  // Render in IST regardless of the host machine's timezone. Using Intl with an
  // explicit timeZone avoids the previous double-offset bug (manually adding
  // 5.5h and then reading local-time getters).
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    ...options,
  })
    .formatToParts(date)
    .reduce<Record<string, string>>((acc, p) => {
      acc[p.type] = p.value;
      return acc;
    }, {});

  return ` ${parts.hour}:${parts.minute} - ${parts.month}. ${parts.day}, ${parts.year}`;
}

/**
 * Duration string ("2h 15m", "3m 42s", "12s") between a scan's created_at and
 * its end_time -- or "now" for a still-running scan (in_progress/queued). A
 * terminal scan (failed/cancelled/interrupted) with no recorded end_time has
 * an unknown duration, not "however long ago it was created", so that case
 * returns '—' rather than guessing.
 */
export function formatDuration(scan: { created_at: string; end_time: string | null; status: string }): string {
  if (!scan.created_at) return '—';
  if (!scan.end_time && scan.status !== 'in_progress' && scan.status !== 'queued') return '—';
  const start = new Date(scan.created_at.replace(/(\.\d{3})\d+/, '$1'));
  if (isNaN(start.getTime())) return '—';
  const end = scan.end_time ? new Date(scan.end_time.replace(/(\.\d{3})\d+/, '$1')) : new Date();
  const totalSeconds = Math.max(0, Math.floor((end.getTime() - start.getTime()) / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}
