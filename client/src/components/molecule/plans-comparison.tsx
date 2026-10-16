import { Check, Minus } from 'lucide-react';
import { cn } from '@/lib/utils';
import type {
  Edition,
  EditionCatalogEntry,
  EditionFeatures,
  EditionLimits,
  EditionsCatalog,
} from '@/types/edition';

const FEATURE_LABELS: Record<keyof EditionFeatures, string> = {
  llm_analysis: 'Bundled local AI model (verification & enrichment)',
  byo_llm: 'Connect your own LLM (verification)',
  sbom_signing: 'SBOM signing (cosign)',
  license_compliance: 'License compliance (grant)',
  api_access: 'REST API / CI-CD keys',
  incremental_scan: 'Incremental re-scans',
  github_scan: 'GitHub repo scanning',
  sso: 'SSO / SAML / OIDC',
  audit_log: 'Audit logging',
};

// Limits shown as their own rows (window_days is folded into the scan labels).
const LIMIT_ROWS: { key: keyof EditionLimits; label: string }[] = [
  { key: 'projects', label: 'Projects' },
  { key: 'code_scans_per_window', label: 'Code scans / 30 days' },
  { key: 'sbom_scans_per_window', label: 'SBOM scans / 30 days' },
  { key: 'max_codebase_mb', label: 'Max codebase size' },
  { key: 'seats', label: 'User seats' },
];

// limit key -> the matching field in `active.usage` (max_codebase_mb has none).
const USAGE_FIELD: Partial<
  Record<keyof EditionLimits, 'projects' | 'code_scans_in_window' | 'sbom_scans_in_window' | 'seats'>
> = {
  projects: 'projects',
  code_scans_per_window: 'code_scans_in_window',
  sbom_scans_per_window: 'sbom_scans_in_window',
  seats: 'seats',
};

const MODEL_LABEL: Record<'low' | 'mid' | 'high', string> = {
  low: 'Compact (1.5B)',
  mid: 'Standard (7B)',
  high: 'Large (14B)',
};

function toneFor(edition: Edition): string {
  if (edition === 'enterprise')
    return 'bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-200';
  if (edition === 'pro')
    return 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200';
  return 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300';
}

function formatLimit(key: keyof EditionLimits, value: number | null): string {
  if (value === null || value === undefined) return 'Unlimited';
  if (key === 'max_codebase_mb') {
    return value >= 1024 ? `${(value / 1024).toFixed(value % 1024 === 0 ? 0 : 1)} GB` : `${value} MB`;
  }
  return String(value);
}

function FeatureCell({ on }: { on: boolean }) {
  return on ? (
    <Check className="mx-auto h-4 w-4 text-emerald-600 dark:text-emerald-400" aria-label="included" />
  ) : (
    <Minus className="mx-auto h-4 w-4 text-muted-foreground/40" aria-label="not included" />
  );
}

interface Props {
  catalog: EditionsCatalog;
}

export function PlansComparison({ catalog }: Props) {
  const { editions, feature_keys, active } = catalog;
  const isActive = (e: EditionCatalogEntry) => e.edition === active.edition;

  const usageFor = (limitKey: keyof EditionLimits): number | undefined => {
    const f = USAGE_FIELD[limitKey];
    return f ? (active.usage[f] as number | undefined) : undefined;
  };

  const orderedFeatureKeys = (feature_keys && feature_keys.length
    ? feature_keys
    : (Object.keys(FEATURE_LABELS) as (keyof EditionFeatures)[]));

  return (
    <div className="w-full overflow-x-auto">
      <table className="w-full min-w-[640px] border-separate border-spacing-0 text-sm">
        <thead>
          <tr>
            <th className="w-[220px] p-3 text-left align-bottom font-medium text-muted-foreground">
              <div className="text-base font-semibold text-foreground">Plans</div>
              <div className="mt-1 text-xs font-normal">
                {active.source === 'signed' && active.customer
                  ? `Licensed to ${active.customer}`
                  : active.source === 'env'
                    ? 'Set via CODESENSE_EDITION'
                    : active.source === 'signed'
                      ? 'Signed entitlement'
                      : active.source === 'error'
                        ? 'Resolution failed — showing Community'
                        : 'No entitlement file — default'}
              </div>
            </th>
            {editions.map((e) => (
              <th
                key={e.edition}
                className={cn(
                  'p-3 text-center align-bottom border-t border-x rounded-t-lg',
                  isActive(e)
                    ? 'border-brand-red/60 bg-brand-red/5'
                    : 'border-transparent',
                )}
              >
                <div className="flex flex-col items-center gap-1.5">
                  <span className={cn('rounded px-2 py-0.5 text-xs font-medium', toneFor(e.edition))}>
                    {e.label}
                  </span>
                  {isActive(e) && (
                    <span className="rounded bg-brand-red px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-white">
                      Active plan
                    </span>
                  )}
                  <span className="text-[11px] text-muted-foreground">
                    {MODEL_LABEL[e.model_tier]}
                  </span>
                  {isActive(e) && active.expires_at && (
                    <span className="text-[11px] text-muted-foreground">
                      Expires {new Date(active.expires_at).toLocaleDateString()}
                    </span>
                  )}
                </div>
              </th>
            ))}
          </tr>
        </thead>

        <tbody>
          <tr>
            <td
              colSpan={editions.length + 1}
              className="px-3 pb-1 pt-4 text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground"
            >
              Features
            </td>
          </tr>
          {orderedFeatureKeys.map((fk) => (
            <tr key={fk} className="border-b border-border/50">
              <td className="border-b border-border/50 p-3 text-foreground">
                {FEATURE_LABELS[fk] ?? fk}
              </td>
              {editions.map((e) => (
                <td
                  key={e.edition}
                  className={cn(
                    'border-b border-border/50 border-x p-3 text-center',
                    isActive(e) ? 'border-x-brand-red/60 bg-brand-red/5' : 'border-x-transparent',
                  )}
                >
                  <FeatureCell on={!!e.features[fk]} />
                </td>
              ))}
            </tr>
          ))}

          <tr>
            <td
              colSpan={editions.length + 1}
              className="px-3 pb-1 pt-5 text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground"
            >
              Limits
            </td>
          </tr>
          {LIMIT_ROWS.map(({ key, label }) => {
            const used = usageFor(key);
            return (
              <tr key={key}>
                <td className="border-b border-border/50 p-3 text-foreground">{label}</td>
                {editions.map((e) => {
                  const limitVal = e.limits[key];
                  const over =
                    isActive(e) &&
                    used !== undefined &&
                    limitVal !== null &&
                    limitVal !== undefined &&
                    used >= (limitVal as number);
                  return (
                    <td
                      key={e.edition}
                      className={cn(
                        'border-b border-border/50 border-x p-3 text-center',
                        isActive(e) ? 'border-x-brand-red/60 bg-brand-red/5' : 'border-x-transparent',
                      )}
                    >
                      <div className="font-medium text-foreground">
                        {formatLimit(key, limitVal as number | null)}
                      </div>
                      {isActive(e) && used !== undefined && (
                        <div
                          className={cn(
                            'text-[11px]',
                            over ? 'font-semibold text-brand-red' : 'text-muted-foreground',
                          )}
                        >
                          {used} in use{over ? ' — over limit' : ''}
                        </div>
                      )}
                    </td>
                  );
                })}
              </tr>
            );
          })}

          <tr>
            <td className="p-3 text-foreground">AI model</td>
            {editions.map((e) => (
              <td
                key={e.edition}
                className={cn(
                  'border-x p-3 text-center border-b rounded-b-lg',
                  isActive(e)
                    ? 'border-brand-red/60 bg-brand-red/5'
                    : 'border-x-transparent border-b-transparent',
                )}
              >
                <span className="text-foreground">{MODEL_LABEL[e.model_tier]}</span>
              </td>
            ))}
          </tr>
        </tbody>
      </table>

      {active.warnings.length > 0 && (
        <div className="mt-4 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200">
          {active.warnings.map((w, i) => (
            <div key={i}>⚠️ {w}</div>
          ))}
        </div>
      )}
    </div>
  );
}
