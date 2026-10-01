import { describe, it, expect } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import { PlansComparison } from './plans-comparison';
import type {
  EditionCatalogEntry,
  EditionsCatalog,
  Edition,
  EditionFeatures,
  EditionLimits,
} from '@/types/edition';

const FEATURE_KEYS: (keyof EditionFeatures)[] = [
  'llm_analysis', 'sbom_signing', 'license_compliance', 'api_access',
  'incremental_scan', 'github_scan', 'sso', 'audit_log',
];
const LIMIT_KEYS: (keyof EditionLimits)[] = [
  'projects', 'code_scans_per_window', 'sbom_scans_per_window',
  'window_days', 'max_codebase_mb', 'seats',
];

function entry(
  edition: Edition,
  label: string,
  tier: 'low' | 'mid' | 'high',
  feat: Partial<EditionFeatures>,
  lim: Partial<EditionLimits>,
): EditionCatalogEntry {
  return {
    edition,
    label,
    model_tier: tier,
    features: Object.fromEntries(FEATURE_KEYS.map((k) => [k, !!feat[k]])) as EditionFeatures,
    limits: {
      projects: null, code_scans_per_window: null, sbom_scans_per_window: null,
      window_days: 30, max_codebase_mb: null, seats: null, ...lim,
    },
  };
}

function catalog(activeEdition: Edition, over = false): EditionsCatalog {
  return {
    feature_keys: FEATURE_KEYS,
    limit_keys: LIMIT_KEYS,
    editions: [
      entry('community', 'Community', 'low',
        { github_scan: true },
        { projects: 1, code_scans_per_window: 25, sbom_scans_per_window: 25, max_codebase_mb: 250, seats: 3 }),
      entry('pro', 'Pro', 'mid',
        { llm_analysis: true, sbom_signing: true, api_access: true, incremental_scan: true, github_scan: true, license_compliance: true },
        { projects: 10, code_scans_per_window: 500, sbom_scans_per_window: 500, max_codebase_mb: 2048, seats: 25 }),
      entry('enterprise', 'Enterprise', 'high',
        Object.fromEntries(FEATURE_KEYS.map((k) => [k, true])) as EditionFeatures,
        {}),
    ],
    active: {
      edition: activeEdition,
      source: 'default',
      customer: '',
      expires_at: null,
      warnings: [],
      usage: { projects: over ? 5 : 0, code_scans_in_window: 0, sbom_scans_in_window: 0, seats: over ? 5 : 1 },
    },
  };
}

describe('PlansComparison', () => {
  it('renders all three plans with the active one marked', () => {
    render(<PlansComparison catalog={catalog('community')} />);
    expect(screen.getByText('Community')).toBeInTheDocument();
    expect(screen.getByText('Pro')).toBeInTheDocument();
    expect(screen.getByText('Enterprise')).toBeInTheDocument();
    expect(screen.getByText(/active plan/i)).toBeInTheDocument();
  });

  it('shows feature rows and Enterprise unlimited limits', () => {
    render(<PlansComparison catalog={catalog('enterprise')} />);
    expect(screen.getByText('AI verification & enrichment')).toBeInTheDocument();
    expect(screen.getByText('SSO / SAML / OIDC')).toBeInTheDocument();
    // Enterprise column: every limit reads "Unlimited"
    expect(screen.getAllByText('Unlimited').length).toBeGreaterThanOrEqual(5);
  });

  it('renders live usage under the active column and flags over-limit', () => {
    render(<PlansComparison catalog={catalog('community', true)} />);
    // community: projects 5/1 and seats 5/3 are both over -> at least one "over limit" note
    const over = screen.getAllByText(/5 in use — over limit/i);
    expect(over.length).toBeGreaterThanOrEqual(1);
  });

  it('shows a warning banner when the active entitlement has warnings', () => {
    const c = catalog('community');
    c.active.warnings = ['entitlements expired on 2026-01-01; defaulting to Community'];
    render(<PlansComparison catalog={c} />);
    expect(screen.getByText(/entitlements expired/i)).toBeInTheDocument();
  });

  it('formats max codebase size in MB / GB', () => {
    render(<PlansComparison catalog={catalog('pro')} />);
    expect(screen.getByText('250 MB')).toBeInTheDocument();   // community
    expect(screen.getByText('2 GB')).toBeInTheDocument();     // pro (2048 MB)
  });
});
