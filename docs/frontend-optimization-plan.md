# Frontend Optimization Plan

**Branch:** `feat/frontend-optimization` (off `origin/main` @ `b90290c`)
**Date:** 2026-09-08
**Scope:** bundle/load perf · data layer · architecture/scalability · UI/UX polish
**Cadence:** plan approved first, then execute phase by phase; each phase is an
independent, revertable set of commits.

---

## STATUS — 2026-09-08 (session 1)

Committed on `feat/frontend-optimization` (not pushed):

| commit | phase | verified |
|---|---|---|
| `28e3046` | 1 — vendor chunk split, recharts deferred, woff2 fonts, visualizer | prod build + login network trace + live dashboard |
| `aac374f` | 2 — single axios instance, shared QueryClient, dashboard loader, error boundaries, polling hygiene | login + dashboard live (loader = no waterfall) |
| `72d7e94` | 3.3 GenericTable memo + `<TablePagination>`/`useColumnVisibility`; 3.5 eslint scoping | tsc / build / test |
| `340b988` | 3 — vite dep-scan scoped to app entry (real dev bug), drop dead next-themes | vite log clean |
| `127ebc2` | 3.1 — app shell → CSS grid | live scroll test: header+sidebar fixed, content scrolls |
| `7149713` | revert scan-detail route loader (stuck blank+spinner on not-found id in dev) | scan detail + dashboard live |

**Metrics:** eager JS 954 KB / 292 KB gzip → ~632 KB / ~198 KB gzip; recharts (113 KB gzip)
out of first load. `npm test` 59/59. `tsc -b` 97 → **93** (still 93 pre-existing errors on
`main` — see below). `vite build` clean. Dev-server login `grvchindarkar@gmail.com` (password
with the user).

---

## STATUS — 2026-09-08 (session 2 — 3.2 + Phase 4)

On `feat/frontend-optimization`, continuing from `0349877`:

| area | what changed | verified |
|---|---|---|
| **3.2 token consolidation** | folded `client/tailwind.config.js` into `index.css` `@theme` (`primary-50..950`, `brand.{red,dark,light,white}`, `--font-custom`); deleted the file + `@config` line + the 8 hand-rolled `.brand-*` utilities | `build` clean · CSS diff: `primary-*`/`font-custom` identical, `brand-*` now resolves to the config hexes (was a cascade of oklch approximations + hexes) · light+dark smoke on 6 views |
| **Phase 4 tokens** | `index.css`: severity ramp (`--sev-critical/high/medium/low/info`, light + lifted-dark) + neutral graphite ramp (`--data-1..4`) + chart chrome vars, all mapped through `@theme inline` to `bg-sev-*`/`text-sev-*` utilities. `src/lib/chart-tokens.ts` — `useChartTokens()` reads them per theme for recharts. | `build` clean |
| **Phase 4 shell** | `components/charts/_chart-card.tsx` — `<ChartCard>` (flat `bg-card` + hairline border, no nested panel, no shadow) + `<ChartCardSkeleton>` (footprint-matched) + `<ChartEmpty>`. `components/atomic/skeleton.tsx`. All 9 charts dropped their bespoke `dark:bg-[#…]` + `transition-colors duration-300` chrome for it. | render tests |
| **Phase 4 dashboard** | `routes/_authenticated/index.tsx` rebuilt on a 12-col grid: hero band (open-findings count in **ink**, no brand red, drawn *as* a stacked `<SeverityRamp>` + 30d trend delta) → severity breakdown / findings trend (col-6) → by-language / scan-throughput / scan-health (col-4) → top-CWEs (col-8) / top-projects (col-4) → recent-scans (col-12) → **demoted KPI strip** (col-12, thin). Per-card skeletons via `<Suspense>`; `pendingComponent` matches. | live smoke light+dark |
| **Phase 4 a11y** | global `:focus-visible` ring; `@media (prefers-reduced-motion: reduce)` kills transitions/animations app-wide; `<SeverityRamp>` bar has an `aria-label` distribution summary; trend range toggle is a labelled `role="group"` with `aria-pressed`. | — |
| **states** | every chart/list has an explicit `<ChartEmpty>` (recent-scans + "Start a scan" link); route load failure still `RouteError`. | render tests |
| **severity badges unified** | `enum-badge.tsx` `SecurityBadge`/`PriorityBadge` share one `SEVERITY_BADGE` map on `bg-sev-*/15 text-sev-* border-sev-*/35` (was `bg-red-100 …`, light-only — broken in dark). `UpdatedFinding.tsx` top-border accent → `border-t-sev-*`. `finding/sbom.$sbomfindingId.tsx` severity pill → `bg-sev-*/15 …`. Severity now reads identically across dashboard, tables, live feed and both detail pages. | live smoke: findings table + code/SBOM detail, both themes |

**Gate:** `npm test` **68/68** (was 59; +9 — `_chart-card`, `severity-ramp`, `count-by-severity`).
`tsc -b` **92** (down 1 from the 93 `main` baseline; 0 in touched files). `vite build` clean
(42s). Live smoke on the dev server: dashboard both themes, findings table, finding detail —
no regressions, console clean bar the pre-existing recharts `width(-1)` warning (now reduced —
the `<ChartCard>` bodies give `<ResponsiveContainer>` a real height).

**Carried / follow-ups:**
- Hero severity segments are display-only (no cross-project findings route to filter into yet).
- `client/src/components/update/FindingList.tsx` is **dead code** — a self-contained dummy-data
  table (`seedFindings`, 48 fake rows) imported nowhere. Left as-is; candidate for deletion.
- `count-by-severity.test.tsx` logs one jsdom `width(-1)` recharts warning (no layout engine) —
  cosmetic, test passes.

**Not done — still carried:**
- **3.4 feature-folder move** — deferred to its own session (decided session 1).

**Baseline debt discovered:** `origin/main`'s frontend has **~93 `tsc -b` errors** and ~3,000
eslint errors (mostly `no-explicit-any` + unused vars + stale route-path strings). `npm run
build` (esbuild, no typecheck) is clean. Per-phase gate this session was: `npm test` green +
`vite build` clean + no *new* tsc/lint errors in touched files + live smoke — not global-green.

---

## Baseline (measured — `vite build`, this checkout)

| Metric | Value |
|---|---|
| Eager JS before any route renders | **535 KB + 419 KB = 954 KB raw / ~292 KB gzip** (two undifferentiated `index-*.js`) |
| Largest chunk | 535 KB raw / 172 KB gzip — over Vite's 500 KB warning |
| App code vs vendor | fused in the same chunks (any app edit busts all 535 KB of cache) |
| Recharts (~130–160 KB gzip) | in the initial load path (dashboard statically imports all 9 chart components) |
| CSS | ~100 KB |
| Build time | 1m 21s |
| Route-level code splitting | working (`autoCodeSplitting: true`) |
| Error boundaries / Suspense | none in the app |
| axios instances | 11 (one per service subclass), 11 interceptor pairs |
| Fonts | 4 × `.ttf` (no `woff2`, no `font-display`) |
| Design tokens | defined twice — `index.css` `@theme` **and** CommonJS `tailwind.config.js` |
| Toast theme | `sonner` reads `next-themes` but no next-themes provider exists → toasts ignore dark mode |

---

## Phase 1 — Bundle & load performance
No behavior change, no UI change. Risk: very low. Verify with build output + visual smoke.

1. **Bundle visibility** — add `rollup-plugin-visualizer` (devDep) → `dist/stats.html` on build.
2. **Vendor `manualChunks`** in `vite.config.ts`: split `vendor-react`, `vendor-tanstack`,
   `vendor-charts` (recharts + d3 + victory-vendor), `vendor-radix`, `vendor-http`, `vendor-icons`.
   Target: no chunk > 120 KB gzip; app code separated from vendor.
3. **Lazy-load charts** — dashboard (`_authenticated/index.tsx`) converts its 9 chart imports to
   `React.lazy` behind a `<Suspense>` with per-card skeletons. Recharts then loads only on the
   dashboard, in parallel with the dashboard data fetch. Confirm devtools packages are `DEV`-only.
4. **Fonts** — convert the 4 `.ttf` faces to `.woff2`; `preload` the Regular weight in `index.html`;
   `font-display: swap`; fix the `'WF Visual Sans', sans-serif, Arial` mid-stack typo.

**Exit targets:** eager JS < 150 KB gzip (from 292) · largest chunk < 120 KB gzip (from 172) ·
recharts out of initial load · dashboard TTI (local throttled) ≥ 25% faster.

---

## Phase 2 — Data layer
Risk: low–medium. Covered by existing `npm test` + manual smoke.

1. **Single axios instance** — collapse the 11 `BaseApiClient` subclasses onto one module-level
   `apiClient` with interceptors registered once; services keep their exact public method surface
   (no call-site churn).
2. **QueryClient config** — keep `staleTime 60s`; add `gcTime: 5min`,
   `refetchOnWindowFocus: false` (Tauri webview — focus storms are noise), `refetchOnReconnect: true`;
   global `QueryCache.onError` → `sonner` toast (replaces scattered `console.error`).
3. **Polling hygiene** — `use-scans`: `refetchIntervalInBackground: true` → `false`
   (stop polling a hidden tab); keep 2.5s while visible + running.
4. **Route loaders** — `loader` + `queryClient.ensureQueryData` on the heaviest routes
   (dashboard, scan detail first; then project detail, findings list) to kill the
   mount → spinner → fetch waterfall; pair with `pendingComponent` skeletons.
5. **Error + Suspense boundaries** — top-level `ErrorBoundary` with a recoverable fallback +
   per-route `errorComponent` on data routes; Suspense fallbacks for lazy chunks.

**Exit:** `npm test` green · no waterfall on dashboard/scan-detail · hidden-tab network silent.

---

## Phase 3 — Architecture / scalability
Risk: medium (layout + file moves). Verify tsc + tests + visual smoke (light & dark).

1. **App shell → CSS grid** — `_authenticated.tsx`: replace `position: fixed` + `ml-64`/`left-64`/
   `mt-16` with `grid grid-cols-[var(--sidebar-w)_1fr] grid-rows-[4rem_1fr]`; only the content
   region scrolls; one source for the sidebar width. Responsive-ready.
2. **One design-token source** — fold `tailwind.config.js` into the `@theme` block in `index.css`
   (Tailwind v4 is CSS-first); delete the redundant hand-rolled `.text-brand-*` / `.bg-brand-*`
   utilities; standardize on the custom `use-theme` hook, fix `sonner`, drop `next-themes`.
3. **GenericTable** — `React.memo` the component; `useMemo` derived data
   (`baseData`, `visibleColumns`, page slice, page-number array); `useCallback` handlers;
   extract `<Pagination>` and a `useColumnVisibility` hook. ~523 → ~300 lines + 2 co-located files.
4. **Feature-folder the tree** *(high churn — explicit go/no-go)* —
   `src/features/{dashboard,scans,findings,projects,users,auth}/{components,hooks,api}`;
   rename `components/atomic` → `components/ui` (matches `components.json`); move each feature's
   service + hook + types next to its components. Done last, one feature at a time, or deferred.
5. **Tooling** — `eslint.config.js`: `ecmaVersion 2020 → 2022`, add `jsx-a11y` + `import`
   (order, no-cycle); `tsconfig.app.json`: add `noImplicitOverride`,
   `forceConsistentCasingInFileNames`.

---

## Phase 4 — UI/UX polish
Needs your review. Per the frontend-design brief I produce a short token plan
(color / type / layout / principles), check it against the brief for generic tells, then apply.

1. **Design direction pass** — current identity: red `#bf0000` + greys + Chakra Petch display.
   Candidate work: dashboard on a real 12-col hierarchy (KPIs → severity → trends → activity)
   instead of uniform `grid-cols-3` rows where every card weighs the same; a shared `<ChartCard>`
   shell; all chart colors through `--chart-1..5`; one severity palette
   (critical/high/medium/low) used identically across badges, bars, donut.
2. **States** — skeletons that match final layout (no layout-shift dots-loader); empty states that
   direct action ("No scans yet — start one"); consistent error cards.
3. **Accessibility floor** — `:focus-visible` rings, `prefers-reduced-motion`, contrast check on
   red-on-grey, real `<label>` / `aria` on the table search + column toggles.

---

## Decisions (2026-09-08)

- **3.4 feature-folder move** — **deferred** to its own session (high churn, would also
  collide with the unmerged editions branch). Phase 3 does 3.1–3.3 + 3.5 only.
- **Phase 4 dashboard** — **reshape the layout** on a real 12-col hierarchy. Design/token
  plan reviewed with the user before any Phase 4 code.

## Per-phase deliverable

Green `npm test` + `tsc --noEmit` + `npm run lint`; a before/after bundle table;
screenshot smoke of dashboard + one table page + one detail page in light & dark.
