# Frontend optimization — session 2 handoff (3.2 + Phase 4)

Pick up on branch **`feat/frontend-optimization`** (HEAD `7149713`, 6 commits ahead of
`origin/main`, **not pushed**). Session 1 summary + metrics: `docs/frontend-optimization-plan.md`
("STATUS — 2026-09-08"). Everything below is design work that needs the visual review loop.

## Local run (session 1 setup)

```
# backend  (Django/waitress, port 8586)
cd server && DJANGO_DEBUG=true ./.venv/Scripts/python.exe run_server.py 127.0.0.1 8586

# frontend (vite dev, port 8282, points at :8586)
cd client && VITE_BACKEND_URL=http://localhost:8586 npx vite --port 8282 --host
```

Login: `grvchindarkar@gmail.com` / (password with the user — not in repo).
Kill stragglers first: `powershell "Get-CimInstance Win32_Process -Filter \"Name='node.exe' OR Name='python.exe'\" | ? { $_.CommandLine -match 'vite|run_server' } | % { Stop-Process -Id $_.ProcessId -Force }"`.
Never set `CODESENSE_EDITION` / `ENTITLEMENTS_PUBLIC_KEY` (this branch is off `main`, pre-editions).

**Dev-server gotcha (fixed, but know it):** a Tauri build left ~18 MB of Semgrep rule fixtures
(`*.html`) under `client/src-tauri/target/`; vite's dep scanner choked on them. `vite.config.ts`
now pins `optimizeDeps.entries: ['index.html']` + `server.watch.ignored`. If the dev server ever
starts thrashing (`504 Outdated Optimize Dep`, "more than one copy of React"), `rm -rf
client/node_modules/.vite` and restart with `--force`.

---

## Task 3.2 — one design-token source (do first; it feeds Phase 4)

`index.css` `@theme` and `tailwind.config.js` (CommonJS) **both** define the palette. Tailwind v4
is CSS-first; the JS config is loaded only via `@config "../tailwind.config.js"`.

1. Port everything still used from `tailwind.config.js` into the `@theme` block in `index.css`:
   - the numbered `primary-50..950` scale (used as `bg-primary-100`, `text-primary-600/700/800`,
     `text-primary-950`, `dark:text-primary-300` — grep `primary-[0-9]`)
   - `fontFamily.custom` → `--font-custom` (used as `font-custom` in `sidebar.tsx` header)
   - `brand.{red,dark,light,white}` if anything still uses `bg-brand-*` / `text-brand-*` /
     `border-brand-*` (grep — `sidebar.tsx` `badgeVariants` uses `bg-brand-red`, `bg-brand-dark`,
     `text-brand-light`, `border-brand-light`)
2. Delete the hand-rolled `.text-brand-*` / `.bg-brand-*` / `.border-brand-*` utility classes at
   the bottom of `index.css` — Tailwind generates these from `@theme` tokens.
3. Delete `tailwind.config.js` + the `@config` line (or keep the file with only what genuinely
   can't move — there shouldn't be anything).
4. Verify: `npm run build`, then diff screenshots of dashboard + a table page + a detail page in
   **light and dark** (theme toggle top-right). This touches the whole color system — eyeball it.

---

## Phase 4 — dashboard reshape + chart system + states + a11y

The user chose **reshape the layout** (not conservative). Bring the design plan below to them,
get sign-off / edits, *then* build. Follow `anthropic-skills:frontend-design`.

### Current state (for reference)

`routes/_authenticated/index.tsx` — 6 identical KPI cards in `grid-cols-3`, then three
`grid-cols-3` / `grid-cols-4` rows of chart cards, every card the same visual weight. 9 chart
components in `components/charts/`, each hardcoding hex colors + duplicated
`dark:` class soup + its own card chrome (`count-by-severity.tsx` repeats
`transition-colors duration-300` 6×). Severity colors differ between the bar chart
(`#7e0e0e/#be0707/#ffc000/#04c73b`), the donut, and the badges.

### DRAFT design plan (to review with the user)

**Subject.** An offline SAST console for security engineers triaging findings across projects.
The dashboard's job: *how much risk is open, where, and is it trending the right way* — at a
glance, then drill in. Audience reads it daily; it should feel like an instrument panel, not a
marketing page.

**Color** (extends the existing red/graphite identity — don't reinvent it):
- `--surface` graphite `#f5f5f5` / dark `#1f1f1f`; `--panel` `#ffffff` / `#262626`
- `--ink` `#1a1a1a` / `#ededed`; `--ink-dim` `#6b7280` / `#9ca3af`
- `--accent` (brand red) `#bf0000` — reserved for the single most important number + active nav,
  **not** every card
- **Severity ramp, used identically everywhere** (bars, donut, badges, sparklines):
  `--sev-critical #7f1d1d` · `--sev-high #dc2626` · `--sev-medium #d97706` · `--sev-low #ca8a04`
  · `--sev-info #6b7280`. (Move greens out — "low" isn't "good", it's still a finding.)
- neutral data series (non-severity charts): a 4-step graphite ramp, not rainbow.

**Type.** Keep `WF Visual Sans` for UI. Give the hero metric a real display size (56–64px,
tabular-nums). Chakra Petch stays for the wordmark only. Scale: 12 / 14 / 16 / 20 / 32 / 56,
line-height 1.2 display / 1.5 body. No all-caps eyebrows.

**Layout — 12-col grid, real hierarchy** (not uniform rows):

```
┌─────────────────────────────────────────────────────────────┐
│  OPEN FINDINGS            ▁▂▃▅▇  trend 30d      [ Critical ▸ ]│  ← hero band, col-span-12
│      635        +12% ▲                          [ High     ▸ ]│    big number + sparkline +
│  across 5 projects                              [ Medium   ▸ ]│    severity quick-filters
├──────────────────────────────┬──────────────────────────────┤
│  Severity breakdown          │  Findings trend (7/30/90)     │  ← col-span-6 each
│  ▇▇▇▇▇▇ critical             │      ╱╲    ╱                   │
│  ▇▇▇ high                     │  ╱╲╱   ╲╱                     │
├───────────────┬──────────────┴──────────────┬───────────────┤
│ By language   │  Scan throughput            │  Scan health   │  ← col-span-4 each
│ (top 5 bars)  │  59 total · 83/17 code/sbom │  36✓ 10✗ 2⧗   │
├───────────────┴─────────────────────────────┴───────────────┤
│  Top CWEs (rank list, count bars)  │  Recent scans (feed)    │  ← 7 / 5 split
└────────────────────────────────────┴─────────────────────────┘
```

Left-aligned throughout. KPI strip (Users / Projects / SBOM counts) demotes to a thin
`col-span-12` stat row *below* the fold or into the header — they're context, not the story.

**Principles.**
1. One hero number (open findings), one accent color on it. Everything else is graphite + the
   severity ramp.
2. Severity is the app's visual language — same 5 colors, same order, everywhere.
3. Cards earn their size by importance (hero band > breakdown/trend > the 4-ups > lists), not a
   uniform grid.
4. Motion only on user action (filter, drill-in). No section fade-ins.

### Build steps (after sign-off)

1. **`<ChartCard>` shell** (`components/charts/_chart-card.tsx`) — title, subtitle, `children`,
   optional right-slot (range toggle). All 9 charts drop their bespoke card chrome and the
   `transition-colors duration-300` repetition for this.
2. **`chart-tokens.ts`** — export the severity ramp + neutral ramp reading CSS vars
   (`getComputedStyle` once, or hard-map to the `--sev-*` names). Every chart imports from here;
   delete inline hex.
3. Rebuild `routes/_authenticated/index.tsx` to the 12-col layout above. The `<Suspense>` +
   `React.lazy` chart loading from session 1 stays; give it **skeletons that match each card's
   final footprint** (not the centered `<DotsLoader/>` — that causes layout shift).
4. **States:** every chart/list gets an explicit empty state (`"No scans yet — "` + a link to
   `/scan/start`) and reuses `RouteError` semantics for load failure. Skeletons via a small
   `<Skeleton/>` atom.
5. **a11y pass** (whole app, not just dashboard): `:focus-visible` rings on nav + cards +
   table controls; `@media (prefers-reduced-motion: reduce)` disables the sidebar
   `hover:translate-x-1` + accent-bar transitions; contrast-check red-on-graphite (the
   `#bf0000` on `#f5f5f5` body text fails AA — only use it at ≥18px/bold or for non-text);
   real `<label>`/`aria-*` on `generic-table` search + column toggles (partly done in
   `72d7e94`), and on the chart range toggles.
6. Verify: build; screenshot dashboard + one table + one detail, light **and** dark; scroll
   test; `npm test` (add a render test for the new dashboard layout + `<ChartCard>`).

### Watch out
- `count-by-severity.tsx` maps `type` → hardcoded color object; `donut-chart.tsx` and the
  badges have their own. Consolidating these will shift on-screen colors — that's the point,
  but call it out in the screenshot review.
- The dashboard `loader` (session 1) prefetches `['dashboard', 7]`. If the reshape adds a
  second above-the-fold query, prefetch it in the same loader.
- Recharts `<ResponsiveContainer>` needs a sized parent (`min-h-0` / explicit height) inside
  the new grid cells or it logs `width(-1) height(-1)` and renders nothing.

---

## LOCKED + SHIPPED — 2026-09-08 (session 2)

Reviewed the draft with the user; decisions:

1. **Hero** — open-findings count is drawn *as* a full-width stacked `<SeverityRamp>` (segments
   labelled with counts), with a large tabular-nums count + 30d trend delta beneath. Not the
   "big lone number + sparkline" the draft first sketched.
2. **Accent** — **no brand red inside dashboard content.** The hero number is `--foreground`
   (ink); brand `#bf0000` stays in the sidebar/nav chrome + wordmark only. Panels use ink + the
   severity ramp + the neutral graphite `--data-*` ramp for non-severity series.
3. **Severity ramp** — `critical #7f1d1d · high #dc2626 · medium #ea7317 · low #a16207 ·
   info #6b7280` (light); lifted for dark (`#dc2626 / #f87171 / #fb923c / #facc15 / #9ca3af`).
   medium/low pushed apart in hue (orange vs brass) so a small stacked bar stays legible. No
   green — "low" is a graded finding, not "good".
4. **KPI strip** (`cards.tsx`) — demoted to one thin `col-span-12` row below the fold; the six
   big gradient/icon-box cards are gone.

Build-step list executed as written (`<ChartCard>` → `chart-tokens.ts` → 12-col `index.tsx`
→ per-card skeletons → empty states → a11y pass → verify). See the session-2 STATUS table in
`docs/frontend-optimization-plan.md` for the file list and gate results.

**Deferred (needs its own visual review):** unifying the severity *badges*
(`enum-badge.tsx`, `FindingList.tsx`, `UpdatedFinding.tsx`, `finding/sbom.$sbomfindingId.tsx`)
onto the `bg-sev-*` tokens — touches every findings table + detail page.
