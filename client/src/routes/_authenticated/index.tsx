import { lazy, Suspense, useMemo, useState } from 'react'
import { ArrowDownRight, ArrowUpRight } from 'lucide-react'
import { ChartCardSkeleton } from '@/components/charts/_chart-card'
import { SeverityRamp } from '@/components/charts/severity-ramp'
import LicenseStatusCard from '@/components/molecule/license-status-card'
import { RouteError } from '@/components/molecule/route-error'
import { authService } from '@/lib/auth'
import { queryClient } from '@/lib/query-client'
import { generalService } from '@/services/general.service'
import type { FindingsTrendItem, StatCountDetails } from '@/types/dashboard'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'

// The charts pull in recharts + d3 (~110 KB gzip). Loading them lazily keeps that
// weight out of the initial bundle and off the dashboard's first paint — the page
// shell, license card and hero band render immediately while the chart chunk
// streams in behind a footprint-matched skeleton.
const KpiStrip = lazy(() => import('@/components/charts/cards'))
const SeverityBreakdown = lazy(() => import('@/components/charts/count-by-severity'))
const FindingsTrend = lazy(() => import('@/components/charts/analysis-by-trend'))
const ByLanguage = lazy(() => import('@/components/charts/count-by-language'))
const ScanThroughput = lazy(() => import('@/components/charts/scan-distribution'))
const ScanHealth = lazy(() => import('@/components/charts/donut-chart'))
const TopCwes = lazy(() => import('@/components/charts/cveid-list'))
const TopProjects = lazy(() => import('@/components/charts/scan-projects'))
const RecentScans = lazy(() => import('@/components/charts/recent-activity'))

const DEFAULT_TREND_DAYS = 7 as const

const dashboardQuery = (trendDays: number) => ({
  queryKey: ['dashboard', trendDays],
  queryFn: () => generalService.fetchDashboard(trendDays),
})

export const Route = createFileRoute('/_authenticated/')({
  beforeLoad: () => {
    authService.requireAuth();
  },
  // Kick the dashboard fetch off on navigation, not after the component mounts —
  // the component's useQuery then reads straight from cache with no spinner.
  loader: () => queryClient.ensureQueryData(dashboardQuery(DEFAULT_TREND_DAYS)),
  component: Index,
  pendingComponent: DashboardSkeleton,
  errorComponent: RouteError,
})

/** Net change in total findings across the loaded trend window. */
function trendDelta(trend: FindingsTrendItem[] | undefined) {
  if (!trend || trend.length < 2) return null
  const first = trend[0]?.total ?? 0
  const last = trend[trend.length - 1]?.total ?? 0
  return last - first
}

function HeroBand({
  counts,
  bySeverity,
  trend,
  rangeDays,
}: {
  counts?: StatCountDetails
  bySeverity?: React.ComponentProps<typeof SeverityRamp>['data']
  trend?: FindingsTrendItem[]
  rangeDays: number
}) {
  const total = counts?.findings ?? 0
  const projects = counts?.projects ?? 0
  const delta = trendDelta(trend)

  return (
    <section className="col-span-12 rounded-lg border border-border bg-card p-5">
      <div className="flex flex-wrap items-end justify-between gap-x-8 gap-y-3">
        <div>
          <p className="text-sm text-muted-foreground">Open findings</p>
          <div className="mt-1 flex items-baseline gap-3">
            <span className="text-5xl font-semibold leading-none tabular-nums text-foreground">
              {total.toLocaleString()}
            </span>
            {delta !== null && delta !== 0 && (
              <span
                className={
                  'inline-flex items-center gap-0.5 text-sm font-medium ' +
                  // more findings than the start of the window is the bad direction
                  (delta > 0 ? 'text-sev-high' : 'text-emerald-600 dark:text-emerald-400')
                }
              >
                {delta > 0 ? (
                  <ArrowUpRight className="size-4" />
                ) : (
                  <ArrowDownRight className="size-4" />
                )}
                {Math.abs(delta).toLocaleString()} over {rangeDays}d
              </span>
            )}
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            across {projects.toLocaleString()} {projects === 1 ? 'project' : 'projects'}
          </p>
        </div>
      </div>
      <div className="mt-5">
        <SeverityRamp data={bySeverity} />
      </div>
    </section>
  )
}

function DashboardSkeleton() {
  return (
    <div className="p-3">
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12">
          <ChartCardSkeleton height={92} />
        </div>
        <div className="col-span-12 lg:col-span-6">
          <ChartCardSkeleton height={260} />
        </div>
        <div className="col-span-12 lg:col-span-6">
          <ChartCardSkeleton height={260} />
        </div>
        <div className="col-span-12 md:col-span-4">
          <ChartCardSkeleton height={240} />
        </div>
        <div className="col-span-12 md:col-span-4">
          <ChartCardSkeleton height={240} />
        </div>
        <div className="col-span-12 md:col-span-4">
          <ChartCardSkeleton height={240} />
        </div>
        <div className="col-span-12 lg:col-span-8">
          <ChartCardSkeleton height={380} />
        </div>
        <div className="col-span-12 lg:col-span-4">
          <ChartCardSkeleton height={380} />
        </div>
        <div className="col-span-12">
          <ChartCardSkeleton height={200} />
        </div>
      </div>
    </div>
  )
}

function Index() {
  const [trendDays, setTrendDays] = useState<7 | 30 | 90>(DEFAULT_TREND_DAYS);
  const { data } = useQuery({
    ...dashboardQuery(trendDays),
    placeholderData: keepPreviousData,
  });

  // Keep the hero's trend delta in step with whichever range the trend card shows.
  const trend = useMemo(() => data?.findings_trend, [data?.findings_trend])

  return (
    <div className="p-3">
      <div className="mb-4">
        <LicenseStatusCard />
      </div>

      <div className="grid grid-cols-12 gap-4">
        <HeroBand
          counts={data?.top_counts}
          bySeverity={data?.count_by_severity}
          trend={trend}
          rangeDays={trendDays}
        />

        <Suspense fallback={<ChartAreaSkeleton />}>
          <div className="col-span-12 lg:col-span-6">
            <SeverityBreakdown data={data?.count_by_severity} />
          </div>
          <div className="col-span-12 lg:col-span-6">
            <FindingsTrend
              data={data?.findings_trend}
              rangeDays={trendDays}
              onRangeChange={setTrendDays}
            />
          </div>

          <div className="col-span-12 md:col-span-4">
            <ByLanguage data={data?.language_distribution} />
          </div>
          <div className="col-span-12 md:col-span-4">
            <ScanThroughput data={data?.scan_distribution} />
          </div>
          <div className="col-span-12 md:col-span-4">
            <ScanHealth data={data?.system_status} />
          </div>

          <div className="col-span-12 lg:col-span-8">
            <TopCwes data={data?.top_cwe} />
          </div>
          <div className="col-span-12 lg:col-span-4">
            <TopProjects data={data?.scans_by_project} />
          </div>

          <div className="col-span-12">
            <RecentScans data={data?.recent_scans} />
          </div>

          {/* Context, not the story — demoted below the fold. */}
          <div className="col-span-12">
            <KpiStrip data={data?.top_counts} trend={data?.top_counts_trend} />
          </div>
        </Suspense>
      </div>
    </div>
  )
}

/** Fills the same grid tracks as the real chart area while the chunk loads. */
function ChartAreaSkeleton() {
  return (
    <>
      <div className="col-span-12 lg:col-span-6"><ChartCardSkeleton height={260} /></div>
      <div className="col-span-12 lg:col-span-6"><ChartCardSkeleton height={260} /></div>
      <div className="col-span-12 md:col-span-4"><ChartCardSkeleton height={240} /></div>
      <div className="col-span-12 md:col-span-4"><ChartCardSkeleton height={240} /></div>
      <div className="col-span-12 md:col-span-4"><ChartCardSkeleton height={240} /></div>
      <div className="col-span-12 lg:col-span-8"><ChartCardSkeleton height={380} /></div>
      <div className="col-span-12 lg:col-span-4"><ChartCardSkeleton height={380} /></div>
      <div className="col-span-12"><ChartCardSkeleton height={200} /></div>
      <div className="col-span-12"><ChartCardSkeleton height={64} /></div>
    </>
  )
}
