import { Area, AreaChart, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { FindingsTrendItem } from '@/types/dashboard';
import { DASHBOARD_SEVERITY_ORDER, useChartTokens } from '@/lib/chart-tokens';
import { cn } from '@/lib/utils';
import { ChartCard, ChartEmpty } from './_chart-card';

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div
      className="rounded-md border p-2.5 text-xs font-semibold shadow-md"
      style={{ background: 'var(--chart-tooltip-bg)', borderColor: 'var(--chart-tooltip-border)' }}
    >
      <p className="mb-1 text-sm font-bold text-muted-foreground">{label}</p>
      {payload.map((entry: any) => (
        <p key={entry.dataKey} style={{ color: entry.color }} className="capitalize">
          {entry.dataKey}: {entry.value}
        </p>
      ))}
    </div>
  );
};

const RANGE_OPTIONS = [
  { days: 7 as const, label: '7d' },
  { days: 30 as const, label: '30d' },
  { days: 90 as const, label: '90d' },
];

type RangeDays = 7 | 30 | 90;

function RangeToggle({
  value,
  onChange,
}: {
  value: RangeDays;
  onChange: (days: RangeDays) => void;
}) {
  return (
    <div
      role="group"
      aria-label="Trend range"
      className="flex overflow-hidden rounded-md border border-border"
    >
      {RANGE_OPTIONS.map(({ days, label }) => (
        <button
          key={days}
          type="button"
          aria-pressed={value === days}
          onClick={() => onChange(days)}
          className={cn(
            'px-2 py-1 text-xs font-medium transition-colors',
            value === days
              ? 'bg-foreground text-background'
              : 'bg-transparent text-muted-foreground hover:bg-muted',
          )}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

function AnalysisTrend({
  data = [],
  rangeDays = 7,
  onRangeChange,
}: {
  data?: FindingsTrendItem[];
  rangeDays?: RangeDays;
  onRangeChange?: (days: RangeDays) => void;
}) {
  const t = useChartTokens();
  const latestTotal = data[data.length - 1]?.total ?? 0;

  return (
    <ChartCard
      title="Findings trend"
      subtitle={
        data.length
          ? `${latestTotal.toLocaleString()} findings on the latest day`
          : 'Daily finding counts by severity'
      }
      action={onRangeChange && <RangeToggle value={rangeDays} onChange={onRangeChange} />}
      footnote={`Last ${rangeDays} days from the findings store`}
    >
      {data.length === 0 ? (
        <ChartEmpty message="Not enough history yet — the trend fills in as scans run day over day." />
      ) : (
        <div className="h-[240px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
              <defs>
                {DASHBOARD_SEVERITY_ORDER.map((k) => (
                  <linearGradient key={k} id={`trend-${k}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={t.severity[k]} stopOpacity={0.7} />
                    <stop offset="95%" stopColor={t.severity[k]} stopOpacity={0.05} />
                  </linearGradient>
                ))}
              </defs>
              <XAxis
                dataKey="date"
                tick={{ fontSize: 11, fill: t.axis }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fontSize: 11, fill: t.axis }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip
                content={<CustomTooltip />}
                cursor={{ stroke: 'rgba(128,128,128,0.2)', strokeWidth: 1 }}
              />
              <Legend
                wrapperStyle={{ fontSize: '11px', paddingTop: '12px' }}
                formatter={(value) => <span className="capitalize text-muted-foreground">{value}</span>}
              />
              {DASHBOARD_SEVERITY_ORDER.map((k) => (
                <Area
                  key={k}
                  type="monotone"
                  dataKey={k}
                  stroke={t.severity[k]}
                  fill={`url(#trend-${k})`}
                  strokeWidth={1.5}
                  isAnimationActive={false}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </ChartCard>
  );
}

export default AnalysisTrend;
