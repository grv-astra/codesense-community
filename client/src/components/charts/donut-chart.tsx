import type { SystemStatus } from '@/types/dashboard';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import { useChartTokens } from '@/lib/chart-tokens';
import { ChartCard, ChartEmpty } from './_chart-card';

const prettyStatus = (s: string) =>
  s.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());

const DonutChart = ({ data }: { data?: SystemStatus }) => {
  const t = useChartTokens();
  const counts = (data?.counts ?? {}) as Record<string, number>;
  const total = data?.total_scans ?? 0;

  // Failed scans get the one warm colour; every other state rides the neutral
  // graphite ramp so the chart doesn't turn into a traffic light.
  const colorFor = (status: string) => {
    const s = status.toLowerCase();
    if (s === 'failed') return t.severity.high;
    if (s === 'completed' || s === 'success') return t.data[1];
    if (s === 'in_progress' || s === 'running') return t.data[2];
    return t.data[3];
  };

  const chartData = Object.entries(counts)
    .filter(([, value]) => value > 0)
    .map(([status, value]) => ({ name: prettyStatus(status), value, color: colorFor(status) }));

  const CustomTooltip = ({ active, payload }: any) => {
    if (!active || !payload?.length) return null;
    const p = payload[0];
    return (
      <div
        className="rounded-md border p-2.5 text-xs font-semibold shadow-md"
        style={{ background: 'var(--chart-tooltip-bg)', borderColor: 'var(--chart-tooltip-border)' }}
      >
        <div className="mb-1 flex items-center gap-1.5 text-sm font-bold text-foreground">
          <span className="size-2.5 rounded-full" style={{ backgroundColor: p.payload.color }} />
          {p.name}
        </div>
        <p className="text-foreground">{p.value} scans</p>
        {total > 0 && (
          <p className="text-muted-foreground">{((p.value / total) * 100).toFixed(1)}% of total</p>
        )}
      </div>
    );
  };

  return (
    <ChartCard
      title="Scan health"
      subtitle={total ? `${total.toLocaleString()} scans recorded` : 'Scan outcomes'}
      footnote="Live from the scan store"
    >
      {chartData.length === 0 ? (
        <ChartEmpty message="No scans recorded yet." />
      ) : (
        <>
          <div className="relative h-[210px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={62}
                  outerRadius={88}
                  paddingAngle={4}
                  dataKey="value"
                  strokeWidth={0}
                  isAnimationActive={false}
                >
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} cursor={false} />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-xl font-semibold tabular-nums text-foreground">
                {total.toLocaleString()}
              </span>
              <span className="text-xs text-muted-foreground">scans</span>
            </div>
          </div>
          <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1.5">
            {chartData.map((item) => (
              <div key={item.name} className="flex items-center gap-1.5">
                <span className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-xs text-muted-foreground">{item.name}</span>
                <span className="ml-auto text-xs font-semibold tabular-nums text-foreground">
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </ChartCard>
  );
};

export default DonutChart;
