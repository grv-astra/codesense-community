import type { ScanDistributionItem } from '@/types/dashboard';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import { useChartTokens } from '@/lib/chart-tokens';
import { ChartCard, ChartEmpty } from './_chart-card';

function ScanDistribution({ data = [] }: { data?: ScanDistributionItem[] }) {
  const t = useChartTokens();
  const total = data.reduce((sum, item) => sum + item.value, 0);
  // Ignore the API-supplied `color`; ride the neutral ramp so every non-severity
  // chart shares one visual family.
  const ramp = [t.data[0], t.data[2], t.data[1], t.data[3]];
  const rows = data.map((d, i) => ({ ...d, color: ramp[i % ramp.length] }));

  const CustomTooltip = ({ active, payload }: any) => {
    if (!active || !payload?.length) return null;
    const p = payload[0];
    return (
      <div
        className="rounded-md border p-2.5 text-xs font-semibold shadow-md"
        style={{ background: 'var(--chart-tooltip-bg)', borderColor: 'var(--chart-tooltip-border)' }}
      >
        <p className="mb-1 text-sm font-bold" style={{ color: p.payload.color }}>
          {p.name}
        </p>
        <p className="text-foreground">Count: {p.value}</p>
      </div>
    );
  };

  return (
    <ChartCard
      title="Scan throughput"
      subtitle="Code scans vs SBOM scans"
      footnote="Live scan-source breakdown"
    >
      {rows.length === 0 || total === 0 ? (
        <ChartEmpty message="No scans yet." />
      ) : (
        <>
          <div className="relative h-[210px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={rows}
                  cx="50%"
                  cy="50%"
                  innerRadius={62}
                  outerRadius={88}
                  dataKey="value"
                  strokeWidth={0}
                  isAnimationActive={false}
                >
                  {rows.map((entry) => (
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
          <div className="mt-2 flex justify-center gap-6">
            {rows.map((entry) => (
              <div key={entry.name} className="flex items-center gap-1.5">
                <span className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: entry.color }} />
                <span className="text-xs text-muted-foreground">{entry.name}</span>
                <span className="text-xs font-semibold tabular-nums text-foreground">
                  {total ? ((entry.value / total) * 100).toFixed(0) : 0}%
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </ChartCard>
  );
}

export default ScanDistribution;
