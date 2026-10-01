import type { TopCweItem } from '@/types/dashboard';
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { useChartTokens } from '@/lib/chart-tokens';
import { ChartCard, ChartEmpty } from './_chart-card';

const CustomTooltip = ({ active, payload }: any) => {
  if (!active || !payload?.length) return null;
  const p = payload[0];
  return (
    <div
      className="rounded-md border p-2.5 text-xs font-semibold shadow-md"
      style={{ background: 'var(--chart-tooltip-bg)', borderColor: 'var(--chart-tooltip-border)' }}
    >
      <p className="text-sm font-bold text-foreground">{p.payload.id}</p>
      <p className="text-muted-foreground">{p.payload.name}</p>
      <p className="text-foreground">Count: {p.value}</p>
    </div>
  );
};

function CveidList({ data = [] }: { data?: TopCweItem[] }) {
  const t = useChartTokens();

  return (
    <ChartCard
      title="Top CWEs"
      subtitle="Most frequently observed weaknesses"
      footnote="Live CWE aggregation across findings"
    >
      {data.length === 0 ? (
        <ChartEmpty message="No weaknesses catalogued yet — they rank here as findings accrue." />
      ) : (
        <div className="h-[380px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={data}
              layout="vertical"
              margin={{ top: 0, right: 16, left: 10, bottom: 0 }}
              barCategoryGap="30%"
            >
              <XAxis
                type="number"
                tick={{ fontSize: 11, fill: t.axis }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <YAxis
                dataKey="name"
                type="category"
                width={160}
                tick={{ fontSize: 12, fill: t.axis }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(128,128,128,0.06)' }} />
              <Bar dataKey="count" fill={t.data[0]} radius={[0, 3, 3, 0]} barSize={18} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </ChartCard>
  );
}

export default CveidList;
