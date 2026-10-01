import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { SeverityData } from '@/types/dashboard';
import { DASHBOARD_SEVERITY_ORDER, useChartTokens } from '@/lib/chart-tokens';
import { ChartCard, ChartEmpty } from './_chart-card';

const CustomTooltip = ({ active, payload }: any) => {
  if (!active || !payload?.length) return null;
  const entry = payload[0];
  return (
    <div
      className="rounded-md border p-2.5 text-xs font-semibold shadow-md"
      style={{ background: 'var(--chart-tooltip-bg)', borderColor: 'var(--chart-tooltip-border)' }}
    >
      <span style={{ color: entry.payload.fill }}>
        {entry.payload.type}: {entry.value}
      </span>
    </div>
  );
};

const ChartComponent = ({ data }: { data?: SeverityData }) => {
  const t = useChartTokens();
  const severity = data ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const chartData = DASHBOARD_SEVERITY_ORDER.map((k) => ({
    type: k[0].toUpperCase() + k.slice(1),
    value: severity[k] ?? 0,
    fill: t.severity[k],
  }));
  const isEmpty = chartData.every((d) => d.value === 0);

  return (
    <ChartCard
      title="Severity breakdown"
      subtitle="Open findings by severity, all projects"
      footnote="Live from the findings store"
    >
      {isEmpty ? (
        <ChartEmpty message="No findings yet — severity appears here once a scan completes." />
      ) : (
        <div className="h-[240px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={chartData}
              layout="vertical"
              margin={{ top: 4, right: 16, left: 8, bottom: 0 }}
              barCategoryGap="28%"
            >
              <XAxis
                type="number"
                tick={{ fontSize: 11, fill: t.axis }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <YAxis
                type="category"
                dataKey="type"
                tick={{ fontSize: 12, fill: t.axis }}
                axisLine={false}
                tickLine={false}
                width={62}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(128,128,128,0.06)' }} />
              <Bar dataKey="value" radius={[0, 3, 3, 0]} isAnimationActive={false}>
                {chartData.map((entry) => (
                  <Cell key={entry.type} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </ChartCard>
  );
};

export default ChartComponent;
