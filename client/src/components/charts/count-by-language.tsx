import type { LanguageDistributionItem } from '@/types/dashboard';
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
      <p className="mb-1 text-sm font-bold text-foreground">{p.payload.language}</p>
      <p className="text-foreground">Vulnerabilities: {p.value}</p>
      <p className="text-muted-foreground">Scans: {p.payload.scans}</p>
    </div>
  );
};

function CountLanguage({ data = [] }: { data?: LanguageDistributionItem[] }) {
  const t = useChartTokens();

  return (
    <ChartCard
      title="By language"
      subtitle="Vulnerabilities per language"
      footnote="Derived from stored scan metrics"
    >
      {data.length === 0 ? (
        <ChartEmpty message="No language data yet — run a code scan to populate this." />
      ) : (
        <div className="h-[240px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }} barCategoryGap="35%">
              <XAxis
                dataKey="language"
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
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(128,128,128,0.06)' }} />
              <Bar dataKey="vulnerabilities" fill={t.data[0]} radius={[3, 3, 0, 0]} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </ChartCard>
  );
}

export default CountLanguage;
