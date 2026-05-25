type RiskDatum = {
  label: string;
  value: number;
};

const fallbackData: RiskDatum[] = [
  { label: "Critical", value: 0 },
  { label: "High", value: 0 },
  { label: "Medium", value: 0 },
  { label: "Low", value: 0 }
];

type RiskChartProps = {
  data?: RiskDatum[];
};

const colorMap: Record<string, { bar: string; text: string; bg: string }> = {
  Critical: { bar: "from-red-600 to-red-400", text: "text-red-400", bg: "bg-red-500/10" },
  High: { bar: "from-orange-600 to-orange-400", text: "text-orange-400", bg: "bg-orange-500/10" },
  Medium: { bar: "from-yellow-600 to-yellow-400", text: "text-yellow-400", bg: "bg-yellow-500/10" },
  Low: { bar: "from-blue-600 to-blue-400", text: "text-blue-400", bg: "bg-blue-500/10" },
  Info: { bar: "from-cyan-600 to-cyan-400", text: "text-cyan-400", bg: "bg-cyan-500/10" }
};

export function RiskChart({ data = fallbackData }: RiskChartProps) {
  const total = data.reduce((sum, item) => sum + item.value, 0) || 1;
  
  return (
    <div className="rounded-xl border border-slate-700/50 bg-slate-900/20 backdrop-blur-sm p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-lg font-semibold text-white">Risk Distribution</h2>
          <p className="text-xs text-slate-400 mt-1">Severity breakdown from latest scans</p>
        </div>
        <span className="text-xs uppercase tracking-[0.15em] text-slate-500 font-medium">
          {total} Issues
        </span>
      </div>
      
      <div className="space-y-4">
        {data.map((item) => {
          const colors = colorMap[item.label] || colorMap.Info;
          
          return (
            <div key={item.label} className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-300">{item.label}</span>
                <span className={`text-sm font-semibold ${colors.text}`}>{item.value}%</span>
              </div>
              <div className={`h-2.5 w-full rounded-full ${colors.bg} overflow-hidden`}>
                <div
                  className={`h-full rounded-full bg-gradient-to-r ${colors.bar} shadow-lg`}
                  style={{ width: `${item.value}%`, transition: "width 0.3s ease" }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
