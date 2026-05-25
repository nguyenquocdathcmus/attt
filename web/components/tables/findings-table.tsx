export type FindingRow = {
  id: string;
  title: string;
  severity: string;
  cwe?: string | null;
  status: string;
};

type FindingsTableProps = {
  rows: FindingRow[];
};

const severityColors: Record<string, { bg: string; text: string; dot: string }> = {
  Critical: { bg: "bg-red-500/10", text: "text-red-400", dot: "bg-red-500" },
  High: { bg: "bg-orange-500/10", text: "text-orange-400", dot: "bg-orange-500" },
  Medium: { bg: "bg-yellow-500/10", text: "text-yellow-400", dot: "bg-yellow-500" },
  Low: { bg: "bg-blue-500/10", text: "text-blue-400", dot: "bg-blue-500" },
  Info: { bg: "bg-cyan-500/10", text: "text-cyan-400", dot: "bg-cyan-500" }
};

const statusColors: Record<string, string> = {
  "Likely FP": "bg-purple-500/10 text-purple-400",
  "Needs triage": "bg-slate-500/10 text-slate-300"
};

export function FindingsTable({ rows }: FindingsTableProps) {
  return (
    <div>
      {rows.length === 0 ? (
        <div className="rounded-2xl border border-slate-700/50 bg-slate-900/40 p-8 text-center">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-slate-800 mb-3">
            <svg className="w-6 h-6 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <p className="text-slate-400">No findings yet. Start a scan to populate results.</p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-700/50 bg-slate-900/20 backdrop-blur-sm">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/60 border-b border-slate-700/50">
              <tr>
                <th className="px-4 py-4 font-semibold text-slate-300">ID</th>
                <th className="px-4 py-4 font-semibold text-slate-300">Finding</th>
                <th className="px-4 py-4 font-semibold text-slate-300">Severity</th>
                <th className="px-4 py-4 font-semibold text-slate-300">CWE</th>
                <th className="px-4 py-4 font-semibold text-slate-300">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/30">
              {rows.map((row) => {
                const severityColor = severityColors[row.severity] || severityColors.Info;
                const statusColor = statusColors[row.status] || statusColors["Needs triage"];
                
                return (
                  <tr key={row.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="px-4 py-4 font-mono text-xs text-slate-400 font-medium">
                      {row.id}
                    </td>
                    <td className="px-4 py-4 text-slate-200">{row.title}</td>
                    <td className="px-4 py-4">
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${severityColor.dot}`} />
                        <span className={`text-xs font-semibold ${severityColor.text}`}>
                          {row.severity}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-4 text-slate-400">{row.cwe || "-"}</td>
                    <td className="px-4 py-4">
                      <span className={`inline-block px-2.5 py-1 rounded-full text-xs font-medium ${statusColor}`}>
                        {row.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
