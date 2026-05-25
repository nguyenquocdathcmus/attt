"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";

type Remediation = { summary?: string; steps?: string[]; references?: string[] };
type Finding = {
  id?: string; title?: string; severity?: string; description?: string | null;
  cwe?: string | null; owasp?: string | null; risk_score?: number | null;
  false_positive_score?: number | null; remediation?: Remediation | null;
  evidence?: Record<string, unknown> | null;
};

type Tab = "summary" | "findings" | "raw";

const SEV_COLOR: Record<string, string> = {
  Critical: "bg-red-500/15 text-red-400 border-red-500/30",
  High:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  Medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  Low:      "bg-blue-500/15 text-blue-400 border-blue-500/30",
  Info:     "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
};

const SEV_DOT: Record<string, string> = {
  Critical: "bg-red-500", High: "bg-orange-500", Medium: "bg-yellow-500",
  Low: "bg-blue-400", Info: "bg-cyan-400",
};

function normSev(v?: string | null) {
  if (!v) return "Info";
  const n = v.charAt(0).toUpperCase() + v.slice(1).toLowerCase();
  return ["Critical","High","Medium","Low","Info"].includes(n) ? n : "Info";
}

function RiskBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = pct >= 80 ? "bg-red-500" : pct >= 55 ? "bg-orange-500" : pct >= 30 ? "bg-yellow-500" : "bg-blue-400";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-slate-800">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-400 w-8 text-right">{pct}%</span>
    </div>
  );
}

function JsonViewer({ data }: { data: unknown }) {
  const [collapsed, setCollapsed] = useState(true);
  const json = JSON.stringify(data, null, 2);
  const lines = json.split("\n");
  const preview = lines.slice(0, 8).join("\n");
  return (
    <div className="rounded-lg bg-slate-950 border border-slate-800 overflow-hidden">
      <pre className="text-xs text-slate-300 p-4 overflow-x-auto leading-relaxed">
        {collapsed && lines.length > 8 ? preview + "\n  …" : json}
      </pre>
      {lines.length > 8 && (
        <button onClick={() => setCollapsed(v => !v)}
          className="w-full py-2 text-xs text-slate-500 hover:text-slate-300 border-t border-slate-800 transition-colors">
          {collapsed ? `Show all ${lines.length} lines ▼` : "Collapse ▲"}
        </button>
      )}
    </div>
  );
}

export default function ReportPreview({
  content,
  scanId,
}: {
  content: Record<string, unknown>;
  scanId?: string;
}) {
  const [tab, setTab] = useState<Tab>("summary");
  const [openId, setOpenId] = useState<string | null>(null);

  const summary  = (content?.summary as string) || "Executive summary pending AI analysis.";
  const findings = (Array.isArray(content?.findings) ? content.findings : []) as Finding[];
  const rawOutput = content?.raw_output as Record<string, unknown> | undefined;

  const sorted = [...findings].sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0));
  const sevCounts = sorted.reduce((acc, f) => {
    const s = normSev(f.severity); acc[s] = (acc[s] ?? 0) + 1; return acc;
  }, {} as Record<string, number>);

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(content, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `report-${(scanId ?? "export").slice(0, 8)}.json`;
    a.click();
  };

  const tabs: { id: Tab; label: string }[] = [
    { id: "summary",  label: "Summary" },
    { id: "findings", label: `Findings & Fix (${findings.length})` },
    { id: "raw",      label: "Raw Output" },
  ];

  return (
    <div className="rounded-2xl border border-slate-700/50 bg-slate-900/50 overflow-hidden">
      {/* Tab bar */}
      <div className="flex items-center justify-between border-b border-slate-700/50 px-6 pt-4">
        <div className="flex gap-1">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg border border-b-0 transition-colors ${
                tab === t.id
                  ? "bg-slate-800 border-slate-700/50 text-white"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}>
              {t.label}
            </button>
          ))}
        </div>
        <Button variant="ghost" size="sm" onClick={exportJson}
          className="text-xs text-cyan-400 hover:text-cyan-300 mb-1">
          📥 Export JSON
        </Button>
      </div>

      <div className="p-6">
        {/* ── Tab: Summary ── */}
        {tab === "summary" && (
          <div className="space-y-6">
            {/* Severity counts */}
            <div className="grid grid-cols-5 gap-3">
              {["Critical","High","Medium","Low","Info"].map(sev => (
                <div key={sev} className={`rounded-xl border px-3 py-3 text-center ${SEV_COLOR[sev]}`}>
                  <p className="text-xl font-bold">{sevCounts[sev] ?? 0}</p>
                  <p className="text-xs mt-0.5 opacity-70">{sev}</p>
                </div>
              ))}
            </div>

            {/* Executive summary */}
            <div className="rounded-xl border border-slate-700/50 bg-slate-800/40 p-5">
              <p className="text-xs text-slate-500 uppercase tracking-wider mb-3">Executive Summary</p>
              <p className="text-slate-200 text-sm leading-relaxed whitespace-pre-line">{summary}</p>
            </div>

            {/* Top 3 risks */}
            {sorted.slice(0, 3).length > 0 && (
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-3">Top Risks</p>
                <div className="space-y-2">
                  {sorted.slice(0, 3).map((f, i) => {
                    const sev = normSev(f.severity);
                    return (
                      <div key={f.id ?? i} className="flex items-center gap-3 rounded-lg bg-slate-800/40 border border-slate-700/30 px-4 py-3">
                        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${SEV_DOT[sev]}`} />
                        <span className="text-sm text-slate-200 flex-1">{f.title}</span>
                        {f.risk_score != null && (
                          <div className="w-24 flex-shrink-0"><RiskBar score={f.risk_score} /></div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Tab: Findings & Fix ── */}
        {tab === "findings" && (
          <div className="space-y-3">
            {sorted.length === 0 ? (
              <p className="text-slate-500 text-sm text-center py-8">No findings</p>
            ) : sorted.map((f, i) => {
              const sev = normSev(f.severity);
              const isOpen = openId === (f.id ?? String(i));
              const rem = f.remediation;
              const isFP = (f.false_positive_score ?? 0) >= 0.7;
              return (
                <div key={f.id ?? i} className={`rounded-xl border overflow-hidden transition-all ${
                  isOpen ? "border-slate-600" : "border-slate-700/50"
                } bg-slate-800/30`}>
                  {/* Row */}
                  <button className="w-full text-left px-5 py-4 flex items-center gap-3"
                    onClick={() => setOpenId(isOpen ? null : (f.id ?? String(i)))}>
                    <span className={`w-2 h-2 rounded-full flex-shrink-0 ${SEV_DOT[sev]}`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium text-slate-200">{f.title}</span>
                        <span className={`text-xs px-1.5 py-0.5 rounded border ${SEV_COLOR[sev]}`}>{sev}</span>
                        {isFP && <span className="text-xs px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30">Likely FP</span>}
                        {f.cwe && <span className="text-xs text-slate-500 font-mono">{f.cwe}</span>}
                      </div>
                    </div>
                    {f.risk_score != null && (
                      <div className="w-20 flex-shrink-0"><RiskBar score={f.risk_score} /></div>
                    )}
                    <span className="text-slate-600 text-xs flex-shrink-0">{isOpen ? "▲" : "▼"}</span>
                  </button>

                  {/* Detail */}
                  {isOpen && (
                    <div className="border-t border-slate-700/50 px-5 py-4 space-y-4">
                      {f.description && (
                        <div>
                          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Description</p>
                          <p className="text-sm text-slate-300">{f.description}</p>
                        </div>
                      )}

                      {/* Remediation */}
                      {rem ? (
                        <div className="rounded-lg bg-green-500/5 border border-green-500/20 p-4">
                          <p className="text-xs text-green-400 uppercase tracking-wider mb-2">AI Remediation</p>
                          {rem.summary && (
                            <p className="text-sm text-green-200 font-medium mb-3">{rem.summary}</p>
                          )}
                          {rem.steps && rem.steps.length > 0 && (
                            <ol className="space-y-1.5">
                              {rem.steps.map((s, si) => (
                                <li key={si} className="flex gap-2 text-sm text-slate-300">
                                  <span className="text-green-500 font-bold flex-shrink-0">{si + 1}.</span>
                                  {s}
                                </li>
                              ))}
                            </ol>
                          )}
                          {rem.references && rem.references.filter(Boolean).length > 0 && (
                            <div className="mt-3 pt-3 border-t border-green-500/20">
                              <p className="text-xs text-slate-500 mb-1">References</p>
                              {rem.references.filter(Boolean).map((r, ri) => (
                                <p key={ri} className="text-xs text-cyan-400 break-all">{r}</p>
                              ))}
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="rounded-lg bg-slate-900/50 border border-slate-700/30 px-4 py-3">
                          <p className="text-xs text-slate-500">AI remediation not yet available</p>
                        </div>
                      )}

                      {/* Evidence */}
                      {!!f.evidence?.url && (
                        <div className="flex gap-4 text-xs text-slate-500 flex-wrap">
                          <span>URL: <span className="text-slate-400 font-mono">{String(f.evidence.url)}</span></span>
                          {!!f.evidence.param && <span>Param: <span className="text-slate-400 font-mono">{String(f.evidence.param)}</span></span>}
                          {f.owasp && <span>{f.owasp}</span>}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* ── Tab: Raw Output ── */}
        {tab === "raw" && (
          <div className="space-y-6">
            {!rawOutput || Object.keys(rawOutput).length === 0 ? (
              <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 p-8 text-center">
                <p className="text-slate-500 text-sm">Raw scanner output not available.</p>
                <p className="text-slate-600 text-xs mt-1">Run a new scan to capture raw ZAP / Nikto output.</p>
              </div>
            ) : (
              <>
                <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 px-5 py-3 flex items-center gap-3">
                  <span className="text-lg">{rawOutput.scanner === "nikto" ? "🔍" : "🕷️"}</span>
                  <div>
                    <p className="text-sm font-semibold text-white">
                      {String(rawOutput.scanner ?? "").toUpperCase()} — Raw Output
                    </p>
                    <p className="text-xs text-slate-400">{String(rawOutput.target ?? "")}</p>
                  </div>
                </div>

                {/* ZAP: list alerts in a table, full JSON below */}
                {rawOutput.scanner === "zap" && Array.isArray(rawOutput.alerts) && (
                  <div>
                    <p className="text-xs text-slate-500 uppercase tracking-wider mb-3">
                      Alerts ({(rawOutput.alerts as unknown[]).length})
                    </p>
                    <div className="rounded-xl border border-slate-700/50 overflow-hidden">
                      <table className="w-full text-xs">
                        <thead className="bg-slate-900/60 border-b border-slate-700/40">
                          <tr>
                            <th className="px-3 py-2 text-left text-slate-400">Risk</th>
                            <th className="px-3 py-2 text-left text-slate-400">Alert</th>
                            <th className="px-3 py-2 text-left text-slate-400">URL</th>
                            <th className="px-3 py-2 text-left text-slate-400">Param</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {(rawOutput.alerts as Record<string, unknown>[]).map((a, i) => {
                            const sev = normSev(String(a.risk ?? ""));
                            const url = String(a.url ?? a.uri ?? "");
                            return (
                              <tr key={i} className="hover:bg-slate-800/20">
                                <td className="px-3 py-2">
                                  <span className={`px-1.5 py-0.5 rounded text-xs border ${SEV_COLOR[sev]}`}>{sev}</span>
                                </td>
                                <td className="px-3 py-2 text-slate-300 max-w-xs truncate">{String(a.alert ?? a.name ?? "")}</td>
                                <td className="px-3 py-2 text-slate-500 font-mono truncate max-w-xs" title={url}>
                                  {url ? url.replace(/^https?:\/\/[^/]+/, "") || url : "—"}
                                </td>
                                <td className="px-3 py-2 text-slate-500 font-mono">{String(a.param ?? "—")}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Nikto: raw scan data */}
                {rawOutput.scanner === "nikto" && rawOutput.raw && (
                  <div>
                    <p className="text-xs text-slate-500 uppercase tracking-wider mb-3">Nikto Raw Data</p>
                    <JsonViewer data={rawOutput.raw} />
                  </div>
                )}

                {/* Full raw JSON */}
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-3">Full JSON</p>
                  <JsonViewer data={rawOutput} />
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
