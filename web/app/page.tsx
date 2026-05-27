"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import ReportPreview from "@/components/reports/report-preview";
import {
  apiGet, apiPost, apiPostForm, clearToken, getToken, scanWsUrl, setToken,
} from "@/lib/api";

// ─── Types ────────────────────────────────────────────────────────────────────

type Step = "login" | "scan" | "scanning" | "results" | "analyzing" | "report";

type UserProfile = { username: string; roles: string[] };
type Asset       = { id: string; url: string };
type Scan = {
  id: string; asset_id: string; status: string; scanner: string;
  started_at?: string | null; finished_at?: string | null; created_at: string;
};
type Finding = {
  id: string; scan_id: string; type: string; severity: string; title: string;
  description?: string | null; evidence?: Record<string, unknown> | null;
  cwe?: string | null; owasp?: string | null;
  false_positive_score?: number | null; risk_score?: number | null;
  remediation?: { summary?: string; steps?: string[]; references?: string[] } | null;
  created_at: string;
};
type Report = {
  id: string; scan_id: string; report_type: string;
  content: Record<string, unknown>; created_at: string;
};
type WsMsg = {
  status: string; scanner?: string; findings_count?: number;
  ai_ready?: boolean; started_at?: string | null; finished_at?: string | null;
};

// ─── Severity helpers ─────────────────────────────────────────────────────────

const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"] as const;
type Sev = (typeof SEV_ORDER)[number];

const SEV_COLOR: Record<Sev, { dot: string; badge: string; text: string }> = {
  Critical: { dot: "bg-red-500",    badge: "bg-red-500/15 text-red-400",    text: "text-red-400" },
  High:     { dot: "bg-orange-500", badge: "bg-orange-500/15 text-orange-400", text: "text-orange-400" },
  Medium:   { dot: "bg-yellow-500", badge: "bg-yellow-500/15 text-yellow-400", text: "text-yellow-400" },
  Low:      { dot: "bg-blue-400",   badge: "bg-blue-500/15 text-blue-400",   text: "text-blue-400" },
  Info:     { dot: "bg-cyan-400",   badge: "bg-cyan-500/15 text-cyan-400",   text: "text-cyan-400" },
};

function normSev(v?: string | null): Sev {
  if (!v) return "Info";
  const n = v.charAt(0).toUpperCase() + v.slice(1).toLowerCase() as Sev;
  return SEV_ORDER.includes(n) ? n : "Info";
}

function sevCounts(findings: Finding[]) {
  const c = Object.fromEntries(SEV_ORDER.map(s => [s, 0])) as Record<Sev, number>;
  findings.forEach(f => { c[normSev(f.severity)]++; });
  return c;
}

function formatDuration(startedAt?: string | null, finishedAt?: string | null): string {
  if (!startedAt) return "—";
  const ms = (finishedAt ? new Date(finishedAt) : new Date()).getTime() - new Date(startedAt).getTime();
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return rem > 0 ? `${m}m ${rem}s` : `${m}m`;
}

function formatDate(dt?: string | null): string {
  if (!dt) return "—";
  return new Date(dt).toLocaleString(undefined, { dateStyle: "short", timeStyle: "medium" });
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StepBreadcrumb({ step }: { step: Step }) {
  const steps: { id: Step; label: string }[] = [
    { id: "login",     label: "1. Login" },
    { id: "scan",      label: "2. Launch Scan" },
    { id: "scanning",  label: "3. Scanning" },
    { id: "results",   label: "4. Results" },
    { id: "analyzing", label: "5. AI Analysis" },
    { id: "report",    label: "6. Report" },
  ];
  const idx = steps.findIndex(s => s.id === step);
  return (
    <div className="flex items-center gap-1 flex-wrap">
      {steps.map((s, i) => (
        <div key={s.id} className="flex items-center gap-1">
          <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${
            i === idx
              ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
              : i < idx
              ? "text-slate-500 line-through"
              : "text-slate-600"
          }`}>{s.label}</span>
          {i < steps.length - 1 && <span className="text-slate-700 text-xs">›</span>}
        </div>
      ))}
    </div>
  );
}

function SeverityBadge({ sev }: { sev: Sev }) {
  const c = SEV_COLOR[sev];
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-0.5 rounded-full ${c.badge}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {sev}
    </span>
  );
}

// ─── Step 1: Login ────────────────────────────────────────────────────────────

function LoginStep({ onSuccess }: { onSuccess: (token: string, user: UserProfile) => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    setError(null);
    setLoading(true);
    try {
      const res = await apiPostForm<{ access_token: string; roles: string[] }>(
        "/api/v1/auth/token",
        new URLSearchParams({ username, password }),
      );
      setToken(res.access_token);
      const profile = await apiGet<UserProfile>("/api/v1/auth/me");
      onSuccess(res.access_token, profile);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 mb-4">
            <div className="w-3 h-3 rounded-full bg-gradient-to-r from-cyan-400 to-blue-500" />
            <span className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              ATTT
            </span>
          </div>
          <h1 className="text-2xl font-bold text-white mb-1">Security Platform</h1>
          <p className="text-slate-400 text-sm">AI-augmented vulnerability assessment</p>
        </div>

        <div className="rounded-2xl border border-slate-700/50 bg-slate-900/60 backdrop-blur-sm p-8">
          <h2 className="text-lg font-semibold text-white mb-6">Sign in</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wider">Username</label>
              <Input value={username} onChange={e => setUsername(e.target.value)}
                className="bg-slate-800/60 border-slate-700 text-white placeholder:text-slate-500"
                onKeyDown={e => e.key === "Enter" && handleLogin()} />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wider">Password</label>
              <Input type="password" value={password} onChange={e => setPassword(e.target.value)}
                className="bg-slate-800/60 border-slate-700 text-white placeholder:text-slate-500"
                onKeyDown={e => e.key === "Enter" && handleLogin()} />
            </div>
            {error && (
              <div className="rounded-lg bg-red-500/10 border border-red-500/30 px-3 py-2 text-sm text-red-300">{error}</div>
            )}
            <Button onClick={handleLogin} disabled={loading}
              className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold hover:opacity-90 disabled:opacity-50">
              {loading ? "Signing in…" : "Sign In"}
            </Button>
          </div>

          <div className="mt-6 pt-6 border-t border-slate-700/50">
            <p className="text-xs text-slate-500 mb-2 uppercase tracking-wider">Demo accounts</p>
            <div className="space-y-1 text-xs text-slate-400">
              {[["admin", "admin123", "Admin"], ["analyst", "analyst123", "Analyst"], ["viewer", "viewer123", "Viewer"]].map(([u, p, r]) => (
                <button key={u} onClick={() => { setUsername(u); setPassword(p); }}
                  className="w-full text-left px-3 py-1.5 rounded-lg hover:bg-slate-800/60 flex justify-between">
                  <span><span className="text-cyan-400 font-medium">{u}</span> / {p}</span>
                  <span className="text-slate-500">{r}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Step 2: Launch Scan ──────────────────────────────────────────────────────

function ScanStep({
  authUser, onLogout, onScanStarted, onViewScan,
}: {
  authUser: UserProfile;
  onLogout: () => void;
  onScanStarted: (scan: Scan) => void;
  onViewScan: (scan: Scan) => void;
}) {
  const [url, setUrl]           = useState("https://demo.owasp-juice.shop/");
  const [scanner, setScanner]   = useState("zap");
  const [ajaxSpider, setAjax]   = useState(true);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState<string | null>(null);
  const [recentScans, setRecent] = useState<Scan[]>([]);

  useEffect(() => {
    apiGet<Scan[]>("/api/v1/scans").then(setRecent).catch(() => {});
  }, []);

  const start = async () => {
    if (!url.trim()) { setError("Enter a target URL"); return; }
    setLoading(true); setError(null);
    try {
      const asset = await apiPost<Asset, { url: string }>("/api/v1/assets", { url: url.trim() });
      const config = scanner === "zap"
        ? { spider: true, active: true, ajax_spider: ajaxSpider, timeout_seconds: 900, priority: 5 }
        : { timeout_seconds: 600, priority: 5 };
      const scan = await apiPost<Scan, { asset_id: string; scanner: string; config: object }>(
        "/api/v1/scans", { asset_id: asset.id, scanner, config },
      );
      onScanStarted(scan);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to start scan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Nav */}
      <nav className="border-b border-slate-700/50 bg-slate-950/80 sticky top-0 z-40 backdrop-blur">
        <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-gradient-to-r from-cyan-400 to-blue-500" />
            <span className="font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">ATTT</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-cyan-400 to-blue-500 flex items-center justify-center text-xs font-bold text-white">
              {authUser.username[0].toUpperCase()}
            </div>
            <span className="text-sm text-slate-300">{authUser.username}</span>
            <Button variant="ghost" size="sm" onClick={onLogout} className="text-slate-400 hover:text-white text-xs">Sign out</Button>
          </div>
        </div>
      </nav>

      <main className="max-w-5xl mx-auto px-4 py-10 space-y-8">
        <StepBreadcrumb step="scan" />

        <div className="grid md:grid-cols-2 gap-6">
          {/* Launch form */}
          <div className="rounded-2xl border border-slate-700/50 bg-slate-900/50 p-8">
            <div className="mb-6">
              <h2 className="text-xl font-bold text-white mb-1">Launch Scan</h2>
              <p className="text-sm text-slate-400">Choose a scanner and target URL</p>
            </div>

            <div className="space-y-5">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wider">Target URL</label>
                <Input value={url} onChange={e => setUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="bg-slate-800/60 border-slate-700 text-white placeholder:text-slate-500"
                  onKeyDown={e => e.key === "Enter" && start()} />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wider">Scanner</label>
                <Select value={scanner} onChange={e => setScanner(e.target.value)}
                  className="bg-slate-800/60 border-slate-700 text-white w-full">
                  <option value="zap">🕷️ OWASP ZAP (Web Application)</option>
                  <option value="nikto">🔍 Nikto (Server Scanner)</option>
                </Select>
              </div>

              {scanner === "zap" && (
                <label className="flex items-center gap-3 cursor-pointer group">
                  <div
                    onClick={() => setAjax(v => !v)}
                    className={`w-10 h-5 rounded-full transition-colors relative ${ajaxSpider ? "bg-cyan-500" : "bg-slate-700"}`}>
                    <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${ajaxSpider ? "translate-x-5" : "translate-x-0.5"}`} />
                  </div>
                  <div>
                    <p className="text-sm text-slate-200 font-medium">Enable AJAX Spider</p>
                    <p className="text-xs text-slate-500">Required for Angular / React SPAs like Juice Shop</p>
                  </div>
                </label>
              )}

              {error && (
                <div className="rounded-lg bg-red-500/10 border border-red-500/30 px-3 py-2 text-sm text-red-300">{error}</div>
              )}

              <Button onClick={start} disabled={loading}
                className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold hover:opacity-90 disabled:opacity-50">
                {loading ? "Starting…" : "Start Scan"}
              </Button>
            </div>
          </div>

          {/* Recent scans */}
          <div className="rounded-2xl border border-slate-700/50 bg-slate-900/50 p-8">
            <h3 className="text-base font-semibold text-white mb-4">Recent Scans</h3>
            {recentScans.length === 0 ? (
              <p className="text-sm text-slate-500 text-center py-8">No scans yet</p>
            ) : (
              <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                {recentScans.slice(0, 15).map(s => {
                  const statusCls =
                    s.status === "completed" ? "bg-green-500/15 text-green-400" :
                    s.status === "running"   ? "bg-yellow-500/15 text-yellow-400 animate-pulse" :
                    s.status === "queued"    ? "bg-slate-600/40 text-slate-300" :
                    s.status === "failed"    ? "bg-red-500/15 text-red-400" :
                    "bg-slate-700 text-slate-400";
                  const dur = formatDuration(s.started_at, s.finished_at);
                  const isClickable = s.status === "completed" || s.status === "running";
                  const inner = (
                    <>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-mono text-slate-300">{s.id.slice(0, 8)}</span>
                        <div className="flex items-center gap-1.5">
                          {isClickable && (
                            <span className="text-xs text-cyan-500 opacity-70">View →</span>
                          )}
                          <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${statusCls}`}>
                            {s.status}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center justify-between text-xs text-slate-500">
                        <span>{s.scanner.toUpperCase()}</span>
                        <span>{formatDate(s.created_at)}</span>
                      </div>
                      {s.started_at && (
                        <div className="flex items-center justify-between text-xs mt-1">
                          <span className="text-slate-600">Duration</span>
                          <span className={s.status === "running" ? "text-yellow-500" : "text-slate-400"}>
                            {s.status === "running" ? `${dur} (running)` : dur}
                          </span>
                        </div>
                      )}
                      {s.status === "failed" && (
                        <div className="mt-1.5 flex items-center gap-1.5 text-xs text-red-400">
                          <span>⚠</span>
                          <span>Scan failed — check worker logs</span>
                        </div>
                      )}
                    </>
                  );
                  return isClickable ? (
                    <button key={s.id} onClick={() => onViewScan(s)}
                      className={`w-full text-left rounded-lg border px-3 py-2.5 transition-colors hover:border-cyan-500/40 hover:bg-slate-700/50 ${
                        s.status === "failed"
                          ? "bg-red-500/5 border-red-500/20"
                          : "bg-slate-800/50 border-slate-700/40"
                      }`}>
                      {inner}
                    </button>
                  ) : (
                    <div key={s.id} className={`rounded-lg border px-3 py-2.5 ${
                      s.status === "failed"
                        ? "bg-red-500/5 border-red-500/20"
                        : "bg-slate-800/50 border-slate-700/40"
                    }`}>
                      {inner}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

// ─── Step 3: Scanning (WebSocket) ─────────────────────────────────────────────

function ScanningStep({ scan, onCompleted, onFailed }: {
  scan: Scan;
  onCompleted: (findings: Finding[], updatedScan: Scan) => void;
  onFailed: () => void;
}) {
  const [wsMsg, setWsMsg] = useState<WsMsg>({ status: "queued" });
  const [log, setLog] = useState<string[]>([]);
  const [failError, setFailError] = useState<string | null>(null);
  const [cancelled, setCancelled] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [now, setNow] = useState(Date.now());

  // Tick every second for live elapsed display
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const ws = new WebSocket(scanWsUrl(scan.id));

    ws.onmessage = async (e) => {
      const msg: WsMsg = JSON.parse(e.data);
      setWsMsg(msg);
      setLog(prev => {
        const ts = new Date().toLocaleTimeString();
        const dur = msg.started_at ? formatDuration(msg.started_at) : "";
        const line = `[${ts}]  ${msg.status.padEnd(10)}  findings=${String(msg.findings_count ?? 0).padStart(3)}${dur ? `  elapsed=${dur}` : ""}`;
        return [line, ...prev].slice(0, 20);
      });

      if (msg.status === "completed") {
        try {
          const [findings, updatedScan] = await Promise.all([
            apiGet<Finding[]>(`/api/v1/findings?scan_id=${scan.id}`),
            apiGet<Scan>(`/api/v1/scans/${scan.id}`),
          ]);
          onCompleted(findings, updatedScan);
        } catch (e) {
          setFailError(e instanceof Error ? e.message : "Failed to load results");
        }
      } else if (msg.status === "cancelled") {
        setCancelled(true);
      } else if (msg.status === "failed") {
        setFailError("Scanner task failed. The target may be unreachable or ZAP timed out.");
      }
    };

    ws.onerror = () => {
      // Fallback to HTTP polling if WebSocket fails
      let pollActive = true;
      const poll = async () => {
        while (pollActive) {
          await new Promise(r => setTimeout(r, 4000));
          try {
            const s = await apiGet<Scan>(`/api/v1/scans/${scan.id}`);
            setWsMsg({ status: s.status, started_at: s.started_at, findings_count: 0 });
            setLog(prev => [`[${new Date().toLocaleTimeString()}]  ${s.status}  (HTTP poll)`, ...prev].slice(0, 20));
            if (s.status === "completed") {
              const findings = await apiGet<Finding[]>(`/api/v1/findings?scan_id=${scan.id}`);
              onCompleted(findings, s);
              return;
            } else if (s.status === "failed") {
              setFailError("Scanner task failed. Check worker logs for details.");
              return;
            }
          } catch {}
        }
      };
      poll();
      return () => { pollActive = false; };
    };

    return () => { ws.close(); };
  }, [scan.id, onCompleted]);

  const handleCancel = async () => {
    setCancelling(true);
    try {
      await apiPost(`/api/v1/scans/${scan.id}/cancel`, {});
      setCancelled(true);
    } catch (e) {
      setCancelling(false);
    }
  };

  const elapsedSec = wsMsg.started_at
    ? Math.floor((now - new Date(wsMsg.started_at).getTime()) / 1000)
    : null;
  const elapsedStr = elapsedSec != null
    ? elapsedSec < 60 ? `${elapsedSec}s` : `${Math.floor(elapsedSec / 60)}m ${elapsedSec % 60}s`
    : null;

  const stages = [
    { label: "Queued",      active: wsMsg.status === "queued",  done: ["running","completed"].includes(wsMsg.status) },
    { label: "Spider",      active: wsMsg.status === "running", done: wsMsg.status === "completed" },
    { label: "Active Scan", active: wsMsg.status === "running", done: wsMsg.status === "completed" },
    { label: "Saving",      active: false,                      done: wsMsg.status === "completed" },
  ];

  if (cancelled) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
        <div className="w-full max-w-lg">
          <StepBreadcrumb step="scanning" />
          <div className="mt-6 rounded-2xl border border-slate-600/40 bg-slate-800/30 p-8">
            <div className="flex items-center gap-3 mb-4">
              <span className="text-2xl">⏹</span>
              <div>
                <h2 className="text-lg font-bold text-white">Scan Cancelled</h2>
                <p className="text-sm text-slate-400">{scan.scanner.toUpperCase()} · {scan.id.slice(0, 8)}</p>
              </div>
            </div>
            <div className="rounded-lg bg-slate-800/60 border border-slate-700/30 px-4 py-3 mb-6 space-y-1 text-xs text-slate-400">
              {wsMsg.started_at && <p>Started: {formatDate(wsMsg.started_at)}</p>}
              {elapsedStr && <p>Ran for: {elapsedStr}</p>}
              {(wsMsg.findings_count ?? 0) > 0 && (
                <p>Partial findings collected: <span className="text-white font-semibold">{wsMsg.findings_count}</span></p>
              )}
            </div>
            <Button onClick={onFailed}
              className="w-full bg-slate-700 hover:bg-slate-600 text-white font-semibold">
              ← New Scan
            </Button>
          </div>
        </div>
      </div>
    );
  }

  if (failError) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
        <div className="w-full max-w-lg">
          <StepBreadcrumb step="scanning" />
          <div className="mt-6 rounded-2xl border border-red-500/30 bg-red-500/5 p-8">
            <div className="flex items-center gap-3 mb-4">
              <span className="text-2xl">⚠️</span>
              <div>
                <h2 className="text-lg font-bold text-white">Scan Failed</h2>
                <p className="text-sm text-slate-400">{scan.scanner.toUpperCase()} · {scan.id.slice(0, 8)}</p>
              </div>
            </div>
            <div className="rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3 mb-4">
              <p className="text-sm text-red-300">{failError}</p>
            </div>
            <div className="space-y-2 text-xs text-slate-500 mb-6">
              {wsMsg.started_at && <p>Started: {formatDate(wsMsg.started_at)}</p>}
              {elapsedStr && <p>Ran for: {elapsedStr} before failing</p>}
              <p>Scan ID: <span className="font-mono text-slate-400">{scan.id}</span></p>
            </div>
            <div className="rounded-lg bg-slate-900/60 border border-slate-700/30 p-3 mb-6">
              <p className="text-xs text-slate-500 mb-2 uppercase tracking-wider">Last log entries</p>
              <div className="font-mono text-xs text-slate-400 space-y-0.5 max-h-28 overflow-y-auto">
                {log.map((l, i) => <p key={i}>{l}</p>)}
              </div>
            </div>
            <Button onClick={onFailed}
              className="w-full bg-slate-700 hover:bg-slate-600 text-white font-semibold">
              ← Try Again
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-lg">
        <StepBreadcrumb step="scanning" />
        <div className="mt-6 rounded-2xl border border-slate-700/50 bg-slate-900/60 p-8">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-8 h-8 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin flex-shrink-0" />
            <div className="flex-1">
              <h2 className="text-lg font-bold text-white">Scan in Progress</h2>
              <p className="text-sm text-slate-400">{scan.scanner.toUpperCase()} · {scan.id.slice(0, 8)}</p>
            </div>
            {elapsedStr && (
              <div className="text-right">
                <p className="text-xs text-slate-500">Elapsed</p>
                <p className="text-sm font-mono font-semibold text-cyan-400">{elapsedStr}</p>
              </div>
            )}
          </div>

          {/* Stage pipeline */}
          <div className="flex items-center gap-1 mb-6">
            {stages.map((s, i) => (
              <div key={s.label} className="flex items-center gap-1 flex-1">
                {i > 0 && <div className={`flex-1 h-px ${s.done ? "bg-cyan-500" : "bg-slate-700"}`} />}
                <div className="flex flex-col items-center gap-1">
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${
                    s.done   ? "bg-cyan-500 text-white" :
                    s.active ? "border-2 border-cyan-500 border-t-transparent animate-spin bg-transparent" :
                    "bg-slate-800 border border-slate-600 text-slate-500"
                  }`}>
                    {s.done ? "✓" : s.active ? "" : i + 1}
                  </div>
                  <span className={`text-xs whitespace-nowrap ${s.done || s.active ? "text-slate-300" : "text-slate-600"}`}>
                    {s.label}
                  </span>
                </div>
              </div>
            ))}
          </div>

          {/* Stats grid */}
          <div className="grid grid-cols-3 gap-3 mb-6">
            <div className="rounded-lg bg-slate-800/60 border border-slate-700/40 px-3 py-3">
              <p className="text-xs text-slate-500">Status</p>
              <p className={`text-sm font-semibold mt-0.5 ${
                wsMsg.status === "running"   ? "text-yellow-400" :
                wsMsg.status === "completed" ? "text-green-400" :
                wsMsg.status === "failed"    ? "text-red-400"   : "text-slate-300"
              }`}>{wsMsg.status}</p>
            </div>
            <div className="rounded-lg bg-slate-800/60 border border-slate-700/40 px-3 py-3">
              <p className="text-xs text-slate-500">Findings</p>
              <p className="text-sm font-semibold text-white mt-0.5">{wsMsg.findings_count ?? 0}</p>
            </div>
            <div className="rounded-lg bg-slate-800/60 border border-slate-700/40 px-3 py-3">
              <p className="text-xs text-slate-500">Started</p>
              <p className="text-xs font-mono text-slate-300 mt-0.5 truncate">
                {wsMsg.started_at ? new Date(wsMsg.started_at).toLocaleTimeString() : "—"}
              </p>
            </div>
          </div>

          {/* Live log */}
          <div className="rounded-lg bg-slate-950/60 border border-slate-800 p-3 mb-4">
            <p className="text-xs text-slate-500 mb-2 uppercase tracking-wider">Live log</p>
            <div className="font-mono text-xs text-slate-400 space-y-0.5 max-h-40 overflow-y-auto">
              {log.length === 0
                ? <p className="text-slate-600">Waiting for WebSocket updates…</p>
                : log.map((l, i) => <p key={i} className="whitespace-pre">{l}</p>)
              }
            </div>
          </div>

          {/* Cancel */}
          {(wsMsg.status === "queued" || wsMsg.status === "running") && (
            <Button
              variant="ghost"
              size="sm"
              onClick={handleCancel}
              disabled={cancelling}
              className="w-full text-slate-500 hover:text-red-400 hover:bg-red-500/5 border border-slate-700/50 text-xs"
            >
              {cancelling ? "Stopping…" : "⏹ Stop Scan"}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Step 4: Results ──────────────────────────────────────────────────────────

function ResultsStep({ scan, findings, onRunAI, onBack }: {
  scan: Scan;     // up-to-date scan (with started_at / finished_at)
  findings: Finding[];
  onRunAI: () => void;
  onBack: () => void;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const counts = sevCounts(findings);

  return (
    <div className="min-h-screen bg-slate-950">
      <div className="max-w-5xl mx-auto px-4 py-8 space-y-6">
        <div className="flex items-center justify-between">
          <StepBreadcrumb step="results" />
          <Button variant="ghost" size="sm" onClick={onBack} className="text-slate-400 hover:text-white text-xs">
            ← New Scan
          </Button>
        </div>

        {/* Header */}
        <div className="rounded-2xl border border-green-500/30 bg-green-500/5 px-6 py-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className="text-green-400 text-lg">✓</span>
                <h2 className="text-lg font-bold text-white">Scan Complete</h2>
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm text-slate-400">
                <span>{scan.scanner.toUpperCase()}</span>
                <span>{findings.length} findings</span>
                <span className="font-mono text-xs text-slate-500">{scan.id.slice(0, 8)}</span>
              </div>
              {(scan.started_at || scan.finished_at) && (
                <div className="flex flex-wrap gap-x-5 gap-y-1 mt-2 text-xs text-slate-500">
                  {scan.started_at && (
                    <span>Started: <span className="text-slate-400">{formatDate(scan.started_at)}</span></span>
                  )}
                  {scan.finished_at && (
                    <span>Finished: <span className="text-slate-400">{formatDate(scan.finished_at)}</span></span>
                  )}
                  {scan.started_at && scan.finished_at && (
                    <span className="text-cyan-400 font-medium">
                      Duration: {formatDuration(scan.started_at, scan.finished_at)}
                    </span>
                  )}
                </div>
              )}
            </div>
            <Button onClick={onRunAI}
              className="flex-shrink-0 bg-gradient-to-r from-purple-500 to-indigo-600 text-white font-semibold hover:opacity-90 flex items-center gap-2">
              <span>🤖</span> Run AI Analysis
            </Button>
          </div>
        </div>

        {/* Severity summary */}
        <div className="grid grid-cols-5 gap-3">
          {SEV_ORDER.map(sev => {
            const c = SEV_COLOR[sev];
            return (
              <div key={sev} className="rounded-xl border border-slate-700/50 bg-slate-900/50 px-4 py-3 text-center">
                <p className={`text-2xl font-bold ${c.text}`}>{counts[sev]}</p>
                <p className="text-xs text-slate-500 mt-0.5">{sev}</p>
              </div>
            );
          })}
        </div>

        {/* Findings table */}
        <div className="rounded-2xl border border-slate-700/50 bg-slate-900/20 overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-700/40 flex items-center justify-between">
            <h3 className="font-semibold text-white">Findings — Raw Scanner Output</h3>
            <span className="text-xs text-slate-500">{findings.length} total · click row to expand</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-900/60 border-b border-slate-700/40">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Severity</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Title</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">CWE</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">URL</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Param</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {findings.map(f => {
                  const sev = normSev(f.severity);
                  const url = String(f.evidence?.url ?? "");
                  const param = String(f.evidence?.param ?? "");
                  const isOpen = expanded === f.id;
                  return [
                    <tr key={f.id}
                      onClick={() => setExpanded(isOpen ? null : f.id)}
                      className="hover:bg-slate-800/30 cursor-pointer transition-colors">
                      <td className="px-4 py-3"><SeverityBadge sev={sev} /></td>
                      <td className="px-4 py-3 text-slate-200 max-w-xs">
                        <div className="flex items-center gap-2">
                          <span>{f.title}</span>
                          <span className="text-slate-600 text-xs">{isOpen ? "▲" : "▼"}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-slate-400 text-xs font-mono">{f.cwe ?? "—"}</td>
                      <td className="px-4 py-3 text-slate-400 text-xs max-w-xs truncate" title={url}>{url || "—"}</td>
                      <td className="px-4 py-3 text-slate-400 text-xs font-mono">{param || "—"}</td>
                    </tr>,
                    isOpen && (
                      <tr key={`${f.id}-detail`} className="bg-slate-950/60">
                        <td colSpan={5} className="px-6 py-4">
                          <div className="space-y-3">
                            {f.description && (
                              <div>
                                <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Description</p>
                                <p className="text-sm text-slate-300">{f.description}</p>
                              </div>
                            )}
                            {!!f.evidence?.evidence && (
                              <div>
                                <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Evidence</p>
                                <p className="text-xs font-mono text-slate-400 bg-slate-900 rounded p-2">{String(f.evidence.evidence)}</p>
                              </div>
                            )}
                            {!!f.evidence?.solution && (
                              <div>
                                <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Scanner Solution Hint</p>
                                <p className="text-sm text-slate-300">{String(f.evidence.solution)}</p>
                              </div>
                            )}
                            <div className="flex items-center gap-4 text-xs text-slate-500">
                              {f.owasp && <span>OWASP: {f.owasp}</span>}
                              {!!f.evidence?.confidence && <span>Confidence: {String(f.evidence.confidence)}</span>}
                              {!!f.evidence?.method && <span>Method: {String(f.evidence.method)}</span>}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )
                  ];
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Step 5: AI Analysis ──────────────────────────────────────────────────────

function AnalyzingStep({ scan, onDone }: { scan: Scan; onDone: (findings: Finding[]) => void }) {
  const [stage, setStage] = useState(0);
  const stages = ["Risk scoring", "False positive detection", "Generating remediation"];

  useEffect(() => {
    const ticker = setInterval(() => setStage(s => Math.min(s + 1, stages.length - 1)), 6000);
    return () => clearInterval(ticker);
  }, [stages.length]);

  useEffect(() => {
    const poll = setInterval(async () => {
      try {
        const findings = await apiGet<Finding[]>(`/api/v1/findings?scan_id=${scan.id}`);
        const hasRemediation = (r?: Finding["remediation"] | null) =>
          !!(r && (r.summary || (r.steps && r.steps.length > 0) || (r.references && r.references.length > 0)));
        const aiDone = findings.length === 0 || findings.every(f => hasRemediation(f.remediation));
        if (aiDone) {
          clearInterval(poll);
          onDone(findings);
        }
      } catch {}
    }, 4000);
    return () => clearInterval(poll);
  }, [scan.id, onDone]);

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <StepBreadcrumb step="analyzing" />
        <div className="mt-6 rounded-2xl border border-slate-700/50 bg-slate-900/60 p-8">
          <div className="flex items-center gap-3 mb-6">
            <div className="text-2xl">🤖</div>
            <div>
              <h2 className="text-lg font-bold text-white">AI Analysis Running</h2>
              <p className="text-sm text-slate-400">Ollama processing findings…</p>
            </div>
          </div>

          <div className="space-y-4">
            {stages.map((s, i) => (
              <div key={s} className={`flex items-center gap-3 rounded-lg px-4 py-3 ${
                i < stage ? "bg-green-500/10 border border-green-500/30" :
                i === stage ? "bg-purple-500/10 border border-purple-500/30" :
                "bg-slate-800/40 border border-slate-700/30"
              }`}>
                {i < stage ? (
                  <span className="text-green-400 text-sm font-bold">✓</span>
                ) : i === stage ? (
                  <div className="w-4 h-4 rounded-full border-2 border-purple-400 border-t-transparent animate-spin" />
                ) : (
                  <div className="w-4 h-4 rounded-full bg-slate-700" />
                )}
                <span className={`text-sm font-medium ${
                  i < stage ? "text-green-300" : i === stage ? "text-purple-200" : "text-slate-500"
                }`}>{s}</span>
              </div>
            ))}
          </div>

          <p className="mt-6 text-xs text-slate-500 text-center">
            This may take a minute depending on the number of findings
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Step 6: Report ───────────────────────────────────────────────────────────

function ReportStep({ scan, findings, onBack, initialReport }: {
  scan: Scan;
  findings: Finding[];
  onBack: () => void;
  initialReport?: Report;
}) {
  const [report, setReport]         = useState<Report | null>(initialReport ?? null);
  const [generating, setGenerating] = useState(false);
  const [error, setError]           = useState<string | null>(null);

  const generateReport = useCallback(async () => {
    setGenerating(true); setError(null);
    try {
      const r = await apiPost<Report, { scan_id: string; report_type: string }>(
        "/api/v1/reports", { scan_id: scan.id, report_type: "executive" },
      );
      // poll until content.summary is populated
      let fetched = r;
      for (let i = 0; i < 30; i++) {
        await new Promise(res => setTimeout(res, 4000));
        const fresh = await apiGet<Report>(`/api/v1/reports/${r.id}`);
        if (fresh.content?.summary && fresh.content.summary !== "Executive summary pending AI analysis.") {
          fetched = fresh;
          break;
        }
        fetched = fresh;
      }
      setReport(fetched);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate report");
    } finally {
      setGenerating(false);
    }
  }, [scan.id]);

  useEffect(() => {
    if (!initialReport) generateReport();
  }, [generateReport, initialReport]);

  return (
    <div className="min-h-screen bg-slate-950">
      <div className="max-w-5xl mx-auto px-4 py-8 space-y-6">
        <div className="flex items-center justify-between">
          <StepBreadcrumb step="report" />
          <Button variant="ghost" size="sm" onClick={onBack} className="text-slate-400 hover:text-white text-xs">
            ← New Scan
          </Button>
        </div>

        <div className="rounded-xl border border-slate-700/50 bg-slate-900/40 px-5 py-4">
          <h2 className="text-lg font-bold text-white mb-1">Security Report</h2>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm text-slate-400">
            <span>{scan.scanner.toUpperCase()}</span>
            <span>{findings.length} findings · AI-analyzed</span>
            <span className="font-mono text-xs text-slate-500">{scan.id.slice(0, 8)}</span>
          </div>
          {(scan.started_at || scan.finished_at) && (
            <div className="flex flex-wrap gap-x-5 mt-1.5 text-xs text-slate-500">
              {scan.started_at && <span>Started: {formatDate(scan.started_at)}</span>}
              {scan.finished_at && <span>Finished: {formatDate(scan.finished_at)}</span>}
              {scan.started_at && scan.finished_at && (
                <span className="text-cyan-400">Duration: {formatDuration(scan.started_at, scan.finished_at)}</span>
              )}
            </div>
          )}
        </div>

        {generating && !report && (
          <div className="rounded-2xl border border-slate-700/50 bg-slate-900/50 p-12 text-center">
            <div className="w-8 h-8 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin mx-auto mb-4" />
            <p className="text-slate-300 font-medium">Generating executive summary…</p>
            <p className="text-slate-500 text-sm mt-1">Ollama is writing the analysis</p>
          </div>
        )}

        {error && (
          <div className="rounded-lg bg-red-500/10 border border-red-500/30 px-4 py-3 text-sm text-red-300">{error}</div>
        )}

        {report && (
          <ReportPreview
            content={{ ...report.content, findings }}
            scanId={scan.id}
          />
        )}
      </div>
    </div>
  );
}

// ─── Root orchestrator ────────────────────────────────────────────────────────

export default function HomePage() {
  const [step, setStep]               = useState<Step>("login");
  const [authUser, setAuthUser]       = useState<UserProfile | null>(null);
  const [activeScan, setActiveScan]   = useState<Scan | null>(null);
  const [findings, setFindings]       = useState<Finding[]>([]);
  const [activeReport, setActiveReport] = useState<Report | undefined>(undefined);

  // Restore session on mount
  useEffect(() => {
    const token = getToken();
    if (!token) return;
    apiGet<UserProfile>("/api/v1/auth/me")
      .then(u => { setAuthUser(u); setStep("scan"); })
      .catch(() => clearToken());
  }, []);

  const handleLogout = () => {
    clearToken(); setAuthUser(null); setActiveScan(null); setFindings([]); setActiveReport(undefined); setStep("login");
  };

  const handleLoginSuccess = (_token: string, user: UserProfile) => {
    setAuthUser(user); setStep("scan");
  };

  const handleScanStarted = (scan: Scan) => {
    setActiveScan(scan); setFindings([]); setActiveReport(undefined); setStep("scanning");
  };

  const handleScanCompleted = useCallback((f: Finding[], updatedScan: Scan) => {
    setFindings(f);
    setActiveScan(updatedScan);
    setActiveReport(undefined);
    setStep("results");
  }, []);

  const handleScanFailed = useCallback(() => {
    setStep("scan");
  }, []);

  const handleRunAI = () => setStep("analyzing");

  const handleAIDone = useCallback((f: Finding[]) => {
    setFindings(f); setActiveReport(undefined); setStep("report");
  }, []);

  const handleBack = () => { setActiveScan(null); setFindings([]); setActiveReport(undefined); setStep("scan"); };

  // Click a Recent Scan: load its findings and existing report (if any)
  const handleViewScan = useCallback(async (scan: Scan) => {
    setActiveScan(scan);
    setFindings([]);
    setActiveReport(undefined);

    if (scan.status === "running") {
      setStep("scanning");
      return;
    }

    if (scan.status === "completed") {
      try {
        const [scanFindings, reports] = await Promise.all([
          apiGet<Finding[]>(`/api/v1/findings?scan_id=${scan.id}`),
          apiGet<Report[]>(`/api/v1/reports?scan_id=${scan.id}`),
        ]);
        setFindings(scanFindings);
        if (reports.length > 0) {
          setActiveReport(reports[0]);
          setStep("report");
        } else {
          setStep("results");
        }
      } catch {
        setStep("results");
      }
    }
  }, []);

  if (step === "login") {
    return <LoginStep onSuccess={handleLoginSuccess} />;
  }
  if (step === "scan" && authUser) {
    return <ScanStep authUser={authUser} onLogout={handleLogout} onScanStarted={handleScanStarted} onViewScan={handleViewScan} />;
  }
  if (step === "scanning" && activeScan) {
    return <ScanningStep scan={activeScan} onCompleted={handleScanCompleted} onFailed={handleScanFailed} />;
  }
  if (step === "results" && activeScan) {
    return <ResultsStep scan={activeScan} findings={findings} onRunAI={handleRunAI} onBack={handleBack} />;
  }
  if (step === "analyzing" && activeScan) {
    return <AnalyzingStep scan={activeScan} onDone={handleAIDone} />;
  }
  if (step === "report" && activeScan) {
    return <ReportStep scan={activeScan} findings={findings} onBack={handleBack} initialReport={activeReport} />;
  }

  // fallback
  return <LoginStep onSuccess={handleLoginSuccess} />;
}
