import { useState, useEffect, useRef, useCallback } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Shield, Play, Square, AlertTriangle, CheckCircle,
  Loader2, ChevronDown, ChevronUp, Clock, Download, Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";

const API = "/scanner-api/api";

const RECON_MODULES = [
  { id: "ghostcrawler",  label: "GhostCrawler",  desc: "Endpoint & token hunt"   },
  { id: "wafshatter",   label: "WAFShatter",     desc: "WAF/CDN bypass"          },
  { id: "headerforge",  label: "HeaderForge",    desc: "Security headers"        },
  { id: "timebleed",    label: "TimeBleed",      desc: "Timing injection"        },
  { id: "authdrift",    label: "AuthDrift",      desc: "Access control"          },
  { id: "tokensniper",  label: "TokenSniper",    desc: "JWT & API tokens"        },
  { id: "deeplogic",    label: "DeepLogic",      desc: "Business logic"          },
  { id: "cryptohunter", label: "CryptoHunter",   desc: "Crypto weaknesses"       },
  { id: "backendprobe", label: "BackendProbe",   desc: "Deep backend scan"       },
  { id: "webprobe",     label: "WebProbe",       desc: "Web vulnerabilities"     },
  { id: "cveprobe",     label: "CVEProbe",       desc: "197 CVE probes"          },
  { id: "rootchain",    label: "RootChain",      desc: "Attack chains"           },
  { id: "graphqlprobe", label: "GraphQLProbe",   desc: "GraphQL deep scan"       },
  { id: "scan_diff",    label: "ScanDiff",       desc: "Change detection"        },
];

const EXPLOIT_MODULES = [
  { id: "authbypass",    label: "AuthBypass",    desc: "Auth bypass PoC"         },
  { id: "idorhunter",   label: "IDORHunter",    desc: "BOLA/IDOR proof"         },
  { id: "ssti_rce",     label: "SSTI/RCE",      desc: "Code execution proof"    },
  { id: "secretharvest",label: "SecretHarvest", desc: "Credential extraction"   },
];

const ALL_MODULES = [...RECON_MODULES, ...EXPLOIT_MODULES];

const SEV_CONFIG = [
  { key: "CRITICAL", label: "Critical", bg: "bg-red-500/15",    border: "border-red-500/40",    text: "text-red-400",    dot: "bg-red-500"    },
  { key: "HIGH",     label: "High",     bg: "bg-orange-500/15", border: "border-orange-500/40", text: "text-orange-400", dot: "bg-orange-500" },
  { key: "MEDIUM",   label: "Medium",   bg: "bg-yellow-500/15", border: "border-yellow-500/40", text: "text-yellow-400", dot: "bg-yellow-500" },
  { key: "LOW",      label: "Low",      bg: "bg-blue-500/15",   border: "border-blue-500/40",   text: "text-blue-400",   dot: "bg-blue-500"   },
  { key: "INFO",     label: "Info",     bg: "bg-slate-500/15",  border: "border-slate-500/40",  text: "text-slate-400",  dot: "bg-slate-400"  },
];

function sevCfg(sev: string) {
  return SEV_CONFIG.find(s => s.key === sev.toUpperCase()) ?? SEV_CONFIG[3];
}

// ── Finding detail modal ─────────────────────────────────────────────────────
function FindingModal({ finding, onClose }: { finding: any; onClose: () => void }) {
  const [showRaw, setShowRaw] = useState(false);
  const sev    = (finding.severity || "LOW").toUpperCase();
  const cfg    = sevCfg(sev);
  const title  = (finding.type || finding.title || finding.name || "Finding")
    .replace(/_/g, " ");

  // Extra metadata tags to show as chips
  const chips: { label: string; value: string | number }[] = [];
  if (finding.confidence !== undefined)
    chips.push({ label: "Confidence", value: `${finding.confidence}%${finding.confidence_label ? " · " + finding.confidence_label : ""}` });
  if (finding.status)
    chips.push({ label: "HTTP", value: finding.status });
  if (finding.response_size)
    chips.push({ label: "Size", value: `${finding.response_size} bytes` });
  if (finding.types_exposed)
    chips.push({ label: "Types exposed", value: finding.types_exposed });
  if (finding.paths_count)
    chips.push({ label: "API paths", value: finding.paths_count });
  if (finding.sources_count)
    chips.push({ label: "Source files", value: finding.sources_count });
  if (finding.content_type)
    chips.push({ label: "Content-Type", value: finding.content_type });
  if (finding.cors_origin)
    chips.push({ label: "CORS-Origin", value: finding.cors_origin });
  if (finding.exploitability !== undefined)
    chips.push({ label: "Exploitability", value: `${finding.exploitability}/10` });

  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="max-w-2xl w-[95vw] p-0 overflow-hidden gap-0 border-border">

        {/* Coloured header */}
        <div className={`px-5 py-4 border-b border-border ${cfg.bg} flex items-start gap-3`}>
          <span className={`text-[10px] px-2 py-1 rounded font-mono font-bold shrink-0 mt-0.5
            border ${cfg.bg} ${cfg.text} ${cfg.border}`}>
            {sev}
          </span>
          <div className="min-w-0 flex-1">
            <DialogTitle className={`text-sm font-semibold ${cfg.text} leading-tight`}>
              {title}
            </DialogTitle>
            {finding._module && (
              <p className="text-[10px] text-muted-foreground mt-0.5">
                Detected by: <span className="font-mono">{finding._module}</span>
              </p>
            )}
          </div>
        </div>

        {/* Scrollable body */}
        <div className="overflow-y-auto max-h-[72vh] p-5 space-y-4">

          {/* URL */}
          {(finding.url || finding.path) && (
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold mb-1">
                URL
              </p>
              <div className="font-mono text-xs text-foreground/80 bg-black/30 px-3 py-2 rounded break-all">
                {finding.url || finding.path}
              </div>
            </div>
          )}

          {/* Description */}
          {(finding.detail || finding.description) && (
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold mb-1">
                Description
              </p>
              <p className="text-xs text-foreground/80 leading-relaxed">
                {finding.detail || finding.description}
              </p>
            </div>
          )}

          {/* Metadata chips */}
          {chips.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {chips.map(({ label, value }) => (
                <span key={label}
                  className="text-[10px] px-2 py-0.5 rounded bg-muted/40 border border-border text-muted-foreground font-mono">
                  {label}: {value}
                </span>
              ))}
            </div>
          )}

          {/* Proof */}
          {finding.proof && (
            <div>
              <p className="text-[10px] text-blue-400/80 uppercase tracking-wider font-semibold mb-1.5">
                Proof / Evidence
              </p>
              <div className="bg-black/40 border-l-2 border-blue-500/60 px-3 py-2.5 rounded-r-md">
                <pre className="text-[11px] text-blue-300/80 whitespace-pre-wrap break-all leading-relaxed font-mono">
                  {finding.proof}
                </pre>
              </div>
            </div>
          )}

          {/* Remediation */}
          {(finding.remediation || finding.fix) && (
            <div>
              <p className="text-[10px] text-green-400/80 uppercase tracking-wider font-semibold mb-1.5">
                Remediation
              </p>
              <div className="bg-black/30 border-l-2 border-green-500/50 px-3 py-2.5 rounded-r-md">
                <p className="text-[11px] text-green-300/80 leading-relaxed">
                  {finding.remediation || finding.fix}
                </p>
              </div>
            </div>
          )}

          {/* Impact */}
          {finding.impact && (
            <div>
              <p className="text-[10px] text-orange-400/80 uppercase tracking-wider font-semibold mb-1">
                Impact
              </p>
              <p className="text-xs text-foreground/70 leading-relaxed">{finding.impact}</p>
            </div>
          )}

          {/* Reproducibility */}
          {finding.reproducibility && finding.reproducibility !== "See proof field." && (
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold mb-1">
                Reproduce
              </p>
              <div className="font-mono text-[11px] text-foreground/70 bg-black/30 px-3 py-2 rounded break-all">
                {finding.reproducibility}
              </div>
            </div>
          )}

          {/* MITRE badge */}
          {finding.mitre_technique && (
            <div>
              <a
                href={`https://attack.mitre.org/techniques/${finding.mitre_technique.replace(".", "/")}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-block text-[10px] px-2.5 py-1 rounded
                  bg-indigo-900/50 border border-indigo-500/30 text-indigo-300 font-mono
                  hover:bg-indigo-900/70 transition-colors"
              >
                ↗ MITRE {finding.mitre_technique}
                {finding.mitre_name ? ` — ${finding.mitre_name}` : ""}
              </a>
            </div>
          )}

          {/* Raw JSON toggle */}
          <div className="border-t border-border/40 pt-3">
            <button
              onClick={() => setShowRaw(v => !v)}
              className="text-[10px] text-muted-foreground hover:text-foreground transition-colors underline underline-offset-2"
            >
              {showRaw ? "Hide" : "Show"} raw finding JSON
            </button>
            {showRaw && (
              <pre className="mt-2 text-[10px] text-muted-foreground bg-black/40 p-3 rounded
                overflow-x-auto leading-relaxed font-mono max-h-64">
                {JSON.stringify(finding, null, 2)}
              </pre>
            )}
          </div>

        </div>
      </DialogContent>
    </Dialog>
  );
}
// ── End FindingModal ─────────────────────────────────────────────────────────

interface ScanStatus {
  status: string;
  current_module: string;
  completed_modules: string[];
  total_modules: number;
  findings_count: number;
}

interface ScanResults {
  findings: any[];
  chains: any[];
  duration: number;
  target: string;
}

export default function Dashboard() {
  const { toast } = useToast();
  const [target, setTarget]                   = useState("");
  const [selected, setSelected]               = useState<string[]>(ALL_MODULES.map(m => m.id));
  const [showModules, setShowModules]         = useState(true);
  const [jobId, setJobId]                     = useState<string | null>(null);
  const [status, setStatus]                   = useState<ScanStatus | null>(null);
  const [lines, setLines]                     = useState<string[]>([]);
  const [results, setResults]                 = useState<ScanResults | null>(null);
  const [loadingResults, setLoadingResults]   = useState(false);
  const [liveFindings, setLiveFindings]       = useState<any[]>([]);
  const [wsConnected, setWsConnected]         = useState(false);
  const [showLivePanel, setShowLivePanel]     = useState(true);
  const [selectedFinding, setSelectedFinding] = useState<any>(null);

  const termRef    = useRef<HTMLDivElement>(null);
  const wsRef      = useRef<WebSocket | null>(null);
  const pollRef    = useRef<ReturnType<typeof setInterval> | null>(null);
  const lineIdxRef = useRef(0);

  const { data: health } = useQuery({
    queryKey: ["health"],
    queryFn: () => fetch(`${API}/health`).then(r => r.json()),
    refetchInterval: 15_000,
  });

  // ── Polling fallback ──────────────────────────────────────────────────────
  const startPolling = useCallback((id: string) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const res  = await fetch(`${API}/scan/status/${id}?since=${lineIdxRef.current}`);
        if (!res.ok) return;
        const data = await res.json();
        setStatus(data);
        if (data.new_output?.length) {
          setLines(prev => [...prev, ...data.new_output]);
          lineIdxRef.current = data.output_index;
        }
        if (["done", "error", "stopped"].includes(data.status)) {
          if (pollRef.current) clearInterval(pollRef.current);
          pollRef.current = null;
          if (data.status === "done") {
            setLoadingResults(true);
            fetch(`${API}/scan/results/${id}`)
              .then(r => r.json())
              .then(rd => setResults(rd))
              .catch(() => toast({ title: "Failed to load results", variant: "destructive" }))
              .finally(() => setLoadingResults(false));
          }
        }
      } catch (_) {}
    }, 1200);
  }, [toast]);

  // ── Start mutation ────────────────────────────────────────────────────────
  const startMut = useMutation({
    mutationFn: (body: object) =>
      fetch(`${API}/scan/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(r => r.json()),
    onSuccess: (data) => {
      if (data.error) {
        toast({ title: "Error", description: data.error, variant: "destructive" });
        return;
      }
      lineIdxRef.current = 0;
      setJobId(data.job_id);
      setLines([]);
      setStatus(null);
      setResults(null);
      setLiveFindings([]);
      setWsConnected(false);
    },
  });

  const stopMut = useMutation({
    mutationFn: (id: string) =>
      fetch(`${API}/scan/stop/${id}`, { method: "POST" }).then(r => r.json()),
  });

  // ── WebSocket primary stream ──────────────────────────────────────────────
  useEffect(() => {
    if (!jobId) return;

    if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/scanner-api/api/scan/ws/${jobId}`;
    const ws    = new WebSocket(wsUrl);
    wsRef.current = ws;
    let usedFallback = false;

    const activateFallback = () => {
      if (usedFallback) return;
      usedFallback = true;
      setWsConnected(false);
      startPolling(jobId);
    };

    ws.onopen  = () => setWsConnected(true);
    ws.onerror = activateFallback;
    ws.onclose = (e) => {
      setWsConnected(false);
      if (e.code !== 1000 && e.code !== 1001) activateFallback();
    };

    ws.onmessage = (e) => {
      try {
        const evt = JSON.parse(e.data as string);
        switch (evt.type) {
          case "ping": break;

          case "log":
            if (evt.data) setLines(prev => [...prev, evt.data as string]);
            break;

          case "module_start":
            setStatus(prev => ({
              status:            "running",
              current_module:    evt.module as string,
              completed_modules: prev?.completed_modules ?? [],
              total_modules:     (evt.total_modules as number) ?? (prev?.total_modules ?? 0),
              findings_count:    prev?.findings_count ?? 0,
            }));
            break;

          case "module_done":
            setStatus(prev => prev ? {
              ...prev,
              current_module:    "",
              completed_modules: [...(prev.completed_modules ?? []), evt.module as string],
              findings_count:    (evt.total as number) ?? prev.findings_count,
            } : prev);
            if (Array.isArray(evt.findings) && evt.findings.length > 0) {
              setLiveFindings(prev => [
                ...prev,
                ...(evt.findings as any[]).map(f => ({ ...f, _module: evt.module as string })),
              ]);
              setShowLivePanel(true);
            }
            break;

          case "done":
            setWsConnected(false);
            setStatus(prev => prev ? { ...prev, status: "done", current_module: "" } : null);
            ws.close(1000);
            setLoadingResults(true);
            fetch(`${API}/scan/results/${jobId}`)
              .then(r => r.json())
              .then(rd => setResults(rd as ScanResults))
              .catch(() => toast({ title: "Failed to load results", variant: "destructive" }))
              .finally(() => setLoadingResults(false));
            break;

          case "stopped":
            setWsConnected(false);
            setStatus(prev => prev ? { ...prev, status: "stopped", current_module: "" } : null);
            ws.close(1000);
            break;

          case "error":
            toast({ title: "Scanner error", description: evt.data as string, variant: "destructive" });
            break;
        }
      } catch (_) {}
    };

    return () => {
      ws.close();
      wsRef.current = null;
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    };
  }, [jobId, startPolling, toast]);

  // Auto-scroll terminal
  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [lines]);

  // ── Derived state ─────────────────────────────────────────────────────────
  const isRunning = status?.status === "running" || status?.status === "queued";
  const isDone    = status?.status === "done";
  const isStopped = status?.status === "stopped";
  const allOn     = selected.length === ALL_MODULES.length;
  const progress  = status?.total_modules
    ? Math.round(((status.completed_modules?.length ?? 0) / status.total_modules) * 100)
    : 0;

  const sevCounts = results?.findings
    ? SEV_CONFIG.reduce((acc, s) => {
        acc[s.key] = results.findings.filter(
          f => (f.severity || f.sev || "").toUpperCase() === s.key
        ).length;
        return acc;
      }, {} as Record<string, number>)
    : null;

  const totalFindings = results?.findings?.length ?? 0;
  const hasFindings   = totalFindings > 0;

  function toggleModule(id: string) {
    setSelected(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  }

  function handleStart(runAll = false) {
    if (!target.trim()) {
      toast({ title: "Enter a target URL", variant: "destructive" });
      return;
    }
    const mods = runAll ? ALL_MODULES.map(m => m.id) : selected;
    if (!mods.length) {
      toast({ title: "Select at least one module", variant: "destructive" });
      return;
    }
    if (runAll) setSelected(ALL_MODULES.map(m => m.id));
    startMut.mutate({ target: target.trim(), modules: mods });
  }

  function downloadFullReport() {
    const a = document.createElement("a");
    a.href = `${API}/reports/combined/html`;
    a.download = "mirror-full-report.html";
    a.click();
  }

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="p-4 md:p-6 space-y-4 max-w-4xl mx-auto">

      {/* Header */}
      <div>
        <h1 className="text-lg md:text-xl font-semibold text-foreground flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary" /> Security Arsenal
        </h1>
        <p className="text-xs md:text-sm text-muted-foreground mt-0.5">Authorized testing only</p>
      </div>

      {/* Scanner status bar */}
      <div className="flex items-center gap-2 p-3 rounded-lg bg-card border border-card-border">
        {health ? (
          <>
            <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
            <span className="text-sm font-medium text-foreground">Scanner online</span>
            <span className="text-xs text-muted-foreground ml-1">
              {health.modules_ready}/{health.modules_total} modules ready
            </span>
          </>
        ) : (
          <>
            <Loader2 className="w-4 h-4 text-muted-foreground animate-spin shrink-0" />
            <span className="text-sm text-muted-foreground">Connecting...</span>
          </>
        )}
        {wsConnected && (
          <span className="ml-auto flex items-center gap-1.5 text-xs font-semibold text-green-400
            bg-green-400/10 border border-green-400/25 px-2 py-0.5 rounded-full">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-400" />
            </span>
            Live stream
          </span>
        )}
      </div>

      {/* ── RESULTS SUMMARY ───────────────────────────────────────────────── */}
      {(loadingResults || results) && (
        <div className="rounded-xl border border-card-border bg-card overflow-hidden">
          <div className="px-4 py-3 border-b border-card-border bg-muted/20 flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              {loadingResults
                ? <Loader2 className="w-4 h-4 animate-spin text-primary" />
                : hasFindings
                  ? <AlertTriangle className="w-4 h-4 text-yellow-400" />
                  : <CheckCircle className="w-4 h-4 text-green-400" />}
              <span className="text-sm font-semibold text-foreground">
                {loadingResults ? "Loading results..." : hasFindings
                  ? `${totalFindings} finding${totalFindings !== 1 ? "s" : ""} detected`
                  : "No findings detected"}
              </span>
            </div>
            {results && (
              <div className="flex items-center gap-2 flex-wrap">
                <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <Clock className="w-3.5 h-3.5" />
                  <span>{results.duration}s</span>
                  {results.chains?.length > 0 && (
                    <span className="ml-2 px-1.5 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-400 font-medium">
                      {results.chains.length} attack chain{results.chains.length !== 1 ? "s" : ""}
                    </span>
                  )}
                </div>
                <button
                  onClick={downloadFullReport}
                  className="inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded-md
                    bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20 transition-colors font-medium"
                >
                  <Download className="w-3 h-3" /> Download Full Report
                </button>
              </div>
            )}
          </div>

          {sevCounts && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4">
              {SEV_CONFIG.slice(0, 4).map(s => (
                <div key={s.key}
                  className={`rounded-lg border ${s.border} ${s.bg} p-3 flex flex-col items-center gap-1`}>
                  <span className={`text-2xl font-bold ${s.text}`}>{sevCounts[s.key] ?? 0}</span>
                  <div className="flex items-center gap-1.5">
                    <div className={`w-2 h-2 rounded-full ${s.dot}`} />
                    <span className={`text-xs font-medium ${s.text}`}>{s.label}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Top findings — clickable to open modal */}
          {results?.findings && results.findings.length > 0 && (
            <div className="border-t border-card-border px-4 pb-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wider mt-3 mb-2 font-medium">
                Top Findings <span className="normal-case font-normal">(click to inspect)</span>
              </p>
              <div className="space-y-1.5">
                {results.findings.slice(0, 5).map((f: any, i: number) => {
                  const sev = (f.severity || f.sev || "LOW").toUpperCase();
                  const cfg = sevCfg(sev);
                  return (
                    <button
                      key={i}
                      onClick={() => setSelectedFinding(f)}
                      className="w-full text-left flex items-start gap-2.5 p-2.5 rounded-lg
                        bg-muted/20 border border-border/50 hover:border-primary/40
                        hover:bg-muted/40 transition-all duration-150 active:scale-[0.99]"
                    >
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-bold shrink-0 mt-0.5 ${cfg.bg} ${cfg.text} border ${cfg.border}`}>
                        {sev}
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="text-xs font-medium text-foreground truncate">
                          {f.title || f.name || f.type || "Finding"}
                        </p>
                        {(f.description || f.detail || f.url) && (
                          <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-1">
                            {f.description || f.detail || f.url}
                          </p>
                        )}
                      </div>
                      {f.module && (
                        <span className="text-[10px] text-muted-foreground shrink-0 hidden sm:block">
                          {f.module}
                        </span>
                      )}
                    </button>
                  );
                })}
                {results.findings.length > 5 && (
                  <p className="text-xs text-muted-foreground text-center py-1">
                    + {results.findings.length - 5} more — download the full report
                  </p>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Target input */}
      <div className="rounded-lg border border-card-border bg-card p-4 space-y-3">
        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Target URL</p>
        <Input
          placeholder="https://target.example.com"
          value={target}
          onChange={e => setTarget(e.target.value)}
          onKeyDown={e => e.key === "Enter" && !isRunning && handleStart()}
          className="font-mono text-sm"
          disabled={isRunning}
        />
        <div className="flex flex-col sm:flex-row gap-2">
          {isRunning ? (
            <Button variant="destructive" className="w-full"
              onClick={() => jobId && stopMut.mutate(jobId)}>
              <Square className="w-3.5 h-3.5 mr-1.5" /> Stop Scan
            </Button>
          ) : (
            <>
              <Button variant="outline" className="flex-1"
                onClick={() => handleStart(false)}
                disabled={startMut.isPending || !selected.length}>
                {startMut.isPending
                  ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                  : <Play className="w-3.5 h-3.5 mr-1.5" />}
                Run Selected ({selected.length})
              </Button>
              <Button className="flex-1"
                onClick={() => handleStart(true)}
                disabled={startMut.isPending}>
                {startMut.isPending
                  ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                  : <Shield className="w-3.5 h-3.5 mr-1.5" />}
                Run All {ALL_MODULES.length}
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Module picker */}
      <div className="rounded-lg border border-card-border bg-card overflow-hidden">
        <button
          className="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/20 transition-colors"
          onClick={() => setShowModules(p => !p)}
        >
          <span className="text-sm font-medium text-foreground">
            Modules
            <span className="ml-2 text-xs text-muted-foreground font-normal">
              {selected.length}/{ALL_MODULES.length} selected
            </span>
          </span>
          <div className="flex items-center gap-3">
            <span
              role="button" tabIndex={0}
              className="text-xs text-primary hover:underline px-1"
              onClick={e => { e.stopPropagation(); setSelected(allOn ? [] : ALL_MODULES.map(m => m.id)); }}
              onKeyDown={e => { if (e.key === "Enter") { e.stopPropagation(); setSelected(allOn ? [] : ALL_MODULES.map(m => m.id)); }}}
            >
              {allOn ? "Clear all" : "Select all"}
            </span>
            {showModules ? <ChevronUp className="w-4 h-4 text-muted-foreground" />
                        : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
          </div>
        </button>

        {showModules && (
          <div className="px-4 pb-4 space-y-3">
            <div>
              <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-primary inline-block" />
                Recon &amp; Analysis
                <span className="ml-1 text-muted-foreground/60 font-normal normal-case">{RECON_MODULES.length} modules</span>
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
                {RECON_MODULES.map(m => {
                  const on = selected.includes(m.id);
                  return (
                    <button key={m.id} onClick={() => toggleModule(m.id)}
                      className={`text-left p-2.5 rounded-lg border transition-all active:scale-95
                        ${on ? "border-primary/50 bg-primary/10 text-foreground"
                              : "border-border bg-muted/20 text-muted-foreground"}`}>
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <div className={`w-2 h-2 rounded-full shrink-0 ${on ? "bg-primary" : "bg-border"}`} />
                        <p className="text-xs font-semibold truncate">{m.label}</p>
                      </div>
                      <p className="text-[10px] opacity-60 leading-tight pl-3.5 line-clamp-1">{m.desc}</p>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="border-t border-border/50" />

            <div>
              <p className="text-[10px] font-semibold text-red-400/80 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500 inline-block" />
                Exploit Provers
                <span className="ml-1 text-muted-foreground/60 font-normal normal-case text-muted-foreground">confirmed PoC — authorized targets only</span>
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
                {EXPLOIT_MODULES.map(m => {
                  const on = selected.includes(m.id);
                  return (
                    <button key={m.id} onClick={() => toggleModule(m.id)}
                      className={`text-left p-2.5 rounded-lg border transition-all active:scale-95
                        ${on ? "border-red-500/50 bg-red-500/10 text-foreground"
                              : "border-border bg-muted/20 text-muted-foreground"}`}>
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <div className={`w-2 h-2 rounded-full shrink-0 ${on ? "bg-red-500" : "bg-border"}`} />
                        <p className="text-xs font-semibold truncate">{m.label}</p>
                      </div>
                      <p className="text-[10px] opacity-60 leading-tight pl-3.5 line-clamp-1">{m.desc}</p>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Progress bar */}
      {status && (
        <div className="rounded-lg border border-card-border bg-card p-4 space-y-2">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2 text-sm">
              {isRunning && <Loader2 className="w-4 h-4 animate-spin text-primary" />}
              {isDone    && <CheckCircle className="w-4 h-4 text-green-400" />}
              {isStopped && <Square className="w-4 h-4 text-muted-foreground" />}
              <span className="font-medium capitalize">{status.status}</span>
              {status.current_module && (
                <span className="text-muted-foreground text-xs">— {status.current_module}</span>
              )}
            </div>
            <span className="text-xs text-muted-foreground font-mono">
              {status.completed_modules?.length ?? 0}/{status.total_modules ?? 0}
              {(status.findings_count ?? 0) > 0 && ` · ${status.findings_count} findings`}
            </span>
          </div>
          <div className="h-2 rounded-full bg-muted overflow-hidden">
            <div className="h-full bg-primary rounded-full transition-all duration-500"
              style={{ width: `${progress}%` }} />
          </div>
          <p className="text-xs text-right text-muted-foreground">{progress}%</p>
        </div>
      )}

      {/* ── LIVE FINDINGS STREAM ──────────────────────────────────────────── */}
      {liveFindings.length > 0 && (
        <div className="rounded-xl border border-card-border bg-card overflow-hidden">
          <button
            className="w-full flex items-center justify-between px-4 py-2.5 border-b border-card-border bg-muted/20 hover:bg-muted/30 transition-colors"
            onClick={() => setShowLivePanel(p => !p)}
          >
            <div className="flex items-center gap-2">
              <Zap className="w-3.5 h-3.5 text-primary" />
              <span className="text-sm font-semibold text-foreground">Live Findings</span>
              <span className="text-xs text-muted-foreground">
                {liveFindings.length} finding{liveFindings.length !== 1 ? "s" : ""}
              </span>
              <span className="text-[10px] text-muted-foreground/60 hidden sm:block">
                — click any card to inspect
              </span>
            </div>
            <div className="flex items-center gap-2">
              {wsConnected && (
                <span className="flex items-center gap-1 text-[10px] font-semibold text-green-400
                  bg-green-400/10 border border-green-400/25 px-1.5 py-0.5 rounded">
                  <span className="relative flex h-1.5 w-1.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-green-400" />
                  </span>
                  LIVE
                </span>
              )}
              {showLivePanel
                ? <ChevronUp className="w-4 h-4 text-muted-foreground" />
                : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
            </div>
          </button>

          {showLivePanel && (
            <div className="max-h-80 overflow-y-auto p-3 space-y-1.5">
              {[...liveFindings].reverse().map((f, i) => {
                const sev = (f.severity || "LOW").toUpperCase();
                const cfg = sevCfg(sev);
                return (
                  <button
                    key={`${f._module ?? ""}-${i}`}
                    onClick={() => setSelectedFinding(f)}
                    className={`w-full text-left flex items-start gap-2.5 p-2.5 rounded-lg border
                      ${cfg.border} ${cfg.bg} transition-all duration-200
                      hover:brightness-110 hover:shadow-sm active:scale-[0.99] cursor-pointer`}
                  >
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-bold shrink-0 mt-0.5
                      ${cfg.bg} ${cfg.text} border ${cfg.border}`}>
                      {sev.slice(0, 4)}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium text-foreground truncate">
                        {f.type || f.title || f.name || "Finding"}
                      </p>
                      {(f.url || f.detail || f.description) && (
                        <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-1">
                          {f.url || f.detail || f.description}
                        </p>
                      )}
                    </div>
                    {f._module && (
                      <span className={`text-[10px] px-1.5 py-0.5 rounded shrink-0 font-mono ${cfg.bg} ${cfg.text}`}>
                        {f._module}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          )}
        </div>
      )}
      {/* ── END LIVE FINDINGS ─────────────────────────────────────────────── */}

      {/* Terminal output */}
      {lines.length > 0 && (
        <div className="rounded-lg border border-card-border overflow-hidden">
          <div className="flex items-center justify-between px-3 py-2 bg-black/40 border-b border-border">
            <span className="text-xs font-mono text-muted-foreground">Output</span>
            <span className="text-xs text-muted-foreground">{lines.length} lines</span>
          </div>
          <div ref={termRef} className="terminal h-56 md:h-72 text-[11px] md:text-xs">
            {lines.map((l, i) => (
              <div key={i} className={
                l.includes("[VULN]") || l.includes("[!]") ? "text-red-400" :
                l.includes("[+]")   ? "text-green-400" :
                l.includes("[X]")   ? "text-red-500" :
                l.startsWith("=")   ? "text-blue-400 font-bold" :
                "text-green-400/80"
              }>{l || "\u00a0"}</div>
            ))}
          </div>
        </div>
      )}

      {/* Legal notice */}
      <div className="flex items-start gap-2 text-xs text-muted-foreground border border-border/50 rounded-lg p-3 bg-muted/10">
        <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-yellow-500 mt-0.5" />
        <span>Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.</span>
      </div>

      {/* ── Per-finding drill-down modal ─────────────────────────────────── */}
      {selectedFinding && (
        <FindingModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}

    </div>
  );
}
