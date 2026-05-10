import { useState, useEffect, useRef } from "react";
  import { useMutation, useQuery } from "@tanstack/react-query";
  import {
    Shield, Play, Square, AlertTriangle, CheckCircle,
    Loader2, ChevronDown, ChevronUp, Clock,
  } from "lucide-react";
  import { Button } from "@/components/ui/button";
  import { Input } from "@/components/ui/input";
  import { useToast } from "@/hooks/use-toast";

  const API = "/scanner-api/api";

  const ALL_MODULES = [
    { id: "ghostcrawler",  label: "GhostCrawler",  desc: "Endpoint & token hunt" },
    { id: "wafshatter",   label: "WAFShatter",     desc: "WAF/CDN bypass" },
    { id: "headerforge",  label: "HeaderForge",    desc: "Security headers" },
    { id: "timebleed",    label: "TimeBleed",      desc: "Timing injection" },
    { id: "authdrift",    label: "AuthDrift",      desc: "Access control" },
    { id: "tokensniper",  label: "TokenSniper",    desc: "JWT & API tokens" },
    { id: "deeplogic",    label: "DeepLogic",      desc: "Business logic" },
    { id: "cryptohunter", label: "CryptoHunter",   desc: "Crypto weaknesses" },
    { id: "backendprobe", label: "BackendProbe",   desc: "Deep backend scan" },
    { id: "webprobe",     label: "WebProbe",       desc: "Web vulnerabilities" },
    { id: "cveprobe",     label: "CVEProbe",       desc: "197 CVE probes" },
    { id: "rootchain",    label: "RootChain",      desc: "Attack chains" },
  ];

  const SEV_CONFIG = [
    { key: "CRITICAL", label: "Critical", bg: "bg-red-500/15",    border: "border-red-500/40",    text: "text-red-400",    dot: "bg-red-500"    },
    { key: "HIGH",     label: "High",     bg: "bg-orange-500/15", border: "border-orange-500/40", text: "text-orange-400", dot: "bg-orange-500" },
    { key: "MEDIUM",   label: "Medium",   bg: "bg-yellow-500/15", border: "border-yellow-500/40", text: "text-yellow-400", dot: "bg-yellow-500" },
    { key: "LOW",      label: "Low",      bg: "bg-blue-500/15",   border: "border-blue-500/40",   text: "text-blue-400",   dot: "bg-blue-500"   },
  ];

  interface ScanResults {
    findings: any[];
    chains: any[];
    duration: number;
    target: string;
  }

  export default function Dashboard() {
    const { toast } = useToast();
    const [target, setTarget]          = useState("");
    const [selected, setSelected]      = useState<string[]>(ALL_MODULES.map(m => m.id));
    const [showModules, setShowModules] = useState(true);
    const [jobId, setJobId]            = useState<string | null>(null);
    const [status, setStatus]          = useState<any>(null);
    const [lines, setLines]            = useState<string[]>([]);
    const [lineIdx, setLineIdx]        = useState(0);
    const [results, setResults]        = useState<ScanResults | null>(null);
    const [loadingResults, setLoadingResults] = useState(false);
    const termRef = useRef<HTMLDivElement>(null);
    const pollRef = useRef<any>(null);

    const { data: health } = useQuery({
      queryKey: ["health"],
      queryFn: () => fetch(`${API}/health`).then(r => r.json()),
      refetchInterval: 15_000,
    });

    const startMut = useMutation({
      mutationFn: (body: object) =>
        fetch(`${API}/scan/start`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }).then(r => r.json()),
      onSuccess: (data) => {
        if (data.error) { toast({ title: "Error", description: data.error, variant: "destructive" }); return; }
        setJobId(data.job_id);
        setLines([]);
        setLineIdx(0);
        setStatus(null);
        setResults(null);
      },
    });

    const stopMut = useMutation({
      mutationFn: (id: string) =>
        fetch(`${API}/scan/stop/${id}`, { method: "POST" }).then(r => r.json()),
    });

    // Poll while running, fetch full results when done
    useEffect(() => {
      if (!jobId) return;
      pollRef.current = setInterval(async () => {
        const res = await fetch(`${API}/scan/status/${jobId}?since=${lineIdx}`);
        const data = await res.json();
        setStatus(data);
        if (data.new_output?.length) {
          setLines(prev => [...prev, ...data.new_output]);
          setLineIdx(data.output_index);
        }
        if (["done", "error", "stopped"].includes(data.status)) {
          clearInterval(pollRef.current);
          // Fetch full results once scan finishes
          if (data.status === "done") {
            setLoadingResults(true);
            try {
              const rr = await fetch(`${API}/scan/results/${jobId}`);
              const rd = await rr.json();
              setResults(rd);
            } finally {
              setLoadingResults(false);
            }
          }
        }
      }, 1200);
      return () => clearInterval(pollRef.current);
    }, [jobId, lineIdx]);

    useEffect(() => {
      if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
    }, [lines]);

    const isRunning = status?.status === "running" || status?.status === "queued";
    const isDone    = status?.status === "done";
    const isStopped = status?.status === "stopped";
    const allOn     = selected.length === ALL_MODULES.length;
    const progress  = status?.total_modules
      ? Math.round(((status.completed_modules?.length ?? 0) / status.total_modules) * 100)
      : 0;

    // Severity counts from results
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
      if (!target.trim()) { toast({ title: "Enter a target URL", variant: "destructive" }); return; }
      const mods = runAll ? ALL_MODULES.map(m => m.id) : selected;
      if (!mods.length) { toast({ title: "Select at least one module", variant: "destructive" }); return; }
      if (runAll) setSelected(ALL_MODULES.map(m => m.id));
      startMut.mutate({ target: target.trim(), modules: mods });
    }

    return (
      <div className="p-4 md:p-6 space-y-4 max-w-4xl mx-auto">

        {/* Header */}
        <div>
          <h1 className="text-lg md:text-xl font-semibold text-foreground flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" /> Security Arsenal
          </h1>
          <p className="text-xs md:text-sm text-muted-foreground mt-0.5">Authorized testing only</p>
        </div>

        {/* Scanner status */}
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
        </div>

        {/* ── RESULTS SUMMARY ────────────────────────────────────────────── */}
        {(loadingResults || results) && (
          <div className="rounded-xl border border-card-border bg-card overflow-hidden">
            {/* Summary header */}
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
                <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <Clock className="w-3.5 h-3.5" />
                  <span>{results.duration}s</span>
                  {results.chains?.length > 0 && (
                    <span className="ml-2 px-1.5 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-400 font-medium">
                      {results.chains.length} attack chain{results.chains.length !== 1 ? "s" : ""}
                    </span>
                  )}
                </div>
              )}
            </div>

            {/* Severity grid */}
            {sevCounts && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4">
                {SEV_CONFIG.map(s => (
                  <div
                    key={s.key}
                    className={`rounded-lg border ${s.border} ${s.bg} p-3 flex flex-col items-center gap-1`}
                  >
                    <span className={`text-2xl font-bold ${s.text}`}>
                      {sevCounts[s.key] ?? 0}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <div className={`w-2 h-2 rounded-full ${s.dot}`} />
                      <span className={`text-xs font-medium ${s.text}`}>{s.label}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Top findings list */}
            {results?.findings && results.findings.length > 0 && (
              <div className="border-t border-card-border px-4 pb-4">
                <p className="text-xs text-muted-foreground uppercase tracking-wider mt-3 mb-2 font-medium">
                  Top Findings
                </p>
                <div className="space-y-1.5">
                  {results.findings.slice(0, 5).map((f: any, i: number) => {
                    const sev = (f.severity || f.sev || "LOW").toUpperCase();
                    const cfg = SEV_CONFIG.find(s => s.key === sev) ?? SEV_CONFIG[3];
                    return (
                      <div key={i}
                        className="flex items-start gap-2.5 p-2.5 rounded-lg bg-muted/20 border border-border/50">
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
                      </div>
                    );
                  })}
                  {results.findings.length > 5 && (
                    <p className="text-xs text-muted-foreground text-center py-1">
                      + {results.findings.length - 5} more findings in Reports
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
        {/* ── END RESULTS ──────────────────────────────────────────────────── */}

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
                  Run All 12
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
                role="button"
                tabIndex={0}
                className="text-xs text-primary hover:underline px-1"
                onClick={e => { e.stopPropagation(); setSelected(allOn ? [] : ALL_MODULES.map(m => m.id)); }}
                onKeyDown={e => { if (e.key === "Enter") { e.stopPropagation(); setSelected(allOn ? [] : ALL_MODULES.map(m => m.id)); }}}
              >
                {allOn ? "Clear all" : "Select all"}
              </span>
              {showModules
                ? <ChevronUp className="w-4 h-4 text-muted-foreground" />
                : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
            </div>
          </button>
          {showModules && (
            <div className="px-4 pb-4 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
              {ALL_MODULES.map(m => {
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
                  <span className="text-muted-foreground text-xs">- {status.current_module}</span>
                )}
              </div>
              <span className="text-xs text-muted-foreground font-mono">
                {status.completed_modules?.length ?? 0}/{status.total_modules ?? 0}
                {(status.findings_count ?? 0) > 0 && ` - ${status.findings_count} findings`}
              </span>
            </div>
            <div className="h-2 rounded-full bg-muted overflow-hidden">
              <div className="h-full bg-primary rounded-full transition-all duration-500"
                style={{ width: `${progress}%` }} />
            </div>
            <p className="text-xs text-right text-muted-foreground">{progress}%</p>
          </div>
        )}

        {/* Terminal */}
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

        {/* Legal */}
        <div className="flex items-start gap-2 text-xs text-muted-foreground border border-border/50 rounded-lg p-3 bg-muted/10">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-yellow-500 mt-0.5" />
          <span>Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.</span>
        </div>

      </div>
    );
  }
  