import { useState, useEffect, useRef } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Shield, Play, Square, AlertTriangle, CheckCircle, Loader2, ChevronDown, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";

const API = "/scanner-api/api";

const ALL_MODULES = [
  { id: "ghostcrawler",  label: "GhostCrawler",  desc: "Endpoint discovery & token hunt" },
  { id: "wafshatter",   label: "WAFShatter",     desc: "WAF/CDN bypass & origin hunt" },
  { id: "headerforge",  label: "HeaderForge",    desc: "Security header & CSP audit" },
  { id: "timebleed",    label: "TimeBleed",      desc: "Blind injection timing oracle" },
  { id: "authdrift",    label: "AuthDrift",      desc: "Broken access control & leaks" },
  { id: "tokensniper",  label: "TokenSniper",    desc: "JWT & API token analysis" },
  { id: "deeplogic",    label: "DeepLogic",      desc: "Business logic flaws" },
  { id: "cryptohunter", label: "CryptoHunter",   desc: "Cryptographic weaknesses" },
  { id: "backendprobe", label: "BackendProbe",   desc: "Deep backend scanning" },
  { id: "webprobe",     label: "WebProbe",       desc: "Modern web vulnerabilities" },
  { id: "cveprobe",     label: "CVEProbe",       desc: "197 HTTP CVE probes (NEW)" },
  { id: "rootchain",    label: "RootChain",      desc: "Attack chain correlation" },
];

function SevBadge({ sev }: { sev: string }) {
  const cls = sev === "CRITICAL" ? "sev-critical" : sev === "HIGH" ? "sev-high"
    : sev === "MEDIUM" ? "sev-medium" : "sev-low";
  return <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono uppercase ${cls}`}>{sev}</span>;
}

export default function Dashboard() {
  const { toast } = useToast();
  const [target, setTarget]         = useState("");
  const [selected, setSelected]     = useState<string[]>(ALL_MODULES.map(m => m.id));
  const [jobId, setJobId]           = useState<string | null>(null);
  const [status, setStatus]         = useState<any>(null);
  const [lines, setLines]           = useState<string[]>([]);
  const [lineIdx, setLineIdx]       = useState(0);
  const [showModules, setShowModules] = useState(true);
  const termRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<any>(null);

  const { data: health } = useQuery({
    queryKey: ["health"],
    queryFn: () => fetch(`${API}/health`).then(r => r.json()),
    refetchInterval: 15_000,
  });

  const startMut = useMutation({
    mutationFn: (body: object) =>
      fetch(`${API}/scan/start`, { method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body) }).then(r => r.json()),
    onSuccess: (data) => {
      if (data.error) { toast({ title: "Error", description: data.error, variant: "destructive" }); return; }
      setJobId(data.job_id);
      setLines([]);
      setLineIdx(0);
      setStatus(null);
    },
  });

  const stopMut = useMutation({
    mutationFn: (id: string) =>
      fetch(`${API}/scan/stop/${id}`, { method: "POST" }).then(r => r.json()),
  });

  // Poll status while running
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
      if (data.status === "done" || data.status === "error" || data.status === "stopped") {
        clearInterval(pollRef.current);
      }
    }, 1200);
    return () => clearInterval(pollRef.current);
  }, [jobId, lineIdx]);

  // Auto-scroll terminal
  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [lines]);

  const isRunning = status?.status === "running" || status?.status === "queued";
  const isDone    = status?.status === "done";
  const isStopped = status?.status === "stopped";

  function toggleModule(id: string) {
    setSelected(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  }

  function handleStart() {
    if (!target.trim()) { toast({ title: "Enter a target URL", variant: "destructive" }); return; }
    if (!selected.length) { toast({ title: "Select at least one module", variant: "destructive" }); return; }
    startMut.mutate({ target: target.trim(), modules: selected });
  }

  const modulesReady = health?.modules_ready ?? 0;
  const modulesTotal = health?.modules_total ?? 0;

  return (
    <div className="p-6 space-y-5 max-w-5xl">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-foreground">Security Arsenal</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Professional vulnerability assessment suite â authorized testing only</p>
      </div>

      {/* Health bar */}
      <div className="flex items-center gap-3 p-3 rounded-lg bg-card border border-card-border text-sm">
        {health ? (
          <>
            <CheckCircle className="w-4 h-4 text-accent shrink-0" />
            <span className="text-foreground font-medium">Scanner online</span>
            <span className="text-muted-foreground">Â·</span>
            <span className="text-muted-foreground">{modulesReady}/{modulesTotal} modules ready</span>
          </>
        ) : (
          <>
            <Loader2 className="w-4 h-4 text-muted-foreground animate-spin shrink-0" />
            <span className="text-muted-foreground">Connecting to scannerâ¦</span>
          </>
        )}
      </div>

      {/* Scan form */}
      <div className="rounded-lg border border-card-border bg-card p-4 space-y-4">
        <h2 className="text-sm font-medium text-foreground">Target</h2>
        <div className="flex gap-2">
          <Input
            placeholder="https://target.example.com"
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={e => e.key === "Enter" && !isRunning && handleStart()}
            className="font-mono text-sm flex-1"
            disabled={isRunning}
          />
          {isRunning ? (
            <Button variant="destructive" size="sm" onClick={() => jobId && stopMut.mutate(jobId)}>
              <Square className="w-3.5 h-3.5 mr-1.5" /> Stop
            </Button>
          ) : (
            <Button size="sm" onClick={handleStart} disabled={startMut.isPending}>
              {startMut.isPending ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Play className="w-3.5 h-3.5 mr-1.5" />}
              Scan
            </Button>
          )}
        </div>

        {/* Module selector */}
        <div>
          <button
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
            onClick={() => setShowModules(p => !p)}
          >
            {showModules ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            {selected.length}/{ALL_MODULES.length} modules selected
          </button>
          {showModules && (
            <div className="mt-3 grid grid-cols-2 gap-1.5">
              {ALL_MODULES.map(m => (
                <label key={m.id} className={`flex items-start gap-2 p-2 rounded border cursor-pointer transition-colors
                  ${selected.includes(m.id)
                    ? "border-primary/40 bg-primary/8 text-foreground"
                    : "border-border bg-muted/30 text-muted-foreground"}`}>
                  <input type="checkbox" checked={selected.includes(m.id)}
                    onChange={() => toggleModule(m.id)} className="mt-0.5 accent-primary" />
                  <div>
                    <p className="text-xs font-medium leading-none">{m.label}</p>
                    <p className="text-[10px] mt-0.5 opacity-70">{m.desc}</p>
                  </div>
                </label>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Progress */}
      {status && (
        <div className="rounded-lg border border-card-border bg-card p-4 space-y-3">
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              {isRunning && <Loader2 className="w-4 h-4 animate-spin text-primary" />}
              {isDone    && <CheckCircle className="w-4 h-4 text-accent" />}
              {isStopped && <Square className="w-4 h-4 text-muted-foreground" />}
              <span className="font-medium capitalize">{status.status}</span>
              {status.current_module && (
                <span className="text-muted-foreground">â {status.current_module}</span>
              )}
            </div>
            <span className="text-muted-foreground font-mono text-xs">
              {status.completed_modules?.length ?? 0}/{status.total_modules ?? 0} modules
              {status.findings_count > 0 && ` Â· ${status.findings_count} findings`}
            </span>
          </div>
          {/* Progress bar */}
          <div className="h-1.5 rounded-full bg-muted overflow-hidden">
            <div className="h-full bg-primary rounded-full transition-all"
              style={{ width: `${status.total_modules ? ((status.completed_modules?.length ?? 0) / status.total_modules) * 100 : 0}%` }} />
          </div>
        </div>
      )}

      {/* Terminal */}
      {lines.length > 0 && (
        <div>
          <h2 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Output</h2>
          <div ref={termRef} className="terminal h-72">
            {lines.map((l, i) => (
              <div key={i} className={
                l.includes("[VULN]") || l.includes("[!]") ? "text-red-400" :
                l.includes("[+]") ? "text-green-400" :
                l.includes("[X]") ? "text-red-500" :
                l.startsWith("=") ? "text-blue-400 font-bold" :
                "text-green-400/80"
              }>{l || " "}</div>
            ))}
          </div>
        </div>
      )}

      {/* Legal */}
      <div className="flex items-center gap-2 text-xs text-muted-foreground border border-border/50 rounded p-2.5 bg-muted/20">
        <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-yellow-500" />
        Authorized testing only. Only scan systems you own or have written permission to test.
      </div>
    </div>
  );
}
