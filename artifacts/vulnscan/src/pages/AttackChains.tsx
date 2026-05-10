import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link2, ChevronDown, ChevronUp, ExternalLink, AlertTriangle } from "lucide-react";

const API = "/scanner-api/api";

const CHAIN_COLORS: Record<string, string> = {
  ProxyLogon:     "border-red-500/40   bg-red-500/5   text-red-400",
  ProxyShell:     "border-orange-500/40 bg-orange-500/5 text-orange-400",
  SharePoint_RCE: "border-yellow-500/40 bg-yellow-500/5 text-yellow-400",
  Log4Shell:      "border-purple-500/40 bg-purple-500/5 text-purple-400",
  F5_BIG_IP:      "border-blue-500/40  bg-blue-500/5  text-blue-400",
  MOVEit:         "border-green-500/40 bg-green-500/5 text-green-400",
};

const CHAIN_ACCENT: Record<string, string> = {
  ProxyLogon:     "bg-red-500",
  ProxyShell:     "bg-orange-500",
  SharePoint_RCE: "bg-yellow-500",
  Log4Shell:      "bg-purple-500",
  F5_BIG_IP:      "bg-blue-500",
  MOVEit:         "bg-green-500",
};

function ChainCard({ chain }: { chain: any }) {
  const [open, setOpen] = useState(false);
  const col = CHAIN_COLORS[chain.id] ?? "border-border bg-card text-foreground";
  const acc = CHAIN_ACCENT[chain.id] ?? "bg-primary";

  return (
    <div className={`rounded-xl border-2 ${col.split(" ")[0]} bg-card overflow-hidden`}>
      {/* Header */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-start gap-4 p-5 text-left hover:bg-muted/20 transition-colors"
      >
        <div className={`w-1.5 self-stretch rounded-full shrink-0 ${acc} opacity-80`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-foreground">{chain.name}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded sev-critical">CRITICAL</span>
          </div>
          <p className="text-xs text-muted-foreground mt-1">{chain.platform}</p>
          <div className="flex flex-wrap gap-1.5 mt-2">
            {chain.cves.map((cve: string) => (
              <span key={cve} className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-muted/50 text-muted-foreground border border-border">
                {cve}
              </span>
            ))}
          </div>
        </div>
        <div className="shrink-0 flex items-center gap-2 mt-0.5">
          <span className="text-xs text-muted-foreground">{chain.steps.length} steps</span>
          {open ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
        </div>
      </button>

      {open && (
        <div className="px-5 pb-5 space-y-4 border-t border-border/50">
          {/* Description */}
          <p className="text-sm text-muted-foreground leading-relaxed pt-4">{chain.description}</p>

          {/* Steps */}
          <div>
            <p className="text-xs font-medium text-foreground uppercase tracking-wider mb-3">Exploitation Steps</p>
            <div className="space-y-2">
              {chain.steps.map((step: any, i: number) => (
                <div key={i} className="flex items-start gap-3">
                  <div className={`w-5 h-5 rounded-full ${acc} opacity-80 flex items-center justify-center shrink-0 mt-0.5`}>
                    <span className="text-[10px] font-bold text-white">{i + 1}</span>
                  </div>
                  <div className="flex-1">
                    {step.cve && (
                      <span className="font-mono text-[10px] text-muted-foreground mr-2">{step.cve}</span>
                    )}
                    <span className="text-sm text-foreground">{step.action}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Indicator tags */}
          {chain.indicator_tags?.length > 0 && (
            <div>
              <p className="text-xs font-medium text-foreground uppercase tracking-wider mb-2">Detection Indicators</p>
              <div className="flex flex-wrap gap-1.5">
                {chain.indicator_tags.map((t: string) => (
                  <span key={t} className="text-[10px] font-mono px-2 py-0.5 rounded bg-muted/60 text-muted-foreground border border-border">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Links to NVD */}
          <div className="flex flex-wrap gap-2 pt-1">
            {chain.cves.map((cve: string) => (
              <a key={cve}
                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                target="_blank" rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
              >
                <ExternalLink className="w-3 h-3" />{cve}
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function AttackChains() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["chains"],
    queryFn: () => fetch(`${API}/chains`).then(r => r.json()),
  });

  const chains: any[] = data?.chains ?? [];

  return (
    <div className="p-6 space-y-5 max-w-4xl">
      <div>
        <h1 className="text-xl font-semibold flex items-center gap-2">
          <Link2 className="w-5 h-5 text-primary" /> Named Attack Chains
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          6 real-world multi-stage exploit chains with CVE correlation and auto-detection
        </p>
      </div>

      {/* Legend */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { id: "ProxyLogon",     label: "ProxyLogon",          platform: "Exchange" },
          { id: "ProxyShell",     label: "ProxyShell",          platform: "Exchange" },
          { id: "SharePoint_RCE", label: "SharePoint RCE",      platform: "SharePoint" },
          { id: "Log4Shell",      label: "Log4Shell",           platform: "Log4j" },
          { id: "F5_BIG_IP",      label: "F5 BIG-IP",           platform: "F5" },
          { id: "MOVEit",         label: "MOVEit SQLi",         platform: "MOVEit" },
        ].map(c => (
          <div key={c.id} className={`rounded-lg border-2 p-3 ${CHAIN_COLORS[c.id]?.split(" ").slice(0,2).join(" ") ?? "border-border bg-card"}`}>
            <p className="text-sm font-medium text-foreground">{c.label}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">{c.platform}</p>
          </div>
        ))}
      </div>

      {isLoading && (
        <div className="text-center py-12 text-muted-foreground text-sm">Loading attack chains…</div>
      )}

      {error && (
        <div className="flex items-center gap-2 p-4 rounded-lg border border-destructive/30 bg-destructive/10 text-sm text-destructive">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          Scanner API not reachable. Start the scanner service to see attack chains.
        </div>
      )}

      {!isLoading && !error && chains.length === 0 && (
        <div className="text-center py-12 text-muted-foreground text-sm">
          No chains returned. Check the scanner API is running.
        </div>
      )}

      <div className="space-y-3">
        {chains.map((c: any) => <ChainCard key={c.id} chain={c} />)}
      </div>

      <div className="flex items-start gap-2 text-xs text-muted-foreground border border-border/50 rounded p-2.5 bg-muted/20">
        <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-yellow-500 mt-0.5" />
        These chains are auto-detected during scans. The RootChain module correlates findings from
        all modules to identify which chains may be exploitable against the target.
      </div>
    </div>
  );
}
