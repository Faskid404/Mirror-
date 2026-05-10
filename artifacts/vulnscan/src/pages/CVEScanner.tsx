import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Shield, Search, ChevronDown, ChevronUp, ExternalLink, Link2 } from "lucide-react";
import { Input } from "@/components/ui/input";

const API = "/scanner-api/api";

function SevBadge({ sev }: { sev: string }) {
  const cls = sev === "CRITICAL" ? "sev-critical" : sev === "HIGH" ? "sev-high"
    : sev === "MEDIUM" ? "sev-medium" : "sev-low";
  return <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${cls}`}>{sev}</span>;
}

function ProbeRow({ probe }: { probe: any }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-card-border rounded-lg bg-card overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-muted/30 transition-colors text-left"
      >
        <SevBadge sev={probe.severity} />
        <span className="font-mono text-xs text-primary shrink-0">{probe.cve}</span>
        <span className="text-sm text-foreground flex-1 truncate">{probe.name}</span>
        <span className="text-xs text-muted-foreground shrink-0 hidden sm:block">{probe.platform}</span>
        {probe.chain && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent/20 text-accent border border-accent/30 shrink-0">
            {probe.chain}
          </span>
        )}
        {open ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
               : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground shrink-0" />}
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-card-border bg-muted/10 space-y-3 pt-3">
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <p className="text-muted-foreground uppercase tracking-wider text-[10px] mb-1">Platform</p>
              <p className="text-foreground">{probe.platform}</p>
            </div>
            <div>
              <p className="text-muted-foreground uppercase tracking-wider text-[10px] mb-1">Method</p>
              <p className="font-mono text-foreground">{probe.method}</p>
            </div>
            <div className="col-span-2">
              <p className="text-muted-foreground uppercase tracking-wider text-[10px] mb-1">Probe Path</p>
              <p className="font-mono text-foreground break-all bg-black/30 px-2 py-1.5 rounded text-[11px]">
                {probe.path}
              </p>
            </div>
            {probe.chain && (
              <div>
                <p className="text-muted-foreground uppercase tracking-wider text-[10px] mb-1">Attack Chain</p>
                <span className="text-accent font-medium flex items-center gap-1">
                  <Link2 className="w-3 h-3" />{probe.chain}
                </span>
              </div>
            )}
            {probe.build_max && (
              <div>
                <p className="text-muted-foreground uppercase tracking-wider text-[10px] mb-1">Max Build (SP)</p>
                <p className="font-mono text-foreground">16.0.{probe.build_max}</p>
              </div>
            )}
          </div>
          {probe.headers && Object.keys(probe.headers).length > 0 && (
            <div>
              <p className="text-muted-foreground uppercase tracking-wider text-[10px] mb-1">Probe Headers</p>
              <pre className="font-mono text-[10px] text-foreground/80 bg-black/30 px-2 py-1.5 rounded overflow-x-auto">
                {JSON.stringify(probe.headers, null, 2)}
              </pre>
            </div>
          )}
          <a
            href={`https://nvd.nist.gov/vuln/detail/${probe.cve}`}
            target="_blank" rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
          >
            <ExternalLink className="w-3 h-3" /> NVD — {probe.cve}
          </a>
        </div>
      )}
    </div>
  );
}

export default function CVEScanner() {
  const [search, setSearch]     = useState("");
  const [platform, setPlatform] = useState("All");
  const [sevFilter, setSevFilter] = useState("All");

  const { data, isLoading, error } = useQuery({
    queryKey: ["cves"],
    queryFn: () => fetch(`${API}/cves`).then(r => r.json()),
  });

  const probes: any[]     = data?.probes   ?? [];
  const platforms: string[] = ["All", ...(data?.platforms ?? [])];
  const sevOptions = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

  const filtered = probes.filter(p => {
    const matchPlatform = platform === "All" || p.platform === platform;
    const matchSev      = sevFilter === "All" || p.severity === sevFilter;
    const q = search.toLowerCase();
    const matchSearch   = !q || p.cve.toLowerCase().includes(q)
      || p.name.toLowerCase().includes(q) || p.platform.toLowerCase().includes(q);
    return matchPlatform && matchSev && matchSearch;
  });

  const bySev = (s: string) => filtered.filter(p => p.severity === s).length;

  return (
    <div className="p-6 space-y-5 max-w-5xl">
      <div>
        <h1 className="text-xl font-semibold flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary" /> CVE Probe Catalogue
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          {probes.length} HTTP probes · {data?.platforms?.length ?? 0} platforms · 48 SharePoint CVEs (version-matched)
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: "Critical", count: probes.filter(p => p.severity === "CRITICAL").length, cls: "text-red-400" },
          { label: "High",     count: probes.filter(p => p.severity === "HIGH").length,     cls: "text-orange-400" },
          { label: "Medium",   count: probes.filter(p => p.severity === "MEDIUM").length,   cls: "text-yellow-400" },
          { label: "With Chain", count: probes.filter(p => p.chain).length,                 cls: "text-accent" },
        ].map(s => (
          <div key={s.label} className="bg-card border border-card-border rounded-lg p-3 text-center">
            <p className={`text-2xl font-bold font-mono ${s.cls}`}>{s.count}</p>
            <p className="text-xs text-muted-foreground mt-0.5">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            placeholder="Search CVE, name, platform…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-8 text-sm h-8"
          />
        </div>
        <select value={platform} onChange={e => setPlatform(e.target.value)}
          className="h-8 rounded-md border border-input bg-background px-2 text-xs text-foreground">
          {platforms.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
          className="h-8 rounded-md border border-input bg-background px-2 text-xs text-foreground">
          {sevOptions.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      <p className="text-xs text-muted-foreground">{filtered.length} probes shown</p>

      {isLoading && (
        <div className="text-center py-12 text-muted-foreground text-sm">Loading CVE catalogue…</div>
      )}

      {error && (
        <div className="text-center py-12">
          <p className="text-destructive text-sm">Scanner API not reachable.</p>
          <p className="text-muted-foreground text-xs mt-1">Start the scanner service to see CVE probes.</p>
        </div>
      )}

      <div className="space-y-2">
        {filtered.map((p, i) => <ProbeRow key={`${p.cve}-${i}`} probe={p} />)}
      </div>
    </div>
  );
}
