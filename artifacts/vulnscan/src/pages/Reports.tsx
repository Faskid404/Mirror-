import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  FileText, RefreshCw, ChevronDown, ChevronUp,
  AlertTriangle, Download, FileDown, Eye, EyeOff,
} from "lucide-react";
import { Button } from "@/components/ui/button";

const API = "/scanner-api/api";

const SEV_CFG: Record<string, { text: string; bg: string; border: string }> = {
  CRITICAL: { text: "text-red-400",    bg: "bg-red-500/15",    border: "border-red-500/40"    },
  HIGH:     { text: "text-orange-400", bg: "bg-orange-500/15", border: "border-orange-500/40" },
  MEDIUM:   { text: "text-yellow-400", bg: "bg-yellow-500/15", border: "border-yellow-500/40" },
  LOW:      { text: "text-blue-400",   bg: "bg-blue-500/15",   border: "border-blue-500/40"   },
  INFO:     { text: "text-slate-400",  bg: "bg-slate-500/15",  border: "border-slate-500/40"  },
};

function getSevCfg(sev: string) {
  return SEV_CFG[(sev || "INFO").toUpperCase()] ?? SEV_CFG["INFO"];
}

function SevBadge({ sev }: { sev: string }) {
  const cfg = getSevCfg(sev);
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-bold shrink-0 ${cfg.bg} ${cfg.text} border ${cfg.border}`}>
      {(sev || "INFO").toUpperCase()}
    </span>
  );
}

function FindingRow({ f }: { f: any }) {
  const [open, setOpen] = useState(false);
  const sev    = (f.severity || f.sev || "INFO").toUpperCase();
  const title  = f.title || f.name || f.type || "Finding";
  const detail = f.detail || f.description || "";
  const proof  = f.proof || "";
  const rem    = f.remediation || f.fix || "";
  const url    = f.url || f.path || "";

  return (
    <div className="border border-card-border rounded-lg bg-card overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2.5 px-3 py-2.5 hover:bg-muted/20 transition-colors text-left"
      >
        <SevBadge sev={sev} />
        <span className="text-xs font-medium text-foreground flex-1 truncate min-w-0">{title}</span>
        {url && (
          <span className="text-[10px] text-muted-foreground font-mono truncate max-w-[160px] hidden sm:block shrink-0">
            {url}
          </span>
        )}
        {f.confidence !== undefined && (
          <span className="text-[10px] text-muted-foreground shrink-0">{f.confidence}%</span>
        )}
        {open
          ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
          : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground shrink-0" />}
      </button>

      {open && (
        <div className="border-t border-card-border px-3 pb-3 pt-2.5 space-y-2 bg-muted/10">
          {detail && (
            <p className="text-xs text-foreground/80 leading-relaxed">{detail}</p>
          )}
          {url && (
            <div className="text-[10px] font-mono text-muted-foreground bg-black/30 px-2 py-1.5 rounded break-all">
              {url}
            </div>
          )}
          {proof && (
            <div className="bg-black/40 border-l-2 border-blue-500/60 px-2.5 py-2 rounded-r-md">
              <p className="text-[10px] text-blue-400/70 uppercase tracking-wider font-semibold mb-1">Proof</p>
              <pre className="text-[10px] text-blue-300/80 whitespace-pre-wrap break-all leading-relaxed">{proof}</pre>
            </div>
          )}
          {rem && (
            <div className="bg-black/30 border-l-2 border-green-500/50 px-2.5 py-2 rounded-r-md">
              <p className="text-[10px] text-green-400/70 uppercase tracking-wider font-semibold mb-1">Remediation</p>
              <p className="text-[10px] text-green-300/80 leading-relaxed">{rem}</p>
            </div>
          )}
          {f.mitre_technique && (
            <span className="inline-block text-[10px] px-2 py-0.5 rounded bg-indigo-900/50 border border-indigo-500/30 text-indigo-300 font-mono">
              MITRE {f.mitre_technique} — {f.mitre_name || ""}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

function ReportRow({ report }: { report: any }) {
  const [open, setOpen]       = useState(false);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading]   = useState(false);
  const [showAll, setShowAll]   = useState(false);

  const modified = new Date(report.modified * 1000).toLocaleString();

  async function toggle() {
    if (!open && findings.length === 0) {
      setLoading(true);
      try {
        const res  = await fetch(`${API}/reports/${report.file}`);
        const data = await res.json();
        const list: any[] = Array.isArray(data)
          ? data
          : Array.isArray(data?.findings) ? data.findings : [];
        setFindings(list);
      } catch (_) {
        // leave empty
      } finally {
        setLoading(false);
      }
    }
    setOpen(o => !o);
  }

  function downloadHTML() {
    const a = document.createElement("a");
    a.href = `${API}/reports/${report.file.replace(".json", "")}/html`;
    a.download = report.file.replace(".json", "") + "-report.html";
    a.click();
  }

  // Severity breakdown from already-loaded findings or from report.count
  const sevCounts = findings.length > 0
    ? ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => ({
        key: s,
        n: findings.filter(f => (f.severity || f.sev || "").toUpperCase() === s).length,
      })).filter(x => x.n > 0)
    : [];

  const displayedFindings = showAll ? findings : findings.slice(0, 10);

  return (
    <div className="border border-card-border rounded-xl bg-card overflow-hidden">
      {/* Row header */}
      <div className="flex items-center gap-3 px-4 py-3">
        <button
          onClick={toggle}
          className="flex items-center gap-3 flex-1 min-w-0 text-left hover:opacity-80 transition-opacity"
        >
          <FileText className="w-4 h-4 text-muted-foreground shrink-0" />
          <span className="text-sm font-mono text-foreground truncate flex-1 min-w-0">{report.file}</span>
        </button>

        <div className="flex items-center gap-2 shrink-0">
          <span className="text-xs text-muted-foreground hidden md:block">{modified}</span>
          <span className="text-xs text-muted-foreground">{report.count} findings</span>
          <span className="text-xs text-muted-foreground hidden sm:block">{(report.size / 1024).toFixed(1)} KB</span>

          <button
            onClick={downloadHTML}
            title="Download as HTML report (works on mobile)"
            className="p-1.5 rounded-md bg-primary/10 border border-primary/20 text-primary hover:bg-primary/20 transition-colors"
          >
            <FileDown className="w-3.5 h-3.5" />
          </button>

          <button onClick={toggle} className="p-1.5 text-muted-foreground hover:text-foreground transition-colors">
            {loading
              ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              : open
                ? <EyeOff className="w-3.5 h-3.5" />
                : <Eye className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Severity pill strip */}
      {sevCounts.length > 0 && (
        <div className="flex gap-1.5 px-4 pb-2 flex-wrap">
          {sevCounts.map(({ key, n }) => {
            const cfg = getSevCfg(key);
            return (
              <span key={key}
                className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-bold ${cfg.bg} ${cfg.text} border ${cfg.border}`}>
                {n} {key}
              </span>
            );
          })}
        </div>
      )}

      {/* Expanded findings */}
      {open && (
        <div className="border-t border-card-border bg-muted/5 p-3 space-y-1.5">
          {findings.length === 0 && !loading && (
            <p className="text-xs text-muted-foreground text-center py-4">No findings in this report.</p>
          )}
          {displayedFindings.map((f: any, i: number) => (
            <FindingRow key={i} f={f} />
          ))}
          {findings.length > 10 && (
            <button
              onClick={() => setShowAll(v => !v)}
              className="w-full text-xs text-primary hover:underline py-1.5 text-center"
            >
              {showAll
                ? "Show fewer"
                : `Show all ${findings.length} findings`}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

export default function Reports() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["reports"],
    queryFn: () => fetch(`${API}/reports`).then(r => r.json()),
  });

  const reports: any[] = Array.isArray(data)
    ? data.sort((a: any, b: any) => b.modified - a.modified)
    : [];
  const totalFindings = reports.reduce((s: number, r: any) => s + r.count, 0);

  function downloadCombined() {
    const a = document.createElement("a");
    a.href = `${API}/reports/combined/html`;
    a.download = "mirror-full-report.html";
    a.click();
  }

  return (
    <div className="p-4 md:p-6 space-y-4 max-w-4xl mx-auto">

      {/* Page header */}
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-lg md:text-xl font-semibold flex items-center gap-2">
            <FileText className="w-5 h-5 text-primary" /> Scan Reports
          </h1>
          <p className="text-xs md:text-sm text-muted-foreground mt-0.5">
            {reports.length} report file{reports.length !== 1 ? "s" : ""} · {totalFindings} total findings
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {reports.length > 0 && (
            <Button
              onClick={downloadCombined}
              className="h-8 text-xs gap-1.5"
            >
              <Download className="w-3.5 h-3.5" />
              Download Full Report
            </Button>
          )}
          <Button variant="outline" size="sm" className="h-8 text-xs" onClick={() => refetch()}>
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
          </Button>
        </div>
      </div>

      {/* Download note for mobile */}
      {reports.length > 0 && (
        <div className="flex items-start gap-2 text-xs text-muted-foreground border border-border/40 rounded-lg p-3 bg-muted/10">
          <FileDown className="w-3.5 h-3.5 shrink-0 text-primary mt-0.5" />
          <span>
            <strong className="text-foreground">Download Full Report</strong> generates a self-contained HTML file with
            built-in PDF export — open it in any browser and tap <em>Download PDF</em>.
            Works offline and saves cleanly on mobile.
          </span>
        </div>
      )}

      {/* States */}
      {isLoading && (
        <div className="text-center py-12 text-muted-foreground text-sm">Loading reports…</div>
      )}

      {error && (
        <div className="flex items-center gap-2 p-4 rounded-lg border border-destructive/30 bg-destructive/10 text-sm text-destructive">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          Scanner API not reachable. Run a scan first.
        </div>
      )}

      {!isLoading && !error && reports.length === 0 && (
        <div className="text-center py-16 space-y-2">
          <FileText className="w-8 h-8 text-muted-foreground/40 mx-auto" />
          <p className="text-muted-foreground text-sm">No reports yet. Run a scan from the Dashboard.</p>
        </div>
      )}

      {/* Report list */}
      <div className="space-y-2">
        {reports.map((r: any) => <ReportRow key={r.file} report={r} />)}
      </div>

    </div>
  );
}
