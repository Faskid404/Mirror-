import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { FileText, RefreshCw, ChevronDown, ChevronUp, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useQueryClient } from "@tanstack/react-query";

const API = "/scanner-api/api";

function ReportRow({ report }: { report: any }) {
  const [open, setOpen]   = useState(false);
  const [data, setData]   = useState<any>(null);
  const [loading, setLoading] = useState(false);

  async function load() {
    if (data) { setOpen(o => !o); return; }
    setLoading(true);
    const res = await fetch(`${API}/reports/${report.file}`);
    setData(await res.json());
    setLoading(false);
    setOpen(true);
  }

  const modified = new Date(report.modified * 1000).toLocaleString();

  return (
    <div className="border border-card-border rounded-lg bg-card overflow-hidden">
      <button onClick={load}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-muted/30 transition-colors text-left">
        <FileText className="w-4 h-4 text-muted-foreground shrink-0" />
        <span className="text-sm font-mono text-foreground flex-1">{report.file}</span>
        <span className="text-xs text-muted-foreground">{report.count} findings</span>
        <span className="text-xs text-muted-foreground hidden sm:block">{modified}</span>
        <span className="text-xs text-muted-foreground">{(report.size / 1024).toFixed(1)} KB</span>
        {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin text-muted-foreground" />
          : open ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground" />
                 : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
      </button>
      {open && data && (
        <div className="border-t border-card-border bg-muted/10 p-4">
          <pre className="font-mono text-[10px] text-foreground/80 overflow-auto max-h-72 bg-black/30 p-3 rounded">
            {JSON.stringify(Array.isArray(data) ? data.slice(0, 20) : data, null, 2)}
            {Array.isArray(data) && data.length > 20 && `\n... and ${data.length - 20} more`}
          </pre>
        </div>
      )}
    </div>
  );
}

export default function Reports() {
  const qc = useQueryClient();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["reports"],
    queryFn: () => fetch(`${API}/reports`).then(r => r.json()),
  });

  const reports: any[] = Array.isArray(data) ? data.sort((a, b) => b.modified - a.modified) : [];
  const totalFindings = reports.reduce((s, r) => s + r.count, 0);

  return (
    <div className="p-6 space-y-5 max-w-4xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <FileText className="w-5 h-5 text-primary" /> Scan Reports
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            {reports.length} report files · {totalFindings} total findings
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
        </Button>
      </div>

      {isLoading && <div className="text-center py-12 text-muted-foreground text-sm">Loading reports…</div>}

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

      <div className="space-y-2">
        {reports.map(r => <ReportRow key={r.file} report={r} />)}
      </div>
    </div>
  );
}
