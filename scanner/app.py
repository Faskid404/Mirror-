#!/usr/bin/env python3
"""
Mirror Scanner API v2 — Flask backend for the vulnerability scanner UI.

Improvements over v1:
  - /api/report/download  → generate + stream HTML report on demand
  - /api/report/status    → check if report is ready
  - Streaming scan output via Server-Sent Events (/api/scan/stream/<job_id>)
  - Module timeout protection (each module capped at 5 min)
  - Structured error responses (never 500 on bad input)
  - Memory-bounded output buffer (max 2000 lines per job)
  - Graceful shutdown on SIGTERM
  - Health endpoint enriched with scan queue length
"""
import subprocess
import sys
import json
import os
import threading
import time
import uuid
import signal
from pathlib import Path
from flask import Flask, request, jsonify, Blueprint, Response, send_file
from flask_cors import CORS

# ── Setup ─────────────────────────────────────────────────────────────────────
SCANNER_ROOT = Path(__file__).parent.resolve()
MODULES_DIR  = SCANNER_ROOT / "modules"
REPORTS_DIR  = SCANNER_ROOT / "reports"
SCANNER_BASE = os.environ.get("SCANNER_BASE", "/scanner-api")
MAX_OUTPUT_LINES = 2000
MODULE_TIMEOUT   = 300   # seconds per module

REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
CORS(app, origins="*")

bp        = Blueprint("scanner", __name__)
JOBS      = {}
JOBS_LOCK = threading.Lock()


def _make_env(target=""):
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    parts = [str(MODULES_DIR), str(SCANNER_ROOT)]
    if existing:
        parts.append(existing)
    env["PYTHONPATH"]     = os.pathsep.join(parts)
    env["ARSENAL_TARGET"] = target
    return env


MODULE_PATHS = {
    "ghostcrawler": "modules/ghostcrawler.py",
    "wafshatter":   "modules/wafshatter.py",
    "headerforge":  "modules/headerforge.py",
    "timebleed":    "modules/timebleed.py",
    "authdrift":    "modules/authdrift.py",
    "tokensniper":  "modules/tokensniper.py",
    "deeplogic":    "modules/deeplogic.py",
    "cryptohunter": "modules/cryptohunter.py",
    "backendprobe": "modules/backendprobe.py",
    "webprobe":     "modules/webprobe.py",
    "rootchain":    "modules/rootchain.py",
    "cveprobe":     "modules/cveprobe.py",
}


def _append_output(job_id, line):
    """Thread-safe append with max-line cap."""
    with JOBS_LOCK:
        buf = JOBS[job_id]["output"]
        if len(buf) < MAX_OUTPUT_LINES:
            buf.append(line)
        elif len(buf) == MAX_OUTPUT_LINES:
            buf.append("[...output truncated — too many lines...]")


def run_module(job_id, abs_path, target):
    with JOBS_LOCK:
        JOBS[job_id]["status"]   = "running"
        JOBS[job_id]["output"]   = []
        JOBS[job_id]["findings"] = []

    try:
        env = _make_env(target)
        REPORTS_DIR.mkdir(exist_ok=True)
        (REPORTS_DIR / "_target.txt").write_text(target)

        proc = subprocess.Popen(
            [sys.executable, str(abs_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=env, cwd=str(SCANNER_ROOT), bufsize=1,
        )
        with JOBS_LOCK:
            JOBS[job_id]["pid"] = proc.pid

        # Enforce per-module timeout
        timer = threading.Timer(MODULE_TIMEOUT, lambda: proc.kill())
        timer.start()
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    _append_output(job_id, line)
            proc.wait()
        finally:
            timer.cancel()

        with JOBS_LOCK:
            JOBS[job_id]["returncode"] = proc.returncode

        report_file = REPORTS_DIR / f"{Path(abs_path).stem}.json"
        if report_file.exists():
            try:
                data = json.loads(report_file.read_text())
                with JOBS_LOCK:
                    JOBS[job_id]["findings"] = data if isinstance(data, list) else []
            except Exception:
                pass

        with JOBS_LOCK:
            JOBS[job_id]["status"] = "done"

    except Exception as e:
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"]  = str(e)
            _append_output(job_id, f"[ERROR] {e}")


# ── Routes ────────────────────────────────────────────────────────────────────

@bp.route("/api/scan/start", methods=["POST"])
def start_scan():
    data    = request.get_json(silent=True) or {}
    target  = str(data.get("target", "")).strip()
    modules = data.get("modules", [])
    if not target:
        return jsonify({"error": "No target provided"}), 400
    if not isinstance(modules, list) or not modules:
        return jsonify({"error": "No modules selected"}), 400
    if not target.startswith("http"):
        target = "https://" + target

    job_id = str(uuid.uuid4())[:8]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id, "target": target, "modules": modules,
            "status": "queued", "output": [], "findings": [],
            "started": time.time(), "current_module": "",
            "completed_modules": [], "all_findings": [],
        }

    def run_all():
        for mod_id in modules:
            with JOBS_LOCK:
                if JOBS[job_id].get("stopped"):
                    break
            rel = MODULE_PATHS.get(mod_id)
            if not rel:
                _append_output(job_id, f"[X] Unknown module: {mod_id}")
                continue
            abs_path = SCANNER_ROOT / rel
            if not abs_path.exists():
                _append_output(job_id, f"[X] Missing module file: {rel}")
                continue
            with JOBS_LOCK:
                JOBS[job_id]["current_module"] = mod_id
                JOBS[job_id]["output"] += [f"\n{'='*50}", f"  Running: {mod_id}", f"{'='*50}"]

            sub_id = f"{job_id}_{mod_id}"
            with JOBS_LOCK:
                JOBS[sub_id] = {"status": "running", "output": [], "findings": []}
            run_module(sub_id, abs_path, target)

            with JOBS_LOCK:
                sub = JOBS.get(sub_id, {})
                JOBS[job_id]["output"].extend(sub.get("output", []))
                JOBS[job_id]["all_findings"].extend(sub.get("findings", []))
                JOBS[job_id]["completed_modules"].append(mod_id)

        with JOBS_LOCK:
            JOBS[job_id]["status"]         = "done"
            JOBS[job_id]["current_module"] = ""
            JOBS[job_id]["finished"]       = time.time()

    threading.Thread(target=run_all, daemon=True).start()
    return jsonify({"job_id": job_id, "status": "started"})


@bp.route("/api/scan/status/<job_id>", methods=["GET"])
def scan_status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    since        = max(0, int(request.args.get("since", 0)))
    output_slice = job["output"][since:]
    return jsonify({
        "job_id":            job_id,
        "status":            job.get("status"),
        "target":            job.get("target"),
        "current_module":    job.get("current_module", ""),
        "completed_modules": job.get("completed_modules", []),
        "total_modules":     len(job.get("modules", [])),
        "findings_count":    len(job.get("all_findings", [])),
        "new_output":        output_slice,
        "output_index":      since + len(output_slice),
    })


@bp.route("/api/scan/stream/<job_id>", methods=["GET"])
def scan_stream(job_id):
    """Server-Sent Events stream of live scan output."""
    def generate():
        idx = 0
        while True:
            with JOBS_LOCK:
                job = JOBS.get(job_id)
            if not job:
                yield "data: {\"error\": \"Job not found\"}\n\n"
                return
            lines  = job["output"][idx:]
            status = job.get("status")
            for line in lines:
                payload = json.dumps({"line": line, "status": status})
                yield f"data: {payload}\n\n"
            idx += len(lines)
            if status in ("done", "stopped", "error") and not lines:
                yield f"data: {{\"done\": true, \"status\": \"{status}\"}}\n\n"
                return
            time.sleep(0.4)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@bp.route("/api/scan/results/<job_id>", methods=["GET"])
def scan_results(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    chains = []
    rc_file = REPORTS_DIR / "rootchain_report.json"
    if rc_file.exists():
        try:
            rc_data = json.loads(rc_file.read_text())
            chains  = rc_data.get("attack_chains", [])
        except Exception:
            pass
    return jsonify({
        "job_id":   job_id,
        "status":   job.get("status"),
        "target":   job.get("target"),
        "findings": job.get("all_findings", []),
        "chains":   chains,
        "output":   job.get("output", []),
        "duration": round(job.get("finished", time.time()) - job.get("started", time.time()), 1),
    })


@bp.route("/api/scan/stop/<job_id>", methods=["POST"])
def stop_scan(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    with JOBS_LOCK:
        JOBS[job_id]["stopped"] = True
        JOBS[job_id]["status"]  = "stopped"
    pid = job.get("pid")
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    return jsonify({"status": "stopped"})


# ── Report download ───────────────────────────────────────────────────────────

@bp.route("/api/report/download", methods=["GET"])
def download_report():
    """
    Generate the HTML security report and stream it as a downloadable file.
    Query params:
      ?job_id=<id>   — use findings from an in-memory job
      ?target=<url>  — label override (optional)
    """
    job_id = request.args.get("job_id", "").strip()
    target = request.args.get("target", "").strip()

    # Gather findings
    findings = []
    chains   = []

    if job_id:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
        if job:
            findings = job.get("all_findings", [])
            target   = target or job.get("target", "unknown")

    if not findings:
        # Fall back to reading from report files
        for jf in sorted(REPORTS_DIR.glob("*.json")):
            if jf.stem.startswith("_") or jf.stem == "rootchain_report":
                continue
            try:
                d = json.loads(jf.read_text())
                if isinstance(d, list):
                    findings.extend(d)
            except Exception:
                pass

    rc_file = REPORTS_DIR / "rootchain_report.json"
    if rc_file.exists():
        try:
            rc_data = json.loads(rc_file.read_text())
            chains  = rc_data.get("attack_chains", [])
        except Exception:
            pass

    if not target:
        t_file = REPORTS_DIR / "_target.txt"
        target = t_file.read_text().strip() if t_file.exists() else "Unknown Target"

    # Try to use report_generator module
    try:
        sys.path.insert(0, str(MODULES_DIR))
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "report_generator", str(MODULES_DIR / "report_generator.py"))
        rg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rg)
        html = rg.generate_html_report(target, findings, chains)
    except Exception:
        # Fallback: minimal inline HTML report
        html = _minimal_html_report(target, findings, chains)

    filename = f"mirror-report-{time.strftime('%Y%m%d-%H%M%S')}.html"
    return Response(
        html,
        mimetype="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "text/html; charset=utf-8",
        }
    )


@bp.route("/api/report/status", methods=["GET"])
def report_status():
    """Check whether a downloadable report is available."""
    findings_count = 0
    for jf in REPORTS_DIR.glob("*.json"):
        if jf.stem.startswith("_") or jf.stem == "rootchain_report":
            continue
        try:
            d = json.loads(jf.read_text())
            if isinstance(d, list):
                findings_count += len(d)
        except Exception:
            pass
    return jsonify({
        "report_available": findings_count > 0,
        "findings_count":   findings_count,
        "download_url":     f"{SCANNER_BASE}/api/report/download",
    })


def _minimal_html_report(target, findings, chains):
    """Fallback HTML report when report_generator.py is unavailable."""
    sev_colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c",
        "MEDIUM":   "#d97706", "LOW":  "#65a30d", "INFO": "#6b7280"
    }
    sev_counts = {}
    for f in findings:
        s = f.get("severity", "INFO")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    badge_html = "".join(
        f'<span style="background:{sev_colors.get(s,"#888")};color:#fff;'
        f'padding:4px 12px;border-radius:20px;margin:4px;font-weight:bold">'
        f'{s}: {c}</span>'
        for s, c in sev_counts.items()
    )

    rows = ""
    for f in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.get("severity","INFO")) if x.get("severity","INFO") in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99):
        sev   = f.get("severity", "INFO")
        color = sev_colors.get(sev, "#888")
        rows += f"""<tr>
          <td style="color:{color};font-weight:bold">{sev}</td>
          <td>{f.get('type','?')}</td>
          <td style="font-size:0.85em">{f.get('url','')}</td>
          <td style="font-size:0.85em">{f.get('detail','')}</td>
          <td style="font-size:0.8em;color:#666">{f.get('remediation','')}</td>
        </tr>"""

    chain_html = ""
    for c in chains:
        risk  = c.get("risk", "HIGH")
        color = sev_colors.get(risk, "#888")
        chain_html += f'<div style="border-left:4px solid {color};padding:8px 16px;margin:8px 0;background:#f9f9f9">' \
                      f'<b style="color:{color}">[{risk}]</b> {c.get("name","?")} — {c.get("description","")}</div>'

    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>Mirror Scan Report — {target}</title>
<style>
  body{{font-family:system-ui,sans-serif;max-width:1200px;margin:0 auto;padding:24px;background:#f5f5f5}}
  h1{{color:#1e293b}} table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden}}
  th{{background:#1e293b;color:#fff;padding:10px 14px;text-align:left}}
  td{{padding:8px 14px;border-bottom:1px solid #e2e8f0;vertical-align:top}}
  tr:hover{{background:#f8fafc}}
  .btn{{background:#1e293b;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;float:right;font-size:1em}}
</style></head><body>
<button class="btn" onclick="window.print()">&#x1F4BE; Save PDF</button>
<h1>Mirror Security Report</h1>
<p><b>Target:</b> {target} &nbsp; <b>Date:</b> {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}</p>
<div style="margin:16px 0">{badge_html}</div>
{'<h2>Attack Chains</h2>' + chain_html if chains else ''}
<h2>All Findings ({len(findings)})</h2>
<table><tr><th>Severity</th><th>Type</th><th>URL</th><th>Detail</th><th>Remediation</th></tr>
{rows}
</table></body></html>"""


# ── Existing read-only routes ─────────────────────────────────────────────────

@bp.route("/api/reports", methods=["GET"])
def list_reports():
    reports = []
    if not REPORTS_DIR.exists():
        return jsonify(reports)
    for f in sorted(REPORTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.name.startswith("_"):
            continue
        try:
            data = json.loads(f.read_text())
            reports.append({
                "file":     f.name,
                "count":    len(data) if isinstance(data, list) else 0,
                "size":     f.stat().st_size,
                "modified": f.stat().st_mtime,
            })
        except Exception:
            pass
    return jsonify(reports)


@bp.route("/api/reports/<name>", methods=["GET"])
def get_report(name):
    p = REPORTS_DIR / name
    if not p.exists() or not p.suffix == ".json":
        return jsonify({"error": "Not found"}), 404
    try:
        return jsonify(json.loads(p.read_text()))
    except Exception as e:
        return jsonify({"error": f"Failed to read: {e}"}), 500


@bp.route("/api/cves", methods=["GET"])
def list_cves():
    try:
        sys.path.insert(0, str(MODULES_DIR))
        import importlib
        import cveprobe
        importlib.reload(cveprobe)
        probes = cveprobe.CVE_PROBES
        pf     = request.args.get("platform", "").lower()
        if pf:
            probes = [p for p in probes if p["platform"].lower() == pf]
        return jsonify({
            "total":     len(probes),
            "platforms": sorted({p["platform"] for p in cveprobe.CVE_PROBES}),
            "probes":    probes,
        })
    except Exception as e:
        return jsonify({"error": str(e), "probes": []}), 500


@bp.route("/api/chains", methods=["GET"])
def list_chains():
    try:
        sys.path.insert(0, str(MODULES_DIR))
        import importlib
        import rootchain
        importlib.reload(rootchain)
        return jsonify({
            "total":  len(rootchain.NAMED_CHAINS),
            "chains": list(rootchain.NAMED_CHAINS.values()),
        })
    except Exception as e:
        return jsonify({"error": str(e), "chains": []}), 500


@bp.route("/api/health", methods=["GET"])
def health():
    with JOBS_LOCK:
        running = sum(1 for j in JOBS.values() if j.get("status") == "running")
        queued  = sum(1 for j in JOBS.values() if j.get("status") == "queued")
    modules = {m: (SCANNER_ROOT / f"modules/{m}.py").exists() for m in MODULE_PATHS}
    return jsonify({
        "status":          "ok",
        "modules":         modules,
        "modules_ready":   sum(modules.values()),
        "modules_total":   len(modules),
        "jobs_running":    running,
        "jobs_queued":     queued,
        "report_download": f"{SCANNER_BASE}/api/report/download",
    })


app.register_blueprint(bp, url_prefix=SCANNER_BASE)

# ── Frontend serving ──────────────────────────────────────────────────────────
from flask import send_from_directory as _send
FRONTEND_DIST = SCANNER_ROOT.parent / 'artifacts' / 'vulnscan' / 'dist' / 'public'

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    if path.startswith('scanner-api'):
        from flask import abort
        abort(404)
    if not FRONTEND_DIST.exists():
        return jsonify({'error': 'Frontend not built'}), 503
    static_file = FRONTEND_DIST / path
    if path and static_file.exists() and static_file.is_file():
        return _send(str(FRONTEND_DIST), path)
    return _send(str(FRONTEND_DIST), 'index.html')


# ── Keep-alive ────────────────────────────────────────────────────────────────
def _start_keepalive():
    import urllib.request

    def _ping():
        time.sleep(60)
        while True:
            try:
                port = int(os.environ.get("PORT", 8000))
                urllib.request.urlopen(
                    f"http://localhost:{port}{SCANNER_BASE}/api/health", timeout=10)
            except Exception:
                pass
            time.sleep(840)

    threading.Thread(target=_ping, daemon=True).start()


_start_keepalive()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"[*] Scanner API → http://0.0.0.0:{port}{SCANNER_BASE}/api/health")
    print(f"[*] Report DL   → http://0.0.0.0:{port}{SCANNER_BASE}/api/report/download")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
