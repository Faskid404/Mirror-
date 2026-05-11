#!/usr/bin/env python3
"""
Mirror Scanner API v3 — Flask backend.

v3 additions:
  - /api/proxy/request  — built-in forward proxy for scanner requests
                          (routes through SCANNER_PROXY env if set)
  - SCANNER_PROXY env var support surfaced in /api/health
  - /api/report/download — HTML report download (from v2)
  - SSE streaming (from v2)
  - Module timeout protection (from v2)
"""
import subprocess
import sys
import json
import os
import threading
import time
import uuid
import signal
import hashlib
from pathlib import Path
from flask import Flask, request, jsonify, Blueprint, Response
from flask_cors import CORS

# ── Setup ─────────────────────────────────────────────────────────────────────
SCANNER_ROOT  = Path(__file__).parent.resolve()
MODULES_DIR   = SCANNER_ROOT / "modules"
REPORTS_DIR   = SCANNER_ROOT / "reports"
SCANNER_BASE  = os.environ.get("SCANNER_BASE", "/scanner-api")
SCANNER_PROXY = os.environ.get("SCANNER_PROXY", "")   # e.g. http://127.0.0.1:8080
MAX_OUTPUT    = 2000
MODULE_TIMEOUT= 300

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
    if SCANNER_PROXY:
        env["SCANNER_PROXY"] = SCANNER_PROXY
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
    with JOBS_LOCK:
        buf = JOBS[job_id]["output"]
        if len(buf) < MAX_OUTPUT:
            buf.append(line)
        elif len(buf) == MAX_OUTPUT:
            buf.append("[output truncated]")


def run_module(job_id, abs_path, target):
    with JOBS_LOCK:
        JOBS[job_id].update({"status": "running", "output": [], "findings": []})
    try:
        env  = _make_env(target)
        REPORTS_DIR.mkdir(exist_ok=True)
        (REPORTS_DIR / "_target.txt").write_text(target)

        proc = subprocess.Popen(
            [sys.executable, str(abs_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=env, cwd=str(SCANNER_ROOT), bufsize=1,
        )
        with JOBS_LOCK:
            JOBS[job_id]["pid"] = proc.pid

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
            JOBS[job_id].update({"status": "error", "error": str(e)})
            _append_output(job_id, f"[ERROR] {e}")


# ── Scan routes ───────────────────────────────────────────────────────────────

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
                _append_output(job_id, f"[X] Missing: {rel}")
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
            JOBS[job_id].update({"status": "done", "current_module": "", "finished": time.time()})

    threading.Thread(target=run_all, daemon=True).start()
    return jsonify({"job_id": job_id, "status": "started"})


@bp.route("/api/scan/status/<job_id>", methods=["GET"])
def scan_status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    since = max(0, int(request.args.get("since", 0)))
    sl    = job["output"][since:]
    return jsonify({
        "job_id": job_id, "status": job.get("status"),
        "target": job.get("target"),
        "current_module":    job.get("current_module", ""),
        "completed_modules": job.get("completed_modules", []),
        "total_modules":     len(job.get("modules", [])),
        "findings_count":    len(job.get("all_findings", [])),
        "new_output":        sl,
        "output_index":      since + len(sl),
    })


@bp.route("/api/scan/stream/<job_id>", methods=["GET"])
def scan_stream(job_id):
    def generate():
        idx = 0
        while True:
            with JOBS_LOCK:
                job = JOBS.get(job_id)
            if not job:
                yield 'data: {"error":"Job not found"}\n\n'
                return
            lines  = job["output"][idx:]
            status = job.get("status")
            for line in lines:
                yield f'data: {json.dumps({"line": line, "status": status})}\n\n'
            idx += len(lines)
            if status in ("done", "stopped", "error") and not lines:
                yield f'data: {json.dumps({"done": True, "status": status})}\n\n'
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
    rc = REPORTS_DIR / "rootchain_report.json"
    if rc.exists():
        try:
            chains = json.loads(rc.read_text()).get("attack_chains", [])
        except Exception:
            pass
    return jsonify({
        "job_id": job_id, "status": job.get("status"), "target": job.get("target"),
        "findings": job.get("all_findings", []), "chains": chains,
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
        JOBS[job_id].update({"stopped": True, "status": "stopped"})
    pid = job.get("pid")
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    return jsonify({"status": "stopped"})


# ── Built-in forward proxy (SCANNER_PROXY passthrough) ───────────────────────

@bp.route("/api/proxy/request", methods=["POST"])
def proxy_request():
    """
    Forward an HTTP request through the configured SCANNER_PROXY.
    Body: { "url": "https://...", "method": "GET", "headers": {}, "body": "" }
    Returns: { "status": int, "headers": {}, "body": "..." }

    This lets the UI send requests through the scanner's proxy without
    browser CORS/mixed-content restrictions.
    """
    try:
        import urllib.request
        import urllib.error

        data   = request.get_json(silent=True) or {}
        url    = data.get("url", "").strip()
        method = data.get("method", "GET").upper()
        hdrs   = data.get("headers", {})
        body   = data.get("body", None)

        if not url or not url.startswith("http"):
            return jsonify({"error": "Invalid or missing URL"}), 400

        # Block requests to localhost/internal ranges (SSRF protection)
        from urllib.parse import urlparse as _up
        parsed_host = _up(url).hostname or ""
        blocked = ["localhost", "127.", "0.0.0.0", "169.254.", "10.", "192.168.", "172."]
        if any(parsed_host.startswith(b) for b in blocked):
            return jsonify({"error": "Requests to internal addresses are blocked"}), 403

        req_body = body.encode() if isinstance(body, str) else None
        req = urllib.request.Request(url, data=req_body, method=method)
        for k, v in hdrs.items():
            req.add_header(k, v)

        # Apply configured proxy
        if SCANNER_PROXY:
            proxy_handler = urllib.request.ProxyHandler({
                "http": SCANNER_PROXY, "https": SCANNER_PROXY
            })
            opener = urllib.request.build_opener(proxy_handler)
        else:
            opener = urllib.request.build_opener()

        with opener.open(req, timeout=15) as resp:
            resp_body = resp.read().decode(errors='replace')
            resp_hdrs = dict(resp.headers)
            return jsonify({
                "status":  resp.status,
                "headers": resp_hdrs,
                "body":    resp_body[:50000],  # cap at 50k
            })

    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Report download ───────────────────────────────────────────────────────────

@bp.route("/api/report/download", methods=["GET"])
def download_report():
    job_id = request.args.get("job_id", "").strip()
    target = request.args.get("target", "").strip()
    findings, chains = [], []

    if job_id:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
        if job:
            findings = job.get("all_findings", [])
            target   = target or job.get("target", "unknown")

    if not findings:
        for jf in sorted(REPORTS_DIR.glob("*.json")):
            if jf.stem.startswith("_") or jf.stem == "rootchain_report":
                continue
            try:
                d = json.loads(jf.read_text())
                if isinstance(d, list):
                    findings.extend(d)
            except Exception:
                pass

    rc = REPORTS_DIR / "rootchain_report.json"
    if rc.exists():
        try:
            chains = json.loads(rc.read_text()).get("attack_chains", [])
        except Exception:
            pass

    if not target:
        tf = REPORTS_DIR / "_target.txt"
        target = tf.read_text().strip() if tf.exists() else "Unknown Target"

    try:
        sys.path.insert(0, str(MODULES_DIR))
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "report_generator", str(MODULES_DIR / "report_generator.py"))
        rg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rg)
        html = rg.generate_html_report(target, findings, chains)
    except Exception:
        html = _minimal_html(target, findings, chains)

    fname = f"mirror-report-{time.strftime('%Y%m%d-%H%M%S')}.html"
    return Response(html, mimetype="text/html",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@bp.route("/api/report/status", methods=["GET"])
def report_status():
    count = 0
    for jf in REPORTS_DIR.glob("*.json"):
        if jf.stem.startswith("_") or jf.stem == "rootchain_report":
            continue
        try:
            d = json.loads(jf.read_text())
            if isinstance(d, list):
                count += len(d)
        except Exception:
            pass
    return jsonify({"report_available": count > 0, "findings_count": count,
                    "download_url": f"{SCANNER_BASE}/api/report/download"})


def _minimal_html(target, findings, chains):
    sev_colors = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706","LOW":"#65a30d","INFO":"#6b7280"}
    sev_counts = {}
    for f in findings:
        s = f.get("severity","INFO"); sev_counts[s] = sev_counts.get(s,0)+1
    badges = "".join(f'<span style="background:{sev_colors.get(s,"#888")};color:#fff;padding:4px 10px;border-radius:16px;margin:3px;font-weight:bold">{s}: {c}</span>' for s,c in sev_counts.items())
    rows   = ""
    order  = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    for f in sorted(findings, key=lambda x: order.index(x.get("severity","INFO")) if x.get("severity","INFO") in order else 99):
        s = f.get("severity","INFO"); c = sev_colors.get(s,"#888")
        rows += f'<tr><td style="color:{c};font-weight:bold">{s}</td><td>{f.get("type","")}</td><td style="font-size:.85em">{f.get("url","")}</td><td style="font-size:.85em">{f.get("detail","")}</td><td style="font-size:.8em;color:#555">{f.get("remediation","")}</td></tr>'
    chain_html = ""
    for c in chains:
        r = c.get("risk","HIGH"); col = sev_colors.get(r,"#888")
        chain_html += f'<div style="border-left:4px solid {col};padding:8px 16px;margin:8px 0;background:#fafafa"><b style="color:{col}">[{r}]</b> {c.get("name","?")} — {c.get("description","")}</div>'
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Mirror Report — {target}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1300px;margin:0 auto;padding:24px;background:#f5f5f5}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.1)}}
th{{background:#1e293b;color:#fff;padding:10px 14px;text-align:left}}td{{padding:8px 14px;border-bottom:1px solid #e2e8f0;vertical-align:top}}
.btn{{background:#1e293b;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;float:right}}</style>
</head><body>
<button class="btn" onclick="window.print()">&#x1F4BE; Save PDF</button>
<h1 style="color:#1e293b">Mirror Security Scan Report</h1>
<p><b>Target:</b> {target} &nbsp; <b>Date:</b> {time.strftime('%Y-%m-%d %H:%M UTC',time.gmtime())}</p>
<div style="margin:16px 0">{badges}</div>
{'<h2>Attack Chains</h2>'+chain_html if chains else ''}
<h2>Findings ({len(findings)})</h2>
<table><tr><th>Severity</th><th>Type</th><th>URL</th><th>Detail</th><th>Remediation</th></tr>{rows}</table>
</body></html>"""


# ── Other routes ──────────────────────────────────────────────────────────────

@bp.route("/api/reports", methods=["GET"])
def list_reports():
    reports = []
    for f in sorted(REPORTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.name.startswith("_"):
            continue
        try:
            d = json.loads(f.read_text())
            reports.append({"file": f.name, "count": len(d) if isinstance(d, list) else 0,
                             "size": f.stat().st_size, "modified": f.stat().st_mtime})
        except Exception:
            pass
    return jsonify(reports)


@bp.route("/api/reports/<name>", methods=["GET"])
def get_report(name):
    p = REPORTS_DIR / name
    if not p.exists() or p.suffix != ".json":
        return jsonify({"error": "Not found"}), 404
    try:
        return jsonify(json.loads(p.read_text()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/api/cves", methods=["GET"])
def list_cves():
    try:
        sys.path.insert(0, str(MODULES_DIR))
        import importlib, cveprobe
        importlib.reload(cveprobe)
        probes = cveprobe.CVE_PROBES
        pf = request.args.get("platform","").lower()
        if pf:
            probes = [p for p in probes if p["platform"].lower() == pf]
        return jsonify({"total": len(probes),
                        "platforms": sorted({p["platform"] for p in cveprobe.CVE_PROBES}),
                        "probes": probes})
    except Exception as e:
        return jsonify({"error": str(e), "probes": []}), 500


@bp.route("/api/chains", methods=["GET"])
def list_chains():
    try:
        sys.path.insert(0, str(MODULES_DIR))
        import importlib, rootchain
        importlib.reload(rootchain)
        return jsonify({"total": len(rootchain.NAMED_CHAINS),
                        "chains": list(rootchain.NAMED_CHAINS.values())})
    except Exception as e:
        return jsonify({"error": str(e), "chains": []}), 500


@bp.route("/api/health", methods=["GET"])
def health():
    with JOBS_LOCK:
        running = sum(1 for j in JOBS.values() if j.get("status") == "running")
        queued  = sum(1 for j in JOBS.values() if j.get("status") == "queued")
    modules = {m: (SCANNER_ROOT / f"modules/{m}.py").exists() for m in MODULE_PATHS}
    return jsonify({
        "status": "ok", "modules": modules,
        "modules_ready": sum(modules.values()), "modules_total": len(modules),
        "jobs_running": running, "jobs_queued": queued,
        "proxy_configured": bool(SCANNER_PROXY),
        "proxy_url": SCANNER_PROXY or None,
        "report_download": f"{SCANNER_BASE}/api/report/download",
        "proxy_endpoint":  f"{SCANNER_BASE}/api/proxy/request",
    })


app.register_blueprint(bp, url_prefix=SCANNER_BASE)

from flask import send_from_directory as _send
FRONTEND_DIST = SCANNER_ROOT.parent / 'artifacts' / 'vulnscan' / 'dist' / 'public'

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    if path.startswith('scanner-api'):
        from flask import abort; abort(404)
    if not FRONTEND_DIST.exists():
        return jsonify({'error': 'Frontend not built'}), 503
    sf = FRONTEND_DIST / path
    if path and sf.exists() and sf.is_file():
        return _send(str(FRONTEND_DIST), path)
    return _send(str(FRONTEND_DIST), 'index.html')


def _start_keepalive():
    import urllib.request

    def _ping():
        time.sleep(60)
        while True:
            try:
                port = int(os.environ.get("PORT", 8000))
                urllib.request.urlopen(f"http://localhost:{port}{SCANNER_BASE}/api/health", timeout=10)
            except Exception:
                pass
            time.sleep(840)

    threading.Thread(target=_ping, daemon=True).start()

_start_keepalive()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"[*] Scanner API  → http://0.0.0.0:{port}{SCANNER_BASE}/api/health")
    print(f"[*] Report DL    → http://0.0.0.0:{port}{SCANNER_BASE}/api/report/download")
    print(f"[*] Forward proxy→ http://0.0.0.0:{port}{SCANNER_BASE}/api/proxy/request")
    if SCANNER_PROXY:
        print(f"[*] Routing via  → {SCANNER_PROXY}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
