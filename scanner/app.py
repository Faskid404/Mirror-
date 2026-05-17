#!/usr/bin/env python3
import subprocess
import sys
import json
import os
import threading
import time
import uuid
import queue
from pathlib import Path
from flask import Flask, request, jsonify, Blueprint, send_from_directory, send_file
from flask_cors import CORS
from flask_sock import Sock

# ─── Setup ────────────────────────────────────────────────────────────────────
SCANNER_ROOT = Path(__file__).parent.resolve()
MODULES_DIR  = SCANNER_ROOT / "modules"
REPORTS_DIR  = SCANNER_ROOT / "reports"
STATIC_DIR   = SCANNER_ROOT.parent / "artifacts" / "vulnscan" / "dist" / "public"
SCANNER_BASE = os.environ.get("SCANNER_BASE", "/scanner-api")

REPORTS_DIR.mkdir(exist_ok=True)

app  = Flask(__name__)
CORS(app, origins="*")
sock = Sock(app)

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
    # ── Reconnaissance & surface mapping ─────────────────────────────────────
    "ghostcrawler":  "modules/ghostcrawler.py",
    "wafshatter":    "modules/wafshatter.py",
    "headerforge":   "modules/headerforge.py",
    "timebleed":     "modules/timebleed.py",
    "tokensniper":   "modules/tokensniper.py",
    "cryptohunter":  "modules/cryptohunter.py",
    "webprobe":      "modules/webprobe.py",
    "cveprobe":      "modules/cveprobe.py",
    "backendprobe":  "modules/backendprobe.py",
    # ── Auth & session ────────────────────────────────────────────────────────
    "authdrift":     "modules/authdrift.py",
    "deeplogic":     "modules/deeplogic.py",
    "rootchain":     "modules/rootchain.py",
    # ── Exploit provers (confirmed PoC) ──────────────────────────────────────
    "authbypass":    "modules/authbypass.py",
    "idorhunter":    "modules/idorhunter.py",
    "ssti_rce":      "modules/ssti_rce.py",
    "secretharvest": "modules/secretharvest.py",
    # ── Protocol-specific deep scanners ──────────────────────────────────────
    "graphqlprobe":  "modules/graphqlprobe.py",
    "scan_diff":     "modules/scan_diff.py",
}


# ─── WebSocket event bus ──────────────────────────────────────────────────────

def _emit_to_job(job_id: str, event: dict):
    """Push a JSON event to all WebSocket clients subscribed to this job.
    Also appends to the replay buffer so late-connecting clients get history."""
    msg = json.dumps(event, default=str)
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job["ws_events"].append(msg)
        queues = list(job.get("ws_queues", []))
    for q in queues:
        try:
            q.put_nowait(msg)
        except Exception:
            pass


# ─── Module runner ────────────────────────────────────────────────────────────

def run_module(job_id, abs_path, target, emit_fn=None):
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

        for line in proc.stdout:
            line = line.rstrip()
            if line:
                with JOBS_LOCK:
                    JOBS[job_id]["output"].append(line)
                if emit_fn:
                    emit_fn({"type": "log", "data": line})

        proc.wait()
        returncode = proc.returncode

        with JOBS_LOCK:
            JOBS[job_id]["returncode"] = returncode

        if returncode != 0:
            msg = f"[X] Module exited with error code {returncode}"
            with JOBS_LOCK:
                JOBS[job_id]["output"].append(msg)
            if emit_fn:
                emit_fn({"type": "log", "data": msg})

        report_file = REPORTS_DIR / f"{Path(abs_path).stem}.json"
        if report_file.exists():
            try:
                data = json.loads(report_file.read_text())
                if isinstance(data, list):
                    findings_list = data
                elif isinstance(data, dict) and "findings" in data:
                    findings_list = data["findings"]
                else:
                    findings_list = []
                with JOBS_LOCK:
                    JOBS[job_id]["findings"] = findings_list
            except Exception:
                pass

        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error" if returncode != 0 else "done"

    except Exception as e:
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"]  = str(e)
            JOBS[job_id]["output"].append(f"[ERROR] {e}")
        if emit_fn:
            emit_fn({"type": "log", "data": f"[ERROR] {e}"})


# ─── Blueprint routes ─────────────────────────────────────────────────────────

@bp.route("/", methods=["GET"])
def bp_index():
    return jsonify({
        "name":    "Mirror Security Scanner API",
        "status":  "running",
        "base":    SCANNER_BASE,
        "health":  f"{SCANNER_BASE}/api/health",
        "modules": list(MODULE_PATHS.keys()),
    })


@bp.route("/api/scan/start", methods=["POST"])
def start_scan():
    data    = request.json or {}
    target  = data.get("target", "").strip()
    modules = data.get("modules", [])
    if not target:
        return jsonify({"error": "No target provided"}), 400
    if not target.startswith("http"):
        target = "https://" + target

    job_id = str(uuid.uuid4())[:8]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id":                job_id,
            "target":            target,
            "modules":           modules,
            "status":            "queued",
            "output":            [],
            "findings":          [],
            "started":           time.time(),
            "current_module":    "",
            "completed_modules": [],
            "all_findings":      [],
            "ws_events":         [],   # replay buffer for late-connecting WS clients
            "ws_queues":         [],   # one queue per active WS connection
        }

    def run_all():
        total_mods = len(modules)

        def emit(event):
            _emit_to_job(job_id, event)

        for idx, mod_id in enumerate(modules):
            with JOBS_LOCK:
                if JOBS[job_id].get("stopped"):
                    break
            rel = MODULE_PATHS.get(mod_id)
            if not rel:
                msg = f"[X] Unknown module: {mod_id}"
                with JOBS_LOCK:
                    JOBS[job_id]["output"].append(msg)
                emit({"type": "log", "data": msg})
                continue
            abs_path = SCANNER_ROOT / rel
            if not abs_path.exists():
                msg = f"[X] Missing: {rel}"
                with JOBS_LOCK:
                    JOBS[job_id]["output"].append(msg)
                emit({"type": "log", "data": msg})
                continue

            separator = [f"\n{'='*50}", f"  Running: {mod_id}", f"{'='*50}"]
            with JOBS_LOCK:
                JOBS[job_id]["current_module"] = mod_id
                JOBS[job_id]["output"] += separator
            for sep_line in separator:
                emit({"type": "log", "data": sep_line})

            emit({
                "type":          "module_start",
                "module":        mod_id,
                "index":         idx,
                "total_modules": total_mods,
            })

            sub_id = f"{job_id}_{mod_id}"
            with JOBS_LOCK:
                JOBS[sub_id] = {"status": "running", "output": [], "findings": []}
            run_module(sub_id, abs_path, target, emit_fn=emit)

            with JOBS_LOCK:
                sub           = JOBS[sub_id]
                findings      = sub.get("findings", [])
                JOBS[job_id]["output"].extend(sub.get("output", []))
                JOBS[job_id]["all_findings"].extend(findings)
                JOBS[job_id]["completed_modules"].append(mod_id)
                total_so_far  = len(JOBS[job_id]["all_findings"])

            emit({
                "type":     "module_done",
                "module":   mod_id,
                "count":    len(findings),
                "total":    total_so_far,
                "findings": findings,
            })

        with JOBS_LOCK:
            total_findings             = len(JOBS[job_id]["all_findings"])
            JOBS[job_id]["status"]         = "done"
            JOBS[job_id]["current_module"] = ""
            JOBS[job_id]["finished"]       = time.time()

        emit({"type": "done", "total_findings": total_findings})

    threading.Thread(target=run_all, daemon=True).start()
    return jsonify({"job_id": job_id, "status": "started"})


@bp.route("/api/scan/status/<job_id>", methods=["GET"])
def scan_status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    since        = int(request.args.get("since", 0))
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


def _filter_403_findings(findings: list) -> list:
    """Remove any finding whose proof string contains an HTTP 403 status line
    and whose type is NOT a WAF-bypass finding (those legitimately document
    403 → 200 bypass chains and must be kept)."""
    WAF_BYPASS_TYPES = {"WAF_BYPASS_CONFIRMED", "WAF_IP_RESTRICTION_BYPASS"}
    filtered = []
    for f in findings:
        if f.get("type") in WAF_BYPASS_TYPES:
            filtered.append(f)
            continue
        proof = str(f.get("proof", ""))
        # Drop findings where the only confirmed status is 403
        if "HTTP 403" in proof and "HTTP 200" not in proof and "HTTP 201" not in proof:
            continue
        filtered.append(f)
    return filtered


@bp.route("/api/scan/results/<job_id>", methods=["GET"])
def scan_results(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    chains  = []
    rc_file = REPORTS_DIR / "rootchain_report.json"
    if rc_file.exists():
        try:
            chains = json.loads(rc_file.read_text()).get("attack_chains", [])
        except Exception:
            pass
    findings = _filter_403_findings(job.get("all_findings", []))
    return jsonify({
        "job_id":    job_id,
        "status":    job.get("status"),
        "target":    job.get("target"),
        "findings":  findings,
        "chains":    chains,
        "output":    job.get("output", []),
        "duration":  round(job.get("finished", time.time()) - job.get("started", time.time()), 1),
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
    _emit_to_job(job_id, {"type": "stopped"})
    return jsonify({"status": "stopped"})


@bp.route("/api/reports", methods=["GET"])
def list_reports():
    reports = []
    if not REPORTS_DIR.exists():
        return jsonify(reports)
    for f in REPORTS_DIR.glob("*.json"):
        if f.name.startswith("_"):
            continue
        try:
            data = json.loads(f.read_text())
            reports.append({
                "file":     f.name,
                "count":    len(data) if isinstance(data, list)
                            else (len(data.get("findings", [])) if isinstance(data, dict) else 0),
                "size":     f.stat().st_size,
                "modified": f.stat().st_mtime,
            })
        except Exception:
            pass
    return jsonify(reports)


@bp.route("/api/reports/<name>", methods=["GET"])
def get_report(name):
    p = REPORTS_DIR / name
    if not p.exists():
        return jsonify({"error": "Not found"}), 404
    try:
        return jsonify(json.loads(p.read_text()))
    except Exception as e:
        return jsonify({"error": f"Failed to read report: {e}"}), 500


@bp.route("/api/reports/<name>/html", methods=["GET"])
def get_report_html(name):
    p = REPORTS_DIR / name
    if not p.exists():
        return jsonify({"error": "Not found"}), 404
    try:
        sys.path.insert(0, str(MODULES_DIR))
        from report_generator import generate_html_report
        data     = json.loads(p.read_text())
        findings = data if isinstance(data, list) else data.get("findings", [])
        target   = data.get("target", "Unknown") if isinstance(data, dict) else "Unknown"
        html     = generate_html_report(target, findings)
        resp = app.make_response(html)
        resp.headers["Content-Type"]        = "text/html; charset=utf-8"
        resp.headers["Content-Disposition"] = f'attachment; filename="{name.replace(".json","")}-report.html"'
        resp.headers["Cache-Control"]       = "no-store"
        return resp
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {e}"}), 500


@bp.route("/api/reports/combined/html", methods=["GET"])
def get_combined_html_report():
    try:
        sys.path.insert(0, str(MODULES_DIR))
        from report_generator import generate_html_report
        all_findings = []
        target       = "Unknown"
        for f in sorted(REPORTS_DIR.glob("*.json")):
            if f.name.startswith("_"):
                continue
            try:
                data = json.loads(f.read_text())
                if isinstance(data, list):
                    all_findings.extend(data)
                elif isinstance(data, dict):
                    all_findings.extend(data.get("findings", []))
                    if data.get("target"):
                        target = data["target"]
            except Exception:
                pass
        target_file = REPORTS_DIR / "_target.txt"
        if target_file.exists():
            target = target_file.read_text().strip()
        html = generate_html_report(target, all_findings)
        resp = app.make_response(html)
        resp.headers["Content-Type"]        = "text/html; charset=utf-8"
        resp.headers["Content-Disposition"] = 'attachment; filename="mirror-full-report.html"'
        resp.headers["Cache-Control"]       = "no-store"
        return resp
    except Exception as e:
        return jsonify({"error": f"Combined report failed: {e}"}), 500


@bp.route("/api/cves", methods=["GET"])
def list_cves():
    try:
        sys.path.insert(0, str(MODULES_DIR))
        import importlib
        import cveprobe
        importlib.reload(cveprobe)
        probes          = cveprobe.CVE_PROBES
        platform_filter = request.args.get("platform", "").lower()
        if platform_filter:
            probes = [p for p in probes if p["platform"].lower() == platform_filter]
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
            "chains": [{"id": k, **v} for k, v in rootchain.NAMED_CHAINS.items()],
        })
    except Exception as e:
        return jsonify({"error": str(e), "chains": []}), 500


@bp.route("/api/health", methods=["GET"])
def health():
    modules = {m: (SCANNER_ROOT / f"modules/{m}.py").exists() for m in MODULE_PATHS}
    return jsonify({
        "status":         "ok",
        "modules":        modules,
        "modules_ready":  sum(modules.values()),
        "modules_total":  len(modules),
    })


app.register_blueprint(bp, url_prefix=SCANNER_BASE)


# ─── WebSocket live-stream endpoint ──────────────────────────────────────────
#
#  Event protocol (newline-delimited JSON sent to the client):
#    {type: "log",          data: "<terminal line>"}
#    {type: "module_start", module: "<id>", index: N, total_modules: N}
#    {type: "module_done",  module: "<id>", count: N, total: N, findings: [...]}
#    {type: "done",         total_findings: N}
#    {type: "stopped"}
#    {type: "ping"}                           ← keepalive every 25 s
#    {type: "error",        data: "<msg>"}
#
#  Late-connecting clients receive a full replay of past events before
#  streaming continues, so page refresh during a scan works correctly.
#
@sock.route(SCANNER_BASE + "/api/scan/ws/<job_id>")
def ws_scan_stream(ws, job_id):
    my_q = queue.Queue()

    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            try:
                ws.send(json.dumps({"type": "error", "data": "Job not found"}))
            except Exception:
                pass
            return
        past_events  = list(job.get("ws_events", []))
        already_done = job.get("status") in ("done", "error", "stopped")
        job.setdefault("ws_queues", []).append(my_q)

    try:
        # Replay events that occurred before this connection was established
        for msg in past_events:
            ws.send(msg)

        if already_done:
            # If scan finished before we connected, ensure client gets a terminal event
            terminal_types = ('"type": "done"', '"type":"done"',
                              '"type": "stopped"', '"type":"stopped"')
            if not any(t in m for m in past_events for t in terminal_types):
                with JOBS_LOCK:
                    total = len(JOBS.get(job_id, {}).get("all_findings", []))
                ws.send(json.dumps({"type": "done", "total_findings": total}))
            return

        # Stream live events from the per-connection queue
        while True:
            try:
                msg = my_q.get(timeout=25)
            except queue.Empty:
                # Keepalive so proxy/browser doesn't kill idle connection
                ws.send(json.dumps({"type": "ping"}))
                continue

            ws.send(msg)

            try:
                if json.loads(msg).get("type") in ("done", "stopped", "error"):
                    break
            except Exception:
                pass

    except Exception:
        pass
    finally:
        with JOBS_LOCK:
            try:
                JOBS[job_id]["ws_queues"].remove(my_q)
            except Exception:
                pass


# ─── Serve React frontend (catch-all — must be last) ─────────────────────────

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    if path.startswith(SCANNER_BASE.lstrip("/")):
        return jsonify({"error": "Not found"}), 404
    file_path = STATIC_DIR / path
    if path and file_path.exists() and file_path.is_file():
        return send_from_directory(STATIC_DIR, path)
    index = STATIC_DIR / "index.html"
    if index.exists():
        return send_file(index)
    return jsonify({"error": "Frontend not built. Run: npm run build in artifacts/vulnscan"}), 503


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"[*] Scanner API  → http://0.0.0.0:{port}{SCANNER_BASE}/api/health")
    print(f"[*] WebSocket    → ws://0.0.0.0:{port}{SCANNER_BASE}/api/scan/ws/<job_id>")
    print(f"[*] Frontend     → http://0.0.0.0:{port}/")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
