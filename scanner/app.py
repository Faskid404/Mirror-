#!/usr/bin/env python3
import subprocess
import sys
import json
import os
import threading
import time
import uuid
from pathlib import Path
from flask import Flask, request, jsonify, Blueprint
from flask_cors import CORS

# âââ Setup ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
SCANNER_ROOT = Path(__file__).parent.resolve()
MODULES_DIR  = SCANNER_ROOT / "modules"
REPORTS_DIR  = SCANNER_ROOT / "reports"
SCANNER_BASE = os.environ.get("SCANNER_BASE", "/scanner-api")

# Ensure reports directory exists at startup
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


def run_module(job_id, abs_path, target):
    with JOBS_LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["output"] = []
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

        proc.wait()

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
            JOBS[job_id]["output"].append(f"[ERROR] {e}")


# âââ Root route âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

@app.route("/")
def index():
    return jsonify({
        "name":    "Mirror Security Scanner API",
        "status":  "running",
        "base":    SCANNER_BASE,
        "health":  f"{SCANNER_BASE}/api/health",
        "modules": list(MODULE_PATHS.keys()),
    })


# âââ Routes (all mounted under SCANNER_BASE by blueprint) âââââââââââââââââââââ

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
                with JOBS_LOCK:
                    JOBS[job_id]["output"].append(f"[X] Unknown module: {mod_id}")
                continue
            abs_path = SCANNER_ROOT / rel
            if not abs_path.exists():
                with JOBS_LOCK:
                    JOBS[job_id]["output"].append(f"[X] Missing: {rel}")
                continue
            with JOBS_LOCK:
                JOBS[job_id]["current_module"] = mod_id
                JOBS[job_id]["output"] += [f"\n{'='*50}", f"  Running: {mod_id}", f"{'='*50}"]

            sub_id = f"{job_id}_{mod_id}"
            with JOBS_LOCK:
                JOBS[sub_id] = {"status": "running", "output": [], "findings": []}
            run_module(sub_id, abs_path, target)

            with JOBS_LOCK:
                sub = JOBS[sub_id]
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
    since        = int(request.args.get("since", 0))
    output_slice = job["output"][since:]
    return jsonify({
        "job_id": job_id, "status": job.get("status"),
        "target": job.get("target"),
        "current_module": job.get("current_module", ""),
        "completed_modules": job.get("completed_modules", []),
        "total_modules": len(job.get("modules", [])),
        "findings_count": len(job.get("all_findings", [])),
        "new_output": output_slice,
        "output_index": since + len(output_slice),
    })


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
            chains = json.loads(rc_file.read_text()).get("attack_chains", [])
        except Exception:
            pass
    return jsonify({
        "job_id": job_id, "status": job.get("status"),
        "target": job.get("target"), "findings": job.get("all_findings", []),
        "chains": chains, "output": job.get("output", []),
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
                "file": f.name,
                "count": len(data) if isinstance(data, list) else 0,
                "size": f.stat().st_size,
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


@bp.route("/api/cves", methods=["GET"])
def list_cves():
    try:
        sys.path.insert(0, str(MODULES_DIR))
        import importlib
        import cveprobe
        importlib.reload(cveprobe)
        probes = cveprobe.CVE_PROBES
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
            "chains": list(rootchain.NAMED_CHAINS.values()),
        })
    except Exception as e:
        return jsonify({"error": str(e), "chains": []}), 500


@bp.route("/api/health", methods=["GET"])
def health():
    modules = {m: (SCANNER_ROOT / f"modules/{m}.py").exists() for m in MODULE_PATHS}
    return jsonify({
        "status": "ok",
        "modules": modules,
        "modules_ready": sum(modules.values()),
        "modules_total": len(modules),
    })


app.register_blueprint(bp, url_prefix=SCANNER_BASE)


# Serve built React frontend
from flask import send_from_directory as _send_from_directory
FRONTEND_DIST = SCANNER_ROOT.parent / 'artifacts' / 'vulnscan' / 'dist' / 'public'

if FRONTEND_DIST.exists():
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def serve_frontend(path):
        if path.startswith('scanner-api'):
            from flask import abort
            abort(404)
        static_file = FRONTEND_DIST / path
        if path and static_file.exists() and static_file.is_file():
            return _send_from_directory(str(FRONTEND_DIST), path)
        return _send_from_directory(str(FRONTEND_DIST), 'index.html')
else:
    @app.route('/')
    def index():
        return jsonify({'name': 'Mirror Scanner API', 'status': 'running'})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"[*] Scanner API â http://0.0.0.0:{port}{SCANNER_BASE}/api/health")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
