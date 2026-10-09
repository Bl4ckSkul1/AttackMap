#!/usr/bin/env python3
"""
AttackMap Web Interface
Flask-based UI for running AttackMap attack surface reconnaissance scans.

Author: Adrian Martinez / HAAK Cybersecurity
Usage:
    pip install flask
    python3 attackmap_web.py                    # starts on http://0.0.0.0:5000
    python3 attackmap_web.py --port 8888        # custom port
    python3 attackmap_web.py --host 127.0.0.1   # localhost only
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, abort, jsonify, redirect, request, url_for

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = BASE_DIR / "atackmap.sh"
SCANS_DIR = BASE_DIR / "attackmap_scans"
HISTORY_FILE = SCANS_DIR / "scans_history.json"

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Thread-safe scan state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_scans: dict = {}
_processes: dict = {}  # scan_id -> subprocess.Popen


def _gen_id() -> str:
    return "scan_" + uuid.uuid4().hex[:8]


def _save_history():
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    serializable = {}
    with _lock:
        for sid, s in _scans.items():
            copy = dict(s)
            copy["output_lines"] = copy.get("output_lines", [])[-100:]
            serializable[sid] = copy
    HISTORY_FILE.write_text(json.dumps(serializable, indent=2, default=str))


def _load_history():
    global _scans
    if HISTORY_FILE.exists():
        try:
            data = json.loads(HISTORY_FILE.read_text())
            with _lock:
                for sid, s in data.items():
                    if s.get("status") == "running":
                        s["status"] = "failed"
                        s["error"] = "Server restarted while scan was running"
                    _scans[sid] = s
        except (json.JSONDecodeError, IOError):
            pass


def get_scan(scan_id: str):
    with _lock:
        return _scans.get(scan_id)


def set_scan(scan_id: str, data: dict):
    with _lock:
        _scans[scan_id] = data


def update_scan(scan_id: str, **kwargs):
    with _lock:
        if scan_id in _scans:
            _scans[scan_id].update(kwargs)


# ---------------------------------------------------------------------------
# Progress parsing
# ---------------------------------------------------------------------------
PHASE_MAP = [
    ("Verificando herramientas", 5, "Checking Tools"),
    ("verificando herramientas", 5, "Checking Tools"),
    ("Recolección de subdominios", 10, "Subdomain Enumeration"),
    ("recolección de subdominios", 10, "Subdomain Enumeration"),
    ("subfinder", 15, "Subdomain Enumeration"),
    ("amass", 18, "Subdomain Enumeration"),
    ("crt.sh", 20, "Subdomain Enumeration"),
    ("assetfinder", 22, "Subdomain Enumeration"),
    ("findomain", 24, "Subdomain Enumeration"),
    ("Procesando resultados", 35, "Processing Results"),
    ("procesando resultados", 35, "Processing Results"),
    ("Resolución DNS", 45, "DNS Resolution"),
    ("resolución dns", 45, "DNS Resolution"),
    ("massdns", 48, "DNS Resolution"),
    ("Port Scanning", 55, "Port Scanning"),
    ("port scanning", 55, "Port Scanning"),
    ("naabu", 58, "Port Scanning"),
    ("masscan", 58, "Port Scanning"),
    ("HTTP Probing", 65, "HTTP Probing"),
    ("http probing", 65, "HTTP Probing"),
    ("httpx", 68, "HTTP Probing"),
    ("Screenshots", 75, "Screenshots"),
    ("screenshots", 75, "Screenshots"),
    ("gowitness", 76, "Screenshots"),
    ("Crawling", 80, "Crawling"),
    ("crawling", 80, "Crawling"),
    ("katana", 82, "Crawling"),
    ("gospider", 82, "Crawling"),
    ("hakrawler", 82, "Crawling"),
    ("Nuclei", 85, "Vulnerability Scanning"),
    ("nuclei", 85, "Vulnerability Scanning"),
    ("Generando reporte", 95, "Generating Report"),
    ("generando reporte", 95, "Generating Report"),
    ("Report generated", 100, "Complete"),
    ("Scan completed", 100, "Complete"),
    ("completado", 100, "Complete"),
]


def update_progress(scan: dict, line: str):
    lower = line.lower()
    for keyword, pct, phase in PHASE_MAP:
        if keyword.lower() in lower:
            if pct > scan.get("progress", 0):
                scan["progress"] = pct
                scan["current_phase"] = phase
            break


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------
def run_scan(scan_id: str, domain: str, options: dict):
    scan = get_scan(scan_id)
    if not scan:
        return

    update_scan(scan_id, status="running", started_at=datetime.now().isoformat())

    results_dir = str(SCANS_DIR / scan_id)
    os.makedirs(results_dir, exist_ok=True)
    update_scan(scan_id, results_dir=results_dir)

    if not SCRIPT_PATH.exists():
        update_scan(
            scan_id,
            status="failed",
            error=f"Script not found: {SCRIPT_PATH}",
            finished_at=datetime.now().isoformat(),
        )
        _save_history()
        return

    cmd = ["bash", str(SCRIPT_PATH), "-d", domain, "-o", results_dir]
    if options.get("quick"):
        cmd.append("--quick")
    if options.get("full"):
        cmd.append("--full")
    if options.get("resolve_only"):
        cmd.append("--resolve-only")
    if options.get("no_nuclei"):
        cmd.append("--no-nuclei")
    cmd.extend(["-t", str(options.get("threads", 50))])
    if options.get("previous_scan"):
        cmd.extend(["--previous", str(options["previous_scan"])])

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        with _lock:
            _processes[scan_id] = process

        for line in process.stdout:
            stripped = line.rstrip()
            with _lock:
                s = _scans.get(scan_id)
                if s:
                    s["output_lines"].append(stripped)
                    if len(s["output_lines"]) > 1000:
                        s["output_lines"] = s["output_lines"][-500:]
                    update_progress(s, stripped)
                    if s.get("status") == "cancelled":
                        process.terminate()
                        break

        process.wait()
        with _lock:
            _processes.pop(scan_id, None)

        scan = get_scan(scan_id)
        if not scan:
            return

        if scan["status"] == "cancelled":
            update_scan(scan_id, finished_at=datetime.now().isoformat())
        elif process.returncode == 0:
            update_scan(scan_id, status="completed", progress=100, current_phase="Complete")
            # Try to find report and scan_data.json
            rd = Path(results_dir)
            for f in rd.rglob("*.html"):
                update_scan(scan_id, report_path=str(f))
                break
            scan_data = rd / "scan_data.json"
            if scan_data.exists():
                update_scan(scan_id, scan_data_path=str(scan_data))
                try:
                    data = json.loads(scan_data.read_text())
                    stats = {
                        "subdomains_unique": len(data.get("subdomains", [])),
                        "hosts_live": len(data.get("live_hosts", data.get("hosts", []))),
                        "vulns_found": len(data.get("vulnerabilities", data.get("vulns", []))),
                        "ports_open": sum(len(h.get("ports", [])) for h in data.get("hosts", [])) if isinstance(data.get("hosts"), list) else 0,
                    }
                    update_scan(scan_id, stats=stats)
                except Exception:
                    pass
            update_scan(scan_id, finished_at=datetime.now().isoformat())
        else:
            update_scan(
                scan_id,
                status="failed",
                error=f"Script exited with code {process.returncode}",
                finished_at=datetime.now().isoformat(),
            )

        # Compute duration
        scan = get_scan(scan_id)
        if scan and scan.get("started_at") and scan.get("finished_at"):
            try:
                t0 = datetime.fromisoformat(scan["started_at"])
                t1 = datetime.fromisoformat(scan["finished_at"])
                update_scan(scan_id, duration_seconds=int((t1 - t0).total_seconds()))
            except Exception:
                pass

    except Exception as exc:
        update_scan(
            scan_id,
            status="failed",
            error=str(exc),
            finished_at=datetime.now().isoformat(),
        )
        with _lock:
            _processes.pop(scan_id, None)

    _save_history()


# ---------------------------------------------------------------------------
# HTML Templates (embedded)
# ---------------------------------------------------------------------------
FAVICON = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>&#x1F310;</text></svg>"

CSS = """
:root {
    --bg-primary: #060a14;
    --bg-secondary: #0a0e1a;
    --bg-card: #0d1321;
    --bg-input: #111827;
    --border: rgba(0, 200, 255, 0.08);
    --border-hover: rgba(0, 200, 255, 0.25);
    --accent: #00c8ff;
    --accent-glow: rgba(0, 200, 255, 0.15);
    --accent-purple: #8b5cf6;
    --critical: #ff0040;
    --high: #ff6b00;
    --medium: #ffaa00;
    --low: #22c55e;
    --info: #3b82f6;
    --text: #e2e8f0;
    --text-muted: #64748b;
    --success: #22c55e;
    --danger: #ef4444;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 15px; }
body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg-primary);
    color: var(--text);
    min-height: 100vh;
}
a { color: var(--accent); text-decoration: none; transition: color .2s; }
a:hover { color: #5cdeff; }

/* --- Navbar --- */
.navbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 0.8rem 2rem;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 100;
}
.navbar .logo {
    font-size: 1.25rem; font-weight: 800; letter-spacing: 2px;
    color: var(--accent); text-transform: uppercase;
}
.navbar .logo span { color: var(--text-muted); font-weight: 400; font-size: .75rem; letter-spacing: 0; margin-left: .5rem; }
.navbar nav { display: flex; gap: 1.5rem; align-items: center; }
.navbar nav a { color: var(--text-muted); font-size: .85rem; font-weight: 500; }
.navbar nav a:hover { color: var(--text); }

/* --- Layout --- */
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

/* --- Buttons --- */
.btn {
    display: inline-flex; align-items: center; gap: .5rem;
    padding: .55rem 1.2rem; border-radius: 8px; font-size: .85rem; font-weight: 600;
    border: none; cursor: pointer; transition: all .2s; text-decoration: none;
}
.btn-primary { background: var(--accent); color: #060a14; }
.btn-primary:hover { background: #33d4ff; box-shadow: 0 0 20px var(--accent-glow); color: #060a14; }
.btn-danger { background: var(--danger); color: #fff; }
.btn-danger:hover { background: #f87171; box-shadow: 0 0 15px rgba(239,68,68,.3); }
.btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--text-muted); }
.btn-ghost:hover { border-color: var(--border-hover); color: var(--text); }
.btn-lg { padding: .75rem 2rem; font-size: 1rem; border-radius: 10px; }
.btn-icon { padding: .4rem .6rem; font-size: 1rem; }

/* --- Cards --- */
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
.stat-card {
    background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
    padding: 1.25rem; transition: border-color .2s, box-shadow .2s;
}
.stat-card:hover { border-color: var(--border-hover); box-shadow: 0 0 20px var(--accent-glow); }
.stat-card .label { font-size: .75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: .5rem; }
.stat-card .value { font-size: 1.8rem; font-weight: 700; }
.stat-card .value.accent { color: var(--accent); }
.stat-card .value.success { color: var(--success); }
.stat-card .value.danger { color: var(--danger); }

/* --- Table --- */
.table-wrap { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
table { width: 100%; border-collapse: collapse; }
thead th {
    text-align: left; padding: .75rem 1rem; font-size: .7rem; text-transform: uppercase;
    letter-spacing: 1px; color: var(--text-muted); border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
}
tbody tr { border-bottom: 1px solid var(--border); transition: background .15s; cursor: pointer; }
tbody tr:hover { background: rgba(0,200,255,.03); }
tbody tr:last-child { border-bottom: none; }
td { padding: .7rem 1rem; font-size: .85rem; vertical-align: middle; }
.actions { display: flex; gap: .4rem; }
.actions .btn-icon { font-size: .85rem; }

/* --- Badge --- */
.badge {
    display: inline-flex; align-items: center; gap: .35rem;
    padding: .2rem .65rem; border-radius: 20px; font-size: .7rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: .5px;
}
.badge-running { background: rgba(0,200,255,.12); color: var(--accent); }
.badge-completed { background: rgba(34,197,94,.12); color: var(--success); }
.badge-failed { background: rgba(239,68,68,.12); color: var(--danger); }
.badge-cancelled { background: rgba(100,116,139,.15); color: var(--text-muted); }
.badge-queued { background: rgba(139,92,246,.12); color: var(--accent-purple); }
.pulse-dot {
    width: 7px; height: 7px; border-radius: 50%; background: var(--accent);
    animation: pulse 1.5s ease-in-out infinite;
}
@keyframes pulse { 0%,100% { opacity: 1; box-shadow: 0 0 0 0 rgba(0,200,255,.4); } 50% { opacity: .6; box-shadow: 0 0 0 6px rgba(0,200,255,0); } }

/* --- Form --- */
.form-group { margin-bottom: 1.25rem; }
.form-group label { display: block; font-size: .8rem; color: var(--text-muted); margin-bottom: .4rem; font-weight: 500; }
.form-control {
    width: 100%; padding: .65rem 1rem; border-radius: 8px; border: 1px solid var(--border);
    background: var(--bg-input); color: var(--text); font-size: .9rem; transition: border-color .2s;
    outline: none; font-family: inherit;
}
.form-control:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
.form-control::placeholder { color: var(--text-muted); }
.form-control-lg { font-size: 1.15rem; padding: .85rem 1.25rem; }
.toggle-group { display: flex; gap: 0; border-radius: 10px; overflow: hidden; border: 1px solid var(--border); }
.toggle-group label {
    flex: 1; padding: .65rem 1rem; text-align: center; cursor: pointer; font-size: .8rem;
    background: var(--bg-input); color: var(--text-muted); font-weight: 500; transition: all .2s;
    border-right: 1px solid var(--border);
}
.toggle-group label:last-child { border-right: none; }
.toggle-group input { display: none; }
.toggle-group input:checked + span { }
.toggle-group label.active { background: var(--accent); color: #060a14; font-weight: 700; }
.toggle-desc { font-size: .7rem; color: var(--text-muted); margin-top: .3rem; text-align: center; min-height: 1.2em; }
.advanced-toggle { color: var(--text-muted); cursor: pointer; font-size: .8rem; margin-bottom: 1rem; display: flex; align-items: center; gap: .4rem; }
.advanced-toggle:hover { color: var(--text); }
.advanced-content { display: none; padding: .5rem 0; }
.advanced-content.open { display: block; }
.checkbox-row { display: flex; align-items: center; gap: .5rem; margin-bottom: .5rem; }
.checkbox-row input[type=checkbox] { accent-color: var(--accent); width: 16px; height: 16px; }
.checkbox-row label { font-size: .85rem; color: var(--text); margin: 0; }

/* --- Progress --- */
.progress-wrap { width: 100%; background: var(--bg-input); border-radius: 10px; height: 10px; overflow: hidden; margin: 1rem 0; }
.progress-bar {
    height: 100%; border-radius: 10px; transition: width .5s ease;
    background: linear-gradient(90deg, var(--accent), var(--accent-purple));
    background-size: 200% 100%;
    animation: shimmer 2s linear infinite;
}
@keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }

/* --- Phase pipeline --- */
.phase-pipeline { display: flex; align-items: center; gap: .3rem; flex-wrap: wrap; margin: 1rem 0; }
.phase-dot {
    width: 10px; height: 10px; border-radius: 50%; background: var(--bg-input); border: 2px solid var(--border);
    transition: all .3s;
}
.phase-dot.done { background: var(--success); border-color: var(--success); }
.phase-dot.active { background: var(--accent); border-color: var(--accent); animation: pulse 1.5s ease-in-out infinite; }
.phase-label { font-size: .7rem; color: var(--text-muted); margin: 0 .3rem; }
.phase-label.active { color: var(--accent); font-weight: 600; }
.phase-label.done { color: var(--success); }
.phase-connector { width: 20px; height: 2px; background: var(--border); }
.phase-connector.done { background: var(--success); }

/* --- Terminal --- */
.terminal {
    background: #0a0a0a; border: 1px solid var(--border); border-radius: 10px;
    padding: 1rem; font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: .75rem; line-height: 1.6; max-height: 450px; overflow-y: auto;
    color: #b0b0b0; position: relative;
}
.terminal.collapsed { max-height: 120px; }
.terminal .line { white-space: pre-wrap; word-break: break-all; }
.terminal .c-green { color: #22c55e; }
.terminal .c-cyan { color: #00c8ff; }
.terminal .c-yellow { color: #ffaa00; }
.terminal .c-red { color: #ef4444; }
.terminal .c-magenta { color: #c084fc; }
.terminal .c-bold { font-weight: 700; }
.terminal .cursor-blink::after { content: '\\2588'; animation: blink 1s step-end infinite; color: var(--accent); }
@keyframes blink { 0%,100%{opacity:1;} 50%{opacity:0;} }

/* --- Misc --- */
.empty-state { text-align: center; padding: 4rem 2rem; color: var(--text-muted); }
.empty-state .icon { font-size: 3rem; margin-bottom: 1rem; opacity: .4; }
.empty-state h3 { color: var(--text); margin-bottom: .5rem; }
.page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem; }
.page-header h1 { font-size: 1.3rem; font-weight: 700; }
.elapsed { font-size: .85rem; color: var(--text-muted); font-variant-numeric: tabular-nums; }
.scan-meta { display: flex; gap: 1.5rem; align-items: center; flex-wrap: wrap; margin-bottom: 1rem; }
.btn-row { display: flex; gap: .75rem; flex-wrap: wrap; margin-top: 1.5rem; }
.error-box { background: rgba(239,68,68,.08); border: 1px solid rgba(239,68,68,.2); border-radius: 10px; padding: 1rem; color: var(--danger); margin: 1rem 0; }

/* --- Toast --- */
.toast-container { position: fixed; bottom: 1.5rem; right: 1.5rem; z-index: 9999; display: flex; flex-direction: column; gap: .5rem; }
.toast {
    background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px;
    padding: .75rem 1.25rem; font-size: .8rem; color: var(--text);
    box-shadow: 0 8px 30px rgba(0,0,0,.4); animation: slideIn .3s ease;
    max-width: 350px;
}
.toast.success { border-color: rgba(34,197,94,.3); }
.toast.error { border-color: rgba(239,68,68,.3); }
@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

@media (max-width: 768px) {
    .container { padding: 1rem; }
    .stat-grid { grid-template-columns: repeat(2, 1fr); }
    .navbar { padding: .6rem 1rem; }
    .phase-pipeline { gap: .15rem; }
}
"""

JS_COMMON = """
function toast(msg, type='info') {
    let c = document.getElementById('toasts');
    if (!c) { c = document.createElement('div'); c.id='toasts'; c.className='toast-container'; document.body.appendChild(c); }
    const t = document.createElement('div');
    t.className = 'toast ' + type;
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(() => { t.style.opacity='0'; t.style.transition='opacity .3s'; setTimeout(()=>t.remove(),300); }, 4000);
}
function confirmDelete(id) {
    if (confirm('Delete this scan and all its files?')) {
        fetch('/api/scan/'+id, {method:'DELETE'}).then(r=>r.json()).then(d=>{
            if(d.ok) { toast('Scan deleted','success'); setTimeout(()=>location.reload(),500); }
            else toast('Failed to delete','error');
        });
    }
}
function fmtDuration(s) {
    if (!s && s !== 0) return '-';
    const m = Math.floor(s/60), sec = s%60;
    return m > 0 ? m+'m '+sec+'s' : sec+'s';
}
function ansiToHtml(text) {
    const map = {'30':'','31':'c-red','32':'c-green','33':'c-yellow','34':'c-cyan','35':'c-magenta','36':'c-cyan','37':'','1':'c-bold','0':''};
    let result = text;
    result = result.replace(/\\x1b\\[([0-9;]+)m/g, function(match, codes) {
        const parts = codes.split(';');
        let cls = [];
        for (const p of parts) { if (map[p]) cls.push(map[p]); }
        if (cls.length) return '<span class="'+cls.join(' ')+'">';
        return '</span>';
    });
    // Close any remaining open spans
    const opens = (result.match(/<span/g)||[]).length;
    const closes = (result.match(/<\\/span>/g)||[]).length;
    for (let i = 0; i < opens - closes; i++) result += '</span>';
    return result;
}
document.addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.key === 'n') { e.preventDefault(); window.location='/scan/new'; }
    if (e.key === 'Escape') { window.location='/'; }
});
"""

NAVBAR = """
<nav class="navbar">
    <a href="/" class="logo">ATTACKMAP<span>Attack Surface Reconnaissance</span></a>
    <nav>
        <a href="/">Dashboard</a>
        <a href="/scan/new">New Scan</a>
    </nav>
</nav>
"""


def _page(title: str, body: str, extra_js: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} - AttackMap</title>
<link rel="icon" href="{FAVICON}">
<style>{CSS}</style>
</head>
<body>
{NAVBAR}
<div class="container">{body}</div>
<div id="toasts" class="toast-container"></div>
<script>{JS_COMMON}{extra_js}</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def dashboard_page(scans_list):
    total = len(scans_list)
    running = sum(1 for s in scans_list if s["status"] == "running")
    domains = len(set(s["domain"] for s in scans_list))
    total_vulns = sum(s.get("stats", {}).get("vulns_found", 0) for s in scans_list)

    rows = ""
    for s in sorted(scans_list, key=lambda x: x.get("started_at", ""), reverse=True):
        sid = s["id"]
        badge_cls = "badge-" + s["status"]
        dot = '<span class="pulse-dot"></span>' if s["status"] == "running" else ""
        icon = {"running": "", "completed": "&#10003;", "failed": "&#10007;", "cancelled": "&#8212;", "queued": "&#9679;"}.get(s["status"], "")
        stats = s.get("stats", {})
        assets = stats.get("subdomains_unique", 0) + stats.get("hosts_live", 0)
        vulns = stats.get("vulns_found", 0)
        dur = fmtDuration_py(s.get("duration_seconds"))
        started = s.get("started_at", "-")[:16].replace("T", " ") if s.get("started_at") else "-"
        profile = s.get("profile", "normal").title()

        report_btn = ""
        if s.get("report_path"):
            report_btn = f'<a class="btn btn-icon btn-ghost" href="/api/scan/{sid}/report" target="_blank" title="Report" onclick="event.stopPropagation()">&#128196;</a>'

        rows += f"""<tr onclick="window.location='/scan/{sid}'">
            <td><span class="badge {badge_cls}">{dot} {icon} {s['status']}</span></td>
            <td><strong>{s['domain']}</strong></td>
            <td>{profile}</td>
            <td>{started}</td>
            <td>{dur}</td>
            <td>{assets}</td>
            <td>{vulns}</td>
            <td class="actions" onclick="event.stopPropagation()">
                <a class="btn btn-icon btn-ghost" href="/scan/{sid}" title="View">&#128065;</a>
                {report_btn}
                <button class="btn btn-icon btn-ghost" onclick="confirmDelete('{sid}')" title="Delete">&#128465;</button>
            </td>
        </tr>"""

    empty = ""
    if not rows:
        empty = """<div class="empty-state"><div class="icon">&#127758;</div>
        <h3>No scans yet</h3><p>Start your first reconnaissance to map an attack surface.</p>
        <a href="/scan/new" class="btn btn-primary btn-lg" style="margin-top:1rem">Launch First Scan</a></div>"""

    table = f"""<div class="table-wrap"><table>
        <thead><tr><th>Status</th><th>Domain</th><th>Profile</th><th>Started</th><th>Duration</th><th>Assets</th><th>Vulns</th><th>Actions</th></tr></thead>
        <tbody>{rows}</tbody></table></div>""" if rows else empty

    body = f"""
    <div class="page-header">
        <h1>Dashboard</h1>
        <a href="/scan/new" class="btn btn-primary">&#43; New Scan</a>
    </div>
    <div class="stat-grid">
        <div class="stat-card"><div class="label">Total Scans</div><div class="value">{total}</div></div>
        <div class="stat-card"><div class="label">Currently Running</div><div class="value accent">{running}</div></div>
        <div class="stat-card"><div class="label">Domains Scanned</div><div class="value">{domains}</div></div>
        <div class="stat-card"><div class="label">Total Vulns Found</div><div class="value danger">{total_vulns}</div></div>
    </div>
    {table}
    """
    js = """
    setInterval(function(){
        fetch('/api/scans').then(r=>r.json()).then(data=>{
            const running = data.filter(s=>s.status==='running').length;
            document.querySelectorAll('.stat-card .value')[1].textContent = running;
        });
    }, 10000);
    """
    return _page("Dashboard", body, js)


def new_scan_page():
    # Build list of previous scans for comparison dropdown
    with _lock:
        prev_scans = [s for s in _scans.values() if s["status"] == "completed"]
    prev_options = '<option value="">None</option>'
    for s in sorted(prev_scans, key=lambda x: x.get("started_at", ""), reverse=True):
        prev_options += f'<option value="{s["results_dir"]}">{s["domain"]} ({s.get("started_at","")[:10]})</option>'

    body = f"""
    <div class="page-header"><h1>New Scan</h1></div>
    <div style="max-width:650px">
        <form id="scanForm">
            <div class="form-group">
                <label>Target Domain</label>
                <input type="text" class="form-control form-control-lg" name="domain" placeholder="example.com" required autofocus>
            </div>
            <div class="form-group">
                <label>Scan Profile</label>
                <div class="toggle-group" id="profileToggle">
                    <label onclick="setProfile('quick',this)" class="">Quick</label>
                    <label onclick="setProfile('normal',this)" class="active">Normal</label>
                    <label onclick="setProfile('full',this)" class="">Full</label>
                </div>
                <div class="toggle-desc" id="profileDesc">All sources + DNS + HTTP probing (~5-10 min)</div>
            </div>
            <input type="hidden" name="profile" id="profileInput" value="normal">
            <div class="form-group">
                <label>Threads</label>
                <input type="number" class="form-control" name="threads" value="50" min="10" max="200">
            </div>
            <div class="advanced-toggle" onclick="toggleAdvanced()">&#9660; Advanced Options</div>
            <div class="advanced-content" id="advOpts">
                <div class="checkbox-row"><input type="checkbox" name="resolve_only" id="ronly"><label for="ronly">Resolve only (skip HTTP probing & scanning)</label></div>
                <div class="checkbox-row"><input type="checkbox" name="no_nuclei" id="nonuc"><label for="nonuc">Skip Nuclei vulnerability scanning</label></div>
                <div class="form-group" style="margin-top:.75rem">
                    <label>Compare with previous scan</label>
                    <select class="form-control" name="previous_scan">{prev_options}</select>
                </div>
            </div>
            <button type="submit" class="btn btn-primary btn-lg" style="width:100%;justify-content:center;margin-top:1rem">
                &#9889; Launch Scan
            </button>
        </form>
    </div>
    """
    js = """
    const descs = {quick:"subfinder + crt.sh only (~2 min)",normal:"All sources + DNS + HTTP probing (~5-10 min)",full:"Everything + ports + screenshots + nuclei (~15-30 min)"};
    function setProfile(p, el) {
        document.getElementById('profileInput').value = p;
        document.querySelectorAll('#profileToggle label').forEach(l=>l.classList.remove('active'));
        el.classList.add('active');
        document.getElementById('profileDesc').textContent = descs[p];
    }
    function toggleAdvanced() {
        document.getElementById('advOpts').classList.toggle('open');
    }
    document.getElementById('scanForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const fd = new FormData(this);
        const body = {
            domain: fd.get('domain').trim(),
            profile: fd.get('profile'),
            threads: parseInt(fd.get('threads')) || 50,
            resolve_only: !!fd.get('resolve_only'),
            no_nuclei: !!fd.get('no_nuclei'),
            previous_scan: fd.get('previous_scan') || null
        };
        if (!body.domain) { toast('Enter a domain','error'); return; }
        fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)})
        .then(r=>r.json()).then(d=>{
            if(d.id) window.location='/scan/'+d.id;
            else toast(d.error||'Failed','error');
        }).catch(()=>toast('Request failed','error'));
    });
    """
    return _page("New Scan", body, js)


def scan_detail_page(scan):
    sid = scan["id"]
    badge_cls = "badge-" + scan["status"]
    status = scan["status"]
    domain = scan["domain"]
    profile = scan.get("profile", "normal").title()
    progress = scan.get("progress", 0)
    phase = scan.get("current_phase", "Initializing")
    stats = scan.get("stats", {})
    error = scan.get("error")

    # Phase pipeline
    all_phases = ["Subdomains", "DNS", "Ports", "HTTP", "Screenshots", "Crawl", "Vulns", "Report"]
    phase_idx = -1
    phase_map = {"Checking Tools": -1, "Subdomain Enumeration": 0, "Processing Results": 0,
                 "DNS Resolution": 1, "Port Scanning": 2, "HTTP Probing": 3,
                 "Screenshots": 4, "Crawling": 5, "Vulnerability Scanning": 6,
                 "Generating Report": 7, "Complete": 8}
    phase_idx = phase_map.get(phase, -1)

    pipeline = ""
    for i, p in enumerate(all_phases):
        if i > 0:
            c = "done" if i <= phase_idx else ""
            pipeline += f'<div class="phase-connector {c}"></div>'
        dot_cls = "done" if i < phase_idx else ("active" if i == phase_idx else "")
        lbl_cls = "done" if i < phase_idx else ("active" if i == phase_idx else "")
        pipeline += f'<div class="phase-dot {dot_cls}"></div><span class="phase-label {lbl_cls}">{p}</span>'

    # Terminal lines
    lines_html = ""
    for ln in scan.get("output_lines", [])[-300:]:
        lines_html += f'<div class="line">{ansi_to_html_py(ln)}</div>'

    # Build page based on status
    header = f"""
    <div class="page-header">
        <div>
            <h1 style="display:flex;align-items:center;gap:.75rem">{domain} <span class="badge {badge_cls}">{status}</span></h1>
            <div class="scan-meta">
                <span style="color:var(--text-muted)">Profile: {profile}</span>
                <span class="elapsed" id="elapsed"></span>
            </div>
        </div>
        <div style="display:flex;gap:.5rem">
            <a href="/" class="btn btn-ghost">&#8592; Back</a>
            {"<button class='btn btn-danger' onclick='cancelScan()'>Cancel Scan</button>" if status == "running" else ""}
        </div>
    </div>"""

    progress_section = ""
    if status == "running":
        progress_section = f"""
        <div class="progress-wrap"><div class="progress-bar" id="progressBar" style="width:{progress}%"></div></div>
        <div style="display:flex;justify-content:space-between;font-size:.8rem;color:var(--text-muted)">
            <span id="phaseText">{phase}</span><span id="pctText">{progress}%</span>
        </div>
        <div class="phase-pipeline" id="pipeline">{pipeline}</div>"""
    elif status == "completed":
        progress_section = f"""
        <div class="stat-grid">
            <div class="stat-card"><div class="label">Subdomains</div><div class="value accent">{stats.get('subdomains_unique',0)}</div></div>
            <div class="stat-card"><div class="label">Live Hosts</div><div class="value success">{stats.get('hosts_live',0)}</div></div>
            <div class="stat-card"><div class="label">Open Ports</div><div class="value">{stats.get('ports_open',0)}</div></div>
            <div class="stat-card"><div class="label">Vulns Found</div><div class="value danger">{stats.get('vulns_found',0)}</div></div>
        </div>
        <div class="btn-row">
            {"<a href='/api/scan/"+sid+"/report' target='_blank' class='btn btn-primary btn-lg'>View Full Report</a>" if scan.get("report_path") else ""}
            {"<a href='/api/scan/"+sid+"/json' target='_blank' class='btn btn-ghost'>Download JSON</a>" if scan.get("scan_data_path") else ""}
            <a href="/scan/new?domain={domain}" class="btn btn-ghost">Re-scan</a>
        </div>"""

    error_section = ""
    if error:
        error_section = f'<div class="error-box"><strong>Error:</strong> {error}</div>'
        if status == "failed":
            error_section += f'<div class="btn-row"><a href="/scan/new?domain={domain}" class="btn btn-primary">Retry</a></div>'

    terminal_cls = "collapsed" if status == "completed" else ""
    toggle_label = "Show" if status == "completed" else "Hide"
    terminal = f"""
    <div style="margin-top:1.5rem">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem">
            <span style="font-size:.8rem;color:var(--text-muted)">Terminal Output</span>
            <button class="btn btn-ghost" style="font-size:.7rem" onclick="toggleTerminal()">{toggle_label} Terminal</button>
        </div>
        <div class="terminal {terminal_cls}" id="terminal">{lines_html}{"<span class='cursor-blink'></span>" if status == "running" else ""}</div>
    </div>"""

    body = header + progress_section + error_section + terminal
    js = f"""
    const scanId = '{sid}';
    const startedAt = '{scan.get("started_at","")}';
    const scanStatus = '{status}';
    function toggleTerminal() {{
        const t = document.getElementById('terminal');
        t.classList.toggle('collapsed');
    }}
    function cancelScan() {{
        if(confirm('Cancel this scan?'))
            fetch('/api/scan/'+scanId+'/cancel',{{method:'POST'}}).then(r=>r.json()).then(d=>{{
                if(d.ok) {{ toast('Scan cancelled','success'); setTimeout(()=>location.reload(),1000); }}
            }});
    }}
    // Elapsed timer
    if (startedAt) {{
        const t0 = new Date(startedAt).getTime();
        function updateElapsed() {{
            const now = Date.now();
            const s = Math.floor((now - t0)/1000);
            const el = document.getElementById('elapsed');
            if (el) el.textContent = 'Elapsed: ' + Math.floor(s/60) + 'm ' + (s%60) + 's';
        }}
        updateElapsed();
        if (scanStatus === 'running') setInterval(updateElapsed, 1000);
    }}
    // SSE for running scans
    if (scanStatus === 'running') {{
        const term = document.getElementById('terminal');
        const es = new EventSource('/api/scan/'+scanId+'/stream');
        es.onmessage = function(e) {{
            try {{
                const d = JSON.parse(e.data);
                if (d.type === 'output') {{
                    // Remove cursor
                    const cursors = term.querySelectorAll('.cursor-blink');
                    cursors.forEach(c=>c.remove());
                    const div = document.createElement('div');
                    div.className = 'line';
                    div.innerHTML = ansiToHtml(d.line);
                    term.appendChild(div);
                    // Add cursor back
                    const cur = document.createElement('span');
                    cur.className = 'cursor-blink';
                    term.appendChild(cur);
                    term.scrollTop = term.scrollHeight;
                }}
                if (d.type === 'progress') {{
                    const bar = document.getElementById('progressBar');
                    const pct = document.getElementById('pctText');
                    const ph = document.getElementById('phaseText');
                    if(bar) bar.style.width = d.value + '%';
                    if(pct) pct.textContent = d.value + '%';
                    if(ph) ph.textContent = d.phase;
                }}
                if (d.type === 'done') {{
                    es.close();
                    toast('Scan ' + d.status, d.status==='completed'?'success':'error');
                    setTimeout(()=>location.reload(), 1500);
                }}
            }} catch(ex) {{}}
        }};
        es.onerror = function() {{ es.close(); }};
    }}
    function ansiToHtml(text) {{
        const map = {{'30':'','31':'c-red','32':'c-green','33':'c-yellow','34':'c-cyan','35':'c-magenta','36':'c-cyan','37':'','1':'c-bold','0':''}};
        let result = text.replace(/</g,'&lt;').replace(/>/g,'&gt;');
        result = result.replace(/\\x1b\\[([0-9;]+)m/g, function(match, codes) {{
            const parts = codes.split(';');
            let cls = [];
            for (const p of parts) {{ if (map[p]) cls.push(map[p]); }}
            if (cls.length) return '<span class="'+cls.join(' ')+'">';
            return '</span>';
        }});
        return result;
    }}
    """
    return _page(f"Scan {domain}", body, js)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def fmtDuration_py(seconds):
    if seconds is None:
        return "-"
    m = seconds // 60
    s = seconds % 60
    return f"{m}m {s}s" if m > 0 else f"{s}s"


def ansi_to_html_py(text: str) -> str:
    import html as _html
    text = _html.escape(text)
    import re
    color_map = {"30": "", "31": "c-red", "32": "c-green", "33": "c-yellow",
                 "34": "c-cyan", "35": "c-magenta", "36": "c-cyan", "37": "", "1": "c-bold", "0": ""}

    def replacer(m):
        codes = m.group(1).split(";")
        cls = [color_map.get(c, "") for c in codes if color_map.get(c)]
        if cls:
            return f'<span class="{" ".join(cls)}">'
        return "</span>"

    result = re.sub(r"\x1b\[([0-9;]+)m", replacer, text)
    return result


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    with _lock:
        scans_list = list(_scans.values())
    return dashboard_page(scans_list)


@app.route("/scan/new")
def new_scan_view():
    return new_scan_page()


@app.route("/scan/<scan_id>")
def scan_detail_view(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    return scan_detail_page(scan)


@app.route("/api/scan", methods=["POST"])
def api_start_scan():
    data = request.get_json(force=True, silent=True) or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    # Basic domain validation — no shell injection
    import re
    if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$", domain):
        return jsonify({"error": "Invalid domain format"}), 400

    profile = data.get("profile", "normal")
    if profile not in ("quick", "normal", "full"):
        profile = "normal"

    threads = data.get("threads", 50)
    try:
        threads = max(10, min(200, int(threads)))
    except (ValueError, TypeError):
        threads = 50

    scan_id = _gen_id()
    options = {
        "quick": profile == "quick",
        "full": profile == "full",
        "resolve_only": bool(data.get("resolve_only")),
        "no_nuclei": bool(data.get("no_nuclei")),
        "threads": threads,
        "previous_scan": data.get("previous_scan"),
    }

    scan = {
        "id": scan_id,
        "domain": domain,
        "status": "queued",
        "profile": profile,
        "started_at": None,
        "finished_at": None,
        "duration_seconds": None,
        "progress": 0,
        "current_phase": "Initializing",
        "output_lines": [],
        "results_dir": str(SCANS_DIR / scan_id),
        "report_path": None,
        "scan_data_path": None,
        "stats": {"subdomains_unique": 0, "hosts_live": 0, "vulns_found": 0, "ports_open": 0},
        "options": options,
        "error": None,
    }
    set_scan(scan_id, scan)
    _save_history()

    t = threading.Thread(target=run_scan, args=(scan_id, domain, options), daemon=True)
    t.start()

    return jsonify({"id": scan_id, "status": "queued"})


@app.route("/api/scans")
def api_list_scans():
    with _lock:
        scans_list = list(_scans.values())
    # Remove large fields for list view
    cleaned = []
    for s in sorted(scans_list, key=lambda x: x.get("started_at", ""), reverse=True):
        c = dict(s)
        c.pop("output_lines", None)
        cleaned.append(c)
    return jsonify(cleaned)


@app.route("/api/scan/<scan_id>")
def api_scan_detail(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    return jsonify(scan)


@app.route("/api/scan/<scan_id>/stream")
def api_scan_stream(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)

    def generate():
        last_line = 0
        while True:
            s = get_scan(scan_id)
            if not s:
                break
            with _lock:
                lines = list(s.get("output_lines", []))
                progress = s.get("progress", 0)
                phase = s.get("current_phase", "")
                status = s.get("status", "")
                stats = s.get("stats", {})

            new_lines = lines[last_line:]
            for ln in new_lines:
                yield f"data: {json.dumps({'type': 'output', 'line': ln})}\n\n"
            last_line = len(lines)

            yield f"data: {json.dumps({'type': 'progress', 'value': progress, 'phase': phase})}\n\n"

            if status in ("completed", "failed", "cancelled"):
                yield f"data: {json.dumps({'type': 'done', 'status': status, 'stats': stats})}\n\n"
                break
            time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/scan/<scan_id>/report")
def api_scan_report(scan_id):
    scan = get_scan(scan_id)
    if not scan or not scan.get("report_path"):
        abort(404)
    report = Path(scan["report_path"])
    if not report.exists():
        abort(404)
    return Response(report.read_text(encoding="utf-8", errors="replace"), mimetype="text/html")


@app.route("/api/scan/<scan_id>/json")
def api_scan_json(scan_id):
    scan = get_scan(scan_id)
    if not scan or not scan.get("scan_data_path"):
        abort(404)
    p = Path(scan["scan_data_path"])
    if not p.exists():
        abort(404)
    return Response(p.read_text(encoding="utf-8", errors="replace"), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=scan_data_{scan['domain']}.json"})


@app.route("/api/scan/<scan_id>/cancel", methods=["POST"])
def api_cancel_scan(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    if scan["status"] != "running":
        return jsonify({"ok": False, "error": "Scan is not running"})

    update_scan(scan_id, status="cancelled")
    with _lock:
        proc = _processes.get(scan_id)
    if proc:
        try:
            proc.terminate()
        except Exception:
            pass
    _save_history()
    return jsonify({"ok": True})


@app.route("/api/scan/<scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)

    # Cancel if running
    if scan["status"] == "running":
        update_scan(scan_id, status="cancelled")
        with _lock:
            proc = _processes.get(scan_id)
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass

    # Remove files
    import shutil
    rd = scan.get("results_dir")
    if rd and Path(rd).exists():
        try:
            shutil.rmtree(rd)
        except Exception:
            pass

    with _lock:
        _scans.pop(scan_id, None)
        _processes.pop(scan_id, None)
    _save_history()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(signum=None, frame=None):
    with _lock:
        for sid, proc in list(_processes.items()):
            try:
                proc.terminate()
            except Exception:
                pass
    _save_history()
    sys.exit(0)


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AttackMap Web Interface")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    _load_history()

    print(f"\n  ATTACKMAP Web Interface")
    print(f"  Listening on http://{args.host}:{args.port}")
    print(f"  Script path: {SCRIPT_PATH}")
    print(f"  Scans directory: {SCANS_DIR}\n")

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
