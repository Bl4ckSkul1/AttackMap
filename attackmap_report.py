#!/usr/bin/env python3
"""AttackMap Report Generator — HAAK Cybersecurity Consulting.

Generates a self-contained HTML attack surface report from scan JSON data.
Zero external dependencies — stdlib only.

Usage:
    python3 attackmap_report.py scan_data.json output_report.html

Author: Adrian Martinez / HAAK Cybersecurity
"""

import json
import sys
import html
from pathlib import Path
from datetime import datetime
import base64


def load_data(json_path: str) -> dict:
    """Load and validate scan data from JSON file."""
    path = Path(json_path)
    if not path.exists():
        print(f"Error: {json_path} not found", file=sys.stderr)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Ensure required keys with defaults
    data.setdefault("meta", {})
    data.setdefault("stats", {})
    data.setdefault("sources", {})
    data.setdefault("assets", [])
    data.setdefault("ports_summary", {})
    data.setdefault("technologies", {})
    data.setdefault("vulnerabilities", [])
    data.setdefault("endpoints", [])
    data.setdefault("comparison", {})
    return data


def embed_screenshot(img_path: str, json_dir: Path) -> str:
    """Return base64 data URI if the image exists, else empty string."""
    if not img_path:
        return ""
    full = json_dir / img_path
    if not full.exists():
        return ""
    try:
        raw = full.read_bytes()
        ext = full.suffix.lower()
        mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                "gif": "image/gif", "webp": "image/webp"}.get(ext.lstrip("."), "image/png")
        return f"data:{mime};base64,{base64.b64encode(raw).decode()}"
    except Exception:
        return ""


def esc(text) -> str:
    """HTML-escape any value safely."""
    if text is None:
        return ""
    return html.escape(str(text))


def classify_risk_color(risk: str) -> str:
    """Return CSS color variable name for a risk level."""
    return {"critical": "var(--critical)", "high": "var(--high)",
            "medium": "var(--medium)", "low": "var(--low)",
            "info": "var(--info)"}.get((risk or "").lower(), "var(--text-muted)")


def status_color(code) -> str:
    """Return CSS color for HTTP status code."""
    try:
        c = int(code)
    except (ValueError, TypeError):
        return "var(--text-muted)"
    if 200 <= c < 300:
        return "var(--low)"
    if 300 <= c < 400:
        return "var(--info)"
    if 400 <= c < 500:
        return "var(--medium)"
    if 500 <= c < 600:
        return "var(--high)"
    return "var(--text-muted)"


def generate_css() -> str:
    """Return all CSS for the report."""
    return """
:root {
  --bg-primary: #060a14;
  --bg-card: #0d1321;
  --bg-card-hover: #111827;
  --border: rgba(0, 200, 255, 0.08);
  --border-hover: rgba(0, 200, 255, 0.2);
  --accent: #00c8ff;
  --accent-dim: rgba(0, 200, 255, 0.1);
  --accent-purple: #8b5cf6;
  --text: #e2e8f0;
  --text-muted: #64748b;
  --text-dim: #334155;
  --critical: #ff0040;
  --high: #ff6b00;
  --medium: #ffaa00;
  --low: #22c55e;
  --info: #3b82f6;
  --sidebar-w: 220px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html { scroll-behavior: smooth; }

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  font-size: 14px;
  background: var(--bg-primary);
  color: var(--text);
  line-height: 1.6;
  overflow-x: hidden;
}

/* Gradient accent line at top */
.top-accent {
  position: fixed; top: 0; left: 0; width: 100%; height: 3px; z-index: 1000;
  background: linear-gradient(90deg, var(--accent), var(--accent-purple), var(--accent));
  background-size: 200% 100%;
  animation: gradientShift 4s ease infinite;
}

@keyframes gradientShift {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}

/* Sidebar */
nav.sidebar {
  position: fixed; left: 0; top: 3px;
  width: var(--sidebar-w); height: calc(100vh - 3px);
  background: rgba(13, 19, 33, 0.95);
  backdrop-filter: blur(10px);
  border-right: 1px solid var(--border);
  padding: 24px 0;
  overflow-y: auto;
  z-index: 100;
}

nav.sidebar .brand {
  padding: 0 20px 20px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 16px;
}

nav.sidebar .brand h2 {
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 15px; font-weight: 700;
  background: linear-gradient(135deg, var(--accent), var(--accent-purple));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text; letter-spacing: 2px;
}

nav.sidebar .brand span {
  font-size: 10px; color: var(--text-muted); letter-spacing: 1px; text-transform: uppercase;
}

nav.sidebar a {
  display: block; padding: 8px 20px;
  color: var(--text-muted); text-decoration: none;
  font-size: 13px; font-weight: 400;
  border-left: 2px solid transparent;
  transition: all 0.2s ease;
}

nav.sidebar a:hover, nav.sidebar a.active {
  color: var(--accent);
  background: var(--accent-dim);
  border-left-color: var(--accent);
}

/* Main content */
main {
  margin-left: var(--sidebar-w);
  padding: 40px 48px 80px;
  max-width: 1400px;
}

section { margin-bottom: 56px; }

h1 {
  font-size: 32px; font-weight: 700;
  background: linear-gradient(135deg, var(--accent), var(--accent-purple));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text; margin-bottom: 8px;
}

h2.section-title {
  font-size: 20px; font-weight: 600; color: var(--text);
  padding-bottom: 12px; margin-bottom: 24px;
  border-bottom: 1px solid var(--border);
}

h2.section-title span.icon { margin-right: 8px; }

/* Cards */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 24px;
  box-shadow: 0 0 20px rgba(0, 200, 255, 0.05);
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.card:hover {
  border-color: var(--border-hover);
  box-shadow: 0 0 30px rgba(0, 200, 255, 0.08);
}

/* Dashboard grid */
.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 20px;
}

.metric-card {
  text-align: center;
  padding: 28px 20px;
  position: relative;
  overflow: hidden;
}

.metric-card .metric-icon { font-size: 28px; margin-bottom: 8px; }

.metric-card .metric-value {
  font-size: 42px; font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
  background: linear-gradient(135deg, var(--accent), var(--accent-purple));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
}

.metric-card .metric-label {
  font-size: 12px; color: var(--text-muted);
  text-transform: uppercase; letter-spacing: 1px; margin-top: 4px;
}

/* Risk overview */
.risk-bar-container {
  width: 100%; height: 32px; border-radius: 8px;
  overflow: hidden; display: flex; margin-bottom: 20px;
  background: var(--bg-card);
}

.risk-bar-segment {
  height: 100%; display: flex; align-items: center; justify-content: center;
  font-size: 11px; font-weight: 600; color: #fff;
  min-width: 30px; transition: width 0.6s ease;
}

.risk-cards { display: flex; gap: 12px; flex-wrap: wrap; }

.risk-card-mini {
  flex: 1; min-width: 100px;
  text-align: center; padding: 12px 16px;
  border-radius: 8px;
  background: var(--bg-card); border: 1px solid var(--border);
}

.risk-card-mini .rc-count {
  font-size: 28px; font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
}

.risk-card-mini .rc-label {
  font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
}

/* Donut chart */
.donut-container { display: flex; align-items: center; gap: 32px; margin-top: 24px; }

.donut {
  width: 140px; height: 140px; border-radius: 50%;
  position: relative; flex-shrink: 0;
}

.donut-hole {
  position: absolute; top: 50%; left: 50%;
  transform: translate(-50%, -50%);
  width: 80px; height: 80px; border-radius: 50%;
  background: var(--bg-card);
  display: flex; align-items: center; justify-content: center;
  font-size: 22px; font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
  color: var(--text);
}

.donut-legend { display: flex; flex-direction: column; gap: 6px; }

.donut-legend-item {
  display: flex; align-items: center; gap: 8px; font-size: 13px;
}

.donut-legend-dot {
  width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
}

/* Bar charts */
.bar-chart { display: flex; flex-direction: column; gap: 10px; }

.bar-row { display: flex; align-items: center; gap: 12px; }

.bar-label {
  width: 120px; text-align: right; font-size: 13px;
  font-family: 'JetBrains Mono', monospace;
  color: var(--text); flex-shrink: 0;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}

.bar-track {
  flex: 1; height: 28px; background: var(--bg-primary);
  border-radius: 6px; overflow: hidden; position: relative;
}

.bar-fill {
  height: 100%; border-radius: 6px;
  display: flex; align-items: center; padding-left: 10px;
  font-size: 12px; font-weight: 600; color: #fff;
  min-width: 36px; transition: width 0.6s ease;
}

.bar-count {
  width: 50px; text-align: left; font-size: 13px;
  font-family: 'JetBrains Mono', monospace;
  color: var(--text-muted); flex-shrink: 0;
}

/* Table */
.table-controls {
  display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center;
}

.table-controls input[type="text"] {
  flex: 1; min-width: 200px; padding: 10px 16px;
  background: var(--bg-primary); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text); font-size: 13px;
  outline: none; transition: border-color 0.2s;
}

.table-controls input[type="text"]:focus { border-color: var(--accent); }

.filter-btn {
  padding: 6px 14px; border-radius: 6px;
  border: 1px solid var(--border);
  background: transparent; color: var(--text-muted);
  font-size: 12px; cursor: pointer;
  transition: all 0.2s;
}

.filter-btn:hover, .filter-btn.active {
  border-color: var(--accent); color: var(--accent);
  background: var(--accent-dim);
}

table.assets-table {
  width: 100%; border-collapse: collapse; font-size: 13px;
}

table.assets-table thead th {
  text-align: left; padding: 12px 14px;
  background: var(--bg-card); color: var(--text-muted);
  font-weight: 600; font-size: 11px;
  text-transform: uppercase; letter-spacing: 0.5px;
  border-bottom: 1px solid var(--border);
  cursor: pointer; user-select: none;
  white-space: nowrap; position: relative;
}

table.assets-table thead th:hover { color: var(--accent); }

table.assets-table thead th .sort-arrow {
  margin-left: 4px; font-size: 10px; color: var(--accent); opacity: 0;
}

table.assets-table thead th.sorted .sort-arrow { opacity: 1; }

table.assets-table tbody tr {
  border-bottom: 1px solid rgba(0,200,255,0.04);
  transition: background 0.15s;
}

table.assets-table tbody tr:nth-child(even) { background: rgba(0,200,255,0.015); }

table.assets-table tbody tr:hover { background: var(--bg-card-hover); }

table.assets-table td { padding: 10px 14px; vertical-align: middle; }

.risk-dot {
  width: 10px; height: 10px; border-radius: 50%;
  display: inline-block;
}

.badge-new {
  display: inline-block; padding: 2px 8px;
  font-size: 10px; font-weight: 700;
  color: var(--accent); border: 1px solid var(--accent);
  border-radius: 4px; letter-spacing: 1px;
  animation: pulse-new 2s ease-in-out infinite;
}

@keyframes pulse-new {
  0%, 100% { box-shadow: 0 0 0 0 rgba(0,200,255,0.3); }
  50% { box-shadow: 0 0 8px 2px rgba(0,200,255,0.15); }
}

.pill {
  display: inline-block; padding: 2px 8px;
  font-size: 11px; border-radius: 4px;
  background: var(--accent-dim); color: var(--accent);
  margin: 1px 2px;
}

.port-badge {
  display: inline-block; padding: 1px 6px;
  font-size: 11px; border-radius: 3px;
  background: rgba(139,92,246,0.12); color: var(--accent-purple);
  font-family: 'JetBrains Mono', monospace;
  margin: 1px 2px;
}

.status-badge {
  display: inline-block; padding: 2px 8px;
  font-size: 12px; border-radius: 4px;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
}

.copy-btn {
  background: none; border: none; color: var(--text-muted);
  cursor: pointer; font-size: 12px; padding: 2px 4px;
  opacity: 0.5; transition: opacity 0.2s;
}

.copy-btn:hover { opacity: 1; color: var(--accent); }

.pagination {
  display: flex; gap: 6px; justify-content: center;
  margin-top: 16px; align-items: center;
}

.pagination button {
  padding: 6px 12px; border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-card); color: var(--text-muted);
  cursor: pointer; font-size: 12px;
  transition: all 0.2s;
}

.pagination button:hover, .pagination button.active {
  border-color: var(--accent); color: var(--accent); background: var(--accent-dim);
}

.pagination button:disabled { opacity: 0.3; cursor: not-allowed; }

.page-info { font-size: 12px; color: var(--text-muted); }

/* Tech landscape */
.tech-cloud {
  display: flex; flex-wrap: wrap; gap: 10px;
  padding: 8px 0;
}

.tech-pill {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 6px 14px; border-radius: 20px;
  border: 1px solid var(--border);
  background: var(--bg-card);
  font-size: 13px; color: var(--text);
  transition: all 0.2s;
}

.tech-pill:hover {
  border-color: var(--border-hover);
  background: var(--bg-card-hover);
}

.tech-pill .tech-count {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px; font-weight: 600;
  color: var(--accent);
}

/* Screenshots gallery */
.screenshots-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}

.screenshot-card {
  border-radius: 10px; overflow: hidden;
  border: 1px solid var(--border);
  background: var(--bg-card);
  cursor: pointer;
  transition: transform 0.2s, box-shadow 0.2s;
}

.screenshot-card:hover {
  transform: scale(1.02);
  box-shadow: 0 0 24px rgba(0,200,255,0.12);
}

.screenshot-card img {
  width: 100%; height: 180px;
  object-fit: cover; display: block;
  background: var(--bg-primary);
}

.screenshot-card .placeholder {
  width: 100%; height: 180px;
  display: flex; align-items: center; justify-content: center;
  background: var(--bg-primary); color: var(--text-dim);
  font-size: 12px;
}

.screenshot-card .ss-info {
  padding: 10px 14px;
  display: flex; justify-content: space-between; align-items: center;
}

.screenshot-card .ss-domain {
  font-size: 12px; font-family: 'JetBrains Mono', monospace;
  color: var(--text); white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis; max-width: 70%;
}

/* Lightbox */
.lightbox {
  display: none; position: fixed;
  top: 0; left: 0; width: 100%; height: 100%;
  background: rgba(0,0,0,0.9);
  z-index: 2000; cursor: pointer;
  align-items: center; justify-content: center;
}

.lightbox.show { display: flex; }

.lightbox img {
  max-width: 90%; max-height: 90%;
  border-radius: 8px;
  box-shadow: 0 0 40px rgba(0,200,255,0.2);
}

/* Vulnerability cards */
.vuln-card {
  padding: 18px 22px; margin-bottom: 12px;
  border-left: 3px solid var(--text-muted);
}

.vuln-card.sev-critical { border-left-color: var(--critical); }
.vuln-card.sev-high { border-left-color: var(--high); }
.vuln-card.sev-medium { border-left-color: var(--medium); }
.vuln-card.sev-low { border-left-color: var(--low); }
.vuln-card.sev-info { border-left-color: var(--info); }

.sev-badge {
  display: inline-block; padding: 2px 10px;
  font-size: 10px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 1px;
  border-radius: 4px; color: #fff;
}

.sev-badge.critical { background: var(--critical); }
.sev-badge.high { background: var(--high); }
.sev-badge.medium { background: var(--medium); }
.sev-badge.low { background: var(--low); }
.sev-badge.info { background: var(--info); }

.vuln-host {
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px; color: var(--accent); margin-top: 6px;
}

.vuln-url {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px; color: var(--text-muted);
  word-break: break-all; margin-top: 4px;
}

.vuln-summary {
  display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap;
}

/* Endpoints */
.collapsible-header {
  cursor: pointer; display: flex; align-items: center; gap: 8px;
  padding: 12px 0; user-select: none;
}

.collapsible-header .arrow {
  transition: transform 0.2s;
  font-size: 12px; color: var(--accent);
}

.collapsible-header.open .arrow { transform: rotate(90deg); }

.collapsible-body { display: none; }
.collapsible-body.open { display: block; }

.endpoint-list {
  max-height: 400px; overflow-y: auto;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px; line-height: 2;
  padding: 16px;
  background: var(--bg-primary);
  border-radius: 8px;
  border: 1px solid var(--border);
}

.endpoint-list .ep { color: var(--text); }
.endpoint-list .ep-path { color: var(--accent); }

/* Comparison */
.comparison-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 20px;
}

.comparison-col { padding: 20px; text-align: center; }

.comparison-col h4 {
  font-size: 14px; margin-bottom: 12px;
  text-transform: uppercase; letter-spacing: 1px;
}

.comparison-col.col-new h4 { color: var(--low); }
.comparison-col.col-removed h4 { color: var(--critical); }
.comparison-col.col-persistent h4 { color: var(--text-muted); }

.comparison-count {
  font-size: 36px; font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
  margin-bottom: 12px;
}

.comparison-col.col-new .comparison-count { color: var(--low); }
.comparison-col.col-removed .comparison-count { color: var(--critical); }
.comparison-col.col-persistent .comparison-count { color: var(--text-muted); }

.comparison-list {
  text-align: left; font-family: 'JetBrains Mono', monospace;
  font-size: 12px; line-height: 2;
  max-height: 200px; overflow-y: auto;
}

/* Methodology */
.pipeline {
  display: flex; gap: 0; align-items: center; flex-wrap: wrap;
  margin: 16px 0;
}

.phase-step {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 18px;
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 8px; font-size: 13px;
}

.phase-step.completed { border-color: var(--low); }
.phase-step.skipped { border-color: var(--text-dim); opacity: 0.5; }

.phase-connector {
  width: 24px; text-align: center;
  color: var(--text-dim); font-size: 14px;
}

/* Header meta */
.header-meta {
  display: flex; gap: 24px; flex-wrap: wrap;
  margin-top: 12px; font-size: 13px; color: var(--text-muted);
}

.header-meta span {
  display: inline-flex; align-items: center; gap: 6px;
}

.target-display {
  font-size: 20px; font-weight: 500;
  font-family: 'JetBrains Mono', monospace;
  color: var(--accent); margin-top: 4px;
}

/* Footer */
footer {
  text-align: center; padding: 32px 0;
  border-top: 1px solid var(--border);
  color: var(--text-muted); font-size: 12px;
  line-height: 1.8;
}

footer .brand-footer {
  font-family: 'JetBrains Mono', monospace;
  color: var(--accent); font-weight: 600;
}

/* Glow effects for critical items */
.glow-critical {
  box-shadow: 0 0 12px rgba(255,0,64,0.15);
}

.glow-high {
  box-shadow: 0 0 12px rgba(255,107,0,0.12);
}

/* Scrollbar styling */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--text-dim); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

/* Print styles */
@media print {
  nav.sidebar, .top-accent, .table-controls, .pagination,
  .copy-btn, .filter-btn, .lightbox { display: none !important; }

  main { margin-left: 0 !important; padding: 20px !important; }

  body { background: #fff !important; color: #1a1a1a !important; font-size: 11px; }

  .card, .metric-card, .vuln-card, .screenshot-card, .comparison-col,
  .phase-step, table.assets-table thead th {
    background: #fff !important;
    border-color: #ddd !important;
    color: #1a1a1a !important;
    box-shadow: none !important;
  }

  .metric-card .metric-value, h1, nav.sidebar .brand h2 {
    -webkit-text-fill-color: #1a1a1a !important;
    color: #1a1a1a !important;
  }

  table.assets-table td, table.assets-table th { padding: 6px 8px; }

  .collapsible-body { display: block !important; }

  .endpoint-list { max-height: none; }
}

@media (max-width: 1100px) {
  .dashboard-grid { grid-template-columns: repeat(2, 1fr); }
  .screenshots-grid { grid-template-columns: repeat(2, 1fr); }
  .comparison-grid { grid-template-columns: 1fr; }
}

@media (max-width: 768px) {
  nav.sidebar { display: none; }
  main { margin-left: 0; padding: 20px; }
  .dashboard-grid { grid-template-columns: 1fr; }
  .screenshots-grid { grid-template-columns: 1fr; }
}
"""


def generate_js() -> str:
    """Return all JavaScript for the report."""
    return """
(function() {
  'use strict';

  // --- Count-up animation ---
  const countUpObserver = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
      if (entry.isIntersecting) {
        const el = entry.target;
        const target = parseInt(el.getAttribute('data-target'), 10);
        if (isNaN(target)) return;
        const duration = 1200;
        const start = performance.now();
        function animate(now) {
          const elapsed = now - start;
          const progress = Math.min(elapsed / duration, 1);
          const eased = 1 - Math.pow(1 - progress, 3);
          el.textContent = Math.floor(eased * target).toLocaleString();
          if (progress < 1) requestAnimationFrame(animate);
          else el.textContent = target.toLocaleString();
        }
        requestAnimationFrame(animate);
        countUpObserver.unobserve(el);
      }
    });
  }, { threshold: 0.3 });

  document.querySelectorAll('.metric-value[data-target]').forEach(function(el) {
    countUpObserver.observe(el);
  });

  // --- Table search ---
  var searchInput = document.getElementById('asset-search');
  if (searchInput) {
    searchInput.addEventListener('input', function() {
      filterAndPaginate();
    });
  }

  // --- Risk filter buttons ---
  var filterBtns = document.querySelectorAll('.filter-btn[data-risk]');
  var activeFilters = new Set();

  filterBtns.forEach(function(btn) {
    btn.addEventListener('click', function() {
      var risk = btn.getAttribute('data-risk');
      if (risk === 'all') {
        activeFilters.clear();
        filterBtns.forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
      } else {
        document.querySelector('.filter-btn[data-risk="all"]')
          ?.classList.remove('active');
        if (activeFilters.has(risk)) {
          activeFilters.delete(risk);
          btn.classList.remove('active');
        } else {
          activeFilters.add(risk);
          btn.classList.add('active');
        }
        if (activeFilters.size === 0) {
          document.querySelector('.filter-btn[data-risk="all"]')
            ?.classList.add('active');
        }
      }
      filterAndPaginate();
    });
  });

  // --- Pagination ---
  var PAGE_SIZE = 50;
  var currentPage = 1;

  function getVisibleRows() {
    var table = document.getElementById('assets-table');
    if (!table) return [];
    var rows = Array.from(table.querySelectorAll('tbody tr'));
    var query = (searchInput ? searchInput.value.toLowerCase() : '');
    return rows.filter(function(row) {
      var text = row.textContent.toLowerCase();
      var matchSearch = !query || text.indexOf(query) !== -1;
      var risk = row.getAttribute('data-risk') || '';
      var matchRisk = activeFilters.size === 0 || activeFilters.has(risk);
      return matchSearch && matchRisk;
    });
  }

  function filterAndPaginate() {
    currentPage = 1;
    renderPage();
  }

  function renderPage() {
    var table = document.getElementById('assets-table');
    if (!table) return;
    var allRows = Array.from(table.querySelectorAll('tbody tr'));
    var visible = getVisibleRows();
    var totalPages = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
    if (currentPage > totalPages) currentPage = totalPages;

    allRows.forEach(function(r) { r.style.display = 'none'; });
    var startIdx = (currentPage - 1) * PAGE_SIZE;
    var endIdx = startIdx + PAGE_SIZE;
    visible.slice(startIdx, endIdx).forEach(function(r) { r.style.display = ''; });

    // Update pagination controls
    var pag = document.getElementById('pagination');
    if (pag) {
      if (visible.length <= PAGE_SIZE) {
        pag.style.display = 'none';
      } else {
        pag.style.display = 'flex';
        pag.innerHTML = '';
        var prevBtn = document.createElement('button');
        prevBtn.textContent = 'Prev';
        prevBtn.disabled = currentPage <= 1;
        prevBtn.onclick = function() { currentPage--; renderPage(); };
        pag.appendChild(prevBtn);

        var info = document.createElement('span');
        info.className = 'page-info';
        info.textContent = 'Page ' + currentPage + ' of ' + totalPages +
                           ' (' + visible.length + ' results)';
        pag.appendChild(info);

        var nextBtn = document.createElement('button');
        nextBtn.textContent = 'Next';
        nextBtn.disabled = currentPage >= totalPages;
        nextBtn.onclick = function() { currentPage++; renderPage(); };
        pag.appendChild(nextBtn);
      }
    }
  }

  // Initial pagination render
  renderPage();

  // --- Table sort ---
  document.querySelectorAll('#assets-table thead th[data-col]').forEach(function(th) {
    th.addEventListener('click', function() {
      var table = document.getElementById('assets-table');
      var tbody = table.querySelector('tbody');
      var col = th.getAttribute('data-col');
      var rows = Array.from(tbody.querySelectorAll('tr'));
      var asc = th.classList.contains('sorted-asc');

      table.querySelectorAll('thead th').forEach(function(h) {
        h.classList.remove('sorted', 'sorted-asc', 'sorted-desc');
        var arrow = h.querySelector('.sort-arrow');
        if (arrow) arrow.textContent = '';
      });

      th.classList.add('sorted');
      var arrow = th.querySelector('.sort-arrow');
      if (asc) {
        th.classList.add('sorted-desc');
        if (arrow) arrow.textContent = ' \\u25BC';
      } else {
        th.classList.add('sorted-asc');
        if (arrow) arrow.textContent = ' \\u25B2';
      }

      rows.sort(function(a, b) {
        var aVal = (a.getAttribute('data-' + col) || '').toLowerCase();
        var bVal = (b.getAttribute('data-' + col) || '').toLowerCase();
        var aNum = parseFloat(aVal);
        var bNum = parseFloat(bVal);
        if (!isNaN(aNum) && !isNaN(bNum)) {
          return asc ? bNum - aNum : aNum - bNum;
        }
        return asc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
      });

      rows.forEach(function(r) { tbody.appendChild(r); });
      filterAndPaginate();
    });
  });

  // --- Sidebar active section ---
  var sections = document.querySelectorAll('section[id]');
  var navLinks = document.querySelectorAll('nav.sidebar a[href^="#"]');

  function updateActiveLink() {
    var scrollPos = window.scrollY + 120;
    var current = '';
    sections.forEach(function(section) {
      if (section.offsetTop <= scrollPos) {
        current = section.id;
      }
    });
    navLinks.forEach(function(link) {
      link.classList.remove('active');
      if (link.getAttribute('href') === '#' + current) {
        link.classList.add('active');
      }
    });
  }

  window.addEventListener('scroll', updateActiveLink, { passive: true });
  updateActiveLink();

  // --- Screenshot lightbox ---
  var lightbox = document.getElementById('lightbox');
  var lightboxImg = lightbox ? lightbox.querySelector('img') : null;

  document.querySelectorAll('.screenshot-card[data-src]').forEach(function(card) {
    card.addEventListener('click', function() {
      var src = card.getAttribute('data-src');
      if (src && lightbox && lightboxImg) {
        lightboxImg.src = src;
        lightbox.classList.add('show');
      }
    });
  });

  if (lightbox) {
    lightbox.addEventListener('click', function() {
      lightbox.classList.remove('show');
    });
  }

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && lightbox) {
      lightbox.classList.remove('show');
    }
  });

  // --- Collapsible sections ---
  document.querySelectorAll('.collapsible-header').forEach(function(header) {
    header.addEventListener('click', function() {
      header.classList.toggle('open');
      var body = header.nextElementSibling;
      if (body) body.classList.toggle('open');
    });
  });

  // --- Copy to clipboard ---
  document.querySelectorAll('.copy-btn').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      var text = btn.getAttribute('data-copy');
      if (text && navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function() {
          var orig = btn.textContent;
          btn.textContent = '\\u2713';
          setTimeout(function() { btn.textContent = orig; }, 1200);
        });
      }
    });
  });

  // --- Endpoint search ---
  var epSearch = document.getElementById('endpoint-search');
  if (epSearch) {
    epSearch.addEventListener('input', function() {
      var q = epSearch.value.toLowerCase();
      document.querySelectorAll('.endpoint-list .ep').forEach(function(ep) {
        ep.style.display = ep.textContent.toLowerCase().indexOf(q) !== -1
          ? '' : 'none';
      });
    });
  }

})();
"""


def generate_sidebar(data: dict) -> str:
    """Generate sidebar navigation HTML."""
    meta = data.get("meta", {})
    sections = [
        ("header", "Overview"),
        ("dashboard", "Dashboard"),
        ("risk-overview", "Risk Overview"),
        ("sources", "Sources"),
        ("assets-section", "Attack Surface"),
        ("ports-section", "Ports"),
        ("tech-section", "Technologies"),
    ]
    if any(a.get("screenshot") for a in data.get("assets", [])):
        sections.append(("screenshots-section", "Screenshots"))
    if data.get("vulnerabilities"):
        sections.append(("vulns-section", "Vulnerabilities"))
    if data.get("endpoints"):
        sections.append(("endpoints-section", "Endpoints"))
    comp = data.get("comparison", {})
    if comp.get("new") or comp.get("removed") or comp.get("persistent"):
        sections.append(("comparison-section", "Comparison"))
    sections.append(("methodology-section", "Methodology"))

    links = ""
    for sid, label in sections:
        links += f'<a href="#{esc(sid)}">{esc(label)}</a>\n'

    return f"""
<nav class="sidebar">
  <div class="brand">
    <h2>ATTACKMAP</h2>
    <span>HAAK Cybersecurity</span>
  </div>
  {links}
</nav>
"""


def generate_header(data: dict) -> str:
    """Generate header section HTML."""
    meta = data.get("meta", {})
    target = esc(meta.get("target", "N/A"))
    date = esc(meta.get("date", "N/A"))
    duration = meta.get("duration_seconds", 0)
    mins = duration // 60
    secs = duration % 60
    duration_str = f"{mins}m {secs}s" if mins else f"{secs}s"
    profile = esc(meta.get("profile", "N/A"))
    version = esc(meta.get("version", ""))

    return f"""
<section id="header">
  <h1>Attack Surface Report</h1>
  <div class="target-display">{target}</div>
  <div class="header-meta">
    <span>&#128197; {date}</span>
    <span>&#9201; {duration_str}</span>
    <span>&#9881; Profile: {profile}</span>
    <span>v{version}</span>
  </div>
</section>
"""


def generate_dashboard(data: dict) -> str:
    """Generate executive dashboard section."""
    stats = data.get("stats", {})
    metrics = [
        ("&#127760;", stats.get("subdomains_unique", stats.get("subdomains_total", 0)), "Total Assets"),
        ("&#9889;", stats.get("hosts_live", 0), "Live Hosts"),
        ("&#128268;", stats.get("ports_open", 0), "Open Ports"),
        ("&#9888;", stats.get("vulns_found", 0), "Vulnerabilities"),
        ("&#128736;", stats.get("tech_count", 0), "Technologies"),
        ("&#128279;", stats.get("endpoints_found", 0), "Endpoints"),
    ]

    cards = ""
    for icon, value, label in metrics:
        cards += f"""
<div class="card metric-card">
  <div class="metric-icon">{icon}</div>
  <div class="metric-value" data-target="{int(value)}">0</div>
  <div class="metric-label">{esc(label)}</div>
</div>
"""

    return f"""
<section id="dashboard">
  <h2 class="section-title"><span class="icon">&#128202;</span>Executive Dashboard</h2>
  <div class="dashboard-grid">
    {cards}
  </div>
</section>
"""


def generate_risk_overview(data: dict) -> str:
    """Generate risk overview section with stacked bar and donut chart."""
    assets = data.get("assets", [])
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for a in assets:
        risk = (a.get("risk") or "info").lower()
        if risk in counts:
            counts[risk] += 1
        else:
            counts["info"] += 1

    total = sum(counts.values()) or 1
    colors = {"critical": "var(--critical)", "high": "var(--high)",
              "medium": "var(--medium)", "low": "var(--low)", "info": "var(--info)"}
    raw_colors = {"critical": "#ff0040", "high": "#ff6b00",
                  "medium": "#ffaa00", "low": "#22c55e", "info": "#3b82f6"}

    # Stacked bar segments
    bar_segments = ""
    for level in ["critical", "high", "medium", "low", "info"]:
        count = counts[level]
        if count == 0:
            continue
        pct = round(count / total * 100, 1)
        bar_segments += (
            f'<div class="risk-bar-segment" '
            f'style="width:{pct}%;background:{colors[level]}">'
            f'{pct}%</div>\n'
        )

    # Mini risk cards
    risk_cards = ""
    for level in ["critical", "high", "medium", "low", "info"]:
        risk_cards += f"""
<div class="risk-card-mini">
  <div class="rc-count" style="color:{colors[level]}">{counts[level]}</div>
  <div class="rc-label" style="color:{colors[level]}">{level.capitalize()}</div>
</div>
"""

    # Donut chart via conic-gradient
    gradient_parts = []
    offset = 0
    for level in ["critical", "high", "medium", "low", "info"]:
        count = counts[level]
        pct = count / total * 100
        gradient_parts.append(f"{raw_colors[level]} {offset}deg {offset + pct * 3.6}deg")
        offset += pct * 3.6

    conic = ", ".join(gradient_parts) if gradient_parts else "#334155 0deg 360deg"

    legend = ""
    for level in ["critical", "high", "medium", "low", "info"]:
        legend += f"""
<div class="donut-legend-item">
  <div class="donut-legend-dot" style="background:{raw_colors[level]}"></div>
  <span>{level.capitalize()}: {counts[level]}</span>
</div>
"""

    return f"""
<section id="risk-overview">
  <h2 class="section-title"><span class="icon">&#128737;</span>Risk Overview</h2>
  <div class="card">
    <div class="risk-bar-container">{bar_segments}</div>
    <div class="risk-cards">{risk_cards}</div>
    <div class="donut-container">
      <div class="donut" style="background:conic-gradient({conic})">
        <div class="donut-hole">{sum(counts.values())}</div>
      </div>
      <div class="donut-legend">{legend}</div>
    </div>
  </div>
</section>
"""


def generate_sources(data: dict) -> str:
    """Generate sources breakdown bar chart."""
    sources = data.get("sources", {})
    if not sources:
        return ""

    sorted_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)
    max_val = max(v for _, v in sorted_sources) if sorted_sources else 1

    bars = ""
    for i, (name, count) in enumerate(sorted_sources):
        pct = round(count / max_val * 100)
        hue = 190 + i * 15  # cyan to blue range
        bars += f"""
<div class="bar-row">
  <div class="bar-label">{esc(name)}</div>
  <div class="bar-track">
    <div class="bar-fill" style="width:{pct}%;background:hsl({hue},80%,50%)">{count}</div>
  </div>
</div>
"""

    return f"""
<section id="sources">
  <h2 class="section-title"><span class="icon">&#128270;</span>Sources Breakdown</h2>
  <div class="card">
    <div class="bar-chart">{bars}</div>
  </div>
</section>
"""


def generate_assets_table(data: dict) -> str:
    """Generate the main attack surface table with search, sort, filter, pagination."""
    assets = data.get("assets", [])
    if not assets:
        return f"""
<section id="assets-section">
  <h2 class="section-title"><span class="icon">&#127919;</span>Attack Surface</h2>
  <div class="card"><p style="color:var(--text-muted)">No assets discovered.</p></div>
</section>
"""

    filters_html = """
<button class="filter-btn active" data-risk="all">All</button>
<button class="filter-btn" data-risk="critical">Critical</button>
<button class="filter-btn" data-risk="high">High</button>
<button class="filter-btn" data-risk="medium">Medium</button>
<button class="filter-btn" data-risk="low">Low</button>
<button class="filter-btn" data-risk="info">Info</button>
"""

    rows = ""
    for a in assets:
        risk = (a.get("risk") or "info").lower()
        subdomain = esc(a.get("subdomain", ""))
        ip = esc(a.get("ip", ""))
        sc = a.get("status_code", "")
        title = esc(a.get("title", ""))
        ports = a.get("ports", [])
        techs = a.get("technologies", [])
        is_new = a.get("is_new", False)

        risk_color = classify_risk_color(risk)
        sc_color = status_color(sc)

        ports_html = " ".join(f'<span class="port-badge">{esc(str(p))}</span>' for p in ports)
        techs_html = " ".join(f'<span class="pill">{esc(str(t))}</span>' for t in techs)
        new_html = '<span class="badge-new">NEW</span>' if is_new else ''

        status_html = ""
        if sc:
            status_html = f'<span class="status-badge" style="color:{sc_color}">{esc(str(sc))}</span>'

        ports_count = len(ports)

        rows += f"""
<tr data-risk="{esc(risk)}"
    data-subdomain="{esc(a.get('subdomain',''))}"
    data-ip="{esc(a.get('ip',''))}"
    data-status="{esc(str(sc))}"
    data-ports="{ports_count}"
    data-title="{esc(a.get('title',''))}">
  <td><span class="risk-dot" style="background:{risk_color}" title="{esc(risk.capitalize())}"></span></td>
  <td>
    {subdomain}
    <button class="copy-btn" data-copy="{esc(a.get('subdomain',''))}" title="Copy">&#128203;</button>
  </td>
  <td style="font-family:'JetBrains Mono',monospace;font-size:12px">{ip}</td>
  <td>{status_html}</td>
  <td>{ports_html}</td>
  <td>{title}</td>
  <td>{techs_html}</td>
  <td>{new_html}</td>
</tr>
"""

    return f"""
<section id="assets-section">
  <h2 class="section-title"><span class="icon">&#127919;</span>Attack Surface ({len(assets)} assets)</h2>
  <div class="card" style="padding:16px">
    <div class="table-controls">
      <input type="text" id="asset-search" placeholder="Search subdomains, IPs, technologies...">
      {filters_html}
    </div>
    <div style="overflow-x:auto">
      <table class="assets-table" id="assets-table">
        <thead>
          <tr>
            <th data-col="risk" style="width:40px">Risk<span class="sort-arrow"></span></th>
            <th data-col="subdomain">Subdomain<span class="sort-arrow"></span></th>
            <th data-col="ip">IP<span class="sort-arrow"></span></th>
            <th data-col="status">Status<span class="sort-arrow"></span></th>
            <th data-col="ports">Ports<span class="sort-arrow"></span></th>
            <th data-col="title">Title<span class="sort-arrow"></span></th>
            <th>Technologies</th>
            <th style="width:60px">New</th>
          </tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </div>
    <div id="pagination" class="pagination"></div>
  </div>
</section>
"""


def generate_ports(data: dict) -> str:
    """Generate port analysis bar chart."""
    ports = data.get("ports_summary", {})
    if not ports:
        return ""

    sorted_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:15]
    max_val = max(v for _, v in sorted_ports) if sorted_ports else 1

    bars = ""
    for i, (port, count) in enumerate(sorted_ports):
        pct = round(count / max_val * 100)
        # gradient from cyan (190) to purple (270)
        hue = 190 + int(i / max(len(sorted_ports) - 1, 1) * 80)
        bars += f"""
<div class="bar-row">
  <div class="bar-label">Port {esc(str(port))}</div>
  <div class="bar-track">
    <div class="bar-fill" style="width:{pct}%;background:hsl({hue},70%,55%)">{count}</div>
  </div>
</div>
"""

    return f"""
<section id="ports-section">
  <h2 class="section-title"><span class="icon">&#128268;</span>Port Analysis</h2>
  <div class="card">
    <div class="bar-chart">{bars}</div>
  </div>
</section>
"""


def generate_tech(data: dict) -> str:
    """Generate technology landscape as tag cloud."""
    techs = data.get("technologies", {})
    if not techs:
        return ""

    sorted_techs = sorted(techs.items(), key=lambda x: x[1], reverse=True)
    max_count = max(v for _, v in sorted_techs) if sorted_techs else 1

    pills = ""
    for name, count in sorted_techs:
        # Scale font size based on frequency
        scale = 0.85 + 0.5 * (count / max_count)
        pills += (
            f'<div class="tech-pill" style="font-size:{scale:.2f}em">'
            f'{esc(name)} <span class="tech-count">{count}</span></div>\n'
        )

    return f"""
<section id="tech-section">
  <h2 class="section-title"><span class="icon">&#128736;</span>Technology Landscape</h2>
  <div class="card">
    <div class="tech-cloud">{pills}</div>
  </div>
</section>
"""


def generate_screenshots(data: dict, json_dir: Path) -> str:
    """Generate screenshots gallery section."""
    assets = data.get("assets", [])
    assets_with_ss = [a for a in assets if a.get("screenshot")]
    if not assets_with_ss:
        return ""

    cards = ""
    for a in assets_with_ss:
        ss_path = a.get("screenshot", "")
        b64 = embed_screenshot(ss_path, json_dir)
        subdomain = esc(a.get("subdomain", ""))
        sc = a.get("status_code", "")
        sc_color = status_color(sc)

        if b64:
            img_html = f'<img src="{b64}" alt="{subdomain}" loading="lazy">'
            data_src = b64
        else:
            img_html = '<div class="placeholder">No screenshot available</div>'
            data_src = ""

        status_html = ""
        if sc:
            status_html = f'<span class="status-badge" style="color:{sc_color};font-size:11px">{esc(str(sc))}</span>'

        cards += f"""
<div class="screenshot-card" data-src="{data_src}">
  {img_html}
  <div class="ss-info">
    <span class="ss-domain">{subdomain}</span>
    {status_html}
  </div>
</div>
"""

    return f"""
<section id="screenshots-section">
  <h2 class="section-title"><span class="icon">&#128248;</span>Screenshots Gallery</h2>
  <div class="screenshots-grid">{cards}</div>
</section>
<div class="lightbox" id="lightbox"><img src="" alt="Screenshot"></div>
"""


def generate_vulns(data: dict) -> str:
    """Generate vulnerabilities section grouped by severity."""
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return ""

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_vulns = sorted(vulns, key=lambda v: severity_order.get(
        (v.get("severity") or "info").lower(), 5))

    sev_counts = {}
    for v in vulns:
        s = (v.get("severity") or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    summary_html = ""
    for level in ["critical", "high", "medium", "low", "info"]:
        if level in sev_counts:
            summary_html += (
                f'<div class="risk-card-mini" style="min-width:80px">'
                f'<div class="rc-count" style="color:{classify_risk_color(level)}">'
                f'{sev_counts[level]}</div>'
                f'<div class="rc-label" style="color:{classify_risk_color(level)}">'
                f'{level.capitalize()}</div></div>\n'
            )

    vuln_cards = ""
    for v in sorted_vulns:
        sev = (v.get("severity") or "info").lower()
        name = esc(v.get("name", v.get("template", "Unknown")))
        host_val = esc(v.get("host", ""))
        url = esc(v.get("url", v.get("matched_at", "")))
        glow = "glow-critical" if sev == "critical" else ("glow-high" if sev == "high" else "")

        vuln_cards += f"""
<div class="card vuln-card sev-{esc(sev)} {glow}">
  <div><span class="sev-badge {esc(sev)}">{esc(sev.upper())}</span></div>
  <div style="font-weight:600;margin-top:8px;font-size:15px">{name}</div>
  <div class="vuln-host">{host_val}</div>
  <div class="vuln-url">{url}</div>
</div>
"""

    return f"""
<section id="vulns-section">
  <h2 class="section-title"><span class="icon">&#9888;</span>Vulnerabilities ({len(vulns)})</h2>
  <div class="vuln-summary">{summary_html}</div>
  {vuln_cards}
</section>
"""


def generate_endpoints(data: dict) -> str:
    """Generate endpoints section, collapsible if large."""
    endpoints = data.get("endpoints", [])
    if not endpoints:
        return ""

    # Group by base path
    grouped: dict[str, list[str]] = {}
    for ep in endpoints:
        ep_str = str(ep)
        try:
            # Extract base: scheme + host
            parts = ep_str.split("/")
            if len(parts) >= 3:
                base = "/".join(parts[:3])
            else:
                base = "Other"
        except Exception:
            base = "Other"
        grouped.setdefault(base, []).append(ep_str)

    ep_list = ""
    for ep in sorted(endpoints, key=str):
        ep_list += f'<div class="ep">{esc(str(ep))}</div>\n'

    is_large = len(endpoints) > 100
    open_class = "" if is_large else "open"

    return f"""
<section id="endpoints-section">
  <h2 class="section-title"><span class="icon">&#128279;</span>Endpoints Discovered ({len(endpoints)})</h2>
  <div class="card">
    <div class="collapsible-header {open_class}">
      <span class="arrow">&#9654;</span>
      <span>{len(endpoints)} endpoints {'(click to expand)' if is_large else ''}</span>
    </div>
    <div class="collapsible-body {open_class}">
      <input type="text" id="endpoint-search"
             placeholder="Search endpoints..."
             style="width:100%;padding:8px 14px;margin-bottom:12px;
                    background:var(--bg-card);border:1px solid var(--border);
                    border-radius:6px;color:var(--text);font-size:13px;outline:none">
      <div class="endpoint-list">{ep_list}</div>
    </div>
  </div>
</section>
"""


def generate_comparison(data: dict) -> str:
    """Generate scan comparison section."""
    comp = data.get("comparison", {})
    new = comp.get("new", [])
    removed = comp.get("removed", [])
    persistent = comp.get("persistent", [])

    if not new and not removed and not persistent:
        return ""

    def make_list(items: list) -> str:
        return "\n".join(f'<div>{esc(str(i))}</div>' for i in items) or "<div>None</div>"

    return f"""
<section id="comparison-section">
  <h2 class="section-title"><span class="icon">&#128260;</span>Scan Comparison</h2>
  <div class="comparison-grid">
    <div class="card comparison-col col-new">
      <h4>+ New</h4>
      <div class="comparison-count">{len(new)}</div>
      <div class="comparison-list">{make_list(new)}</div>
    </div>
    <div class="card comparison-col col-removed">
      <h4>- Removed</h4>
      <div class="comparison-count">{len(removed)}</div>
      <div class="comparison-list">{make_list(removed)}</div>
    </div>
    <div class="card comparison-col col-persistent">
      <h4>= Persistent</h4>
      <div class="comparison-count">{len(persistent)}</div>
      <div class="comparison-list">{make_list(persistent)}</div>
    </div>
  </div>
</section>
"""


def generate_methodology(data: dict) -> str:
    """Generate methodology timeline section."""
    meta = data.get("meta", {})
    phases_completed = meta.get("phases_completed", [])

    all_phases = [
        ("subdomains", "&#128270;", "Subdomains"),
        ("dns", "&#127760;", "DNS Resolution"),
        ("ports", "&#128268;", "Port Scanning"),
        ("http", "&#127758;", "HTTP Probing"),
        ("screenshots", "&#128248;", "Screenshots"),
        ("crawl", "&#128375;", "Crawling"),
        ("vulns", "&#9888;", "Vuln Scanning"),
    ]

    steps = ""
    for i, (phase_id, icon, name) in enumerate(all_phases):
        completed = phase_id in phases_completed
        cls = "completed" if completed else "skipped"
        status_text = "Done" if completed else "Skipped"
        status_color_val = "var(--low)" if completed else "var(--text-dim)"
        steps += f"""
<div class="phase-step {cls}">
  <span>{icon}</span>
  <span>{esc(name)}</span>
  <span style="font-size:11px;color:{status_color_val};margin-left:4px">{status_text}</span>
</div>
"""
        if i < len(all_phases) - 1:
            steps += '<div class="phase-connector">&#8594;</div>'

    sources = data.get("sources", {})
    tools_used = ", ".join(sorted(sources.keys())) if sources else "N/A"

    return f"""
<section id="methodology-section">
  <h2 class="section-title"><span class="icon">&#128736;</span>Methodology</h2>
  <div class="card">
    <div class="pipeline">{steps}</div>
    <div style="margin-top:20px;font-size:13px;color:var(--text-muted)">
      <strong style="color:var(--text)">Tools used:</strong> {esc(tools_used)}<br>
      <strong style="color:var(--text)">Profile:</strong> {esc(meta.get('profile', 'N/A'))}<br>
      <strong style="color:var(--text)">Duration:</strong> {meta.get('duration_seconds', 0)}s
    </div>
  </div>
</section>
"""


def generate_footer(data: dict) -> str:
    """Generate footer section."""
    meta = data.get("meta", {})
    version = esc(meta.get("version", "2.0"))
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""
<footer>
  <div class="brand-footer">Generated by AttackMap v{version} &mdash; HAAK Cybersecurity Consulting</div>
  <div>Adrian Martinez &bull; {now}</div>
  <div style="margin-top:12px;font-size:11px;color:var(--text-dim);max-width:600px;margin-left:auto;margin-right:auto">
    This report was generated as part of an authorized security assessment.
    Unauthorized access to computer systems is illegal. All testing was
    performed with explicit written authorization.
  </div>
</footer>
"""


def generate_report(data: dict, json_dir: Path) -> str:
    """Assemble the complete HTML report."""
    meta = data.get("meta", {})
    target = esc(meta.get("target", "AttackMap Report"))

    css = generate_css()
    js = generate_js()
    sidebar = generate_sidebar(data)
    header_html = generate_header(data)
    dashboard = generate_dashboard(data)
    risk = generate_risk_overview(data)
    sources = generate_sources(data)
    assets = generate_assets_table(data)
    ports = generate_ports(data)
    tech = generate_tech(data)
    screenshots = generate_screenshots(data, json_dir)
    vulns = generate_vulns(data)
    endpoints = generate_endpoints(data)
    comparison = generate_comparison(data)
    methodology = generate_methodology(data)
    footer_html = generate_footer(data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AttackMap Report &mdash; {target}</title>
<style>{css}</style>
</head>
<body>
<div class="top-accent"></div>
{sidebar}
<main>
{header_html}
{dashboard}
{risk}
{sources}
{assets}
{ports}
{tech}
{screenshots}
{vulns}
{endpoints}
{comparison}
{methodology}
{footer_html}
</main>
<script>{js}</script>
</body>
</html>
"""


def main():
    """CLI entry point."""
    if len(sys.argv) < 3:
        print("Usage: python3 attackmap_report.py <scan_data.json> <output.html>",
              file=sys.stderr)
        sys.exit(1)

    json_path = sys.argv[1]
    output_path = sys.argv[2]

    data = load_data(json_path)
    json_dir = Path(json_path).resolve().parent

    report_html = generate_report(data, json_dir)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report_html, encoding="utf-8")

    stats = data.get("stats", {})
    print(f"[+] AttackMap report generated: {out}")
    print(f"    Target: {data.get('meta', {}).get('target', 'N/A')}")
    print(f"    Assets: {len(data.get('assets', []))}")
    print(f"    Vulns:  {stats.get('vulns_found', len(data.get('vulnerabilities', [])))}")
    print(f"    Size:   {out.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
