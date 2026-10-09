# AttackMap

```
 █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗███╗   ███╗ █████╗ ██████╗
██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝████╗ ████║██╔══██╗██╔══██╗
███████║   ██║      ██║   ███████║██║     █████╔╝ ██╔████╔██║███████║██████╔╝
██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ ██║╚██╔╝██║██╔══██║██╔═══╝
██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗██║ ╚═╝ ██║██║  ██║██║
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝

  Attack Surface Reconnaissance Tool
  By Adrian Martinez | HAAK Cybersecurity
```

**Attack surface reconnaissance tool for pentesters and security teams.**

AttackMap combines multiple subdomain enumeration sources, DNS resolution, port scanning, HTTP probing, screenshotting, crawling, and vulnerability detection into a single automated pipeline. Available as a CLI tool and a web application.

---

## Features

- **Multi-source subdomain enumeration** — Subfinder, Amass, Assetfinder, crt.sh, GAU, Waybackurls
- **DNS resolution** with dnsx (filters dead hosts before probing)
- **Port scanning** with naabu (top 1000 ports)
- **HTTP probing** with httpx (status codes, titles, tech detection, IPs)
- **Screenshots** with gowitness (visual recon)
- **Crawling** with katana (endpoint and JS discovery)
- **Vulnerability detection** with nuclei (exposures, misconfigurations)
- **Risk classification** — automatic categorization (critical/high/medium/low/info)
- **Scan comparison** — detect new and removed subdomains between scans
- **HTML report** — professional dark-themed report with interactive tables, charts, and screenshots
- **Web interface** — browser-based dashboard for managing scans with real-time progress
- **Parallel execution** — all enumeration sources run concurrently
- **Smart filtering** — removes CDN IPs, wildcards, and junk results

---

## Quick Start

### Requirements

- Linux or macOS
- Python 3.10+
- At least one enumeration tool: `subfinder`, `amass`, or `assetfinder`
- `curl` and `jq` (for crt.sh)

### Install

```bash
git clone https://github.com/Bl4ckSkul1/AttackMap.git
cd AttackMap
chmod +x atackmap.sh
```

### Install recon tools

```bash
# Required
sudo apt install curl jq

# Subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/tomnomnom/assetfinder@latest

# DNS & HTTP
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Full mode
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sensepost/gowitness@latest

# Historical URLs
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest

# Web interface
pip install flask
```

---

## Usage: CLI

### Basic scan

```bash
./atackmap.sh -d example.com
```

### Quick scan (subfinder + crt.sh only)

```bash
./atackmap.sh -d example.com --quick
```

### Full attack surface scan (ports + screenshots + nuclei)

```bash
./atackmap.sh -d example.com --full
```

### Full scan without nuclei

```bash
./atackmap.sh -d example.com --full --no-nuclei
```

### Compare with previous scan

```bash
./atackmap.sh -d example.com -f resultados/example.com/example.com_2026-10-01.txt
```

### Scan a list of domains

```bash
./atackmap.sh -L domains.txt --full -t 100
```

### DNS resolution only (no HTTP probing)

```bash
./atackmap.sh -d example.com --resolve-only
```

### All options

```
./atackmap.sh [options]

TARGET:
  -d DOMAIN           Target domain
  -L FILE             File with list of domains (one per line)

SCAN PROFILE:
  --quick             Fast: subfinder + crt.sh only
  --full              Complete: + ports + screenshots + crawl + nuclei
  --resolve-only      DNS resolution only, no HTTP probing
  --no-nuclei         Skip nuclei scanning (use with --full)

OPTIONS:
  -f FILE             Previous scan file for comparison
  -o DIR              Output directory (default: resultados/)
  -t THREADS          Threads for httpx/naabu (default: 50)
  -h                  Show help
```

---

## Usage: Web Interface

```bash
# Start the web server
python3 attackmap_web.py

# Custom port
python3 attackmap_web.py --port 8888

# Localhost only (no network access)
python3 attackmap_web.py --host 127.0.0.1
```

Open `http://localhost:5000` in your browser.

### Web Features

- **Dashboard** with scan history and stats
- **New Scan** form with profile selection and advanced options
- **Real-time progress** with live terminal output and phase pipeline
- **Report viewer** — open HTML reports directly in the browser
- **Multiple concurrent scans** supported
- **Scan persistence** — survives server restarts

---

## Scan Phases

```
Phase 0: Subdomain Enumeration  → subfinder, amass, assetfinder, crt.sh, gau, waybackurls
Phase 1: Merge & Filter         → deduplicate, remove CDN/junk, scope validation
Phase 2: DNS Resolution         → dnsx (filter non-resolving hosts)
Phase 3: Port Scanning          → naabu (top 1000 ports)           [--full only]
Phase 4: HTTP Probing           → httpx (status, title, tech, IP)
Phase 5: Screenshots            → gowitness                       [--full only]
Phase 6: Crawling               → katana (endpoints, JS analysis) [--full only]
Phase 7: Vulnerability Scan     → nuclei (exposures, misconfig)   [--full only]
Phase 8: Report                 → HTML report with charts and interactive tables
```

---

## HTML Report

The report includes:

- **Executive Dashboard** — 6 metric cards with animated counters
- **Risk Overview** — stacked bar chart + donut chart by risk level
- **Sources Breakdown** — bar chart showing results per enumeration tool
- **Attack Surface Table** — searchable, sortable, filterable with pagination
- **Port Analysis** — top 15 ports visualized
- **Technology Landscape** — tag cloud sized by frequency
- **Screenshots Gallery** — grid with lightbox viewer
- **Vulnerabilities** — grouped by severity with colored cards
- **Endpoints** — collapsible list of discovered URLs
- **Scan Comparison** — new vs removed vs persistent subdomains
- **Methodology** — pipeline showing completed phases and tools used

---

## Output Structure

```
resultados/
└── example.com/
    ├── example.com_2026-10-09.txt              # All unique subdomains
    ├── example.com_2026-10-09_resueltos.txt    # DNS-resolved subdomains
    ├── example.com_2026-10-09_vivos.txt        # HTTP-live hosts
    ├── example.com_2026-10-09_httpx.jsonl      # Full httpx output
    ├── example.com_2026-10-09_ports.txt        # Open ports (naabu)
    ├── example.com_2026-10-09_endpoints.txt    # Discovered endpoints
    ├── example.com_2026-10-09_nuclei.jsonl     # Nuclei findings
    ├── scan_data.json                          # Structured scan data
    ├── report_example.com_2026-10-09.html      # HTML report
    ├── screenshots/                            # gowitness screenshots
    ├── nuevos_subdominios_example.com.txt       # New (if -f used)
    └── subdominios_inactivos_example.com.txt   # Removed (if -f used)
```

---

## Risk Classification

Subdomains are automatically classified by risk based on hostname patterns:

| Risk | Keywords |
|------|----------|
| **Critical** | admin, panel, dashboard, console, phpmyadmin, cpanel, webmail |
| **High** | dev, staging, test, uat, qa, debug, internal |
| **Medium** | api, gateway, auth, login, sso, vpn, ftp |
| **Low** | www, cdn, static, assets, blog, docs |
| **Info** | Everything else |

---

## Stats

| Component | Count |
|-----------|-------|
| Enumeration sources | 6 |
| Recon phases | 8 |
| Risk levels | 5 |
| Tools supported | 12 |

---

## Author

**Adrian Martinez** — Pentester & COO at HAAK Cybersecurity Consulting

- me@adrianmartinez.lat
- [@adrian.offsec](https://instagram.com/adrian.offsec)
- [@haakconsulting](https://instagram.com/haakconsulting)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is for **authorized security testing only**. Only use against systems where you have explicit written permission. Unauthorized use may be illegal. The authors are not responsible for misuse of this tool.
