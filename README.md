# SentinelWeb

![SentinelWeb v1.0.0](https://img.shields.io/badge/SentinelWeb-v1.0.0-blue) ![Python 3.7+](https://img.shields.io/badge/Python-3.7+-green) ![MIT License](https://img.shields.io/badge/License-MIT-yellow)

<p align="center">
  <img src="assets/sentinel_hero.png" alt="SentinelWeb hero" width="720"/>
</p>

SentinelWeb is an orchestration framework that runs industry-standard web security tools (Nikto, Nmap, testssl.sh, SSLyze, WhatWeb, wafw00f, Gobuster) to produce concise, actionable scan reports. This README is a showcase-style, visual guide with a focused CLI reference for easy adoption.

---

## Table of contents

- Features
- Screenshots
- Installation
- Quick start
- CLI reference
- Output & reports
- Configuration
- Best practices & legal
- Contributing
- License

---

## Features

- Orchestrates multiple scanners (Nikto, Nmap, testssl.sh, SSLyze, WhatWeb, wafw00f, Gobuster)
- SSL/TLS analysis: certificate checks, protocol and cipher enumeration
- HTTP security headers & cookie flag validation (HSTS, CSP, X-Frame-Options, Secure/HttpOnly/SameSite)
- WAF detection and technology fingerprinting
- Directory and file enumeration
- Concurrent scanning with configurable thread count
- JSON and plain-text per-scan reports
- Colorized, human-friendly terminal summaries

---

## Screenshots

Visuals demonstrate expected output and report samples. Replace placeholders with actual PNGs in assets/ (recommended 1280×720 or 2:1 aspect).

- Dashboard / summary
  <p align="center">
    <img src="assets/sentinel_summary.png" alt="Scan summary" width="900"/>
  </p>

- Detailed JSON report preview
  <p align="center">
    <img src="assets/sentinel_report_preview.png" alt="Report JSON preview" width="900"/>
  </p>

- Directory enumeration / Gobuster output
  <p align="center">
    <img src="assets/sentinel_gobuster.png" alt="Directory enumeration" width="900"/>
  </p>

Notes:
- Filenames above are examples — commit your screenshots to assets/ and keep names consistent.
- Use PNGs for lossless clarity in README.

---

## Installation

Prerequisites:
- Python 3.7+
- Linux/Unix recommended
- Root/sudo for certain scans
- External tools: nikto, nmap, whatweb, testssl.sh, gobuster

Install Python deps:
```bash
pip install -r requirements.txt
```

Install core utilities (Debian/Ubuntu example):
```bash
sudo apt-get update
sudo apt-get install -y nikto nmap whatweb gobuster
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh
sudo ln -s "$PWD/testssl.sh" /usr/local/bin/testssl
```

Optional Python packages (if not in requirements.txt):
```bash
pip install colorama requests urllib3 sslyze wafw00f
```

---

## Quick start

Full scan:
```bash
python3 web_scanner.py https://example.com
```

Quick scan (headers, cookies, SSL):
```bash
python3 web_scanner.py https://example.com --quick
```

SSL/TLS only:
```bash
python3 web_scanner.py example.com --ssl-only
```

Custom port and output:
```bash
python3 web_scanner.py example.com -p 8443 -o my_scan_results
```

Increase concurrency:
```bash
python3 web_scanner.py example.com -t 10
```

---

## CLI reference

Important flags (short + long form):

- -u, --url <target>
  - Target URL or hostname (required)
- -p, --port <port>
  - Target port (default: 80/443 inferred)
- -o, --output <dir>
  - Output directory for reports (default: ./results/<timestamp>)
- -t, --threads <n>
  - Number of concurrent worker threads (default: 4)
- --quick
  - Run a low-impact quick scan (headers, cookies, basic SSL checks)
- --ssl-only
  - Run only SSL/TLS checks (testssl.sh / SSLyze)
- --no-nikto
  - Skip Nikto scan (useful to reduce noise)
- --no-enum
  - Skip directory/file enumeration
- --timeout <seconds>
  - Per-request timeout for external tools
- --verbose / -v
  - Verbose output for debugging
- --json
  - Produce JSON report in addition to plain text
- --config <file>
  - Path to config file (override defaults)
- --help / -h
  - Show help and CLI options

Example: quick SSL scan, save JSON:
```bash
python3 web_scanner.py https://example.com --ssl-only --json -o results/example_ssl
```

(If your project has additional options, I can expand this reference into a full auto-generated manpage or include --examples for each tool.)

---

## Output & reports

- JSON: machine-readable report with sections for issues, headers, SSL findings, WAF detection, and enumeration results.
- Plain-text: human-readable summary and per-check logs.
- Terminal: color-coded risk levels (INFO / LOW / MEDIUM / HIGH).

Example report layout (JSON keys):
```json
{
  "target": "https://example.com",
  "timestamp": "2026-08-16T12:34:56Z",
  "summary": { "high": 1, "medium": 3, "low": 5 },
  "ssl": { "expired": false, "ciphers": [...] },
  "headers": { "hsts": true, "csp": null },
  "vulnerabilities": [ ... ],
  "enumeration": { "dirs_found": [...], "nmap": {...} }
}
```

---

## Configuration

Place default overrides in a config file (YAML or JSON). Example keys:
- max_threads
- timeout_seconds
- excluded_checks (list)
- gobuster_wordlist
- output_dir

I can provide a sample config file template (config.example.yml) if you want.

---

## Best practices & legal

- You MUST have explicit written authorization from the system owner before scanning.
- Start with `--quick` on production targets to reduce noise.
- Reduce thread count and use rate limiting to avoid triggering IDS/IPS.
- Nikto and aggressive enumeration are noisy; they will appear in server logs.
- The authors assume no liability for misuse.

---

## Contributing

- Open issues for bugs or feature requests.
- For pull requests: include tests or a runnable example and update README/screenshots as needed.
- Use a feature branch per change and provide a clear description of the change.

---

## Assets / screenshots guidance

- Resolution: 1280×720 recommended (or 2:1 aspect).
- Filenames: use assets/sentinel_summary.png, assets/sentinel_report_preview.png, assets/sentinel_gobuster.png
- Keep images under 1 MB for faster loading, prefer PNG for clarity.

---

## License

MIT — see LICENSE
