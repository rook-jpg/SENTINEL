# SentinelWeb - Advanced Web Security Scanner

<div align="center">

![SentinelWeb Logo](https://img.shields.io/badge/SentinelWeb-v1.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.7+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Security](https://img.shields.io/badge/Security-Scanner-red)

**Comprehensive Web Application Security Assessment Tool**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## ⚠️ LEGAL DISCLAIMER

**IMPORTANT:** This tool is intended for legitimate security testing purposes only. You must:

- ✅ Have **explicit written permission** from the system owner before scanning
- ✅ Use only on systems **you own** or are **authorized to test**
- ✅ Comply with all applicable **laws and regulations**
- ✅ Respect **rate limits** and **terms of service**

**Unauthorized scanning of systems is illegal and unethical. The developers assume no liability for misuse.**

---

## 📖 Overview

SentinelWeb is a comprehensive web security scanner that integrates multiple industry-standard security tools into a single, unified platform. It automates the process of web vulnerability assessment, SSL/TLS analysis, security header inspection, and more.

Built with Python, SentinelWeb orchestrates tools like Nikto, Nmap, SSLyze, and WhatWeb to provide a holistic view of your web application's security posture.

### 🎯 Key Features

- **🔍 Multi-Tool Integration**: Seamlessly integrates with Nikto, Nmap, SSLyze, testssl.sh, WhatWeb, wafw00f, and Gobuster
- **🔒 SSL/TLS Deep Analysis**: Certificate validation, protocol support, cipher strength assessment
- **🛡️ Security Headers Check**: Comprehensive HTTP security headers analysis
- **🍪 Cookie Security Audit**: Secure, HttpOnly, and SameSite flag validation
- **🛑 WAF Detection**: Identifies Web Application Firewalls
- **📊 Technology Fingerprinting**: Discovers web technologies and frameworks
- **📁 Directory Enumeration**: Common directory and file discovery
- **⚡ Concurrent Scanning**: Multi-threaded execution for faster results
- **📝 Comprehensive Reporting**: Detailed JSON and text-based scan reports
- **🎨 Color-Coded Output**: Easy-to-read terminal output with color indicators

---

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- Linux/Unix-based system (recommended)
- Root/sudo privileges (for certain scans)

### Required Tools

```bash
# Update package list
sudo apt-get update

# Install core tools
sudo apt-get install -y nikto nmap whatweb testssl.sh

# Install Python packages
pip install colorama requests urllib3 sslyze wafw00f gobuster

# Clone testssl.sh if not installed via package manager
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh
sudo ln -s $PWD/testssl.sh /usr/local/bin/testssl
```

### Usage Examples


# Full scan
python3 web_scanner.py https://example.com

# SSL/TLS only scan
python3 web_scanner.py example.com --ssl-only

# Quick scan (headers, cookies, SSL)
python3 web_scanner.py https://example.com --quick

# Custom port and output directory
python3 web_scanner.py example.com -p 8443 -o my_scan_results

# With more threads for faster scanning
python3 web_scanner.py https://example.com -t 10



### Important Security Notes


⚠️ CRITICAL WARNINGS:

· Only test systems you own or have explicit written permission to test
· Unauthorized scanning is illegal and unethical
· Some scans can be detected by IDS/IPS systems
· Nikto scans are noisy and will appear in web server logs
· Rate limiting may apply - adjust thread count accordingly

4. What This Scanner Checks

· Nikto: Comprehensive web server vulnerability scanning
· SSL/TLS: Certificate validation, protocol support, cipher strength
· Security Headers: HSTS, CSP, X-Frame-Options, etc.
· Cookie Security: Secure, HttpOnly, SameSite flags
· WAF Detection: Identifies web application firewalls
· Technology Detection: Identifies web technologies in use
· Directory Enumeration: Common directory/file discovery
· Nmap: Service detection and HTTP-specific scripts

