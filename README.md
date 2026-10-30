<div align="center">

# 🛡️ RMUT CERT — All-in-One Vulnerability Toolkit

**Authorized vulnerability scanner · RCE verifier with chain-of-custody · automated report generator**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Code style: ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![Authorized use only](https://img.shields.io/badge/use-authorized%20only-red.svg)](#%EF%B8%8F-legal--responsible-use)

A single-file, dependency-light toolkit used by a university CERT team to **scan**, **verify**, and **report** web-infrastructure vulnerabilities on systems they are **authorized to test**.

</div>

---

> ## ⚠️ Legal & Responsible Use
>
> This tool actively probes targets and can attempt proof-of-concept exploitation (RCE verification). **Use it only against systems you own or have explicit, written permission to test.** Unauthorized scanning or exploitation is illegal in most jurisdictions.
>
> - The `--pipeline` (exploit) mode **requires** the explicit `--i-own-this-target` flag.
> - You are solely responsible for how you use this software. See the [MIT License](LICENSE) — it is provided **"as is", without warranty**.
> - Do **not** commit real scan results, evidence, or host lists. The included [`.gitignore`](.gitignore) blocks them by default.

---

## ✨ Features

- **🔍 Scanner** — checks 13 CVEs across **PHP (3)**, **NGINX (5)**, **Node.js (4)**, and **GitLab (1)**, plus LFI/path-traversal signal detection.
- **🎯 Flexible targeting** — single host, CIDR range, wildcard/subdomain enumeration (optional DNS + c99.nl), or a file list (CSV/TXT).
- **🧪 RCE verification** — safe proof-of-concept checks that produce a **chain-of-custody evidence folder** (`transcript.log`, `metadata.json`, `summary.json`, `rce_proof.txt`).
- **📊 Report generator** — multi-chapter **PDF** + **CSV/Excel** + **4 charts (PNG)**, with a per-host risk index based on **CVSS v3.1**.
- **🔗 Full pipeline** — `Scan → Verify → Report`, fully automated.
- **🖥️ Dual interface** — interactive menu *and* scriptable CLI flags.
- **🧩 Graceful degradation** — optional libraries (`dnspython`, `reportlab`, `matplotlib`) are not required; the tool falls back automatically.
- **🧷 Safe-by-default outputs** — every file is timestamped and auto-renamed; nothing is overwritten.

## 📦 Installation

Requires **Python 3.9+**.

```bash
git clone https://github.com/CybersRMUTL/security-audit-toolkit.git
cd security-audit-toolkit

# install everything (recommended)
pip install -r requirements.txt

# or install as a command-line tool
pip install ".[full]"      # exposes the `rmut-cert` command
```

Minimum is just `requests`; `dnspython`, `reportlab`, and `matplotlib` unlock wildcard enumeration and report generation.

## 🚀 Quick Start

```bash
# Interactive menu
python3 security_audit_toolkit.py

# Show the 13 CVEs checked, then exit
python3 security_audit_toolkit.py --list-cves

# Scan a single host (you must confirm scope at the prompt)
python3 security_audit_toolkit.py --target 192.168.1.10

# Scan a CIDR range
python3 security_audit_toolkit.py --cidr 192.168.1.0/24

# Wildcard / subdomain scan (add --c99-key KEY for broader coverage)
python3 security_audit_toolkit.py --wildcard example.org

# Scan from a host list file
python3 security_audit_toolkit.py --list hosts.csv

# Full pipeline — scan + verify + report (ownership flag REQUIRED)
python3 security_audit_toolkit.py --pipeline 192.168.1.10 --i-own-this-target

# Generate a report from an existing scan JSON
python3 security_audit_toolkit.py --report scan.json
```

If installed with `pip`, replace `python3 security_audit_toolkit.py` with `security-audit`.

### Common options

| Flag | Description | Default |
|------|-------------|---------|
| `--depth N` | Crawl depth (max 20) | `2` |
| `--max-pages N` | Max pages per host | `50` |
| `--timeout SEC` | HTTP timeout | `8.0` |
| `--c99-key KEY` | c99.nl SubdomainFinder API key (optional) | — |
| `--output-dir DIR` | Report output directory | `reports` |
| `--no-verify-ssl` | Skip TLS verification | off |
| `--no-interactive` | Non-interactive mode | off |

## 📂 Output structure

| Mode | Output |
|------|--------|
| Scan | `scan_<mode>_<target>_<timestamp>.json` |
| RCE verify | `evidence/<host>_<timestamp>/` (transcript, metadata, proofs) |
| Report | `reports/<timestamp>/` — PDF (6 chapters) + CSV + 4 charts |
| Pipeline | `pipeline_*.json` + `evidence/` + `reports/` |

> 🔒 All of these are **git-ignored** so real findings never reach the repository.

## 🧮 Risk scoring

Per-host risk is a 0–100 index derived from **CVSS v3.1** base scores of *confirmed* findings, weighted by a Report Confidence multiplier (confirmed = 1.0, signal = 0.6, unknown/safe/N/A = 0.0), normalized against the CVSS cap of 10.0.

## 🗺️ Roadmap

- [ ] Split the single file into an installable package (`src/` layout)
- [ ] Unit tests + CI coverage of the scan/report logic
- [ ] JSON schema for scan output
- [ ] Pluggable CVE check modules

## 🤝 Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Please report security issues privately as described in [SECURITY.md](SECURITY.md).

## 📜 License

Released under the [MIT License](LICENSE).

---

<div align="center">
<sub>Built for defensive security and authorized testing by the RMUT CERT team.</sub>
</div>
