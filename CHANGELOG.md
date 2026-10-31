# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- LAN scanning overhaul for accuracy and coverage:
  - Non-standard web ports are now found and scanned. Host discovery runs in
    two phases — a fast liveness check, then a full web/admin/device port
    enumeration on live hosts (wider list in LAN mode) — and every open port
    becomes its own deep-scan target, so a web UI on an odd port (8443, 10000,
    5000, …) is no longer missed.
  - MAC/vendor detection hardened: in-process cross-platform ARP read
    (`arp`/`ip neigh`, skips incomplete entries), ARP primed with a TCP touch
    (no ICMP needed), an offline OUI table for common vendors, and MAC-vendor →
    device/OS inference (Synology→NAS/Linux, Hikvision→camera, etc.) that fills
    the OS/device fields when HTTP fingerprinting is silent.
  - Clear one-time guidance when LAN detection is blocked: install `nmap`
    (`brew install nmap`, run with sudo) for real OS detection, and grant
    python/Terminal the macOS "Local Network" permission so the ARP table (and
    thus MAC → vendor/device) is visible.

### Known limitations
- On macOS 15+/26, the OS hides the ARP table from the Python process unless it
  has the "Local Network" privacy permission, so MAC/vendor/device-by-MAC can
  come back empty even on the LAN (TCP scanning still works). `nmap -O` OS
  detection needs nmap installed and root.
- Fast host-discovery pre-pass for CIDR / multi-host scans (on by default,
  `--no-discover` or the advanced prompt to turn it off). Instead of waiting
  out the full HTTP timeout on every dead IP, it TCP-knocks the common web
  ports first (80/443/8080/8443, plus device ports in LAN mode) with high
  concurrency and a short timeout, then deep-scans only hosts with an open
  web port — a /24 that used to take minutes of timeouts now resolves in
  seconds. Uses TCP connects (no ICMP), so it still works when ping is
  blocked; skipped IPs are kept in the report as unreachable so totals match.
- LAN mode for internal-network scanning, chosen up front from a scan-mode
  menu (Auto / External / LAN) — also `--lan`, and still auto-enabled for
  private-IP targets in Auto. External forces remote behaviour even for a
  private IP. Raises accuracy on the LAN: `nmap -O`
  uses ARP discovery (and harvests MAC + vendor), MAC/OUI vendor lookup runs
  without the online-CVE opt-in (ARP cache primed with a ping), and the TTL
  heuristic is labelled high-confidence at 0–1 hop. The ThaiCERT 8-group
  coverage now reports a LAN capability ceiling (`cap_lan`) alongside the
  remote one — groups 3/4/6 rise the most (avg ~55% remote → ~66% on LAN) —
  shown with a 🏠 badge and per-group uplift in the HTML and PDF.
- CVE-2026-98432 — Linux kernel IPv4 TCP use-after-free (CVSS 9.8). Tied to
  the OS fingerprint: reported as "unknown — verify on host" for Linux
  (kernel patch state can't be confirmed over HTTP) and "n/a" for Windows,
  with `uname -r` + distro-advisory host-check guidance. New `OS/Kernel`
  finding category; scanner count is now 14 CVEs.
- ThaiCERT 8-group coverage: drill-down in the HTML dashboard (click a
  group to see the matched hosts, their detections and CVEs; host names
  open the full host drawer), plus the group breakdown added to the Excel
  workbook (5th sheet) and a `report_*_thaicert.csv` export.

## [6.4.0] — 2026-10-31

Backward compatible with 6.3.0: scan JSON from older runs still loads, and the
old release stays usable via tag `v6.3.0`.

### Added
- Deep stack fingerprinting: OS version, web-server modules (OpenSSL,
  mod_fcgid, Passenger, …), device/appliance detection (Synology DSM,
  QNAP QTS, TrueNAS, WD MyCloud, pfSense, OPNsense, FortiGate, MikroTik,
  UniFi, CUPS, cPanel/Plesk/DirectAdmin/Webmin), externally-visible
  container/reverse-proxy layer (Traefik, k8s ingress, Envoy/Istio,
  HAProxy), and a layered stack-profile summary.
- Application version detection with EOL and version-spoof flags for
  WordPress, Drupal, Joomla, Nextcloud (`status.php`), plus lightweight
  WordPress plugin + version harvesting.
- Component detection: databases via error/signature leaks
  (MySQL/MariaDB, PostgreSQL, MSSQL, SQLite, Oracle, MongoDB), admin
  tools (phpMyAdmin, Adminer, phpPgAdmin, phpinfo, Jenkins, Grafana,
  Kibana), and client JS libraries (jQuery, Bootstrap, Vue, React,
  AngularJS, Lodash).
- Exposed-file checks with content validators: `.env` and backups,
  `.git/HEAD`+`config`, `composer.lock`/`composer.json`, `package.json`,
  `wp-config` backups, `phpinfo.php`/`info.php`, Apache
  `server-status`/`server-info`, `web.config`, `.aws/credentials`,
  `backup.sql`, `.DS_Store`.
- Framework debug exposure: Laravel Ignition (CVE-2021-3129 risk),
  Symfony Web Profiler, and the `X-Debug-Token` header.
- Security headers audit (HSTS, CSP, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and
  insecure session-cookie flags (Secure/HttpOnly/SameSite).
- WAF / security-proxy detection (Cloudflare, Sucuri, Akamai, Imperva,
  AWS WAF, F5 BIG-IP, ModSecurity, Wordfence, FortiWeb, Barracuda, …).
- TLS inspection via real handshake: expired / expiring (<30d) /
  self-signed / hostname-mismatch / verify-failed certificates, plus a
  best-effort weak-protocol probe (TLS 1.0/1.1).
- Opt-in online CVE lookup (CIRCL cve-search, no API key) correlating
  every detected version — PHP, web server, OpenSSL, device firmware,
  app/CMS, and `composer.lock` packages — with published CVEs. The
  affected-version matcher understands both structured
  (`version`/`lessThan`/`lessThanOrEqual`) and free-text ranges
  (`">= 1.12.0, < 3.5.0"`, `"prior to version X"`).
- Packaging (`pyproject.toml`) with a `security-audit` console entry
  point, and repository scaffolding (README, LICENSE, CONTRIBUTING,
  SECURITY, Code of Conduct, CI, issue/PR templates).

### Changed
- Reports (PDF / Excel / HTML / CSV) now surface every new detection.
  The PDF "Stack Fingerprint" section lists the stack profile, OS
  version, server modules, WAF/CDN, device, container layer, app +
  version (+ plugin count), other components and the composer package
  count; the host CMS column shows the app version; TLS/cert details are
  written back into the fingerprint instead of always "not checked".
  Finding tables and the category/severity charts pick up the new
  categories automatically.
- macOS file/folder picker reworked to use the native `osascript` dialog
  (brought to the foreground) and to stop stealing window focus.

### Security
- `.gitignore` hardened to ignore report files by name
  (`dashboard_*.html`, `report_*.xlsx`, `report_*_findings.csv`,
  `report_*_ip.csv`), not only those inside `reports/`.

## [6.3.0] — 2026-10-30

### Added
- Scanner covering 13 CVEs (PHP 3 / NGINX 5 / Node.js 4 / GitLab 1).
- RCE verification with chain-of-custody evidence folders.
- Report generator: multi-chapter PDF, CSV/Excel, and 4 charts.
- Full pipeline mode (Scan → Verify → Report).
- Targeting by single host, CIDR, wildcard/subdomain, and host-list file.
- Per-host CVSS v3.1 risk index.
- Interactive menu and scriptable CLI.

[Unreleased]: https://github.com/CybersRMUTL/security-audit-toolkit/compare/v6.4.0...HEAD
[6.4.0]: https://github.com/CybersRMUTL/security-audit-toolkit/compare/v6.3.0...v6.4.0
[6.3.0]: https://github.com/CybersRMUTL/security-audit-toolkit/releases/tag/v6.3.0
