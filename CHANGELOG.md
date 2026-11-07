# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [6.5.3] — 2026-11-07

Fix for automatic LAN-mode detection. Backward compatible: older scan JSON still
loads and the command-line usage is unchanged.

### Fixed
- **Auto scan mode now engages LAN mode for internal subnets during host
  discovery** — when scanning a private range (e.g. `192.168.1.0/24`) in `auto`
  mode, the deep OS/MAC probe already switched to LAN per host, but host
  discovery and the report's scan-mode label still used the external port list
  and timing. Host discovery now treats a target set as LAN when every target is
  a private IP (new `_targets_lan_mode()` helper), using the LAN port list and
  faster per-port timeout, and prints a `🏠 auto → LAN` notice so the switch is
  visible. Mixed/public target sets keep external timing (so a 0.6s probe is not
  applied to internet hosts); hostname targets are still auto-detected per host
  in the deep scan.
- **Report scan-mode label reflects the effective mode** — in `auto` mode the PDF
  report now shows `อัตโนมัติ (auto) → ใช้ LAN` or `→ ใช้ External` based on
  whether any reachable host actually ran in LAN mode.

## [6.5.2] — 2026-11-05

Security hardening pass across the whole toolkit, from an internal defensive
code review. Backward compatible: older scan JSON still loads and command-line
usage is unchanged. All findings below were verified with regression tests.

### Security
- **Local GUI server CSRF / DNS-rebinding (High)** — the macOS GUI's local API
  server (`server.py`, bound to 127.0.0.1) sent `Access-Control-Allow-Origin: *`
  and did not validate the request origin, so a web page the operator visited
  could start scans and read results cross-origin. It now rejects any request
  whose `Host` is not loopback (defeats DNS-rebinding) or whose `Origin`/`Referer`
  is not loopback, denies `OPTIONS`, and no longer emits wildcard CORS.
- **CSV / Excel formula injection (High)** — report cells taken from scan data
  (e.g. a server's `Server` header) that began with `= + - @` were written as
  live formulas, so opening a report could run a formula on the analyst's
  machine. Such cells are now prefixed with `'` so spreadsheet apps treat them as
  text.
- **PDF report crash / markup injection (High)** — attacker-controlled fields
  reached reportlab `Paragraph` unescaped; a bare `<` in a `Server` header could
  abort generation of the whole PDF (DoS), and well-formed tags could distort it.
  All scan-derived fields are now routed through `_esc_pdf()`.
- **TLS verification for third-party intel APIs (Medium-High)** — the TLS-tolerant
  session (below) must apply only to scan targets. The subdomain-intel lookups
  (crt.sh / hackertarget / alienvault / anubis / rapiddns) now use a strict
  session that refuses invalid certificates, so a man-in-the-middle cannot forge
  their responses to steer scan scope.
- **Response size cap (Medium)** — responses are now streamed and capped at 5 MB
  (decompressed), so a malicious host cannot exhaust memory with a huge body or a
  gzip bomb.
- **SSRF hardening (Medium)** — `is_private_host` now uses `ipaddress` and covers
  link-local/cloud-metadata (169.254/16), IPv6, CGNAT and 0.0.0.0 instead of a
  bypassable regex; sessions cap redirects at 5.
- **Argument injection into nmap/ping (Medium)** — a hostname beginning with `-`
  (e.g. from a host-list file or poisoned passive-DNS) could be read as a tool
  option. `extract_domain` now rejects labels that start/end with `-`, and
  `_probe_os` refuses such hosts before building the command.
- **Dashboard onclick escaping (Medium)** — the host/CVE values embedded in
  `onclick` JS-string handlers were not correctly escaped (a no-op replace). A
  real JS-string escaper (`jsq`) is now used.
- **Predictable temp font path (Low)** — embedded fonts are written to a per-user
  `0700` temp directory instead of a world-writable, guessable path.

### Fixed
- **Hosts with untrusted TLS certificates no longer reported UNREACHABLE** — a
  server presenting a self-signed, expired, name-mismatched, or unknown-CA
  certificate caused `SSLError: certificate verify failed` during the pre-check /
  fingerprint, and the host was dropped as `UNREACHABLE`. Scanning sessions are
  now TLS-tolerant: on a certificate-verification failure the request is retried
  without verification so the host is still scanned, and a `tls_insecure` flag is
  set. Certificate problems are unchanged and continue to be detected and
  reported separately (TLS probe / `cert_problem`). Genuine handshake failures
  (with verification already off) are still reported as unreachable.
- **Narrowed bare `except:` clauses** to `except Exception:` so real errors are
  no longer silently swallowed.

## [6.5.1] — 2026-11-05

Security and reporting fixes on top of 6.5.0. Backward compatible: older scan
JSON still loads and the command-line usage is unchanged.

### Security
- **Stored XSS in the HTML dashboard (High)** — fields taken from a scanned
  server's response (e.g. the `Server` header) were embedded in the report's
  `<script>` block without neutralising `</script>`. A malicious server could
  make script of its choosing run in the browser of the operator who opened the
  report. The embedded JSON now escapes `&`, `<`, `>`, U+2028 and U+2029 as
  `\uXXXX` (still valid JSON, read identically by the page), and the scan-data
  placeholder is substituted last so report data can never be mistaken for a
  template token. Reported privately by Thana Tingprasom (Incognitolab).

### Fixed
- **Port 80 and 443 reported as two hosts** — when both the HTTP and HTTPS ports
  of the same host were open, discovery scanned `http://` and `https://`
  separately and the host appeared twice in the report. The two are now
  collapsed to a single HTTPS scan per host (non-standard ports are still
  scanned individually).
- **Thai font rendering on some machines** — the dashboard now loads Sarabun /
  Noto Sans Thai as web fonts (with the previous system fonts kept as offline
  fallback), so Thai text renders consistently on Windows/Linux machines without
  a Thai font installed.

### Fixed (accuracy pass, previously under Unreleased)
- **Node.js 24.x false positive** — 24.0.x is no longer flagged "unpatched";
  all Node 24+ are treated as patched, matching the documented stance (the
  version-branch map previously required ≥ 24.1.0).
- **PHP 8.0/8.1 false positive** — these are no longer reported vulnerable to
  the PHP 8.2+-only use-after-free CVEs (CVE-2026-109618 / 109619); their
  end-of-life risk is still reported separately.
- **Per-CVE Node.js matching** — each Node CVE now compares against its own
  fixed-version branches, reducing false negatives on 18.x / 23.x branches that
  had no backport for a given CVE.
- **OS end-of-life regexes** — a minor version no longer trips the wrong rule:
  CentOS 7.6 / 8.6 are classified as 7 / 8 (not the EOL-6 rule), and Debian 11.9
  no longer matches the "≤ 10" rule.
- **Version-range comparison** — version tuples are now zero-padded and keep all
  components, fixing boundary cases (e.g. `16.0.0` vs `≤ 16.0`) and 4-part
  versions (`22.2.10.33` vs `.34`) in GitLab / affected-range checks.
- **Two-part PHP banners** — `PHP/8.2` (no patch digit) is now parsed and
  analysed instead of being dropped.
- **ThaiCERT grouping** — XAMPP is no longer double-counted into group 5
  (Container); the control-panel / appliance split for group 3 no longer falls
  back to the full `DEVICE-` CVE list.
- **jQuery / Bootstrap mislabelling** — jQuery UI and plugins
  (e.g. `jquery.fancybox…`) are no longer recorded as the jQuery *core* version;
  a dedicated jQuery UI entry was added.
- **CUPS detection** — device signatures are matched case-insensitively, so an
  exposed CUPS print service is detected again.
- **MPTCP probe** — now reads the MPTCP fallback flag, so a connection that fell
  back to plain TCP is no longer reported as MPTCP-active (fewer false
  kernel-CVE "likely-vulnerable" results).

### Changed
- **Frozen-build DNS robustness** — builds now collect dnspython submodules so
  `dns.rdtypes.*` resolve when frozen; `dnspython` (and `fonttools`) added to the
  Windows build requirements so DNS enumeration works in the packaged binary.
- **Install guide** — distribution packages now ship a single consolidated
  `HOW_TO_INSTALL.txt` instead of two separate guide files.

## [6.5.0] — 2026-11-01

Backward compatible with 6.3.0 / 6.4.0: older scan JSON still loads, and the
previous releases stay usable via tags `v6.3.0` / `v6.4.0`. This release adds a
second large batch of detection and reporting on top of 6.4.0.

### Added
- Error-page fingerprinting: deliberately triggers 404/400 pages and mines
  them for OS/engine/version that a hardened home page hides — the Apache
  default page's `Apache/2.4.41 (Ubuntu)` (server version + OS, high
  confidence), stack-trace/path disclosure mapped to an OS (`/var/www` →
  Linux, `C:\inetpub` → Windows/IIS, `/Users/` → macOS), leaked server
  modules, PHP versions, and framework debug signatures (Laravel/Whoops,
  Symfony, Django/Flask, Rails, ASP.NET, Tomcat, Spring Boot, Express). Runs
  before the OS probe so the leak feeds OS detection, surfaces the engine in
  the stack profile, and raises an EXPOSURE-ErrorLeak finding when a page
  leaks internal detail.
- ThaiCERT 8-group coverage enhancements:
  - **Group 1 (CMS):** Full detection and version extraction for Moodle (`/admin/environment.xml`, `/lib/upgrade.txt`, cookies and meta markers), along with EOL branch policies.
  - **Group 2 (Frameworks/APIs):** Fingerprinting for Yii and Slim frameworks, Yii Gii code generator exposure check (`?r=gii`), and mapping of exposed Laravel Ignition debug mode to `CVE-2021-3129` (Critical RCE).
  - **Group 5 (Containers) & Group 6 (Windows + PHP):** Active probes for unauthenticated Docker Daemon API (port 2375) and private Docker Registry v2 API (port 5000); detection for WampServer and Laragon Windows web stacks; and direct automatic risk and non-destructive syntax highlight probing for `CVE-2024-4577` (PHP-CGI Argument Injection RCE on Windows).
  - **Group 7 (Test / Legacy / Backup):** Subdomain heuristics automatically classifying hosts matching `dev`, `uat`, `staging`, `test`, `dr`, `old`, `bak`, `temp`, `qa`, `lab` into Group 7, plus exposure probes for `/backup/`, `/old/`, and `/temp/` directory listings.
- IIS and LiteSpeed are now correlated with online CVEs: the detected server
  version is fed into the CIRCL/NVD lookup (previously only NGINX/Apache were),
  with CPE mappings for `microsoft/internet_information_services` and
  `litespeedtech/litespeed_web_server`.
- OS / distro end-of-life (EOL) detection — an offline check over the OS
  fingerprint that flags unsupported systems (CentOS/RHEL 6/7/8, Windows Server
  2003/2008/2012, Windows XP/Vista/7/8, old Ubuntu/Debian/FreeBSD) as a risk in
  its own right, since EOL systems no longer receive security patches. Reported
  under the OS/Kernel category with host-side confirmation guidance.
- Open-source / free hosting control-panel detection (ThaiCERT group 3):
  HestiaCP, VestaCP, CyberPanel, aaPanel/BT-Panel, ISPConfig, ISPmanager,
  Froxlor, Ajenti, Webuzo, CentOS Web Panel (CWP), CloudPanel, Virtualmin,
  KeyHelp, Sentora/ZPanel — with version extraction where the panel leaks it
  (Hestia/Vesta/CyberPanel/ISPConfig/…) and online-CVE (CIRCL) mappings for the
  panels that have NVD CPEs. Their default ports (8083, 8090, 2222, 7800, 888,
  2002/2004, 2030/2031) are added to host discovery, and they now classify
  under group 3 (Control Panel) instead of group 4.
- Banner-based OS detection (pure-Python, no nmap, no root) so OS fingerprinting
  survives compilation to a single .app/.exe without bundling a large external
  binary. Grabs SSH/FTP/SMTP banners and checks the Windows service-port profile
  (RDP/SMB/NetBIOS/MSRPC) concurrently, mapping SSH banners to distros
  (Ubuntu/Debian/CentOS/RHEL/Rocky, FreeBSD, MikroTik RouterOS, Dropbear,
  Windows-OpenSSH, …). It slots in right after the HTTP Server header and ahead
  of nmap/TTL; nmap, when present, stays an optional enhancement for hosts that
  hide every banner.
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

[Unreleased]: https://github.com/CybersRMUTL/security-audit-toolkit/compare/v6.5.3...HEAD
[6.5.3]: https://github.com/CybersRMUTL/security-audit-toolkit/compare/v6.5.2...v6.5.3
[6.5.2]: https://github.com/CybersRMUTL/security-audit-toolkit/compare/v6.5.1...v6.5.2
[6.5.1]: https://github.com/CybersRMUTL/security-audit-toolkit/compare/v6.5.0...v6.5.1
[6.5.0]: https://github.com/CybersRMUTL/security-audit-toolkit/compare/v6.4.0...v6.5.0
[6.4.0]: https://github.com/CybersRMUTL/security-audit-toolkit/compare/v6.3.0...v6.4.0
[6.3.0]: https://github.com/CybersRMUTL/security-audit-toolkit/releases/tag/v6.3.0
