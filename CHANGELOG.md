# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Packaging (`pyproject.toml`) with a `rmut-cert` console entry point.
- Repository scaffolding: README, LICENSE (MIT), CONTRIBUTING, SECURITY, Code of Conduct, CI, and issue/PR templates.

## [6.3.0] — 2026-10-30

### Added
- Scanner covering 13 CVEs (PHP 3 / NGINX 5 / Node.js 4 / GitLab 1).
- RCE verification with chain-of-custody evidence folders.
- Report generator: multi-chapter PDF, CSV/Excel, and 4 charts.
- Full pipeline mode (Scan → Verify → Report).
- Targeting by single host, CIDR, wildcard/subdomain, and host-list file.
- Per-host CVSS v3.1 risk index.
- Interactive menu and scriptable CLI.

[Unreleased]: https://github.com/CybersRMUTL/security-audit-toolkit/compare/v6.3.0...HEAD
[6.3.0]: https://github.com/CybersRMUTL/security-audit-toolkit/releases/tag/v6.3.0
