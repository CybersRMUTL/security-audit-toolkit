# Contributing

Thanks for your interest in improving the RMUT CERT Toolkit! 🙌

## Before you start

This is a **defensive / authorized-testing** project. Contributions that add indiscriminate attack capability, mass-targeting, or detection-evasion features will not be accepted. Keep the tool useful for CERT and blue-team work.

## Development setup

```bash
git clone https://github.com/CybersRMUTL/security-audit-toolkit.git
cd security-audit-toolkit
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[full,dev]"
```

## Workflow

1. **Open an issue** first for anything non-trivial, so we can agree on the approach.
2. Create a feature branch: `git checkout -b feature/short-description`.
3. Make your change. Keep it focused and match the surrounding code style.
4. Run the linter before committing:
   ```bash
   ruff check .
   ```
5. **Never commit** real scan output, evidence, host lists, or API keys (they are git-ignored — keep them that way).
6. Write a clear commit message and open a Pull Request against `main`.

## Commit messages

Use short, imperative subject lines, e.g. `Add CVE-XXXX-NNNN NGINX check`. Conventional Commits (`feat:`, `fix:`, `docs:`) are welcome but not required.

## Adding a CVE check

- Add the CVE metadata (name, severity, trigger, host-check) to the relevant constants section.
- Implement the detection logic conservatively — prefer **signal detection** over destructive probing.
- Document the check in the README's coverage summary.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — report privately, not via public issues.
