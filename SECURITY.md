# Security Policy

## Acceptable use

This toolkit is intended **solely for authorized security testing** — against systems you own or have explicit, written permission to assess. Any unauthorized use is prohibited and may be illegal. The maintainers accept no liability for misuse (see the [MIT License](LICENSE)).

## Reporting a vulnerability

If you discover a security issue **in this toolkit itself** (for example, a flaw that could harm its operator, leak evidence, or be abused), please report it privately rather than opening a public issue.

- Email the maintainers at **cybers@rmutl.ac.th**, or
- Use GitHub's **private vulnerability reporting** (Security → *Report a vulnerability*).

Please include:
- a description of the issue and its impact,
- steps to reproduce,
- any suggested fix.

We aim to acknowledge reports within **5 business days**.

## Scope

- ✅ In scope: bugs in this tool's code (crashes, evidence integrity, accidental out-of-scope requests, credential/API-key handling).
- ❌ Out of scope: vulnerabilities in third-party targets you scan. Report those to the respective asset owner through their own disclosure process.

## Do not commit sensitive data

Never commit real scan results, evidence folders, host/target lists, or API keys. The repository's [`.gitignore`](.gitignore) blocks these by default — keep it intact.
