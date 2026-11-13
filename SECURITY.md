# Security policy

This scanner reads code it does not trust, so security bugs matter here. Examples: escaping the scan
sandbox, reading another user's scans, a secret value ending up in a report, or a crafted zip or git
repository causing harm.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through GitHub instead: on the repository's
**Security** tab, choose **Report a vulnerability**.

Include what you found, how to reproduce it, and what an attacker could do with it. You should get a
reply within a week. Please give us a reasonable time to fix it before you disclose it publicly.

## Supported versions

Only the latest version on the `main` branch gets security fixes.

The design and its limits are described in [docs/security.md](docs/security.md).
