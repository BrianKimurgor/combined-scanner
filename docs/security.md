# Security model

The scanner reads code it does not trust, so the design assumes a scanned project may be hostile.

## Untrusted input

- **Zip uploads** are extracted with limits on size, file count, depth and compression ratio.
  Absolute paths, `..`, links and device files are refused.
- **Git URLs** must be https and are checked before use; refs are validated. Checkouts disable hooks
  and are size-limited. Revisions are exported without running anything from the repository.
- **Configuration** is read only from `--config` or the working directory, never from the project.

## Isolation

Each scan runs in its own container: read-only root filesystem, all capabilities dropped,
`no-new-privileges`, an unprivileged uid, memory, CPU and process limits, the source mounted
read-only, and output only to a per-scan directory. Offline mode removes the network entirely. The
shared cache volume is writable by scans; use offline mode (read-only mirror) when that matters.

`SCANNER_SANDBOX=local` disables all of this and is for development only; the server says so at start.

## Access control

- API keys are random, shown once and stored as hashes. Keys can be rotated and revoked.
- Every query is scoped to the key that created the data; other keys get `404`, not `403`.
- Browser sessions use an HttpOnly, SameSite=Strict cookie, require a custom header and a same-origin
  check for changes, expire, and end when the key is rotated or revoked. Failed logins are throttled.
- Per-key hourly limits and a global queue cap bound abuse.

## Output handling

- Secret and PII values are never stored; source lines near them are never copied into reports.
- Scanner-supplied text is escaped in Markdown and PR comments. The HTML report builds its page with
  text nodes only and is served in a sandbox (`Content-Security-Policy: sandbox`), so its scripts
  cannot reach the API or cookies.
- The web UI uses a strict policy: scripts and styles only from the same site, nothing inline.
- Suppressions need a reason and expire within a year, so accepted risk is reviewed.

## Operator responsibilities

- Put the API behind TLS; keep `SCANNER_COOKIE_SECURE=1` unless you are on plain http.
- Keep `SCANNER_METRICS_TOKEN` secret, and unset if you do not scrape metrics.
- Keep scanner versions current (they are pinned in `docker/Dockerfile.worker`) and rebuild regularly.
- Report vulnerabilities privately to the maintainers rather than in public issues.
