# Code Scanner: Build Plan

A standalone tool that accepts a zipped codebase or a PR/diff and scans it with a set of free, open-source scanners. It merges their results into one normalized report with a pass/fail quality gate.

This project is independent of any other repo. Create it in its own new folder and git repository.

## 1. Goals
- Accept input as (a) a zip upload, (b) a git repo URL plus ref, or (c) a PR (base and head) for diff-only scanning.
- Run the scanners below in parallel, each isolated and time-limited.
- Normalize all findings into one schema, deduplicate them, and apply a quality gate.
- Produce JSON, SARIF and HTML/Markdown reports, plus an optional PR comment or check run.
- Be safe with untrusted uploads (see section 7).

## 2. Scanners (all free and open source)
| Check | Tool | Repo | License | Install |
|---|---|---|---|---|
| Dependency versions and vulnerabilities | OSV-Scanner | google/osv-scanner | Apache-2.0 | release binary / Go |
| Code bugs and security patterns | Semgrep CE | semgrep/semgrep | LGPL-2.1 | `pip install semgrep` |
| Secrets | Gitleaks | gitleaks/gitleaks | MIT | release binary / Go |
| Vulnerabilities, secrets, IaC, licenses | Trivy | aquasecurity/trivy | Apache-2.0 | release binary |
| Duplication | jscpd | kucherenko/jscpd | MIT | `npm i -g jscpd` |
| Complexity | Lizard | terryyin/lizard | MIT | `pip install lizard` |
| IaC and Docker | Checkov | bridgecrewio/checkov | Apache-2.0 | `pip install checkov` |

Overlap notes: Trivy overlaps with OSV, Gitleaks and Checkov, so findings must be deduplicated (section 5).

Licensing caveat: the Semgrep community rules (semgrep/semgrep-rules) use the Semgrep Rules License, which restricts offering them in a commercial hosted service. Keep the rule source configurable and document this. The tool must work with custom or own rule packs.

## 3. Tech decisions (defaults, change if needed)
- **Language:** Python 3.12. Three of the scanners are Python, which makes packaging and orchestration simpler.
- **API:** FastAPI. **Queue:** Redis + RQ (or Celery). **DB:** Postgres (SQLite for MVP). **Storage:** local disk, S3-compatible later.
- **Packaging:** one Docker image with all scanner binaries pinned to specific versions. A separate image for the API, and one for the worker.
- **Interchange format:** internal Finding model, exportable to SARIF 2.1.0.
- **CLI:** Typer. Command: `scanner scan <path|zip|git-url> [--base REF --head REF] [--format json|sarif|md|html] [--fail-on high]`.

## 4. Architecture
```
Upload zip / git URL / PR webhook
        │
   API (FastAPI)  ──►  Job queue (Redis)
                            │
                    Worker (one sandbox container per scan)
                      1. Safe extract / git checkout
                      2. Detect languages and manifests
                      3. Run scanner plugins in parallel (JSON/SARIF output)
                      4. Normalize → dedupe → score → gate
                            │
                    Postgres (scans, findings) + report files
                            │
          Report UI / REST API / PR comments / GitHub check run
```

### Repo layout
```
code-scanner/
  pyproject.toml
  docker/            # Dockerfile.worker, Dockerfile.api, compose.yml
  src/scanner/
    cli.py
    api/             # FastAPI app, routes, auth
    core/            # orchestrator, job model, config, gate
    ingest/          # safe_extract.py, git_checkout.py, diff.py
    plugins/         # one module per scanner
      base.py        # ScannerPlugin interface
      osv.py semgrep.py gitleaks.py trivy.py jscpd.py lizard.py checkov.py
    normalize/       # finding.py (schema), sarif.py, dedupe.py, severity.py
    report/          # json.py, sarif.py, markdown.py, html.py, github.py
  tests/
    fixtures/        # sample vulnerable projects, malicious zips
  docs/
```

## 5. Normalized finding schema
```
Finding {
  id            # stable hash(tool, rule, file, line, key fields)
  tool          # osv | semgrep | gitleaks | trivy | jscpd | lizard | checkov
  category      # dependency | code | secret | iac | duplication | complexity | license
  rule_id       # CVE-2024-xxxx / semgrep rule / gitleaks rule
  severity      # critical | high | medium | low | info (mapped per tool)
  title, message
  file, line_start, line_end
  package, version, fixed_version   # dependency findings
  fingerprint   # for dedupe and baseline comparison
  secret_masked # never store the raw secret value
  raw           # original tool payload (optional, size-limited)
}
```

- **Dedupe rules:** merge by (package, version, CVE) for dependency findings across OSV and Trivy. Merge by (file, line, rule family) for secrets across Gitleaks and Trivy. Keep a `sources: [tools]` list on the merged finding.
- **Severity mapping:** a table per tool in `severity.py`. Lizard and jscpd severity come from configurable thresholds.

## 6. Scanner plugin interface
```python
class ScannerPlugin:
    name: str
    def available(self) -> bool: ...
    def run(self, ctx: ScanContext) -> list[Finding]: ...
```
`ScanContext` holds the workdir, the mode (full or diff), the base and head refs, the changed file list, a timeout and the output dir. Each plugin must:
- Run the tool as a subprocess with a timeout and resource limits, and capture stderr.
- Return findings plus a status (`ok | failed | timeout | skipped`). One failing tool never aborts the scan.

### Commands per tool
| Tool | Full scan | Diff mode |
|---|---|---|
| OSV-Scanner | `osv-scanner scan source -r . --format json` (older versions: `osv-scanner -r .`; detect the version) | Scan the changed lockfiles, or scan base and head and report new findings |
| Semgrep | `semgrep scan --config <rules> --json --metrics=off .` | `--baseline-commit <base>` |
| Gitleaks | `gitleaks detect --source . --report-format json --redact` | `--log-opts "base..head"` |
| Trivy | `trivy fs --scanners vuln,secret,misconfig,license --format json .` | Scan a temp dir of the changed files and manifests, or diff base vs head results |
| jscpd | `jscpd . --reporters json --output <dir>` | Full scan, then keep only clones that touch changed files |
| Lizard | `lizard . -C <ccn> -L <len> -a <args> --xml` (or CSV) | Pass only the changed files |
| Checkov | `checkov -d . -o json` | `-f` per changed IaC file |

Use `--metrics=off` and equivalents wherever a tool has telemetry. Verify the exact flags against each tool's pinned version, since CLIs change between releases.

Generic diff fallback for any tool without native diff support: scan base and head, then report only findings whose fingerprint exists in head but not in base.

## 7. Security requirements (untrusted input)
1. **Zip extraction:**
   - Reject path traversal (`../`, absolute paths) and symlinks or hardlinks that escape the root.
   - Cap compressed size, total extracted size, file count and directory depth. Enforce a compression-ratio limit.
   - Strip special files and set safe permissions.
2. **Sandbox every scan** in a throwaway container:
   - Non-root user, read-only mount of the source, a temp writable output dir, CPU, memory and PID limits, and a wall-clock timeout.
   - No network by default. Only OSV and Trivy need network or DB access, so prefer pre-mirrored offline databases and update them on a schedule outside the sandbox.
3. **Never execute uploaded code.** No `npm install`, `pip install` or build steps. Scan lockfiles and manifests only.
4. **Secrets handling:** run Gitleaks with redaction, store only masked values, and delete uploads and workdirs after the scan (with a configurable retention period).
5. **Auth:** API keys or OAuth. Isolate scans and results per user or tenant. Rate-limit uploads.
6. **Supply chain:** pin scanner versions and verify checksums in the Dockerfile.

## 8. Quality gate
Config file (`scanner.yml`) with defaults:
```yaml
gate:
  fail_on:
    vulnerability: high        # critical | high | medium
    secret: any                # any new secret fails
    code: high
    iac: high
  complexity: { ccn: 15, length: 100, args: 6 }
  duplication: { max_percent: 5 }
scanners:
  enabled: [osv, semgrep, gitleaks, trivy, jscpd, lizard, checkov]
  timeout_seconds: 600
ignore: ["**/node_modules/**", "**/vendor/**", "**/*.min.js"]
suppressions: []               # fingerprint + reason + expiry
```
In diff mode, the gate considers new findings only. Exit code 0 means pass and 1 means gate failed. A distinct non-zero code (for example 2) means a scanner error.

## 9. Phased delivery
**Phase 0, setup:** repo, `pyproject.toml`, linting, pytest, a Dockerfile that installs the pinned scanners, and CI.
**Phase 1, MVP CLI (full-scan mode):**
- The plugin interface, the finding schema, and all seven plugins with JSON parsing.
- Parallel runner with timeouts and per-tool status.
- Dedupe, severity mapping, and the gate.
- JSON and Markdown reports. Unit tests with fixture outputs per tool.
**Phase 2, ingestion and API:**
- Safe zip extraction with tests using malicious zips (zip-slip, bomb, symlinks).
- Git URL checkout.
- FastAPI endpoints and a job queue, plus DB models.
- Sandboxed worker execution.
**Phase 3, diff and PR mode:**
- Diff computation and changed-file list, plus the per-tool diff strategies.
- Base-vs-head fingerprint comparison fallback.
- GitHub Action and/or GitHub App: PR comments, check runs, SARIF upload.
**Phase 4, reports and UI:**
- SARIF and HTML reports.
- A simple web UI: upload, scan history, findings table with filters, and trends.
- Suppressions and baselines.
**Phase 5, hardening:**
- Offline database mirroring, retention policies, auth and tenancy, metrics and logging, load testing, and docs.

## 10. REST API (Phase 2)
- `POST /scans` (multipart zip, or JSON `{git_url, ref}` or `{repo, base, head}`) → `{scan_id}`
- `GET /scans/{id}` → status and per-tool status
- `GET /scans/{id}/findings?severity=&category=&tool=`
- `GET /scans/{id}/report?format=json|sarif|md|html`
- `POST /webhooks/github` (PR events)

## 11. Testing strategy
- **Unit tests:** parsers per tool using recorded JSON outputs, plus dedupe, severity mapping, the gate, and the diff logic.
- **Security tests:** a malicious-zip corpus (traversal, bomb, symlink, huge file count) that must be rejected safely.
- **Integration tests:** scan fixture projects with known issues (an outdated dependency with a known CVE, a hardcoded fake key, a SQL injection pattern, a root Dockerfile, a long function, duplicated blocks) and assert that each tool's expected finding appears.
- **Diff tests:** a git fixture with base and head commits, asserting that only new findings are reported.
- **Resilience:** a missing tool, a timeout, or malformed output must degrade gracefully.

## 12. Acceptance criteria for the MVP
- `scanner scan ./fixture --format json` runs all seven tools and outputs a merged, deduplicated report.
- A failing or missing tool is reported but doesn't abort the scan.
- The gate returns the correct exit code for the fixtures.
- All parsers are covered by tests, and the Docker image builds reproducibly with pinned versions.

## 13. Open questions for the owner
1. Language: Python (default here), or Node/TypeScript or Go?
2. Inputs for v1: zip upload, PR mode, or both?
3. Hosted service or internal/self-hosted tool? This decides the Semgrep rules licensing approach.
4. Which languages and ecosystems must be supported first?
5. Is network access available at scan time, or is offline mode needed?
