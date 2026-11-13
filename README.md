# Code Scanner

Scans a codebase or a pull-request diff with open-source scanners and merges the results into one
report: one list of findings, one quality gate, one health score.

| Concern | Tool |
| --- | --- |
| Vulnerable dependencies | OSV-Scanner, Trivy |
| Code issues | Semgrep |
| Secrets | Gitleaks, TruffleHog, Trivy |
| Infrastructure as code | Checkov, Trivy |
| Duplication | jscpd |
| Complexity | Lizard |
| Personal data (PII) | Presidio (optional) |

Findings from different tools are deduplicated, severities are normalised, and secrets and PII values
are never stored or shown.

## Requirements

- Python 3.12 or newer, and Git.
- Docker, for the scanner image. The server runs every scan in a container built from it, and it is
  the easiest way to get all the scanning tools.
- For the Docker image: an x86-64 (Intel or AMD) machine. The Dockerfile downloads x86-64 builds of
  the tools, so ARM hosts need it changed first.

## Install

Linux or macOS:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,server]"      # add ",pii" for the Presidio scanner
```

Windows (PowerShell):

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[dev,server]"
```

If PowerShell refuses to run `Activate.ps1`, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
once.

Then build the image that holds the scanning tools (several minutes the first time):

```bash
docker build -f docker/Dockerfile.worker -t code-scanner-worker .
```

The image downloads each tool at a pinned version and checks it against a pinned SHA-256 digest;
change the versions in `docker/Dockerfile.worker` and rebuild to update them.

Check the install with `pytest`. The tests use recorded tool output, so they need neither Docker nor
the tools.

## Scan with Docker

The image's entry point is `scanner`, so it can scan a folder without installing any tools locally:

```bash
docker run --rm -v "/path/to/project:/src:ro" code-scanner-worker scan /src -f html > report.html
```

On Windows use a Windows path on the left, for example `-v "C:\code\project:/src:ro"`. The report
goes to standard output because the container runs as an unprivileged user that may not be able to
write into the mounted folder.

To run `scanner scan` directly instead, put the tools you want on your `PATH`; tools that are
missing are reported as skipped. Semgrep does not run natively on Windows, so use Docker there.

## Scan from the command line

```bash
scanner scan ./project                               # JSON report on stdout
scanner scan ./project -f html -o report.html        # also: md, sarif, comment
scanner scan ./project --fail-on medium              # stricter gate
scanner scan ./project --base main                   # only what changed since main
scanner scan ./project --history                     # secrets in every commit, too
scanner baseline ./project -o baseline.json          # accept today's findings
scanner scan ./project --baseline baseline.json      # only new findings gate
scanner render report.json -f md                     # re-render a saved report
```

Exit codes: `0` gate passed, `1` gate failed, `2` a scanner or configuration error, or no scanner ran.

### Scanning the git history

A secret that was committed and deleted later is still in the repository's history, and anyone
who clones it can read it. With `--history` (or "Also scan every commit" when scanning a git URL
in the web UI), Gitleaks and TruffleHog read every commit instead of only the current files, and
each finding names the commit it was found in. Rotate a secret found this way: deleting it in a
new commit does not remove it from the history.

- The web UI and API fetch up to `SCANNER_HISTORY_MAX_COMMITS` commits (1000 by default) of the
  scanned revision; the other scanners still look at the current files only.
- Locally, `--history` reads the repository that contains the scanned folder. Uncommitted changes
  are not in the history, so commit them first or scan without `--history` as well.
- It cannot be combined with `--base` or `--base-path`. Zip uploads have no history to read.
- Author names, emails and commit messages are never stored, only the commit hash.

Settings live in a `scanner.yml` in the current directory or at `--config`. A `scanner.yml` inside the
scanned project is never read.

```yaml
gate:
  fail_on: { vulnerability: high, secret: any, code: high, iac: high, pii: none }
  duplication: { max_percent: 5 }
scanners:
  enabled: [osv, semgrep, gitleaks, trufflehog, trivy, jscpd, lizard, checkov]
  trufflehog_verify: false   # true checks found secrets against their provider (network)
ignore: ["**/node_modules/**", "**/vendor/**"]   # skipped by every scanner
# Skipped only for complexity and duplication; tests are still scanned for secrets and CVEs.
# The default covers __tests__, tests, e2e, cypress, *.test.*, *.spec.*, fixtures and migrations.
quality_ignore: ["**/__tests__/**", "**/*.test.*"]
# Licence findings for these package names are dropped (CVEs for them still show). The default
# is the LGPL libvips binaries that Next.js installs through sharp. Trivy's licence scan is
# currently turned off for speed (src/scanner/plugins/trivy.py), so this has no effect for now.
license_ignore: ["@img/sharp-*"]
suppressions:
  - fingerprint: 0123456789abcdef
    reason: Input is validated upstream
    expires: 2027-01-31          # at most a year ahead; it counts again after this date
```

### Accepting a finding in the code

A finding that is deliberate, such as test data or an intended pattern, can be marked where it
is, with the reason in a comment beside it. The marker travels with the code, so it applies to
every scan, including uploads to the web UI, which never read a project's own `scanner.yml`.

| Tool | Marker |
| --- | --- |
| Semgrep | `# nosemgrep` on the flagged line |
| Gitleaks | `# gitleaks:allow` on the flagged line |
| TruffleHog | `# trufflehog:ignore` on the flagged line |
| Lizard | `# lizard forgives(parameter_count)` (or another metric) inside the function |
| Presidio | `# pii:ignore` on the flagged line (this scanner's own marker) |

Addresses inside URLs, such as `ssh://git@github.com/...`, are not reported as email addresses.

## Run the server

The server needs the scanner image built above. Run each long-running command in its own terminal:

```bash
scanner admin create-key alice       # prints the key once; create one on every new machine
scanner serve --host 127.0.0.1       # API and web UI at http://127.0.0.1:8000/ui/
scanner worker                       # runs queued scans, one sandbox container each
```

Sign in to the web UI with the key, then upload a zip (100 MB at most by default) or give a git URL.
The web UI offers upload and git scans, scan history, a findings table with filters and source
snippets, suppressions, baselines, trends and light or dark themes.

The server keeps its database, uploads and reports in `scanner-data/` (set `SCANNER_DATA_DIR` to
move it). On anything other than your own machine, put it behind a TLS proxy such as nginx or Caddy:
the login cookie is only sent over HTTPS.

## Not in the repository

Two folders are listed in `.gitignore` and are never committed:

- `scanner-data/`: the server's database, uploads and reports. They may describe the code you
  scanned, so they stay local. A fresh clone starts with an empty database.
- `reference/`: copies of each scanner's upstream source, kept only for reading while writing
  plugins. Nothing builds or runs from it. Clone any of these into it when you need one:

  | Tool | Repository |
  | --- | --- |
  | Checkov | https://github.com/bridgecrewio/checkov |
  | Gitleaks | https://github.com/gitleaks/gitleaks |
  | jscpd | https://github.com/kucherenko/jscpd |
  | Lizard | https://github.com/terryyin/lizard |
  | OSV-Scanner | https://github.com/google/osv-scanner |
  | Semgrep | https://github.com/semgrep/semgrep |
  | Trivy | https://github.com/aquasecurity/trivy |
  | TruffleHog | https://github.com/trufflesecurity/trufflehog |

  For example: `git clone --depth 1 https://github.com/gitleaks/gitleaks reference/gitleaks`.

More: [operations](docs/operations.md), [REST API](docs/api.md), [security model](docs/security.md).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) to get set up, and
[SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

[GNU AGPL-3.0](LICENSE) or later. You may use, change and share this project; if you run a modified
version as a network service, you must offer its source code to that service's users. The scanners
it runs are separate programs under their own licences.
