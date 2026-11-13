# Contributing

Thanks for helping. Bug reports, new scanner plugins, report formats and documentation fixes are
all welcome.

## Before you start

- For anything bigger than a small fix, open an issue first so we can agree on the approach.
- Security problems go through private reporting, not public issues: see [SECURITY.md](SECURITY.md).
- By contributing you agree that your work is released under this project's licence, the
  [GNU AGPL-3.0](LICENSE).

## Set up

You need Python 3.12 or newer. Docker is only needed to build the scanner image.

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev,server]"
```

## Checks

CI runs these on every pull request; run them before you push:

```bash
ruff check .
ruff format --check .        # or `ruff format .` to fix
mypy
pytest
```

The tests use recorded scanner output in `tests/fixtures/`, so they need neither Docker nor the
scanners. If you change `docker/Dockerfile.worker`, also check that
`docker build -f docker/Dockerfile.worker -t code-scanner-worker .` still works.

## Scanning this project with itself

The project scans itself and should pass its own quality gate, with no configuration, the same
way an upload to the web UI is scanned. With the scanner image built, run it from the repository
root:

```bash
docker run --rm -v "$PWD:/scan:ro" code-scanner-worker scan /scan -f md
```

When a finding is deliberate, fix it if you can. If you cannot, put the reason in a comment and
mark the line with the tool's inline marker, so the decision stays next to the code and applies
to every scan:

| Tool | Marker |
| --- | --- |
| Semgrep | `# nosemgrep` on the flagged line |
| TruffleHog | `# trufflehog:ignore` on the flagged line |
| Gitleaks | `# gitleaks:allow` on the flagged line |
| Lizard | `# lizard forgives(parameter_count)` (or another metric) inside the function |
| Presidio | `# pii:ignore` on the flagged line (this project's own marker) |

## Adding a scanner

Each scanner is a plugin in `src/scanner/plugins/` that runs the tool as a separate program and
turns its output into findings. `gitleaks.py` and `trufflehog.py` are short examples.

1. Subclass `ScannerPlugin` (`plugins/base.py`): set `name` and `binary`, build the command line in
   `build_command`, and turn the output into `Finding` objects in `parse`.
2. Register it in `plugins/__init__.py` and add its name to `ALL_SCANNERS` in `core/config.py`.
3. Install it in `docker/Dockerfile.worker` at a pinned version, checking the download against a
   pinned SHA-256 digest like the other tools.
4. Add a recorded output sample to `tests/fixtures/` and parser tests to `tests/test_parsers.py`.
5. Add it to the tool list in `src/scanner/api/static/app.js` and the table in the README.

Rules every plugin follows:

- Never store secret or personal-data values. Set `secret_masked=SECRET_MASK` and read only the
  rule, file and line from the tool's output.
- Make no network calls in offline mode (`ctx.config.offline`), and none that send scanned content
  to third parties unless the user turns it on in `scanner.yml`.
- Run the tool only as a separate program. Do not copy a scanner's source code into this
  repository; licences differ between tools.

## Pull requests

- Keep each pull request to one change, with tests for new behaviour.
- Explain what changed and why in the description.
- Update the README or `docs/` when you change behaviour people rely on.
