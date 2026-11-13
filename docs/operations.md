# Operations

## Components

- **API** (`scanner serve`): accepts scans, serves results and the web UI. It never runs scanners.
- **Worker** (`scanner worker`): takes queued scans from the database and runs each one in a
  throwaway Docker container. Run one or several; claiming a scan is atomic.
- **Database**: SQLite by default (`<data dir>/scanner.db`). Set `SCANNER_DATABASE_URL` for another
  SQLAlchemy URL.
- **Data directory**: uploads, working copies and reports.

The API and workers must share the database and data directory.

## Settings

All settings are environment variables.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SCANNER_DATA_DIR` | `scanner-data` | Uploads, work, reports, SQLite file, mirror |
| `SCANNER_DATABASE_URL` | SQLite in the data dir | SQLAlchemy URL |
| `SCANNER_MAX_UPLOAD_MB` | 100 | Largest accepted zip |
| `SCANNER_MAX_SCANS_PER_HOUR` | 30 | Per API key |
| `SCANNER_MAX_QUEUED_SCANS` | 200 | Server-wide queue cap |
| `SCANNER_SCAN_TIMEOUT_SECONDS` | 1800 | Per scan |
| `SCANNER_HISTORY_MAX_COMMITS` | 1000 | Commits fetched for a history scan, counting back from the scanned revision |
| `SCANNER_SANDBOX` | `docker` | `local` runs scans with no sandbox: development only |
| `SCANNER_SANDBOX_IMAGE` | `code-scanner-worker` | Image built from `docker/Dockerfile.worker` |
| `SCANNER_SANDBOX_NETWORK` | `bridge` | Container network (ignored when offline) |
| `SCANNER_SANDBOX_MEMORY` / `_CPUS` / `_PIDS` | `4g` / `2` / `512` | Container limits |
| `SCANNER_SANDBOX_CACHE_VOLUME` | `scanner-cache` | Docker volume for scanner caches; empty means a tmpfs |
| `SCANNER_STAGE_DIR` | set by the worker | Inside the scan container: the source is copied to this 2 GB tmpfs first, because Docker Desktop bind mounts read files too slowly for Semgrep |
| `SCANNER_SESSION_HOURS` | 12 | Browser login lifetime |
| `SCANNER_COOKIE_SECURE` | `1` | Send the login cookie over https only; `0` for plain http beyond localhost |
| `SCANNER_RETENTION_DAYS` | 90 | See retention |
| `SCANNER_METRICS_TOKEN` | empty | Enables `/metrics`; sent as a bearer token |
| `SCANNER_LOG_FORMAT` | `text` | `json` for one JSON object per line |
| `SCANNER_OFFLINE` / `SCANNER_MIRROR_DIR` | `0` / `<data dir>/mirror` | See offline scans |

## Keys

```bash
scanner admin create-key NAME      # shown once; only a hash is stored
scanner admin list-keys            # name, state, scan count, last scan
scanner admin rotate-key NAME      # new secret, same history; the old one stops at once
scanner admin revoke-key NAME      # disables the key and ends its browser logins
```

Each key sees only its own scans, suppressions and baselines.

## Retention

Finished scans older than `SCANNER_RETENTION_DAYS` are deleted with their findings and reports. A
long-running worker prunes hourly. Suppressions and baselines are kept. Scans that are queued or
running are never removed, and neither are the files they use.

```bash
scanner admin prune --dry-run      # report only
scanner admin prune --days 30
```

Pruning also removes expired browser sessions and leftovers of crashed scans (only files named like
scan ids, older than a day).

## Monitoring

- `GET /healthz` is liveness; `GET /readyz` also checks the database.
- `GET /metrics` (Prometheus text, enabled by `SCANNER_METRICS_TOKEN`) exposes scans by status, the
  age of the oldest queued scan, failed gates, active keys and a duration histogram. It is read from
  the database, so every process reports the same numbers, and it contains no names or content.
- Logs go to stderr. With `SCANNER_LOG_FORMAT=json` each line has `ts`, `level`, `logger`, `message`
  and, where relevant, `scan_id`, `outcome`, `seconds`, `findings`, `method`, `path`, `status`, `ms`.
  Access logs omit query strings and headers.

Useful alerts: `scanner_queue_oldest_age_seconds` high (workers stuck or too few), a rising `failed`
count, `/readyz` failing.

## Offline scans

With `SCANNER_OFFLINE=1` each scan container gets no network and reads databases from a read-only
mount of the mirror directory.

```bash
scanner admin mirror-update        # on a connected machine; schedule it (daily)
scanner admin mirror-status        # what is present and how old
```

The mirror holds OSV archives (`osv/`) and Trivy's databases (`trivy/`). Copy the directory to
the scanning host if it is air-gapped. Offline OSV-Scanner cannot resolve transitive dependencies
(that needs the network), so it reports fewer findings than an online scan; Trivy still covers
what it can read from lockfiles. Semgrep's registry rules are downloaded at scan time, so
offline runs need a rules directory at `<mirror>/semgrep-rules` that you provide yourself; without
it Semgrep is reported as skipped. Check the licence of any rule set you use.

## Backups

Back up the database and, if you want to keep reports, the `reports` directory. Everything else is
temporary.

## Load testing

```bash
python scripts/loadtest.py --url http://127.0.0.1:8000 --key cs_... --scans 50 --concurrency 10
```

It uploads a small archive, waits for each scan and prints submit latency and submit-to-finished
percentiles. Use `--zip` to test with a real project. Watch `scanner_queue_oldest_age_seconds` and add
workers if queued scans wait too long.
