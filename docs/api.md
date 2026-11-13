# REST API

Interactive documentation is served at `/docs`.

## Authentication

Send an API key as `X-API-Key: cs_...` or `Authorization: Bearer cs_...`. The web UI instead trades a key for
a cookie at `POST /ui/session`; cookie requests that change data must send `X-Requested-With:
scanner-ui` and come from the same origin.

## Scans

| Method and path | Purpose |
| --- | --- |
| `POST /scans` | Queue a scan; returns `202 {scan_id, status}` |
| `GET /scans` | Your scans, newest first (`status`, `source`, `limit`, `offset`) |
| `GET /scans/{id}` | Status, gate, health score, tool results, counts, diff and baseline info |
| `GET /scans/{id}/findings` | Findings (`severity`, `category`, `tool`, `new`, `suppressed`, `limit`, `offset`) |
| `GET /scans/{id}/report?format=` | `json`, `md`, `html` or `sarif` |

`POST /scans` takes either a multipart `file` (a zip) or JSON:

```json
{ "git_url": "https://github.com/owner/repo.git", "ref": "HEAD", "base": "main", "baseline_id": 3 }
```

`base` makes it a diff scan (only findings new in `ref` count). `baseline_id` (also a form field for
uploads) accepts the findings recorded in that baseline. Statuses: `queued`, `running`, `done`, `failed`.

## Suppressions and baselines

| Method and path | Purpose |
| --- | --- |
| `GET /suppressions` | List |
| `POST /suppressions` | `{scan_id, fingerprint, reason, expires}`; expiry must be in the future and at most a year away |
| `DELETE /suppressions/{id}` | Remove; affected scans are re-evaluated |
| `POST /scans/{id}/baseline` | `{name}`: record the scan's current findings |
| `GET /baselines`, `DELETE /baselines/{id}` | List, delete |

A suppression applies to later scans of the same source (the upload name or git URL).

## History

`GET /sources` lists what you have scanned; `GET /trends?source=` returns health score and finding
counts per finished scan.

## Operational

`GET /healthz`, `GET /readyz`, `GET /metrics` (bearer `SCANNER_METRICS_TOKEN`).

## Limits

Uploads over `SCANNER_MAX_UPLOAD_MB` get `413`. Exceeding the per-key hourly limit gives `429` with
`Retry-After`; a full queue gives `503`.
