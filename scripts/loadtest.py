"""Load test for a running scan server: submit many scans, wait for them, report timings.

    python scripts/loadtest.py --url http://127.0.0.1:8000 --key cs_... --scans 50 --concurrency 10

The server and at least one worker must be running. It uploads a small generated zip, so it
measures queueing and API behaviour, not scanner speed on large projects (use --zip for that).
"""

import argparse
import io
import statistics
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import httpx

SAMPLE_FILES = {
    "proj/app.py": "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n",
    "proj/util.py": "def add(a, b):\n    return a + b\n",
}


@dataclass
class Outcome:
    submit_seconds: float
    total_seconds: float | None
    status: str  # done | failed | timeout | rejected:<code> | error


def sample_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, text in SAMPLE_FILES.items():
            zf.writestr(name, text)
    return buffer.getvalue()


def one_scan(client: httpx.Client, archive: bytes, wait: float, poll: float) -> Outcome:
    started = time.monotonic()
    try:
        response = client.post("/scans", files={"file": ("loadtest.zip", archive)})
    except httpx.HTTPError:
        return Outcome(time.monotonic() - started, None, "error")
    submitted = time.monotonic() - started
    if response.status_code != 202:
        return Outcome(submitted, None, f"rejected:{response.status_code}")
    scan_id = response.json()["scan_id"]
    deadline = started + wait
    while time.monotonic() < deadline:
        try:
            state = client.get(f"/scans/{scan_id}").json()["status"]
        except (httpx.HTTPError, KeyError, ValueError):
            return Outcome(submitted, None, "error")
        if state in {"done", "failed"}:
            return Outcome(submitted, time.monotonic() - started, state)
        time.sleep(poll)
    return Outcome(submitted, None, "timeout")


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def summarise(outcomes: list[Outcome], elapsed: float) -> str:
    lines = [f"{len(outcomes)} scans in {elapsed:.1f}s ({len(outcomes) / elapsed:.2f} scans/s)"]
    by_status: dict[str, int] = {}
    for outcome in outcomes:
        by_status[outcome.status] = by_status.get(outcome.status, 0) + 1
    lines.append("outcomes: " + ", ".join(f"{k}={v}" for k, v in sorted(by_status.items())))
    submits = [o.submit_seconds for o in outcomes]
    lines.append(
        f"submit latency: p50 {statistics.median(submits):.3f}s, "
        f"p95 {percentile(submits, 0.95):.3f}s, max {max(submits):.3f}s"
    )
    totals = [o.total_seconds for o in outcomes if o.total_seconds is not None]
    if totals:
        lines.append(
            f"submit to finished: p50 {statistics.median(totals):.1f}s, "
            f"p95 {percentile(totals, 0.95):.1f}s, max {max(totals):.1f}s"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--key", required=True, help="API key (it is not stored anywhere)")
    parser.add_argument("--scans", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--zip", type=Path, help="Upload this archive instead of the sample")
    parser.add_argument("--wait", type=float, default=600, help="Seconds to wait per scan")
    parser.add_argument("--poll", type=float, default=1.0, help="Seconds between status checks")
    args = parser.parse_args()
    if args.scans < 1 or args.concurrency < 1:
        parser.error("--scans and --concurrency must be at least 1")

    archive = args.zip.read_bytes() if args.zip else sample_zip()
    headers = {"X-API-Key": args.key}
    started = time.monotonic()
    with httpx.Client(base_url=args.url, headers=headers, timeout=60) as client:
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = [
                pool.submit(one_scan, client, archive, args.wait, args.poll)
                for _ in range(args.scans)
            ]
            outcomes = [f.result() for f in futures]
    print(summarise(outcomes, time.monotonic() - started))
    return 0 if all(o.status == "done" for o in outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
