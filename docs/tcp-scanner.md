# M11 — Controlled TCP connect scans

The `ports` profile uses unprivileged TCP connect sockets. It does not invoke
Nmap, use raw sockets, probe UDP, or perform service-version detection. The
existing worker's Docker isolation remains unchanged.

## Authorization and execution

- Only IPv4 addresses/CIDRs accepted by M08's explicit allowlist are scanned.
  Every queued scan is revalidated immediately before execution.
- `POST /api/v1/scans/preflight` is dry-run only and opens no sockets.
- The scan uses M09's durable jobs, status/events polling, and cancellation.
- Default ports: 22,53,80,111,135,139,443,445,548,631,2049,3306,3389,
  5000,5432,5900,8000,8080,8443,9100.
- Operator settings: `SCAN_TCP_PORTS`, `SCAN_TCP_MAX_PORTS` (20),
  `SCAN_TCP_CONNECTIONS_PER_SECOND` (20),
  `SCAN_TCP_CONNECTION_TIMEOUT_SECONDS` (1), and
  `SCAN_TCP_MAX_TOTAL_CONNECTIONS` (5120).
- The ports profile allows at most 256 authorized hosts, 8 concurrent
  connections, and a 900-second job deadline. No elevated privileges are
  needed. Connection starts are rate-limited by the scanner scheduler.
- Cancellation/deadline stops scheduling new connections; in-flight TCP
  connects may take up to their finite socket timeout to finish.
- Scan networks only with explicit authorization; the default is nonintrusive.

## Results and inventory

- Per-port states: `open`, `refused`, `timeout`, or `inconclusive`, each with
  an observation timestamp. Missing responses are never proof a host is offline.
- Successful jobs append newly observed open ports to existing asset `ports`,
  without changing curated ports or erasing them after negative results.
- Each source observation uses scan-job **and host IP** for its reference so
  multiple IP addresses on one asset do not overwrite each other.
- Unmatched/ambiguous IPs are retained only in job results; no new identities
  are invented. Historical TCP observations are capped at 100 per asset,
  retaining observations from unrelated sources.
- The saved job result contains `asset_persistence` counts of matched unique
  assets, newly added open ports, unmatched hosts, and ambiguous hosts.

## Local verification

From `backend` using a disposable test-only SQLite DB (not a live LAN):

```bash
python -m ruff check .
PYTHONPATH=. APP_ENV=test DB_URL=sqlite:///./test.db \
  python -m pytest -q tests/test_tcp_scanner.py tests/test_port_observations.py \
  tests/test_tcp_runner.py
PYTHONPATH=. APP_ENV=test DB_URL=sqlite:///./test.db python -m pytest -q
```

The only real socket test binds to local loopback `127.0.0.1`. All other
TCP probes in the tests use injected fake connectors.
