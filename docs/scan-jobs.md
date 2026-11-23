# Scan jobs and the worker (M09)

Scans never run inside the API. `POST /api/v1/scans/jobs` validates the request
against the authorized scope ([scan-scope.md](scan-scope.md)) and queues a row in
`scan_jobs`; a separate **worker** container polls the database, runs the scanner and
records progress and events. No Redis or other service is involved: SQLite rows plus
time-limited leases are the queue.

## API (all routes need a session; unsafe methods need the CSRF header)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/scans/jobs` | Queue a scan. Body `{"targets": [...], "profile": "discovery"}` (same schema as `/scans/preflight`; unknown fields are rejected). `202` + job. `403` out of scope / profile disabled, `429` too many active jobs. |
| GET | `/api/v1/scans/jobs?status=&limit=` | Recent jobs. |
| GET | `/api/v1/scans/jobs/{id}` | Status, `progress {done,total,percent}` (addresses), attempts, error, result. |
| GET | `/api/v1/scans/jobs/{id}/events?after=<cursor>&limit=` | Poll events. Pass the previous response's `next_after` as `after`; stop when `terminal` is true. |
| POST | `/api/v1/scans/jobs/{id}/cancel` | Cancel. Idempotent; `409` if the job already succeeded/failed. |

Lease owner, lease expiry and process ids are never returned.

## Lifecycle

```
queued -> running -> succeeded | failed | cancelled
              |   \-> cancelling -> cancelled
              \-> queued   (retry with backoff, crash recovery, clean worker shutdown)
```

Every transition is a single guarded `UPDATE`, and worker writes are conditioned on
still owning the lease, so a worker that lost its lease cannot overwrite the new owner.

* **Concurrency:** `WORKER_MAX_CONCURRENT_JOBS` (default 1, max 4) is enforced inside the
  atomic claim, so it holds across worker processes. `SCAN_MAX_ACTIVE_JOBS` (default 5)
  bounds the queue; excess starts get `429`.
* **Retries:** `SCAN_JOB_MAX_ATTEMPTS` (default 3) with exponential backoff
  (`SCAN_JOB_RETRY_BACKOFF_SECONDS`, capped at 300 s). Scanner failures and unexpected
  worker errors retry. Timeouts, a missing scanner and scope rejections do not.
* **Timeouts:** each profile's `timeout_seconds` bounds the whole job.
* **Progress:** targets are split into chunks of at most 32 addresses, one scanner
  invocation each; progress is addresses covered. Per-chunk events are recorded
  (each job keeps at most 500 non-lifecycle events).
* **Cancellation:** a queued job ends at once. A running job is flagged; the worker sees
  it on its next heartbeat (about 1 s) and stops the scanner.
* **Scope is checked twice:** at enqueue and again by the worker right before running,
  so narrowing `SCAN_ALLOWED_CIDRS` stops jobs already queued.

## No orphaned scanners

The scanner runs in its own session/process group with a fixed argv (never a shell, no
operator flags, minimal environment without application secrets). Cancel, timeout, lost
lease and worker shutdown send SIGTERM to the **group**, escalate to SIGKILL after
`WORKER_KILL_GRACE_SECONDS`, then sweep stragglers.

* **Worker restart:** the worker id is the container hostname, so a restarted worker
  recovers its own jobs immediately and kills a leftover scanner group recorded in
  `runner_pid`. It only does that when the pid is still a group leader whose command
  line contains the scanner binary, and never for another worker's jobs.
* **Worker crash:** jobs whose lease (`WORKER_LEASE_SECONDS`, default 30 s) lapses are
  requeued, or failed when attempts are exhausted. Killing the container also tears down
  its PID namespace, which removes the scanner.
* **Clean stop (SIGTERM):** scanners are stopped and jobs requeued without using an
  attempt. Compose gives the worker 30 s (`stop_grace_period`).
* Run **one worker process per hostname**; two with the same id would recover each
  other's jobs.

## Deployment and safe defaults

The `worker` Compose service is built from the `worker` stage of `backend/Dockerfile`
(the only image containing nmap). It runs as UID 10001, read-only root, `cap_drop: ALL`,
`no-new-privileges`, with `pids_limit` and `mem_limit`, publishes no port, and does not
receive the credential-encryption key. It shares only the `api_data` volume.

Because it has no capabilities, profiles use TCP connect probes (`-sT`, `-sn`), so
discovery is an IP-level reachability check rather than ARP, and it sees the LAN through
Docker's network. Host networking or `NET_RAW` are deliberately **not** enabled. The
intrusive `security` profile remains off unless `SCAN_SECURITY_PROFILE_ENABLED=true`.

Results (`result.hosts`) are stored on the job only; writing them into the inventory is
outside this issue.

## Verification

```bash
cd backend
env -u ANTHROPIC_API_KEY ruff check .
env -u ANTHROPIC_API_KEY python -m pytest -q tests/test_jobs_service.py tests/test_worker.py \
  tests/test_scan_jobs_api.py tests/test_migration_scan_jobs.py
env -u ANTHROPIC_API_KEY python -m pytest -q
cd .. && env -u ANTHROPIC_API_KEY docker compose config
```
