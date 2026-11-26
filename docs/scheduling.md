# Scheduled discovery and connector polling (M16)

Recurring jobs run through the **same durable queue, lease and worker** as UI-started scans (`docs/scan-jobs.md`). The worker process runs the scheduler on every tick.

## Kinds
| kind | what runs | requires |
|---|---|---|
| `scan` | ICMP discovery (`discovery`) or TCP ports (`ports`) on authorized CIDRs | targets inside the scan policy |
| `snmp_poll` | SNMPv3 identity + interface poll (M13/M15) of the listed devices (or every device that has SNMPv3 credentials) | stored authPriv credentials; device IP inside policy |
| `unifi_sync` | read-only UniFi import (M14) | connector enabled and token stored |

The intrusive `security` profile can never be scheduled (rejected at creation and again at firing).

## API (session + CSRF)
`GET/POST /api/v1/schedules`, `GET/PATCH/DELETE /api/v1/schedules/{id}`.
`POST` body: `{"name", "kind", "profile"?, "targets", "interval_seconds", "jitter_percent"?, "enabled"?}`. Minimum interval 300 s for scans, 60 s for polls; maximum 7 days; jitter 0–25 %.
Pause/resume = `PATCH {"enabled": false|true}`. Resuming reschedules from *now*; missed runs are never replayed.

## Behaviour
- **Times are UTC.** `next_run_at` is stored in UTC; there is no local-time arithmetic, so DST shifts cannot cause skipped or doubled runs.
- **No duplicates:** firing is a compare-and-set on `next_run_at` committed together with the job insert; restarts or multiple workers cannot enqueue the same run twice. A schedule whose previous job is still active waits (no overlap).
- **Backoff:** if the previous job failed, the interval is multiplied ×2 per consecutive failure (cap ×8); success resets it. Jitter of up to `jitter_percent` is added.
- **Budgets:** at most `SCHEDULER_MAX_NEW_JOBS_PER_TICK` (default 5) schedules fire per tick, and the shared `SCAN_MAX_ACTIVE_JOBS` cap applies; a schedule that finds the queue full retries in 60 s.
- **Fail closed:** scan targets are re-authorized against the *live* policy at every firing; an unauthorized schedule enqueues nothing and records `last_error_code`. Workers re-check each device/controller again before any network I/O.
- **last_seen:** scheduled ICMP/SNMP results reconcile like manual ones; only a successful response advances `last_seen`. A poll in which no device answers fails the job (`poll_failed`) and feeds the backoff.

Verified with a deterministic fake clock (`backend/tests/test_scheduler.py`) and API tests; no real network is used.
