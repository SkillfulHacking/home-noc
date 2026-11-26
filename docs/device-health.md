# Device health (M19)

Health is a **derived status** (`online`, `degraded`, `offline`, `unknown`) stored per device in `device_health`, with a lightweight history in `health_snapshots`. It is separate from inventory freshness (`last_seen`).

## Evidence
| source | success | failure |
|---|---|---|
| `icmp` | device answered an echo scan | known device inside the scanned targets did not answer (weak) |
| `snmp` | SNMPv3 poll succeeded | poll `timeout`/`snmp_error` (auth/permission errors mean the device *answered* and are not failures) |
| `tcp` | at least one open port | — (a closed port is not a device failure) |
| `unifi` | controller reports the device ONLINE (or a client connected) | controller reports OFFLINE/DISCONNECTED (authoritative: confirmed at once) |

## Rules (`app/health.py::evaluate`)
Freshness windows (success older than this is stale): icmp 15 min, snmp 15 min, unifi 30 min, tcp 60 min. A failure counts only after **3 consecutive** failures; a source with confirmed failures is no longer considered fresh even if its last success is recent (authoritative reports confirm immediately). Only sources that have succeeded at least once for the device can count against it.

1. never observed successfully → `unknown`
2. a fresh source and no confirmed-failing source → `online`
3. a fresh source but another confirmed-failing source → `degraded`
4. nothing fresh and a confirmed-failing source → `offline`
5. nothing fresh, failures present but unconfirmed → `degraded`
6. nothing fresh, no failures → `unknown` (we simply have not looked recently)

So an SNMP-only switch that has never answered ICMP is never offline because of ICMP, and one blocked ping never marks a device offline. Out-of-order evidence (older than the stored attempt) is ignored. The worker re-derives statuses once a minute so windows lapse without new events.

## API (session required)
- `GET /api/v1/health/devices?status=&limit=&offset=` → `summary` counts (`total, online, degraded, offline, unknown`; devices with no health row count as unknown), per-device status, reason, `last_success_at`, `last_attempt_at`, `status_changed_at`, `last_seen`, per-source evidence, and the freshness windows.
- `GET /api/v1/devices/{id}/health?history=50` → the same plus recent snapshots.

TCP evidence needs the TCP last_seen fix (#67, PR #73), which this branch merges.

Snapshots are written on every status transition plus an hourly heartbeat and pruned to 500 per device; there is no external telemetry system.

Limits: windows are fixed defaults (tune `FRESH_SECONDS` to your schedule intervals); the dashboard UI is milestone #28.
