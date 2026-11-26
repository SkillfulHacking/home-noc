# Changelog

## 0.1.0-beta.1 (unreleased — pending operator merge of the PR stack)

First MVP beta. Authentication, canonical inventory, scanning, connectors, health, events, findings and UI.

### Added
- **Discovery and scanning:** ICMP discovery and bounded TCP port scans through a durable job queue and an unprivileged scanner worker; runtime scan policy with an immutable deployment ceiling (M08A); TCP open ports now advance `last_seen` (#67).
- **SNMPv3 (authPriv only):** read-only identity poller, bounded interface inventory and standards-based role derivation (M13, M15).
- **UniFi Network 9+:** read-only controller import via the Integration API (M14).
- **Scheduling:** interval schedules for scans, SNMP polls and UniFi sync with exactly-once firing, backoff and jitter (M16); a separate **connector-worker** service holds the credential key so the scanner worker never does.
- **Health and events:** derived online/degraded/offline/unknown status with snapshots (M19); deduplicated operational events with history API (M20).
- **Vulnerability findings (opt-in):** curated read-only Nuclei profile with plan approval, pinned checksum-verified binary/templates (M17); persisted, deduplicated findings with lifecycle and audit trail (M18).
- **UI:** operations overview and timeline (M25), connector setup (M23), findings and approval-gated vulnerability scans (M24), sortable inventory table with numeric IP sort, bulk scan hand-off and auth-aware navigation (#68).
- **Hardening:** production API docs disabled, CSP and browser headers, `.dockerignore`, scan-target bypass regression tests, threat model and runbook (M27, `docs/security.md`).
- **Operations:** canonical `docs/openapi.json` with a drift test, release/upgrade/rollback guide, scan safety guide, supported-devices matrix, end-to-end pipeline tests (M26).
- Claude/Gitar development runner reliability fixes (#71).

### Changed
- `restore.sh` now refuses to run while any of backend, worker, connector-worker or frontend containers exist.
- The landing page is now the operations overview.

### Upgrade notes
- Database migrations 0009–0013 are applied automatically at backend start (`alembic upgrade head`). **Back up first** (`scripts/backup.sh`). See `docs/release.md`.
- New service `connector-worker` needs the same credential-key secret as `backend`; `worker` must **not** receive it.
- `SCAN_VULN_PROFILE_ENABLED` is off by default.

### Known limitations
See `docs/supported-devices.md` and `docs/release.md#known-limitations`.
