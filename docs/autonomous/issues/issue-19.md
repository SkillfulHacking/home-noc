# Issue #19 (M16) — periodic discovery and connector polling

**Implemented:** `schedules` table (migration 0010, round-trip tested), `app/scheduler.py` (pure `tick(db, clock, rng)`), `app/connector_jobs.py` (`snmp_poll`, `unifi_sync` executors), worker dispatch by job kind + scheduler tick, `/api/v1/schedules` CRUD with pause/resume, `jobs.enqueue_scan(kind=, commit=)`, shared `connectors/snmp_service.py` (route + worker), docs/scheduling.md. Branch merges #17 and #18 (stacked).
**Decisions:** UTC-only times (timezone-safe by construction); CAS-in-transaction for exactly-once enqueue; missed runs skipped; intrusive profile never schedulable; connector jobs reuse the scan_jobs queue with `kind` (no second queue/service); backoff derived from previous job outcome at next fire.
**Tests:** 18 scheduler (fake clock, races, restart, backoff, budgets, fail-closed, end-to-end ICMP/SNMP/UniFi via worker) + 8 API + migration; backend 671 passed/1 skipped on file-backed SQLite; ruff clean.
**Limits:** no calendar/cron windows (interval only); UI for schedules belongs to later UI milestones; not run against real devices.
