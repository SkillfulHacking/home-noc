# Issue #17 (M14) — read-only UniFi connector

**Implemented:** `connectors/unifi.py`, `unifi_sync.py`, routes `/connectors/unifi` (GET/PUT/test/sync), table `connector_settings` (migration 0009, round-trip tested), docs/unifi-connector.md. Stacked on #16 (PR #74) for the connector interface and migration chain.
**Decisions:** (1) Official Integration API (`X-API-KEY`) chosen over legacy cookie login (no password storage). (2) base_url restricted to https IPv4 literal passing scan policy (SSRF/scope safety); hostnames deferred. (3) New non-secret `connector_settings` table for enabled/health state instead of overloading credential metadata. (4) Sync is manual (route); scheduling is #19. (5) Clients imported only with MAC.
**Tests:** 17 connector + 12 API + migration round trip; backend 622 passed/1 skipped; ruff clean.
**Not verified:** real controller; Docker-level run.
