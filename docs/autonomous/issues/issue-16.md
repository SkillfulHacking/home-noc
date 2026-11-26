# Issue #16 (M13) — SNMPv3 read-only poller and connector interface

**Implemented:** `app/connectors/{base,snmp}.py`, route `POST /devices/{id}/snmp/test`, `docs/snmp-connector.md`, dependency `pysnmp` + `pyasn1` (hash-locked).
**Decisions:** (1) pysnmp 7.1.32 over a hand-written USM stack (crypto must not be home-grown; only two new packages, BSD-2). (2) SNMPv2c opt-in **deferred** (issue says optional; avoids new insecure credential type). (3) Port fixed at 161, no override in the API (prevents using the route as an arbitrary UDP prober). (4) Connect-test enforces the runtime scan policy via `resolve_targets(DISCOVERY)`. (5) Values mapped to OIDs by request order because pysnmp returns symbolic names.
**Tests:** 19 connector tests (including real loopback USM agent) + 8 API tests; backend suite 587 passed, 1 skipped; ruff clean.
**Not verified:** UniFi switch lab test (operator action; procedure in docs). Poller persistence into inventory comes with #18/#19.
