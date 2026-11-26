# Issue #18 (M15) — SNMP interface and role enrichment

**Implemented:** `connectors/snmp_interfaces.py` (bounded IF-MIB walk, normalization, role derivation), `snmp_sync.py` (persist via reconcile), route `POST /devices/{id}/snmp/poll`, `PySnmpTransport.walk` (bounded, deadline, USM priming), shared `_raise_for`, extra scalar OIDs (sysServices, ipForwarding, dot1dBaseBridgeAddress). Stacked on #16.
**Decisions:** roles from standard MIB semantics only and applied only to devices without roles; interface MACs never touch device MAC; poll attached to the polled device by IP (mismatch => no write); no schema change (observations carry the interface list).
**Defect found while testing:** walking a fresh USM engine surfaced the discovery REPORT as an error; fixed by priming with an allowlisted GET. Loopback agent needed Next/Bulk responders.
**Tests:** 9 interface tests, 4 poll API tests, real-transport bounded-walk test; backend 599 passed/1 skipped; ruff clean.
**Not verified:** real switch (operator lab step in docs/snmp-connector.md); persistence scheduling is #19.
