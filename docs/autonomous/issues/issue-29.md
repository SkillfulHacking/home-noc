# Issue #29 (M26) — end-to-end integration suite

**Implemented:** `backend/tests/test_e2e_pipeline.py` (6 tests), docs/testing.md section. Stacked on #68 (#85), i.e. the whole stack.
**Verified:** the full pipeline test (ping → ports → dedup → SNMP+UniFi → findings → health/events/secret scan) and 5 fault tests pass; backend suite result recorded on the PR.
**Limits (explicit):** ICMP/TCP edges use executor result fixtures rather than live sockets (scope policy forbids loopback targets); the browser flow in CI uses the mocked API, not a compose stack driven by a browser; no real UniFi/SNMP hardware. A compose-level browser E2E remains a follow-up.
