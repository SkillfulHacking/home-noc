# Issue #67 — TCP observations not advancing device `last_seen`

**Root cause (verified):** `persist_tcp_scan_result` (`backend/app/port_observations.py`) stored observation rows and added open ports but never touched `Device.first_seen/last_seen`; only the reconcile path (ICMP/connectors) did. So a later successful TCP scan left `last_seen` at the earlier ICMP time.

**Fix:** a host with at least one `open` observation advances `last_seen` to the latest positive observation time (per-observation `observed_at`, falling back to job `finished_at`, clamped to now+5 min). `first_seen` only moves earlier; `last_seen` only moves later (out-of-order scans cannot regress). `refused`, `timeout`, `inconclusive`, unmatched/ambiguous hosts and job completion do not change freshness. Result gains `asset_persistence.last_seen_advanced` (additive).

**Decision:** `refused` is *not* treated as reachability (an RST can come from a middlebox); conservative and reversible. Provenance is unchanged: each scan still writes a `DeviceObservation(source="scan", source_ref="tcp-connect:<job>:<ip>")`.

**Tests:** 8 new tests (+ parametrized) in `backend/tests/test_port_observations.py`; full backend suite 569 passed, 1 skipped; `ruff check` clean. One existing exact-dict assertion updated for the new additive key.

**Limitations:** UI "freshness vs online" distinction and a browser E2E for scan→inventory were not changed here (belongs with #22 health snapshots / #68 UI polish; no UI test run). Verified only with synthetic data.
