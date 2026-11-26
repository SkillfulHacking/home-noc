# Issue #20 (M17) — Nuclei opt-in low-impact scanner

**Implemented:** `vuln` profile (`scan_scope`), `SCAN_VULN_PROFILE_ENABLED` switch, `app/nuclei.py` (plan, approval digest, fixed argv, JSONL parser, bounded process-group runner), `app/redaction.py`, approval flow in `/scans/preflight` and `/scans/jobs`, worker dispatch, pinned checksum-verified binary/templates in the worker image, docs/nuclei.md. Stacked on #23 (includes the connector-worker fix).
**Decisions:** URLs only from already-known open HTTP ports (never guess/expand); plan-digest approval stored on the job and re-verified by the worker; explicit template allowlist instead of tag filtering; vuln profile intrusive-class (no public targets); scanner worker keeps no credential key.
**Verified:** 746+ backend tests incl. 20 Nuclei tests; real pinned Nuclei vs loopback lab on host and inside the built worker image.
**Limits:** persistence of findings is #21; no LAN lab verification; the `DEBUG` verb probe of the ASP.NET template is a read-only but unusual request.
