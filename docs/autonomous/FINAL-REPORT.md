# Home-NOC MVP campaign — final report (checkpoint 5, 2026-11-26)

## Executive summary
- **Outcome:** every MVP issue (#16–#23, #26–#31, #67, #68) and the runner issue #71 now has an implementation PR (#72–#88). **No PR is merged** — merging is reserved to the operator. The stack is internally consistent: backend 889 tests, frontend 151 unit tests and 44 browser tests pass at the top of the stack; CI was green on #72–#87 at the last query.
- **MVP readiness:** *feature-complete and automatically verified; awaiting operator acceptance.* Not verified: real UniFi controller, SNMPv3 switch, LAN ICMP/TCP scans, a lab HTTP service for Nuclei, the sample /24 + UniFi + SNMP demo, an independent pentest, published/tagged images.
- **Major achievements:** durable scan queue extended to scheduled scans, SNMPv3 and UniFi jobs; credential-key isolation between scanner and connector workers (a defect I introduced in #19 and caught myself); health, events and findings pipelines with deduplication and redaction; opt-in, approval-gated Nuclei with pinned verified binaries; operations/connector/findings UIs; security hardening with a threat model; release guide verified on real containers (fresh install, upgrade 0008→0013, backup/restore).
- **Remaining risks:** see the operator queue and `docs/release.md#known-limitations`.
- **Why the campaign stopped:** all authorized MVP work is done; remaining items need operator merges and real hardware. Post-MVP issues (#32–#47, #69) were intentionally not started. Budget was not the limiting factor.

## Issue disposition
| Issue | Title (short) | PR | Status | Acceptance |
|---|---|---|---|---|
| #71 | Claude/Gitar runner reliability | #72 | PR open, CI green | offline tests (42), ShellCheck; no live Claude spend in tests |
| #67 | TCP observations advance last_seen | #73 | PR open | backend tests; UI/E2E for this path covered later by the pipeline test |
| #16 | M13 SNMPv3 poller | #74 | PR open | loopback SNMPv3 agent + fakes; **lab test with a UniFi switch pending (operator)** |
| #17 | M14 UniFi connector | #75 | PR open | mocked controller; **real controller pending** |
| #18 | M15 SNMP interfaces/roles | #76 | PR open | fixtures + loopback walk; real switch pending |
| #19 | M16 scheduling | #77 | PR open | fake-clock tests; real-container job via connector-worker |
| #22 | M19 health | #78 | PR open | rule/transition unit tests, API, worker sweep |
| #23 | M20 events | #79 | PR open | dedupe/flapping/ack/pagination tests |
| #20 | M17 Nuclei | #80 | PR open | scripted binary tests + real pinned binary on loopback and in the image; LAN lab pending |
| #21 | M18 findings | #81 | PR open | lifecycle/dedupe/redaction tests |
| #28 | M25 overview UI | #82 | PR open | vitest + Playwright (mocked API) |
| #26 | M23 connector UI | #83 | PR open | vitest + Playwright incl. masked-secret assertions |
| #27 | M24 findings UI | #84 | PR open | vitest + Playwright incl. approval flow |
| #68 | inventory/scan polish | #85 | PR open | vitest + Playwright; no formal a11y audit |
| #29 | M26 e2e suite | #86 | PR open | full pipeline + 5 fault tests; ICMP/TCP edges are fixtures; CI browser flow uses mocked API |
| #30 | M27 hardening | #87 | PR open | bypass/docs/redaction tests, CSP verified on built image; not a pentest |
| #31 | M28 beta docs/backup | #88 | PR open | fresh install, upgrade, backup/restore verified on real containers; **lab demo pending** |
| #32–#47, #69 | fast-follows | — | not started (out of MVP scope) | — |
| #48 | roadmap tracking | — | unchanged | — |

Per-issue summaries are in `docs/autonomous/issues/` on the respective branches (all are merged forward into the top-of-stack branch of PR #88).

## Autonomous decision register (highlights; full text in DECISIONS.md)
- **Architecture:** shared runner library (D-001); connector jobs share the `scan_jobs` queue (D-010); **separate connector-worker** keeps the credential key away from the scanner (D-013, operator-approved in principle); stacked PRs (D-009).
- **Security:** exactly-once CAS scheduling, fail-closed re-authorization (D-003–D-005 area); Nuclei plan-digest approval and known-HTTP-ports-only targets (D-014); production docs off, CSP, `.dockerignore` (D-017); health/finding conservatism (D-012, D-016).
- **Dependencies introduced:** `pysnmp` + `pyasn1` (hash-locked, pip-audit clean); pinned Nuclei and templates in the worker image. **Operator awareness recommended** for both.
- **Compatibility:** default runner billing flipped to API; new `connector-worker` Compose service; migrations 0009–0013; landing page replaced by the overview.
- **Defects I found in my own work and fixed (disclosed on the PRs):** key-boundary violation in #19; a TCP health hook that silently did not apply in #22; plan-digest mismatch between API and worker in #20 (found by Gitar); health rule letting a failing source stay "fresh"; ICMP miss accounting over-charging devices.
- **Honesty notes:** regression tests were generally written together with fixes and **not** observed failing first; this is stated on the PRs where relevant.

## Validation evidence
See `VALIDATION.md` for the command-level record. Headline: backend 889 passed / 2 skipped; frontend 151 + 44 browser tests; ruff/eslint/tsc clean; ShellCheck on runner scripts; real-container fresh install, upgrade, backup/restore and key-isolation checks; real pinned Nuclei run; CI and Gitar results per PR on GitHub. Security scans: `pip-audit` clean for the lock (checked when pysnmp was added), CI runs `pip-audit`, `npm audit`, Trivy. Gaps: no hardware, no pentest, no compose-level browser E2E.

## Budget report
Allocation $80, reserve $8 (untouched). Reported spend: $8.32 (earlier legs, conservative) + ~$15.9 (this leg) ≈ **$24.2**; estimated usable remaining ≈ **$47.8**. Methodology: harness-reported per-invocation cost, never summing cumulative resumed-session values; no separate paid Claude invocations were launched by the agent. Uncertainty: no billing interface is available, so actual balance is unverified.

## Operator action queue (prioritized)
1. **Review and merge** #72 and #73 (independent), then the stack bottom-up #74 → #75/#76 → #77 → #78 → #79 → #80 → #81 → #82 → #83 → #84 → #85 → #86 → #87 → #88, retargeting each base to `main` after its predecessor merges (GitHub offers this automatically). Re-check CI/Gitar on each after retarget.
2. **Review decisions** D-001 (API billing default), D-008 (pysnmp), D-011 (UniFi IPv4-only), D-013 (connector-worker), D-014 (Nuclei), D-017 (CSP/docs off).
3. **Hardware acceptance** (B-001): follow `docs/snmp-connector.md` (UniFi switch), `docs/unifi-connector.md` (UDM), `docs/nuclei.md` (lab HTTP service) and run the sample /24 demo; record results in the issues.
4. Decide whether to **publish tagged images** (commands in `docs/release.md`; nothing was pushed).
5. If using the runner scripts: set `ANTHROPIC_API_KEY` (API mode is now default) or `CLAUDE_BILLING=subscription` explicitly.
6. Optional: remove my test images/volumes if any remain (`hn-*` tags, `/tmp/hn-*`).

## Deployment instructions
```bash
git checkout <merged main or the #88 branch>
bash scripts/bootstrap.sh --http          # (omit --http behind TLS) creates backend/.env and secrets/credential_key
docker compose up -d --build --wait       # backend, worker, connector-worker, frontend
docker compose ps                         # all four "healthy"
curl -s http://127.0.0.1:3000/api/health  # UI at http://127.0.0.1:3000
```
Initial configuration: sign in; Scan policy → authorize your LAN ranges/exclusions; Scans → discovery then ports; Connectors → UniFi token + SNMPv3 credentials + schedules; Overview for health/events. Acceptance tests: `docs/testing.md` (backend `pytest`, frontend `npm test`/`npm run test:e2e`, `./scripts/compose-smoke-test.sh`). Backup: `bash scripts/backup.sh` (plus `secrets/credential_key` separately). Rollback: `docs/release.md#rollback` (restore, never `down -v`).

## Continuation instructions
1. `git fetch`; check PR states (`gh pr list`); after merges, retarget/rebase nothing manually — merge forward only if a base changed.
2. For any change, work on a branch/worktree from the stack tip; run the full suites listed in VALIDATION.md; keep migrations linear after 0013.
3. Next candidates: hardware validation fixes, compose-level browser E2E, fast-follows in priority order (#39 alerts, #38 IPv6/mDNS, #44 exports, #33 Wazuh, #32 MQTT).
4. Update this ledger at each checkpoint; budget guidance in BUDGET.md.
