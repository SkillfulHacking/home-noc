# Decision log

## D-001 — Shared runner library (2026-11-26, #71)
- Problem: both runners duplicated billing/limit/tool/report logic.
- Alternatives: copy-paste; single combined script; sourced `scripts/lib/claude-common.sh` + Python helpers.
- Selected: sourced shell lib + `validate_report.py`, `issue_context.py`, `gitar_feedback.py` (run with `python3 -I`).
- Security: one place defines tool restrictions (Read/Edit/Write/Glob/Grep, Bash disallowed, hooks/MCP off, no `--bare`). Compatibility: scripts now depend on `scripts/lib/`. Reversible: yes. Operator review: recommended (default billing flipped to API).

## D-002 — Exit code 3 for incomplete runs (2026-11-26, #71)
- Turn/budget exhaustion (`subtype` error_max_*) is resumable work, not failure; exit 3 distinguishes it. Reversible.

## D-003 — Lock shared between issue and review runners (2026-11-26, #71)
- Lock lives at `.claude-issue/issue-<n>/run.lock` in the main checkout (derived from PR branch name; `pr-<n>` otherwise).

## D-004 — Gitar actionable definition (2026-11-26, #71)
- Actionable = unresolved Gitar review thread, or latest Gitar review CHANGES_REQUESTED. Summary comments are context only; no actionable item ⇒ no model call.

## D-005 — Worktree permissions (2026-11-26, #71)
- State dir/reports 0700/0600 (umask 077); worktree creation and Claude's file writes run under umask 022 so Docker builds can read sources.

## D-006 — Helpers read stdin/fds, not argv paths (2026-11-26, #71/PR #72)
- Sonar flagged path traversal on CLI paths. Selected: Python helpers read stdin or fds 3-5; bash owns file redirection. Reversible; improves safety.

## D-007 — TCP `refused` is not reachability (2026-11-26, #67/PR #73)
- Only `open` advances `last_seen`; RSTs can come from middleboxes. Conservative, reversible.

## D-008 — pysnmp dependency; SNMPv2c deferred (2026-11-26, #16/PR #74)
- Use pysnmp 7.1.32 (+pyasn1) rather than custom USM crypto; hash-locked, pip-audit clean. v2c opt-in deferred (optional in issue). Operator review recommended for the new dependency.

## D-009 — Stacked PRs for dependent issues (2026-11-26)
- Operator must merge PRs; to avoid stalling, dependent issues branch from the predecessor's branch and are noted as stacked. Reversible.

## D-010 — Connector jobs share the scan_jobs queue (2026-11-26, #19/PR #77)
- Alternatives: separate poll queue/service; thread in API process. Selected: new job `kind`s dispatched in the existing worker (single lease/cap model, no new service). Reversible.

## D-011 — UniFi: Integration API, https IPv4 literal base_url inside scan policy (#17/PR #75)
- Token-based API avoids storing a controller password; IP-only + policy check prevents SSRF/out-of-scope targets. Hostnames deferred. Operator review recommended (UDM users may expect hostnames).

## D-012 — Health derivation rules (#22/PR #78)
- Per-source windows, 3-failure confirmation, ever-succeeded sources only; auth/permission SNMP errors count as alive. Windows are static constants — tune to schedules.

## D-013 — Separate connector-worker preserves the credential-key boundary (2026-11-26, #19/PR #77)
- Problem: #19 ran SNMP/UniFi jobs in the scanner worker, which by design has no credential key; it would have failed in production.
- Alternatives: give the scanner worker the key (rejected: key beside the process parsing untrusted network content); run polling in the API process; new service. Selected: `connector-worker` (api image, no scanner binary, key as read-only secret) with job-kind filtering (`WORKER_JOB_KINDS`) and per-kind-group concurrency caps. Operator-approved in principle.
- Verified on real containers (isolated compose project): isolation, health, and an enqueued job claimed by the connector worker. New long-running service: justified by security separation.

## D-014 — Nuclei: known-HTTP-ports only + plan-digest approval (2026-11-26, #20/PR #80)
- Targets never guessed or expanded; operator approves a digest of the exact plan; worker re-verifies. Pinned checksum-verified binary/templates. Operator review recommended.

## D-015 — UI stack order and prefill-only scan hand-off (2026-11-26, #28/#26/#27/#68)
- Frontend work stacked after the backend so UIs build against real APIs; inventory "scan selected" only prefills the Scans page (all authorization stays server-side). Reversible.

## D-016 — Findings resolve only after 2 consecutive conclusive misses with positive host evidence (#21/PR #81)
- Avoids flapping from silently failed requests. Adds `missed_runs` to unmerged migration 0013.

## D-017 — Production hardening choices (#30/PR #87)
- API docs/schema off in prod; strict CSP (keeps style-src 'unsafe-inline' for React inline styles); 256 KiB body cap; `.dockerignore` files. Accepted risks listed in docs/security.md. Operator review recommended.

## D-018 — Backup/restore guards all four services; rollback = restore (#31/PR #88)
- restore.sh refuses while backend/worker/connector-worker/frontend containers exist; documented rollback prefers restore over alembic downgrade.
