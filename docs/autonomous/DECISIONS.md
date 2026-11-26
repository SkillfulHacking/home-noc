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
