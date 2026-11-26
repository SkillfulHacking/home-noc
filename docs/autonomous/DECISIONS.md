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
