#!/usr/bin/env bash
# Run one issue with an existing Claude subscription login, or linked Console API credits.
# Usage: ./scripts/claude-issue.sh 4
# API credits: CLAUDE_BILLING=api ANTHROPIC_API_KEY=... ./scripts/claude-issue.sh 4
# No commit, push, PR creation or merge is performed automatically.
set -euo pipefail

usage() { echo "Usage: $0 <numeric-github-issue>" >&2; exit 2; }
fail() { echo "ERROR: $*" >&2; exit 1; }
[[ ${1:-} =~ ^[0-9]+$ ]] || usage
ISSUE="$1"
REPO="SkillfulHacking/home-noc"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v claude >/dev/null || fail "Claude CLI is not installed"
command -v gh >/dev/null || fail "GitHub CLI (gh) is not installed"
# Explicit billing selection prevents accidental API-credit spending.
# subscription: use the existing Claude Code OAuth login and its plan limits.
# api: requires a Console API key from the org linked to the monthly API credits.
CLAUDE_BILLING="${CLAUDE_BILLING:-subscription}"
case "$CLAUDE_BILLING" in
  subscription)
    [[ -z "${ANTHROPIC_API_KEY:-}" && -z "${ANTHROPIC_AUTH_TOKEN:-}" ]] ||
      fail "Subscription mode found API credentials in your environment; unset them or choose CLAUDE_BILLING=api"
    ;;
  api)
    [[ -n "${ANTHROPIC_API_KEY:-}" ]] ||
      fail "API-credit mode requires ANTHROPIC_API_KEY from your linked Console organization"
    ;;
  *) fail "CLAUDE_BILLING must be 'subscription' or 'api'" ;;
esac
[[ -z "$(git status --porcelain)" ]] || fail "Working tree is not clean; commit/stash changes before starting another issue"
[[ "$(git branch --show-current)" == "main" ]] || fail "Start on main, not an existing feature branch"
gh auth status >/dev/null || fail "Run gh auth login first"

TITLE="$(gh issue view "$ISSUE" --repo "$REPO" --json title --jq '.title')"
BODY="$(gh issue view "$ISSUE" --repo "$REPO" --json body --jq '.body')"
[[ -n "$TITLE" && -n "$BODY" ]] || fail "Unable to fetch issue title/body"

# Avoid editing main; always start from the current remote default branch.
git fetch origin main
BRANCH="feat/home-noc-issue-$ISSUE"
git switch -c "$BRANCH" origin/main

PROMPT="$(cat <<EOF
Implement exactly GitHub issue #$ISSUE for $REPO.
Title: $TITLE

Issue requirements:
$BODY

You are working on feature branch $BRANCH. Follow the repository instructions
in CLAUDE.md (supplied as an appended system prompt). Implement code, focused
tests and documentation; do not execute commands in this unsandboxed CLI run.
Do NOT commit, push, create a PR, bypass security safeguards, or read real
secrets. Stop when the issue is completed or when a blocker/budget is reached.
Return: changes, exact manual verification commands (not executed), remaining risks,
and the next steps needed before a human opens the PR.
EOF
)"

# Estimated client-side cap, not a guaranteed maximum billed amount.
MAX_BUDGET_USD="${MAX_BUDGET_USD:-8}"
MAX_TURNS="${MAX_TURNS:-35}"
MODEL="${CLAUDE_MODEL:-sonnet}"
REPORT="$(mktemp "${TMPDIR:-/tmp}/home-noc-issue-${ISSUE}.XXXXXX.json")"
printf 'Issue #%s | branch %s | model %s | estimated cap $%s\n' "$ISSUE" "$BRANCH" "$MODEL" "$MAX_BUDGET_USD"
printf 'Billing mode: %s (subscription uses plan limits; api uses Console credits)\n' "$CLAUDE_BILLING"
echo "Output report: $REPORT"
set +e
# env -u prevents inherited API variables from silently overriding OAuth plan login.
if [[ "$CLAUDE_BILLING" == "subscription" ]]; then
  CLAUDE_CMD=(env -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN claude)
else
  CLAUDE_CMD=(claude)
fi
"${CLAUDE_CMD[@]}" --bare -p "$PROMPT" \
  --append-system-prompt-file "$ROOT/CLAUDE.md" \
  --model "$MODEL" --max-budget-usd "$MAX_BUDGET_USD" --max-turns "$MAX_TURNS" \
  --permission-mode dontAsk --output-format json \
  --tools "Read,Edit,Write,Glob,Grep" \
  --allowedTools "Read" "Glob" "Grep" "Edit" "Write" \
  > "$REPORT"
STATUS=$?
set -e
python3 - "$REPORT" <<'PY'
import json
import sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text())
except (ValueError, OSError) as exc:
    print(f"Could not parse Claude JSON report: {exc}")
    raise SystemExit(0)
print(f"Estimated run spend: ${data.get('total_cost_usd', 'not reported')}")
print(f"Result: {data.get('result', 'no result text')}")
PY
echo "Review changes with: git diff --check && git diff"
echo "Claude exit status: $STATUS"
exit "$STATUS"
