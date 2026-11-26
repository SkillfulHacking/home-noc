#!/usr/bin/env bash
# Shared helpers for claude-issue.sh and claude-review-pr.sh. Source only.
# shellcheck shell=bash
# shellcheck disable=SC2034  # variables are consumed by the sourcing scripts

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# API-credit billing is the default; subscription must be chosen explicitly.
# Never falls back silently from one mode to the other.
claude_check_billing() {
  CLAUDE_BILLING="${CLAUDE_BILLING:-api}"
  case "$CLAUDE_BILLING" in
    api)
      [[ -n "${ANTHROPIC_API_KEY:-}" ]] ||
        fail "API mode (default) requires ANTHROPIC_API_KEY from your Console organization; for plan limits set CLAUDE_BILLING=subscription explicitly"
      ;;
    subscription)
      [[ -z "${ANTHROPIC_API_KEY:-}" && -z "${ANTHROPIC_AUTH_TOKEN:-}" ]] ||
        fail "API credentials found in subscription mode; unset them or use CLAUDE_BILLING=api"
      ;;
    *) fail "CLAUDE_BILLING must be api or subscription" ;;
  esac
}

# $1 = default turns, $2 = default budget
claude_check_limits() {
  MODEL="${CLAUDE_MODEL:-sonnet}"
  MAX_TURNS="${MAX_TURNS:-$1}"
  MAX_BUDGET_USD="${MAX_BUDGET_USD:-$2}"
  [[ $MAX_TURNS =~ ^[1-9][0-9]*$ ]] || fail "MAX_TURNS must be a positive integer"
  [[ $MAX_BUDGET_USD =~ ^(0|[1-9][0-9]*)(\.[0-9]{1,2})?$ ]] ||
    fail "MAX_BUDGET_USD must be a dollar amount with at most two decimals"
  [[ $MAX_BUDGET_USD =~ ^0(\.0{1,2})?$ ]] &&
    fail "MAX_BUDGET_USD must be greater than zero"
  return 0
}

# Builds CLAUDE_CMD (prefix) and CLAUDE_TOOL_ARGS (restrictions). No --bare:
# it breaks file-tool availability. Hooks, project settings and MCP are disabled.
claude_build_cmd() {
  if [[ $CLAUDE_BILLING == subscription ]]; then
    CLAUDE_CMD=(env -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN claude)
  else
    CLAUDE_CMD=(env -u ANTHROPIC_AUTH_TOKEN claude)
  fi
  CLAUDE_CMD+=(--setting-sources user --strict-mcp-config
    --mcp-config '{"mcpServers":{}}'
    --settings '{"disableAllHooks":true}')
  CLAUDE_TOOL_ARGS=(--permission-mode dontAsk --output-format json
    --tools "Read,Edit,Write,Glob,Grep"
    --allowedTools "Read" "Glob" "Grep" "Edit" "Write"
    --disallowedTools "Bash")
}

# Shared lock on a state directory ($1); fd 9 stays open for the script's life.
claude_lock() {
  mkdir -p "$1"
  chmod 700 "$1"
  exec 9> "$1/run.lock"
  flock -n 9 || fail "$2 is already running (implementation or review pass holds the lock); refusing concurrent execution"
}

# Validate a JSON report. $1 report, $2 expected session id (or ""), $3 cost ledger (or "").
# Exit 0 complete; 1 invalid/error; 3 incomplete (turn/budget exhausted; resumable).
claude_validate_report() {
  local report="$1" session="$2" ledger="${3:-}" prev=""
  if [[ -n $ledger ]]; then
    [[ ! -f $ledger ]] || prev="$(cat -- "$ledger")"
    HN_LEDGER="$prev" python3 -I "$LIB_DIR/validate_report.py" "$session" < "$report" 3>> "$ledger"
  else
    python3 -I "$LIB_DIR/validate_report.py" "$session" < "$report"
  fi
}
