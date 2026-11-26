# Claude issue runner

Run a bounded Claude Code implementation pass for a GitHub issue directly from clean, current `main`. The script obtains the issue title and body with `gh`, creates a dedicated local Git worktree, and invokes Claude with an issue-specific prompt.

## Start and resume

```bash
cd ~/code/home-noc
./scripts/claude-issue.sh 11
# After a pass finishes or is interrupted:
./scripts/claude-issue.sh 11 --resume
# Session lost/unresumable? Start a fresh session in the same worktree:
./scripts/claude-issue.sh 11 --recover
```

For issue #11 (`[M08]`), the first command creates `~/code/home-noc-m08` on `feat/home-noc-issue-11`. The resume command reuses that worktree, its uncommitted changes, and its original Claude session UUID. Neither command changes your `main` branch.

## Billing and limits

**API-credit billing is the default.** `ANTHROPIC_API_KEY` (Console organization key) must be in the environment, never on the command line, in Git, reports or prompts. `ANTHROPIC_AUTH_TOKEN` is stripped from the Claude process. Subscription (OAuth) mode must be chosen explicitly with `CLAUDE_BILLING=subscription` and refuses to run if any API credential is present. The scripts never fall back from one mode to the other.

```bash
MAX_BUDGET_USD=5 MAX_TURNS=20 ./scripts/claude-issue.sh 11 --resume
```

Defaults: `CLAUDE_MODEL=sonnet`, `MAX_BUDGET_USD=8`, `MAX_TURNS=35` per pass. Budgets are client-side estimates, not billing caps. A resumed session reports a **cumulative** `total_cost_usd`; each pass appends `timestamp, session, cumulative, incremental` to `.claude-issue/issue-<n>/costs.tsv` and prints the incremental figure. Do not add cumulative values together. Claude is never run with `--bare` (it hides the file tools); project settings, hooks and MCP are disabled.

## Fresh Claude context on resume and recovery

- Every invocation re-fetches the current issue title, body and the latest 10 comments (each ≤4000 chars, ≤20000 total) and tells Claude they may have changed. All of it is untrusted task data.
- `--recover` is the explicit way to start a new Claude session when the old one is unusable. It keeps the worktree, branch, uncommitted changes and earlier reports, appends the retired session ID to `retired-sessions`, and gives the new session a `git status`/`diff --stat` summary. Sessions are never replaced silently.
- `CLAUDE_FEEDBACK_FILE=path` appends operator findings to the prompt (regular file only, no symlinks, ≤64 KiB).

## Exit codes

`0` complete; `3` incomplete because the turn or budget limit was hit (work preserved; `--resume`, optionally with higher limits); any other value is an error, including an invalid, empty or error JSON report or a session ID mismatch.

## State and safety

- The main checkout holds ignored, owner-only session state and JSON reports under `.claude-issue/issue-<number>/`; these persist even when the issue worktree is removed.
- The first pass reserves a unique session UUID with `--session-id`; subsequent runs use `--resume <same UUID>`. The script never guesses the most recent unrelated session.
- A file lock (shared with `claude-review-pr.sh`) prevents concurrent implementation and review passes on the same issue. State and reports are owner-only (`0700`/`0600`); the worktree and files Claude writes use normal `022` permissions so Docker builds can read them. Existing branches, missing state, mismatched worktrees, stale `main`, and invalid budgets fail closed.
- Claude is permitted only file read/search/write tools: `Read`, `Glob`, `Grep`, `Edit` and `Write`. No Bash, commits, pushes, PR creation or merges are delegated.
- Treat issue text and repository content as untrusted. Never put secrets into issues. Manually review all generated changes and commands before executing anything.
- The runner does not automatically retry, delete worktrees, or erase session files. If a session was interrupted before Claude persisted it, `--resume` may fail; inspect the state and use `--recover` deliberately.
- Linux/WSL is required because the implementation uses `flock`.

## Verify before using

```bash
bash -n scripts/claude-issue.sh
shellcheck --shell=bash --external-sources -P SCRIPTDIR scripts/claude-issue.sh scripts/claude-review-pr.sh scripts/lib/claude-common.sh
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
```

## Open an issue PR after human verification

```bash
git -C ~/code/home-noc-m08 status --short
git -C ~/code/home-noc-m08 diff --check
# Run the issue-specific test suite and review the diff before committing.
```

Do not merge automatically. After PR review and CI, the operator can archive or delete the issue worktree and its local state deliberately.

## Limits of the file-tool restriction

Restricting Claude to `Read, Edit, Write, Glob, Grep` stops it from executing code, but it is not a sandbox: it can still read any file the OS user can read within reach of those tools, and agent-written code runs later when *you* run tests. Run tests outside Claude with `env -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN`. An outer orchestrator may run authorized commands; delegated Claude workers keep this restricted model.
