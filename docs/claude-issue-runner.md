# Claude issue runner

Run a bounded Claude Code implementation pass for a GitHub issue directly from clean, current `main`. The script obtains the issue title and body with `gh`, creates a dedicated local Git worktree, and invokes Claude with an issue-specific prompt.

## Start and resume

```bash
cd ~/code/home-noc
./scripts/claude-issue.sh 11
# After a pass finishes or is interrupted:
./scripts/claude-issue.sh 11 --resume
```

For issue #11 (`[M08]`), the first command creates `~/code/home-noc-m08` on `feat/home-noc-issue-11`. The resume command reuses that worktree, its uncommitted changes, and its original Claude session UUID. Neither command changes your `main` branch.

## Billing and limits

Subscription mode is the default and uses the existing Claude Code OAuth login. It refuses to run if API credentials are present. To explicitly use Console API credits, first set `ANTHROPIC_API_KEY` securely in the environment (never in shell history), then run:

```bash
CLAUDE_BILLING=api MAX_BUDGET_USD=5 MAX_TURNS=20 ./scripts/claude-issue.sh 11 --resume
```

Defaults: `CLAUDE_MODEL=sonnet`, `MAX_BUDGET_USD=8` and `MAX_TURNS=35` for each pass. Client-side budget settings are estimates, not guaranteed billing caps. A resumed conversation's reported cost may be cumulative.

## State and safety

- The main checkout holds ignored, owner-only session state and JSON reports under `.claude-issue/issue-<number>/`; these persist even when the issue worktree is removed.
- The first pass reserves a unique session UUID with `--session-id`; subsequent runs use `--resume <same UUID>`. The script never guesses the most recent unrelated session.
- A file lock prevents concurrent passes on the same issue. Existing branches, missing state, mismatched worktrees, stale `main`, and invalid budgets fail closed.
- Claude is permitted only file read/search/write tools: `Read`, `Glob`, `Grep`, `Edit` and `Write`. No Bash, commits, pushes, PR creation or merges are delegated.
- Treat issue text and repository content as untrusted. Never put secrets into issues. Manually review all generated changes and commands before executing anything.
- The runner does not automatically retry, delete worktrees, or erase session files. If a session was interrupted before Claude persisted it, `--resume` may fail; inspect the state and reports rather than silently starting a new session.
- Linux/WSL is required because the implementation uses `flock`.

## Verify before using

```bash
bash -n scripts/claude-issue.sh
shellcheck --shell=bash --external-sources scripts/claude-issue.sh
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
```

## Open an issue PR after human verification

```bash
git -C ~/code/home-noc-m08 status --short
git -C ~/code/home-noc-m08 diff --check
# Run the issue-specific test suite and review the diff before committing.
```

Do not merge automatically. After PR review and CI, the operator can archive or delete the issue worktree and its local state deliberately.
