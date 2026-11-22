# Home-NOC — Claude CLI (OAuth or Max API credits) + Gitar peer review

## Intended loop
**Local `claude -p` → feature branch → operator-reviewed diff → manual tests/CI → PR → Gitar review → Claude proposes verified fixes → manual tests/CI → human merge.**

### Authentication versus billing (IMPORTANT)
- **Subscription / OAuth (default):** already logged into Claude Code? No API key needed. `claude -p` uses your Max subscription's usage limits and **does not consume** the separately granted $100 monthly API credit. The scripts run `claude -p` without `--bare` because `--bare` does **not** read subscription OAuth login.
- **$100 monthly API-credit mode:** Anthropic requires `ANTHROPIC_API_KEY` generated in the **linked Console organization**. Use `CLAUDE_BILLING=api` with that key. `--bare` is appropriate in this API-key mode. The key must stay outside Git, logs, PRs and prompts.
- **Never confuse these pools:** signing in with OAuth does not automatically unlock spending the separate API credit. Check the current login via `/status` inside Claude, and check Console promotional balance in https://platform.claude.com/settings/billing.
- Anthropic says runs launched through a Claude Code GitHub Action or IDE/Desktop count as Claude Code usage even when `-p` is used; this local self-run flow is intentionally separate.

### Initial checkout on a new WSL/Linux machine
```bash
mkdir -p ~/code
cd ~/code
git clone https://github.com/SkillfulHacking/home-noc.git
cd home-noc

# Verify tools. Claude is already installed if this prints a version.
claude --version
git --version
gh --version
gh auth status
```

If `gh` is missing, install GitHub CLI for your Linux distribution and sign in with `gh auth login`. **PR #49 must be merged first** before the scripts exist on `main`. Alternatively, checkout its branch strictly for inspecting the workflow; do not start M01 from the unmerged branch.

### One-time billing setup if using the separate monthly API credit
1. Claim/link your Console organization from Claude Settings > Billing; confirm promotional credits in https://platform.claude.com/settings/billing.
2. Create a dedicated Console workspace for Home-NOC with a spend limit (e.g. $90 for planned work and $10 reserve). Consider disabling auto-reload to avoid unexpected charges.
3. Generate a scoped Console API key and keep it in a local secret manager or ephemeral environment. Never paste it into an issue or PR.
4. For an API-credit run, first set the key in your terminal without echoing it:
   ```bash
   read -rsp "Anthropic Console API key: " ANTHROPIC_API_KEY
   echo
   export ANTHROPIC_API_KEY
   CLAUDE_BILLING=api ./scripts/claude-issue.sh 4
   unset ANTHROPIC_API_KEY
   ```
5. **Verified on November 22, 2026:** `gitar-bot[bot]` reviewed [PR #49](https://github.com/SkillfulHacking/home-noc/pull/49), confirming the repository is connected. Gitar will read `.gitar/review/` rules for subsequent PRs once #49 is merged.

## Run one issue with bounded usage

From a clean local clone on the updated `main` branch, using your already-authenticated **Max plan** (no API key):

```bash
git switch main
git pull --ff-only

# Uses your Claude Code subscription login; DOES NOT spend the $100 API grant.
# Model: Sonnet, up to 35 turns; a $8 model-estimate cap is not subscription billing.
./scripts/claude-issue.sh 4
```

To spend the **separate $100 monthly API credit** instead, use the explicit `CLAUDE_BILLING=api` invocation above with the linked Console key.

The default runner grants **file read/edit only**; it intentionally cannot run tests or shell commands. An LLM that can edit tests or npm scripts and then execute them could access the API key or local GitHub credentials, even with a Bash command allowlist. This is not a full sandbox. For any externally authored issue/PR text, use an isolated throwaway environment with strictly controlled file access and network egress before letting an agent modify code.

Read the resulting `git diff` first. Then **outside the Claude process**, run appropriate checks with the Anthropic key removed from the command environment:

```bash
# For frontend issues, after visually inspecting the changed scripts:
(cd frontend && env -u ANTHROPIC_API_KEY npm ci && env -u ANTHROPIC_API_KEY npm run build)
# For backend issues, with dependencies already installed:
(cd backend && env -u ANTHROPIC_API_KEY python -m pytest -q)
(cd backend && env -u ANTHROPIC_API_KEY ruff check .)
env -u ANTHROPIC_API_KEY docker compose config
```

Only then commit/push yourself:

```bash
git diff --check
git add <reviewed-files>
git commit -m "fix: restore frontend API and auth modules (#4)"
git push -u origin HEAD
gh pr create --base main --title "M01: restore frontend API/auth modules" --body "Closes #4"
```

Once `gitar-bot[bot]` has posted a review, collect actual inline and top-level feedback **from that exact bot identity**, and invoke a bounded file-edit-only remediation session:

```bash
./scripts/claude-review-pr.sh <pr-number>
```

Inspect the resulting changes, run tests manually without the Anthropic key available to test/build processes, commit and push, verify CI and outstanding findings, then merge manually when satisfied. If no Gitar feedback is visible, the review script **exits without calling Claude**. Check Gitar's installation/access and plan status before proceeding.

## Budget and escalation

Use a fixed per-run `--max-budget-usd`; this is a **client-side cost estimate**, not a guaranteed billing ceiling. When using subscription OAuth it **does not mean dollars are charged**; it only limits the model-computed estimate. With API-key billing, check `total_cost_usd` against the linked Console balance periodically. No keys should be left in persistent shell profiles unless intentionally configured. Work on M01 and M02 first, then M05/M06, then auth/secrets work, then deployment. Prefer short targeted follow-ups over repeatedly scanning the whole repo. Keep the review step independent: do not invoke Codex as a wrapper around Claude, and do not run simultaneous Gitar auto-fix and local Claude remediation on one branch.

## Limitations

Gitar has already commented on PR #49, confirming live integration. The `.gitar/review/` rules become persistent review guidance for future PRs **after this PR is merged**. The runner uses fixed bot identification rather than fuzzy usernames because PR comments are untrusted. The `--max-budget-usd` cap is client-estimated; Console workspace spend caps provide additional protection in API mode, but always check the actual balance. The default OAuth mode instead consumes subscription usage limits. Subscription-mode Claude disables repository-sourced settings, hooks and MCP configuration while keeping OAuth login. The PR-review runner refuses to operate on diffs that modify `.claude/` or `.mcp.json` files. The local runner still does not provide process/file-system isolation; the absence of execution tools limits, but does not eliminate, risks from agent-written code. Gitar and SonarQube checks supplement—not replace—deterministic tests and human review.

Source guidance:
- https://support.claude.com/en/articles/17154008-monthly-api-credits-for-max-ultra-and-team-plans
- https://code.claude.com/docs/en/headless
- https://www.sonarsource.com/developers/blueprints/gitar-knowledge/
