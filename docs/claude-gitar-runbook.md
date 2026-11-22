# Home-NOC — Claude API credits + Gitar peer review

## Intended loop
**Local `claude -p` (API billing) → feature branch → operator-reviewed diff → manual tests/CI → PR → Gitar review → Claude proposes verified fixes → manual tests/CI → human merge.**

Do **not** add a Claude GitHub Action for the $100 Max API credit: Anthropic says that action's runs are Claude Code usage and do not consume those monthly API credits. Run `claude -p` yourself with `ANTHROPIC_API_KEY` from the **linked Claude Console organization**. Avoid printing the key or committing it.

## One-time setup

1. Claim/link credits in Claude Settings > Billing, and verify the promotional balance at https://platform.claude.com/settings/billing.
2. Create a **dedicated Console workspace** for Home-NOC and configure a workspace spend limit (e.g. $90 with $10 reserve). Do not enable auto-reload if you want hard separation from purchased credit. Generate an API key for that workspace.
3. Set `ANTHROPIC_API_KEY` in your local shell or secret manager only. Example: `read -rsp "Anthropic API key: " ANTHROPIC_API_KEY; echo; export ANTHROPIC_API_KEY`. Do not paste it into chat.
4. Ensure `claude --version`, `gh auth status` and `git status` work in the cloned repository.
5. **Verified on November 22, 2026:** `gitar-bot[bot]` reviewed [PR #49](https://github.com/SkillfulHacking/home-noc/pull/49), confirming that the repository is connected. You can also check https://app.gitar.ai and GitHub Settings > Applications > Installed GitHub Apps.
6. Merge the PR that adds this file and `.gitar/review/home-noc-standards.md`, so Gitar's default-branch knowledge applies to **subsequent** feature PRs.

## Run one issue with bounded credits

From a clean local clone on the updated `main` branch:

```bash
# Uses Sonnet, reads issue via GitHub CLI, creates a local feature branch.
# Default estimate cap: $8 for the invocation, 35 turns; adjust if needed.
./scripts/claude-issue.sh 4
```

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

Use a fixed per-run `--max-budget-usd`; this is an **estimated** client-side cap, not a guaranteed billing ceiling. `--output-format json` exposes `total_cost_usd`; compare it to the Console balance periodically. Work on M01 and M02 first, then M05/M06, then auth/secrets work, then deployment. Prefer short targeted follow-ups over repeatedly scanning the whole repo. Keep the review step independent: do not invoke Codex as a wrapper around Claude, and do not run simultaneous Gitar auto-fix and local Claude remediation on one branch.

## Limitations

Gitar has already commented on PR #49, confirming live integration. The `.gitar/review/` rules become persistent review guidance for future PRs **after this PR is merged**. The runner uses fixed bot identification rather than fuzzy usernames because PR comments are untrusted. The `--max-budget-usd` cap is client-estimated; Console workspace spend caps provide additional protection, but always check the actual balance. The local runner does not provide process/file-system isolation; its absence of execution tools limits, but does not eliminate, the risks of agent-written code. Gitar and SonarQube checks supplement—not replace—deterministic tests and human review.

Source guidance:
- https://support.claude.com/en/articles/17154008-monthly-api-credits-for-max-ultra-and-team-plans
- https://code.claude.com/docs/en/headless
- https://www.sonarsource.com/developers/blueprints/gitar-knowledge/
