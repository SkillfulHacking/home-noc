# Home-NOC — Claude API credits + Gitar peer review

## Intended loop
**Local `claude -p` (API billing) → feature branch → tests → PR → Gitar review → Claude addresses verified feedback → CI green → human merge.**

Do **not** add a Claude GitHub Action for the $100 Max API credit: Anthropic says that action's runs are Claude Code usage and do not consume those monthly API credits. Run `claude -p` yourself with `ANTHROPIC_API_KEY` from the **linked Claude Console organization**. Avoid printing the key or committing it.

## One-time setup

1. Claim/link credits in Claude Settings > Billing, and verify the promotional balance at https://platform.claude.com/settings/billing.
2. Create a **dedicated Console workspace** for Home-NOC and configure a workspace spend limit (e.g. $90 with $10 reserve). Do not enable auto-reload if you want hard separation from purchased credit. Generate an API key for that workspace.
3. Set `ANTHROPIC_API_KEY` in your local shell or secret manager only. Example: `read -rsp "Anthropic API key: " ANTHROPIC_API_KEY; echo; export ANTHROPIC_API_KEY`. Do not paste it into chat.
4. Ensure `claude --version`, `gh auth status` and `git status` work in the cloned repository.
5. In https://app.gitar.ai, verify that `SkillfulHacking/home-noc` is enabled. Alternatively check GitHub Settings > Applications > Installed GitHub Apps > Gitar Bot. A real `gitar-bot` review on a new pull request is the definitive proof.
6. Merge the PR that adds this file and `.gitar/review/home-noc-standards.md`, so Gitar's default-branch knowledge applies to **subsequent** feature PRs.

## Run one issue with bounded credits

From a clean local clone on the updated `main` branch:

```bash
# Uses Sonnet, reads issue via GitHub CLI, creates a local feature branch.
# Default estimate cap: $8 for the invocation, 35 turns; adjust if needed.
./scripts/claude-issue.sh 4
```

Read the resulting `git diff`, execute additional checks as needed, and commit/push yourself:

```bash
git diff --check
git add <reviewed-files>
git commit -m "fix: restore frontend API and auth modules (#4)"
git push -u origin HEAD
gh pr create --base main --title "M01: restore frontend API/auth modules" --body "Closes #4"
```

Once `gitar-bot` has posted a review, get actual inline and top-level feedback and invoke a bounded remediation session:

```bash
./scripts/claude-review-pr.sh <pr-number>
```

Inspect and commit these changes, push again, verify CI and review outstanding findings, then merge manually when satisfied. If no Gitar feedback is visible, the review script **exits without calling Claude**. Check Gitar's installation/access and plan status before proceeding.

## Budget and escalation

Use a fixed per-run `--max-budget-usd`; this is an **estimated** client-side cap, not a guaranteed billing ceiling. `--output-format json` exposes `total_cost_usd`; compare it to the Console balance periodically. Work on M01 and M02 first, then M05/M06, then auth/secrets work, then deployment. Prefer short targeted follow-ups over repeatedly scanning the whole repo. Keep the review step independent: do not invoke Codex as a wrapper around Claude, and do not run simultaneous Gitar auto-fix and local Claude remediation on one branch.

## Limitations

We cannot prove Gitar is watching a repository just because it is public or its GitHub App exists. The bot's **real PR activity**, installation settings, or Gitar dashboard must confirm connection. Gitar's `.gitar/review/` rules supplement, rather than replace, code tests, security checks or human review.

Source guidance:
- https://support.claude.com/en/articles/17154008-monthly-api-credits-for-max-ultra-and-team-plans
- https://code.claude.com/docs/en/headless
- https://www.sonarsource.com/developers/blueprints/gitar-knowledge/
