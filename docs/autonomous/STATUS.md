# Status (checkpoint 4, 2026-11-26) — reconciled with GitHub

Operator merges PRs; the agent never self-merges. All PRs below were OPEN/CLEAN with required checks passing when last queried (CI for #79/#80 was still running).

| PR | Issue | Branch | Base | Notes |
|---|---|---|---|---|
| #72 | #71 | fix/claude-runner-reliability | main | Gitar approved |
| #73 | #67 | fix/issue-67-tcp-last-seen | main | Gitar approved |
| #74 | #16 | feat/home-noc-issue-16 | main | Gitar approved |
| #75 | #17 | feat/home-noc-issue-17 | #74 branch | findings remediated |
| #76 | #18 | feat/home-noc-issue-18 | #74 branch | Gitar approved |
| #77 | #19 | feat/home-noc-issue-19 | #75 branch (merges #76) | Gitar approved; credential-key isolation fix added after approval (connector-worker) — needs re-review |
| #78 | #22 | feat/home-noc-issue-22 | #77 branch | merges #73; Gitar findings remediated |
| #79 | #23 | feat/home-noc-issue-23 | #78 branch | opened, review pending |
| #80 | #20 | feat/home-noc-issue-20 | #79 branch | opened this session |

Merge order: #72, #73 any time; #74 -> #75, #76 -> #77 -> #78 -> #79 -> #80. Migrations 0009-0012 chain.
Next: #21 findings persistence/API, then UI (#26/#27/#28/#68), #29, #30, #31.
Worktrees preserved: home-noc-m13/m14/m15/m16/m17/m19/m20, issue-66, issue-67, ui-spike.
