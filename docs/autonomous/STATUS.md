# Status (checkpoint 3, 2026-11-26)

Objective: complete the MVP (ROADMAP.md). Operator merges PRs; the agent never self-merges.

| PR | Issue | Branch | State |
|---|---|---|---|
| #72 | #71 runner reliability | fix/claude-runner-reliability | CI green, Gitar approved, ready for operator merge |
| #73 | #67 TCP last_seen | fix/issue-67-tcp-last-seen | CI green, Gitar approved, ready |
| #74 | #16 M13 SNMPv3 | feat/home-noc-issue-16 | CI green, Gitar approved, ready (merge first of the stack) |
| #75 | #17 M14 UniFi | feat/home-noc-issue-17 (base: #16 branch) | CI green, Gitar findings remediated |
| #76 | #18 M15 SNMP interfaces | feat/home-noc-issue-18 (base: #16 branch) | CI green; Gitar finding remediated, re-review pending |
| #77 | #19 M16 scheduling | feat/home-noc-issue-19 (base: #17; merges #18) | Gitar findings remediated, CI re-running |
| #78 | #22 M19 health | feat/home-noc-issue-22 (base: #19) | opened, CI/Gitar pending |

Stack/merge order: #72, #73 independent; #74 → #75, #76 → #77 → #78 (migrations 0009→0010→0011 chain).
Next: #23 events, then Nuclei (#20/#21), UI issues (#26/#27/#28/#68), #29 e2e, #30 hardening, #31 beta.
Worktrees (~/code/home-noc-m13/m14/m15/m16/m19, issue-67, issue-66, ui-spike) are preserved; nothing deleted.
