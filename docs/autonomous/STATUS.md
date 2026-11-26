# Status (checkpoint 5, 2026-11-26) — reconciled with GitHub

All MVP issues have an implementation PR; **every PR is OPEN and awaits operator merge** (the agent never merges). At the last query all required checks were passing for #72–#87; #88 was still running. Gitar had approved #72–#87 after remediation of every actionable finding (a few late suggestions are answered on the PRs).

| PR | Issue | Base |
|---|---|---|
| #72 | #71 runner reliability (+ this ledger) | main |
| #73 | #67 TCP last_seen | main |
| #74 | #16 SNMPv3 connector | main |
| #75, #76 | #17 UniFi, #18 SNMP interfaces | #74 branch |
| #77 | #19 scheduling + connector-worker key isolation | #75 branch (merges #76) |
| #78 | #22 health | #77 |
| #79 | #23 events | #78 |
| #80 | #20 Nuclei | #79 |
| #81 | #21 findings | #80 |
| #82 | #28 overview UI | #81 |
| #83 | #26 connector UI | #82 |
| #84 | #27 findings UI | #83 |
| #85 | #68 inventory polish | #84 |
| #86 | #29 e2e pipeline suite | #85 |
| #87 | #30 security hardening | #86 |
| #88 | #31 beta release docs | #87 |

Merge order: #72, #73 any time; then the stack bottom-up (#74 → #75/#76 → #77 → … → #88), retargeting each PR to `main` as its base merges. Migrations 0009–0013 chain in that order. #67 is merged into the stack from its own branch, so the stack tolerates either order.
Next action: operator merges; then hardware lab validation (see FINAL-REPORT.md operator queue).
Worktrees preserved: home-noc-m13..m28, ui68, issue-66/67, ui-spike (do not delete before merge).
