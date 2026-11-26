# Blockers

| ID | Affected | Description | Status |
|---|---|---|---|
| B-001 | #29/#31/#17/#16/#20 acceptance | Real hardware (UniFi controller, SNMPv3 switch, LAN ICMP, lab HTTP service for Nuclei) is not available to the agent, so lab demos/acceptance cannot be marked verified. Everything possible was verified with mocks, a loopback SNMPv3 agent, the real pinned Nuclei binary against a loopback server, and real-container deployment tests. | Needs operator (see FINAL-REPORT operator queue); other work unaffected |
| B-002 | merge/propagation | Human merge approval is required; a 17-PR stack therefore waits for the operator. Bases retarget as predecessors merge. | By design |
| B-003 (resolved) | tooling | Bash permission was denied twice mid-campaign; resolved by the operator re-authorizing. Exact blocked operation the second time: a combined `python3` heredoc edit + `cat >> tests/…` + `docker compose config` command. | Resolved |
