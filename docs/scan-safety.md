# Scan safety guide

Home-NOC only scans networks you explicitly authorize, and fails closed when it cannot tell.

1. **Only scan what you own or are permitted to test.** Discovery and port scans are gentle; the opt-in vulnerability profile sends real (read-only) HTTP requests.
2. **Authorization has three layers:** an immutable deployment ceiling (`SCAN_ALLOWED_CIDRS`, empty = RFC1918 only), an administrator-managed runtime policy (private ranges, exclusions, public opt-in with an explicit allowlist) and per-request validation (strict IPv4/CIDR, no hostnames, host caps per profile). Workers re-check before every probe, so revoking a range stops a running scan at the next check. See `docs/scan-scope.md`.
3. **Defaults:** private ranges only; public scanning off; the intrusive `security` profile and the Nuclei `vuln` profile **off**; rate, concurrency, size and time limits bounded.
4. **Exclude fragile devices** (printers, building control, medical, anything that dislikes probes) in the scan policy before scheduling anything.
5. **Schedules** are re-authorized at every firing; an unauthorized or disabled schedule enqueues nothing. Pause schedules before maintenance.
6. **Vulnerability scans** are never scheduled. Review the plan (exact URLs, templates, versions, limits), approve it, and keep to hosts you administer. Results are findings you can suppress with a reason; resolution needs repeated conclusive reruns.
7. **Credentials** for SNMP/UniFi are write-only in the UI/API, encrypted at rest, and only usable by the connector worker. Use a view-only UniFi token and an SNMPv3 user with a read-only view.
8. **If something goes wrong:** pause or delete the schedule, revoke the range in the scan policy, cancel jobs on the Scans page, then read the audit lines (`scan_authorization`) in the logs. See `docs/security.md` (runbook).
