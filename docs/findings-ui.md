# Findings and vulnerability-scan UI (M24)

`/findings` (nav: **Findings**).

- **List:** severity badge (text label, not colour alone), name, status, `host:port` linking to the asset, last seen (local time, UTC in tooltip). Filters: severity, status (defaults to *open*), search; page size 25 with Previous/Next; counts by status for the current filter. Auto-refreshes while the tab is visible.
- **Details:** description, template id and the template/scanner versions that produced it, occurrence count, first seen, CVE/CWE ids, redacted evidence, full history (opened/seen/resolved/reopened/suppressed with actor and note). The UI shows only what the API stores — sanitized, redacted fields; raw requests/responses do not exist in the system.
- **Suppress / unsuppress:** suppression requires a reason (≥ 3 characters); both are CSRF-protected POSTs and appear in the history.
- **Vulnerability scan panel (opt-in, approval required):** enter authorized targets → *Review plan* shows exactly which URLs, how many read-only templates, pinned versions and limits will be used → tick the approval box → *Start*. The start request carries the reviewed plan's digest; if the plan changed meanwhile the server answers 409 and the UI asks for a new review. If no HTTP services are known, the plan says nothing would be scanned and offers no start button. If the deployment has not enabled the profile (`SCAN_VULN_PROFILE_ENABLED`), the UI says so. Progress is on the Scans page.

The generic Scans page still never offers intrusive profiles; vulnerability scanning is deliberately a separate, approval-gated flow.

Tests: `src/pages/Findings.test.tsx` (vitest), `e2e/findings.spec.ts` (Playwright, mocked API).
