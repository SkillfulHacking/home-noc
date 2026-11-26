# Issue #26 (M23) — SNMP and UniFi connector setup and test UI

**Implemented:** `src/pages/Connectors.tsx`, `src/lib/connectors.ts`, route `/connectors`, nav link, mock API extensions, docs/connectors-ui.md. Stacked on #28 (#82).
**Decisions:** write-only secret fields cleared after save; SNMP authPriv enforced in the UI; client-side controller URL validation mirrors server rules; schedules managed from the same page.
**Verified:** vitest 120 passed; tsc/eslint clean; Playwright connectors + overview specs pass with the mocked API (secret masking asserted in the browser). A first e2e run failed 2 tests due to my selectors (ambiguous button; label text includes option text) — test-side, fixed.
**Limits:** not exercised against the real backend/UniFi/SNMP hardware; "edit" of an existing connector is re-saving the form; no per-schedule device scoping UI (all devices with credentials).
