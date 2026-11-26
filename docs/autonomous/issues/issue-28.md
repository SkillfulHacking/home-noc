# Issue #28 (M25) — operations overview dashboard and event timeline

**Implemented:** `src/pages/Overview.tsx` (replaces the raw-JSON Index page), `src/lib/operations.ts`, route `/`, nav label, `usePolling` restart key, mock API extensions, docs/overview-ui.md. Stacked on #81 (needs the health/events/findings APIs).
**Decisions:** independent panel loading/error isolation; filters apply immediately (polling restart key); status never colour-only; timestamps local with UTC tooltip.
**Verified:** vitest 105 passed; tsc/eslint clean; production build ok; Playwright full suite 36 tests passing (35 + the fixed empty-state test) with mocked API. A first run failed one new e2e test because it did not request the mock-API fixture (test bug).
**Limits:** not exercised against the real backend in a browser (that is #29's compose-level E2E); no device-level drill-down beyond links to inventory.
