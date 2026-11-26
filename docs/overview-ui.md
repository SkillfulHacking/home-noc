# Operations overview (M25)

`/` (nav: **Overview**) is the landing page after sign-in.

- **Device health:** counts for online / degraded / offline / unknown from `GET /api/v1/health/devices` (status text is always shown, never colour alone) and a *Needs attention* list of offline and degraded devices with the derivation reason and the time the status last changed. Health is derived (see `device-health.md`); inventory freshness (`last seen`) stays separate.
- **Findings:** count of open findings (and suppressed) from `GET /api/v1/findings`.
- **Event timeline:** newest first from `GET /api/v1/events`, with severity and "unacknowledged only" filters (applied immediately), "Load older events" using the API's opaque cursor, repeat counts, local times with the exact UTC instant in the tooltip, and a CSRF-protected *Acknowledge* action.
- Each panel loads independently and refreshes every 30 s while the tab is visible; one failing API shows an alert for that panel only.

Tests: `src/pages/Overview.test.tsx` (vitest) and `e2e/overview.spec.ts` (Playwright with the mocked API; no backend or real network).
