# Scanning UI (M22)

The `/scans` page drives the existing backend job API (M08–M11). The browser never
scans anything itself and holds no scan state: job status, progress and events are
persisted by the backend, so a page refresh, a closed tab or an API/worker restart
loses nothing.

## Flow

1. **Choose targets and mode.** Targets are IPv4 addresses or CIDRs separated by
   spaces/commas. Modes offered: ICMP host discovery (`discovery`) and limited TCP
   connect scan (`ports`). The intrusive `security` profile is deliberately not
   selectable in this UI (it stays opt-in on the server).
2. **Preview** (`POST /api/v1/scans/preflight`, dry run). Shows resolved ranges,
   usable host count and the server-enforced limits. A target outside the configured
   `SCAN_ALLOWED_CIDRS` (or public, or over the host cap) is rejected with the
   backend's message shown in an alert, and no start button is offered.
3. **Confirm and start.** "Start scan" stays disabled until a preview succeeded
   *and* the operator ticked the ownership/permission box. Editing targets or mode
   discards the preview and the confirmation. The server re-validates scope when
   the job is created (`POST /api/v1/scans/jobs`), so the preview is a convenience,
   not a control.
4. **Watch.** The page polls `GET /scans/jobs/{id}` and `/events?after=<cursor>`
   every 2 s until the job is terminal. ICMP progress counts addresses; TCP
   progress counts connect attempts. If the API is unreachable it keeps retrying
   with exponential back-off (max 15 s) and says so; the scan continues on the
   server. A 404/401 stops polling.
5. **Cancel** (`POST /scans/jobs/{id}/cancel`) is available while the job is active.
6. **History** lists recent runs (newest 25); "View" re-attaches to any of them.
   On load the page automatically resumes the newest queued/running/cancelling job.

When a discovery scan succeeds, responsive hosts are reconciled into the inventory
(M12). The page displays responsive-host and reconciliation counts. The inventory
browser and asset-list navigation arrive with M21.

## Safe defaults

- Gentle modes only; no free-form scanner flags are sent (`extra="forbid"` on the API).
- Mutating requests carry the CSRF header via `lib/api.ts`; same-origin only.
- Only one active job at a time is started from the UI, and the server caps active jobs.
- Error text comes from the backend's `detail.message`; validation errors never echo
  the submitted input.

## Tests

- `frontend/src/lib/scans.test.ts`: polling, cursor, back-off, restart recovery, stop.
- `frontend/src/pages/Scans.test.tsx`: unsafe target rejection, consent gating,
  start → progress → cancel, resume after reload.
- `frontend/e2e/*.spec.ts`: 11 Chromium browser tests with mocked API responses,
  including authentication, scope failures, cancellation and refresh recovery.
  They exercise the production frontend bundle but not the real scanner worker.
  Run with `cd frontend && npm run test:e2e` after installing Chromium.

## Manual end-to-end check (isolated lab network you own)

1. Set `SCAN_ALLOWED_CIDRS` to an authorized lab range and start the API, worker
   and frontend services (see `docs/scan-jobs.md`); sign in.
2. Enter a public address such as `8.8.8.8`: expect a red message and no start button
   (nothing is sent to that address; preview is a dry run).
3. Enter a small lab CIDR, preview, tick the box, start. Refresh the page mid-scan:
   progress must reappear. Start a larger range and cancel: status becomes
   `cancelled`.
4. After a completed discovery scan, check the displayed `hosts_up` and
   reconciliation counts. Verify persisted devices through the authenticated
   `GET /api/v1/devices` API; the browser inventory view is scheduled for M21.

The Playwright suite uses intercepted API responses and intentionally performs no
real scanning. Actual worker-to-inventory persistence is covered by backend tests
and should also be checked in this authorized isolated lab.
