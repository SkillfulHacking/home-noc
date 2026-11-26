# Connector setup UI (M23)

`/connectors` (admin session; nav: **Connectors**).

- **UniFi controller:** address (`https://<IPv4>[:port]`, validated client-side to mirror the server: no hostnames, userinfo or paths), optional site, TLS verification, enabled flag, write-only API token. Buttons: Save, Test connection, Sync now (only when enabled), Remove token. Shows whether a token is configured, last successful sync, and consecutive failures.
- **SNMPv3 devices:** choose an inventory device; username, authentication protocol + passphrase, privacy protocol + passphrase. **authPriv only**: both passphrases (≥ 8 characters) are required. Buttons: Save credentials, Test connection, Poll now, Remove credentials. Only a "configured / not configured" flag is shown.
- **Polling schedules:** list/pause/resume/delete and add `unifi_sync` or `snmp_poll` schedules (interval in minutes) using the schedule API (docs/scheduling.md).

Secret handling: every secret input is `type="password"` with `autocomplete="new-password"`; secrets are sent only in PUT bodies, the field is cleared immediately after saving, and nothing the API returns can contain a secret (the credential API returns masked status only). Tests assert the secret never appears in the rendered DOM, that settings requests never carry it, and that state-changing requests carry the CSRF header.

Tests: `src/pages/Connectors.test.tsx` (vitest) and `e2e/connectors.spec.ts` (Playwright, mocked API).
