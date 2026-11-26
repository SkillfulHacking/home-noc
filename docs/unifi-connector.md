# UniFi Network connector (M14)

Read-only import of managed devices and connected clients from a UniFi Network application (UDM/UDM Pro/Cloud Key, **Network 9+ Integration API**: `/proxy/network/integration/v1`).

## Setup
1. In UniFi Network create an API token with the least privilege available (view-only).
2. Store it: `PUT /api/v1/credentials/connectors/unifi/unifi_api_token` with `{"secret": {"token": "..."}}` (see `connector-credentials.md`).
3. Configure: `PUT /api/v1/connectors/unifi` with `{"enabled": true, "base_url": "https://10.0.0.1", "site": "Default", "verify_tls": true}`.
   - `base_url` must be `https://<IPv4>[:port]` (no hostname, userinfo, path or query) and inside the runtime scan policy; the policy is re-checked on every use and audited.
   - `verify_tls` defaults to true. UDM devices use self-signed certificates; set it to false only on a trusted LAN (or install the CA in the container).
   - `site` is optional when exactly one site exists (or one has reference `default`).
4. `POST /api/v1/connectors/unifi/test` checks the token (reports application version and site count).
5. `POST /api/v1/connectors/unifi/sync` imports into the inventory.

## Behaviour
- GET only; there is no controller mutation code path. Redirects are refused, bodies capped at 5 MiB, 10 s timeout.
- Paging: 100 rows per page, at most 50 pages per collection; malformed rows are skipped and counted (`invalid`).
- Devices are matched by the UniFi device id (`unifi` identifier), then MAC, then a unique non-contradicting IP, through `app.reconcile`; an existing ICMP/TCP-discovered asset is merged, never duplicated. Curated fields (hostname, roles, notes…) are never overwritten. Clients are bound by MAC (`unifi_client` identifier) and need a MAC.
- Disabled by default; `sync` (and later scheduled polling) refuse while disabled (`409`); `test` is an explicit admin action and may run before enabling. Failures record `last_status=error`, `last_error_code`, and increment `consecutive_failures` but never disable or delete the credential; the next successful sync resets the state.
- The token is never returned or logged; `GET /api/v1/connectors/unifi` only reports `credential_configured`.

## Verification
Automated with a mocked controller (`tests/test_unifi_connector.py`, `tests/test_unifi_api.py`) and an httpx MockTransport check of the header/redirect behaviour. **Not verified against a real UniFi controller**: field names follow the documented Integration API and tolerate `mac`/`macAddress` and `ip`/`ipAddress`. Operator lab check: run test + sync against the UDM and confirm switches/APs appear once each.
