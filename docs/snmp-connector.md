# SNMPv3 connector (M13)

Read-only identity poller built on the `Connector` interface (`backend/app/connectors/`).

## Behaviour and safety
- **SNMPv3 authPriv only.** Both `snmpv3_auth` (username, SHA/SHA224/SHA256/SHA384/SHA512) and `snmpv3_priv` (AES128/192/256) credentials must be stored for the device (see `connector-credentials.md`). authNoPriv/noAuth and SNMPv1/v2c are **not implemented**; an explicit insecure v2c opt-in was deferred (decision recorded in the ledger) and can be added later as a separate credential type.
- **GET-only, fixed OID allowlist:** sysDescr, sysObjectID, sysUpTime, sysName, snmpEngineID. Nothing else is requested; no SET/WALK.
- **Missing data stays missing.** `noSuchObject`/`noSuchInstance`/`endOfMibView`, empty and malformed values become `null`. Model and serial are never derived from these scalars.
- **Identity is interface-independent:** `identity_key` is the snmpEngineID (hex), else `sysObjectID|sysName`, else `null`.
- Fixed timeout (2 s) and one retry, UDP/161 only, at most two concurrent tests.
- Secrets are decrypted in-process only; never logged, returned, or placed in errors.

## Connect-test route
`POST /api/v1/devices/{id}/snmp/test` with optional `{"ip": "<one of the device's IPv4 addresses>"}`; requires an admin session and `X-CSRF-Token`.
- 403 if the address is outside the runtime scan policy (RFC1918/allowlist/exclusions/ceiling) — audited like scans.
- 409 if either credential is missing; 422 for an IP that is not the device's; 503 if the credential key is unusable.
- 200 `{ok: true, result: {sys_name, sys_object_id, identity_key}}` or `{ok: false, error: {code, message}}` with codes `timeout`, `authentication_failed`, `credentials_incomplete`, `snmp_error`.

## Verification
Automated (`backend/tests/test_snmp_connector.py`, `test_snmp_api.py`): fake-transport tests, plus the real pysnmp transport against an in-process loopback SNMPv3 agent (127.0.0.1, ephemeral port) covering success, wrong secret and timeout.

### Lab test with a UniFi switch (operator, not yet performed)
1. In UniFi Network → Settings → Services (or device settings), enable SNMPv3 with an authPriv user; use SHA256/AES128 or stronger if supported.
2. Add the switch to Home-NOC with its IP inside the configured scan scope.
3. Store the credentials: `PUT /api/v1/credentials/devices/<id>/snmpv3_auth` (metadata `username`, `protocol`) and `.../snmpv3_priv`.
4. `POST /api/v1/devices/<id>/snmp/test` and confirm `sys_name`, `sys_object_id` (UniFi enterprise `1.3.6.1.4.1.41112...`) and `identity_key`.
5. Confirm a wrong passphrase returns `authentication_failed` and that no secret appears in API responses or container logs.

## Dependency
`pysnmp==7.1.32` (BSD-2) and `pyasn1==0.6.5` were added, hash-locked in `requirements.lock`; `pip-audit` reports no known vulnerabilities; install from the lock with `--require-hashes` verified.
