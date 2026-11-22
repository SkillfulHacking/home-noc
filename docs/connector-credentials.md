# Connector credential storage (M04)

Stores UniFi API tokens and SNMPv3 authentication/privacy secrets encrypted at
rest, separately from the canonical inventory. Nothing here contacts a device.

## Design
- **Cipher:** AES-256-GCM (`cryptography`), fresh random 96-bit nonce per write.
- **Envelope:** `version(1 byte) | nonce(12) | ciphertext+tag`. The version is also
  part of the authenticated data, leaving room for algorithm/key rotation.
- **Identity binding (AAD):** `credential id + scope (device:<uuid> | connector:<name>) +
  credential type + version`. A ciphertext copied to another row/scope/type fails
  authentication.
- **Key:** supplied by configuration only, never generated, never stored in SQLite.
  Missing/malformed key => credential endpoints answer `503`; nothing is written in
  plaintext. In production a *configured but invalid* key stops startup.
- **Storage:** table `connector_credentials` (migration `0004_connector_credentials`):
  ciphertext, `enc_version`, non-secret `meta` JSON, timestamps. Rotation overwrites the
  row in place; deletion removes it; SQLite `secure_delete` is enabled so freed pages
  are zeroed. Deleting a device cascades to its credentials.
- **Types:** `unifi_api_token` (connector or device scope), `snmpv3_auth`,
  `snmpv3_priv` (device scope). Add a type by adding a `CredentialTypeSpec` in
  `app/credential_schemas.py`.
- Credentials never touch `Device.snmp`, `Device.api`, `Device.notes` or observations.

## Key provisioning
```bash
python -c "import base64,secrets;print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```
Provide it as `CREDENTIAL_ENCRYPTION_KEY` in the untracked `backend/.env`, or mount it as a
file and set `CREDENTIAL_ENCRYPTION_KEY_FILE` (set only one). Keep it out of Git, images,
and the `/data` volume. The same key must be supplied on every restart.

## Backup and key loss
- Back up the key **separately** from the database backup (e.g. password manager).
  A database backup alone cannot reveal credentials; a key alone is useless without it.
- **If the key is lost, every stored credential is permanently unrecoverable.** Delete
  and re-enter them through the API with a new key. Changing the key without
  re-entering credentials makes existing rows fail authentication (they are never
  returned or silently ignored).
- No key-rotation tooling ships in M04; the format version reserves the upgrade path.

## API (session cookie required; PUT/DELETE also need `X-CSRF-Token`)
Secrets only in bodies, never URLs. Responses are `Cache-Control: no-store`.

```
PUT /api/v1/credentials/connectors/unifi/unifi_api_token
{"secret": {"token": "<token>"}, "metadata": {"label": "main controller"}}

201 Created   (200 on rotation)
{"scope": "connector", "device_id": null, "connector": "unifi",
 "credential_type": "unifi_api_token", "configured": true, "masked": "********",
 "metadata": {"label": "main controller"},
 "created_at": "...", "updated_at": "...", "rotated_at": null}
```
```
PUT /api/v1/credentials/devices/<device-uuid>/snmpv3_auth
{"secret": {"password": "<passphrase>"}, "metadata": {"username": "monitor", "protocol": "SHA256"}}
```
```
GET    /api/v1/credentials/devices/<device-uuid>            -> configured/unconfigured per type
GET    /api/v1/credentials/devices/<device-uuid>/snmpv3_priv -> {"configured": false, "masked": null, ...}
DELETE /api/v1/credentials/devices/<device-uuid>/snmpv3_priv -> 204
```
Validation errors (422) on `/api/v1/credentials/*` contain only `loc`, `msg`, `type`.

## Required follow-up: regenerate `backend/requirements.lock`
`cryptography==46.0.3` was added to `requirements.txt` / `pyproject.toml`, but the hashed
lock could not be regenerated without running commands, and no hashes were invented. Until
it is regenerated the Docker build (`--require-hashes`) will fail. From `backend/`, with
network access and `pip-tools` installed (use Python 3.12 to match the image):
```bash
pip-compile --generate-hashes --strip-extras --upgrade-package cryptography \
  --output-file=requirements.lock requirements.txt
git diff requirements.lock   # expect cryptography, cffi, pycparser added; nothing else bumped
```
If `46.0.3` is not the version you want, change it in both files first.

## Known limits
- `Device.notes` is free text; it cannot be reliably scanned for secrets. Operators must
  not paste credentials there.
- SQLite WAL files may retain old frames until checkpointed; the old ciphertext is
  encrypted regardless.
- Broader Compose hardening (secrets mounts, volume permissions) is M07.
