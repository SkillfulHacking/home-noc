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

The Compose deployment (M07) uses the file form: `secrets/credential_key`, mounted read-only and
selected through `CREDENTIAL_ENCRYPTION_KEY_FILE`. **Already running with an inline key from M04?**
Move that exact key into the file and delete the inline line; do not generate a new one. Steps and
the read-only `python -m app.dbtool check-key` verification are in `docs/installation.md`
("Upgrading from M04").

## Backup and key loss
- Back up the key **separately** from the database backup (e.g. password manager).
  A database backup alone cannot reveal credentials; a key alone is useless without it.
- **If the key is lost, every stored credential is permanently unrecoverable.** Delete
  and re-enter them (see "Master key mismatch and recovery" for the manual reset). A
  changed key is detected and refused rather than accepted; rows are never returned or
  silently ignored.
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

## Dependency
The cipher comes from `cryptography==50.0.2`, which is pinned and hash-locked in
`backend/requirements.lock` (installed with `--require-hashes`; the lock was verified,
the production image builds from it, and `pip-audit` reports no known vulnerabilities).
No lock regeneration is needed for this feature.

## Master key and database binding
The master key is bound to the database so a different (even perfectly valid) key can
never be mixed in with credentials written under the previous one.

- Table `credential_key_verifier` (migration `0005_credential_key_verifier`, separate from
  `connector_credentials`) holds one row: a format version, a random 16-byte salt and
  `HMAC-SHA256(master_key, "home-noc/credential-key-verifier" 0x00 "v1" 0x00 salt)`.
  It is one-way; the key itself is never stored or logged, and neither is the verifier.
- **Before every credential write** the key is checked against the verifier. A mismatch
  returns `503 {"detail": "Credential encryption is not available"}`, writes nothing, and
  the verifier is never replaced.
- **Empty database:** the verifier is created in the same transaction as the first
  credential (the singleton primary key serialises concurrent first writes; the loser is
  re-checked against the winner's verifier).
- **Database from before 0005 that already holds credentials:** no verifier exists, so
  every stored ciphertext must first authenticate with the supplied key. If any fails,
  nothing is bound or written. If all succeed the verifier is created on the next write.
- The verifier outlives the credentials: deleting every credential does not make a
  different key acceptable.
- **Restart and requests:** startup verifies the key against the database (a mismatch
  stops a production start; elsewhere it is logged), and every `/api/v1/credentials/*`
  request, including status reads and deletes, re-checks it. Status endpoints therefore
  answer `503` rather than `configured: true` when the key is wrong.
- With no key configured, inventory and authentication keep working; credential
  endpoints answer `503`.
- Downgrading past 0005 drops only the verifier; credentials are kept and the binding is
  re-established (after authenticating them) on the next write once upgraded again.

## Master key mismatch and recovery
Changing `CREDENTIAL_ENCRYPTION_KEY` is **not** supported key rotation. A different key is
refused, and existing credentials stay unreadable until the original key is restored.

1. Restore the original key (from your separate key backup) and restart. Nothing was
   modified by the refused requests.
2. If the original key is truly lost, the credentials are unrecoverable. This is a
   deliberate, manual, destructive decision: stop the service, back up the database file,
   then discard the stored credentials **and** the verifier together
   (`DELETE FROM connector_credentials; DELETE FROM credential_key_verifier;` in `sqlite3`),
   start with the new key, and re-enter every credential. The application never does this
   on its own.

## Backup requirements
Back up the database **and** the master key together as a pair, but store them separately
(e.g. database in your normal backup, key in a password manager). A restored database is only
useful with the key that was active when its credentials were written; an old backup
therefore needs the old key. Keep a copy of the key before the first credential is stored.

`scripts/restore.sh` enforces this before installing anything: a backup with a verifier must match
the configured key, and a backup from before migration 0005 (no verifier) is accepted only if every
stored ciphertext authenticates under that key. Backup files are not encrypted and expose the
inventory and other non-credential data; see `docs/installation.md` ("Backups").

## Known limits
- `Device.notes` is free text; it cannot be reliably scanned for secrets. Operators must
  not paste credentials there.
- SQLite WAL files may retain old frames until checkpointed; the old ciphertext is
  encrypted regardless.
- Compose secret mount, bootstrap and database backup/restore are described in
  `docs/installation.md` (M07).
