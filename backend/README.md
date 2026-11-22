<!-- backend/README.md -->
# Home-NOC API (Base Bootstrap)

## Quickstart (Local)
```bash
cd backend
make install
make dev
# open http://localhost:8000/docs
```

## Asset schema (canonical devices)

`Device` (`/api/v1/devices`) is the curated, operator-reviewed asset record:
`id`, `hostname`, `ip[]`, `mac`, `first_seen`/`last_seen`, `discovery_method`,
`vendor`/`model`/`os`/`serial`/`location`, `roles[]`, `ports[]`, `snmp`, `api`,
`notes`. It never stores credentials:

- `snmp` only carries `enabled`/`version` status, not community strings.
- `api.url` is rejected (422) if it embeds `user:pass@host` credentials.
- See `docs/claude-gitar-runbook.md` / M04 for where connector credentials
  actually live (a dedicated secrets store, not this table).

Validation: `ip[]` entries must be valid IPv4/IPv6 addresses (normalized to
canonical form); `mac` must be a valid MAC address (normalized to lowercase
`aa:bb:cc:dd:ee:ff`); `ports[].port` must be 1-65535 with `proto` in
`{tcp, udp}`. `first_seen`/`last_seen` are normalized to timezone-aware UTC
(naive input is assumed to already be UTC) so values round-trip consistently
regardless of the underlying DB's timezone support.

Raw sightings and source de-duplication are tracked separately from the
curated fields:

- `POST/GET /api/v1/devices/{id}/observations` — append-only history of what
  a scanner/connector/operator saw at a point in time (`source`,
  `source_ref`, `observed_at`, `data`). `data` is rejected (422) if it
  contains credential-shaped keys (`password`, `token`, `community`, etc.).
  Posting an observation never mutates the curated `Device` fields.
- `POST/GET /api/v1/devices/{id}/identities` — source-specific unique keys
  (e.g. `source="mac"`, `source="connector:unifi"`) used to prevent the same
  physical device from being re-created as a duplicate row. A `mac` identity
  is kept in sync automatically from `Device.mac`; conflicting creates/updates
  return `409 Conflict`.

## Migrations
```bash
cd backend
alembic upgrade head
```
