# Asset reconciliation (M12)

Source observations (ICMP discovery, SNMP/API connectors, operators) are merged
into one deduplicated device inventory by `backend/app/reconcile.py`.

## Identity priority

1. **Trusted vendor identifiers** (`identifiers: {"unifi": "<id>"}`), stored as
   `device_identities` rows.
2. **Normalized MAC** (lowercase colon form).
3. **IP / hostname — weak, used with caution.** An IP match is accepted only if
   exactly one device holds the address *and* nothing contradicts it (different
   MAC, different vendor id, different non-placeholder hostname). Hostname alone
   is used only when the observation carries no IP or strong id. If weak
   evidence matches several devices the observation is refused
   (`409` via API, counted as `ambiguous` for scans) and nothing is written.

Serial numbers are *not* identities (duplicated serials would collapse
unrelated hosts); they only fill an empty field. A contradicting identity never
merges two devices: it is recorded under `reconciliation.conflicts`. When strong
identity evidence contradicts a matched device, the observation is retained
with `data.reconciliation.quarantined: true`, but its disputed IPs, ports,
identities, hardware facts and timestamps do not modify canonical inventory.

## Merge rules

- `first_seen` only moves earlier; `last_seen` only later (future timestamps
  are clamped to now + 5 min). IPs and open ports are unioned, never removed.
- **Curated fields are protected.** `location`, `roles`, `notes`, `snmp`, `api`
  are never changed. `hostname` is replaced only when it is an auto-generated
  placeholder (equal to one of the device's IPs). `vendor`/`model`/`os`/
  `serial`/`mac` are filled only when empty; a differing report becomes a
  `field_conflict` on the observation.
- **One observation row per (device, source, source_ref)**, updated in place, so
  two sources for one switch yield one asset with distinct observations and
  repeated scans do not grow history.
- **Stale** observations (older than the stored row for the same source/ref)
  change nothing except pulling `first_seen` earlier.

## Provenance

`GET /api/v1/devices/{id}/observations` lists each source's latest sighting;
`data.reconciliation` holds `matched_by`, `applied_fields` and `conflicts`.
`GET /api/v1/devices/{id}/identities` lists bound identities.

## API

`POST /api/v1/devices/reconcile` (session + CSRF required). Body: `source`
(`scan|snmp|api|manual`), optional `source_ref`, `observed_at`, `hostname`,
`ip[]`, `mac`, `identifiers{}`, `vendor`, `model`, `os`, `serial`, `ports[]`,
`data{}`. At least one of ip/mac/identifiers/hostname is required; credential-
shaped keys anywhere in `data` are rejected; loopback/unspecified/multicast IPs
are rejected. Response: `device_id`, `observation_id`, `action`
(`created|merged`), `matched_by`, `stale`, `applied_fields`, `conflicts`.

## Scans

The worker now also reconciles `icmp_echo` discovery results: each responsive
host is an IP-only sighting (source `scan`, ref `icmp-echo`) that attaches to its
unique compatible holder or creates a placeholder asset named after the IP.
Totals are added to the job result as `asset_reconciliation`. Unanswered hosts
are never treated as offline. TCP port results keep the M11 behaviour (attach
only, never create).

## Known limits

- No manual merge/split tooling yet: weak-evidence churn (IP changed, no MAC or
  vendor id seen) creates a new asset rather than guessing.
- Reused IPs leave the old holder's IP list intact (history is never erased),
  so later IP-only sightings of that address are refused as ambiguous until an
  operator edits the stale address.
- Observation rows per device are bounded only by distinct `source_ref` values.
