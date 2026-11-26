# Operational events (M20)

A searchable, deduplicated history of **actionable** changes. Routine scans produce nothing; each real change produces one event.

| type | when | severity | dedupe |
|---|---|---|---|
| `device_discovered` | a new asset is created | info | once per device |
| `address_changed` | a *new* IP is added to an existing asset | info | once per (device, IP) |
| `port_opened` | a *new* open port is added | warning | once per (device, proto, port) |
| `device_offline` | health transitions to `offline` (confirmed repeated failures, see `device-health.md`) | critical | 1 h cooldown → `count` |
| `device_degraded` | health transitions to `degraded` | warning | 1 h cooldown → `count` |
| `device_recovered` | `offline`/`degraded` → `online` | info | 1 h cooldown → `count` |
| `managed_device_missing` | a UniFi-managed device disappears from the controller | warning | 7 d cooldown |

Aging from `online` to `unknown` (data simply got old) and the first `online` are silent. Flapping inside the cooldown increments `count`/`last_at` of the existing event instead of creating rows. Events keep the device id (set to null if the device is deleted) and a hostname snapshot; they never contain credentials. Retention: 90 days and at most 20 000 rows (pruned by the worker).

## API (session required; acknowledge also needs CSRF)
- `GET /api/v1/events` — newest first. Filters: `type`, `severity`, `device_id`, `since`, `until` (ISO 8601), `q` (substring of summary/hostname; wildcards escaped), `acknowledged`. Time filters, ordering and the cursor use the event's most recent occurrence (`last_at`), so a repeat folded into an older event reappears at the top. A repeat of an acknowledged event is a new, unacknowledged event. Keyset pagination: `limit` (1–200, default 50) and `cursor` (= previous `next_cursor`); response `{total, events, next_cursor}`.
- `GET /api/v1/events/{id}`; `POST /api/v1/events/{id}/ack`.

Notification delivery (email/webhooks/MQTT) is out of scope for the MVP (fast-follow F08).
