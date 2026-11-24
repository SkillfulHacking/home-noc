# Inventory UI (M21)

Routes (all behind `RequireAuth`): `/inventory` (list) and `/inventory/:id` (detail).

## Behavior
- **List**: responsive card grid; search (hostname, IP, MAC, vendor, model, location) and role / vendor /
  status filters run in the browser **only over the records already loaded**. The API returns at most 500
  devices and there is no pagination yet; when 500 are loaded the UI warns that the inventory may be
  incomplete and that search/filters cannot find devices outside the loaded records. Loading, empty and
  error states are shown. A failed refresh keeps the last list.
- **Freshness** is derived from `last_seen`: `Recently seen` (within 1 hour), `Stale`, or `Never seen`.
  It records when a source last observed the device and is **not** a reachability or "online" indicator.
- **Auto refresh**: the list and detail poll every 5 s (paused while the tab is hidden), so devices imported
  by a finished scan appear without a manual reload. Filters are component state and survive polling.
- **Detail**: identity, addresses, ports, freshness, discovery method, source identifiers and the
  observation history (source, reference, time). The route wrapper keys the detail component by device ID,
  so navigating A → B resets all state, drafts and polling; late responses from A are discarded and saves
  always target the device on screen. Long unbroken identifiers wrap (no horizontal page scroll at 360px).
- **Sensitive-value display policy** (`displayIdentity` / `displayObservation` in `lib/inventory.ts`):
  identity `external_id` values are shown only for known hardware-identifier sources (`mac`, `mac_address`,
  `serial`, `serial_number`, `uuid`, `chassis_id`, `hardware_id`) and only if the value is a plain identifier
  (`[A-Za-z0-9:._-]`, ≤128 chars). Any other source shows the source name with the value hidden. Observation
  `source_ref` is shown only for `scan`/`import` sources under the same value rule. Observation `data`
  payloads and SNMP/API metadata are never rendered. To display a new source, add it to the allowlist.
- **User labels**: location, roles and notes are edited in a draft. Polling updates read-only data but never
  overwrites the draft; save sends a PATCH with only those three fields. Credentials are not in the canonical
  device model, and nothing credential-related is requested or shown.

## Known limits
- Filtering is client-side over at most 500 loaded devices; server-side filters/pagination are a follow-up.
  Until then, devices beyond the first 500 are not reachable from the UI.
- If a device is edited elsewhere while a draft is open, last save wins (no conflict detection yet).

## Verification
`cd frontend && npm ci && npm run lint && npm run typecheck && npm test && npm run build && npm run test:e2e`
