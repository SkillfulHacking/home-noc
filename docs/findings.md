# Vulnerability findings (M18)

Nuclei results (docs/nuclei.md) are persisted as **findings**, one row per distinct issue on an asset/service.

- **Identity / dedupe:** `sha256(device | template | scheme | port | matcher | path)` per device. Finding the same issue again updates the row (`last_seen`, `occurrences`, `last_job_id`, template/scanner versions) and never creates a duplicate. Only hosts that map to exactly one inventory device are stored (`unmatched` counted in the job result under `finding_persistence`).
- **Lifecycle:** `open` → `resolved` only when a later run was **conclusive** — not timed out, no malformed or over-limit/truncated output — covered the same template, **and the same host:port produced at least one result in that run** (positive evidence the service answered; a down or skipped host never resolves anything) — and the finding was not reported again (including for hosts that could not be matched to a single device) — **in 2 consecutive such runs** (`missed_runs`), because a single request can fail silently inside an otherwise healthy run; a sighting resets the counter → `open` again (`reopened`) if it comes back. `suppressed` is an explicit operator decision with a reason; reruns update `last_seen` but never change it, and a suppressed finding is never auto-resolved.
- **Audit trail:** `finding_events` records opened / seen / resolved / reopened / suppressed / unsuppressed with job id, actor and note (200 per finding retained).
- **Sanitization:** only whitelisted, length-bounded, secret-redacted fields are stored (`app/redaction.py` is applied again at persistence). Raw requests/responses/curl commands are never stored or returned.
- **Events:** the first time a `medium`/`high`/`critical` finding opens, one `finding_opened` event is emitted (docs/events.md); lows and repeats are silent.

## API (session required; suppress/unsuppress also need CSRF)
- `GET /api/v1/findings` — filters `device_id`, `severity`, `status`, `template_id`, `since`, `q`; `limit`/`offset`; ordered by severity then recency; returns `total` and `by_status` counts for the filter.
- `GET /api/v1/findings/{id}` — finding plus history (latest 100).
- `POST /api/v1/findings/{id}/suppress` `{"reason": "..."}` and `POST .../unsuppress`.

Limits: findings come from the Nuclei profile only; suppression is per finding (no global rules); severity comes from the template.
