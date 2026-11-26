# Authorized scan scope (M08)

Only scan networks you own or have explicit written permission to test.

## Runtime scan policy (M08A, issue #66)
Administrators manage policy in **Settings → Security → Scan Policy** (API:
`GET/PUT /api/v1/scan-policy`, `GET /api/v1/scan-policy/audit`; admin session + CSRF).
No restart is needed. It is stored in the `scan_policy` table (single row, `revision`
for optimistic locking) and every change is audited in `scan_policy_audit`
(actor, prior/new configuration, revisions, time, outcome) in the same transaction.

| Setting | Default (fresh install) | Meaning |
|---|---|---|
| Private scanning | on | Targets must be inside exactly `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (explicit list, not `is_private`). Targets are still chosen explicitly per scan. |
| Strict private mode | off | Explicit toggle. Off: all RFC1918 (subject to ceiling and exclusions). On with an **empty** list: nothing is authorized. On with a populated list: only the listed RFC1918 ranges. A list without strict mode is rejected (`allowlist_requires_strict`). Leaving strict mode, or widening its list, is *broadening* and needs confirmation. |
| Private allowlist | empty | RFC1918 CIDRs used only in strict mode. |
| Exclusions | empty | Any target range that *overlaps* an exclusion is rejected whole. |
| Public scanning | off | Needs the toggle **and** an explicit public allowlist entry covering the whole target. Public entries may not be wider than /16, and only the `discovery`/`ports` profiles may target public addresses. Only scan infrastructure you own or are approved to test. |

Never scannable (any policy): `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16` (incl. cloud
metadata `169.254.169.254`), `224.0.0.0/4`, `240.0.0.0/4` (incl. `255.255.255.255`), and
network/broadcast addresses of private blocks. Ranges spanning authorized and
unauthorized space (mixed ranges) are rejected, not trimmed. Non-RFC1918 special-use
space (e.g. CGNAT, TEST-NETs) is a **legacy exception**, not private authorization: it is
scannable only if `SCAN_ALLOWED_CIDRS` lists it explicitly, private scanning is on and
strict mode is **off**. Strict mode never authorizes it, and the UI/API show it separately
(`effective.special_use_networks`). Runtime policy can never add such ranges.

Precedence — any denial wins: forbidden space → exclusions → environment ceiling →
runtime toggles/allowlists → profile limits (host count, concurrency, timeout, per-request
entry caps, queue cap). The `security` profile remains controlled only by
`SCAN_SECURITY_PROFILE_ENABLED`; policy never enables it.

### Upgrade and fresh-install handling
Migration `0007_scan_policy` seeds the single row (`0008_scan_policy_strict` then adds the
strict toggle, setting it on for any row that already had a non-empty allowlist, so no
authorization changes):
- **Fresh** — explicit evidence only: `alembic/env.py` found a database with **no tables at
  all** before the run. Private on, public off. An existing but *empty* schema (or any
  ambiguous situation, e.g. a driver that did not set the marker) is an upgrade, not fresh.
- **Upgrade, `SCAN_ALLOWED_CIDRS` set**: private on; the env list stays an immutable ceiling.
- **Upgrade, `SCAN_ALLOWED_CIDRS` empty** (legacy "everything refused"): private seeded **off**; an administrator must enable it. Authorization is never silently broadened.
- Public is never seeded on, even if `SCAN_ALLOW_PUBLIC=true`.

If the row is missing in production, invalid, or the database is unreadable, scanning is
denied (HTTP 503 `policy_missing`/`policy_invalid`/`policy_unavailable`; the worker fails the
job with `scope_rejected`). Rollback: `alembic downgrade 0006_scan_jobs` drops both tables
(policy history is lost; inventory untouched); the older release then authorizes from the
environment alone.

### Revocation boundary
API and worker each re-read the stored policy; neither caches it. Saving a policy fails
queued jobs it no longer authorizes (same transaction).

Ordering contract for running jobs: a policy change is durable when the API transaction
commits; the worker calls its authorization check, which opens a fresh session and reads the
stored policy, immediately **before every probe dispatch** (each ICMP send, TCP connect
submission, Nmap chunk spawn) and on every poll of a running Nmap subprocess. There is no
timer or cache, so any check that starts after the commit sees the revocation and the job
ends `failed` / `authorization_revoked`, keeping observations gathered earlier. If the policy
cannot be read for **any** reason (transient database error, missing or invalid row) no
further probe is dispatched and the job ends `failed` / `authorization_unverified`.

Boundary and **known gap**: the check cannot be atomic with the operating-system send, and
the API does not wait for workers to acknowledge a revocation, so revocation is eventual
with a bound, not instantaneous: a probe whose check preceded the commit may still go out
(at most one per in-flight slot, i.e. the profile's `max_concurrency`), and a running Nmap
chunk is killed at its next poll (`POLL_SECONDS` plus one policy read). Probes already
dispatched may complete or time out. Closing the gap fully would need a worker
acknowledgement barrier in the API, which is out of scope here.

### Worker network vantage point
Scans originate from the **worker container's** network position, which may differ from the
browser's or host's. Docker-network overlap, collector routing and IPv6 are out of scope.

## Environment ceilings (unchanged variables, new semantics)
| Variable | Default | Meaning |
|---|---|---|
| `SCAN_ALLOWED_CIDRS` | unset | Optional immutable ceiling (comma-separated or JSON list of IPv4 CIDRs). Runtime policy can only narrow it. Set but unusable → every scan is refused. |
| `SCAN_ALLOW_PUBLIC` | unset | Explicit `false` blocks public scanning at runtime. `true` authorizes nothing by itself. |
| `SCAN_SECURITY_PROFILE_ENABLED` | `false` | Enables the opt-in `security` profile. |

## Validation rules
- Targets are IPv4 addresses or strict CIDRs only. Hostnames are rejected, so nothing is resolved after validation (no DNS rebinding).
- Targets must sit inside an allowlisted CIDR. Loopback, link-local, multicast, unspecified and reserved ranges are never scannable.
- Host counts are bounded per profile (discovery 1024, ports 256, security 64); at most 64 target entries per request; overlaps are de-duplicated.
- No free-form scanner flags: the request schema forbids extra fields, and profiles map to fixed argv owned by `app/scan_scope.py`.

## Profiles
`discovery` (bounded ICMP echo only, no port probing, default), `ports` (top 20 TCP ports),
`security` (opt-in service detection). ICMP silence is inconclusive, never a definitive
offline state.

## API
- `GET /api/v1/scans/scope` – configured scope and profile availability.
- `POST /api/v1/scans/preflight` `{targets, profile}` – dry run returning `resolved_targets`, `resolved_target_count`, `mode`, limits. 403 for scope/profile violations, 422 for malformed input; `detail` is `{code, message}`.
- `POST /api/v1/scans/ping-sweep` – legacy validation/dry-run route; it never executes.
- `POST /api/v1/scans/jobs` – queues validated execution in the durable worker. Scope is
  validated again immediately before execution.

Every approval or rejection is logged by logger `home_noc.scan_authorization` with the
operator username, profile, normalized networks and outcome (rejections log only the
reason code).
