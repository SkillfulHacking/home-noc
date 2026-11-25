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
| Private allowlist | empty | Optional strict RFC1918 CIDRs; when non-empty only these are scannable. |
| Exclusions | empty | Any target range that *overlaps* an exclusion is rejected whole. |
| Public scanning | off | Needs the toggle **and** an explicit public allowlist entry covering the whole target. Public entries may not be wider than /16, and only the `discovery`/`ports` profiles may target public addresses. Only scan infrastructure you own or are approved to test. |

Never scannable (any policy): `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16` (incl. cloud
metadata `169.254.169.254`), `224.0.0.0/4`, `240.0.0.0/4` (incl. `255.255.255.255`), and
network/broadcast addresses of private blocks. Ranges spanning authorized and
unauthorized space (mixed ranges) are rejected, not trimmed. Non-RFC1918 special-use
space (e.g. CGNAT, TEST-NETs) is only scannable if the environment lists it explicitly.

Precedence — any denial wins: forbidden space → exclusions → environment ceiling →
runtime toggles/allowlists → profile limits (host count, concurrency, timeout, per-request
entry caps, queue cap). The `security` profile remains controlled only by
`SCAN_SECURITY_PROFILE_ENABLED`; policy never enables it.

### Upgrade and fresh-install handling
Migration `0007_scan_policy` seeds the single row:
- **Fresh** (no inventory/jobs/sessions/credentials): private on, public off.
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
queued jobs it no longer authorizes (same transaction). A running job re-validates when the
revision changes (checked at least every 0.5 s, before every probe dispatch) and ends as
`failed` / `authorization_revoked`, keeping observations already gathered. Probes already
dispatched when the revocation is observed may complete or time out (bounded by the
profile's concurrency and the 1 s probe timeouts). If the policy store is transiently
unreadable the job continues for at most one lease period (`WORKER_LEASE_SECONDS`) before
it is stopped.

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
