# Authorized scan scope (M08)

Only scan networks you own or have explicit written permission to test.

## Configuration (environment)
| Variable | Default | Meaning |
|---|---|---|
| `SCAN_ALLOWED_CIDRS` | empty | Comma-separated (or JSON list) IPv4 CIDRs, e.g. `192.168.50.0/24`. Empty = every scan is refused. Invalid or IPv6 entries are ignored, never widening scope. |
| `SCAN_ALLOW_PUBLIC` | `false` | Global addresses are refused unless this is `true` **and** the range is allowlisted. |
| `SCAN_SECURITY_PROFILE_ENABLED` | `false` | Enables the opt-in `security` profile. |

## Validation rules
- Targets are IPv4 addresses or strict CIDRs only. Hostnames are rejected, so nothing is resolved after validation (no DNS rebinding).
- Targets must sit inside an allowlisted CIDR. Loopback, link-local, multicast, unspecified and reserved ranges are never scannable.
- Host counts are bounded per profile (discovery 1024, ports 256, security 64); at most 64 target entries per request; overlaps are de-duplicated.
- No free-form scanner flags: the request schema forbids extra fields, and profiles map to fixed argv owned by `app/scan_scope.py`.

## Profiles
`discovery` (gentle, no port probing, default), `ports` (top 20 TCP ports), `security` (opt-in service detection).

## API
- `GET /api/v1/scans/scope` – configured scope and profile availability.
- `POST /api/v1/scans/preflight` `{targets, profile}` – dry run returning `resolved_targets`, `resolved_target_count`, `mode`, limits. 403 for scope/profile violations, 422 for malformed input; `detail` is `{code, message}`.
- `POST /api/v1/scans/ping-sweep` – same validation; execution remains disabled.

Every approval or rejection is logged by logger `home_noc.scan_authorization` with the operator username, profile, normalized networks and outcome (rejections log only the reason code). This issue adds no scan execution; a future executor must call `resolve_targets` itself.
