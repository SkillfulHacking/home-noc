# Home-NOC PR review standards

Review this repository as a security-sensitive, local-first network management tool. Focus on regressions and concrete, reproducible defects. Mark findings with file/line references and suggest minimum scoped fixes. CI success is necessary but not sufficient.

## Backend and inventory (backend/)
- API validation must match the canonical inventory schema and preserve UUID, device/source identity, timestamps, and explicitly curated user labels.
- A device identified via ICMP, SNMP or UniFi must not be duplicated merely because the source differs; reject unsafe identity merges where DHCP/IP reuse can cause collisions.
- DB schema changes require reversible Alembic migrations, tests and a safe upgrade path. Do not depend on `create_all()` in production.
- Ensure `PUT` and `PATCH` round-trip nested ports and roles correctly; never store `No Such Object` as a real hardware property.
- Protect inventory reads as well as mutations when authentication is enabled. Production must fail closed when auth config is missing/weak.

## Security and secrets (backend/, docker-compose.yml)
- No keys, SNMP communities/users/passwords, API tokens or credentials in source, API read responses, logs or exported inventory. Sensitive connection details must be masked; encrypted-at-rest connector secrets use a key outside the database.
- Watch for authorization bypass, SSRF, shell injection, unbounded memory/workers, and scanner targets outside operator-approved address scopes.
- Network scans require explicit authorized scope and conservative defaults. Nuclei, intrusive templates and internet scanning must never be enabled implicitly.
- Docker should minimize published ports, privileges/capabilities and writable mounts; avoid root processes where practical.

## Frontend and routing (frontend/)
- A clean `npm ci && npm run build` must work; watch for unresolved `src/lib/*` imports and broken TypeScript paths.
- Browser API requests must work through one same-origin Nginx route. `/api/v1/*` must reach the backend without dropping its prefix. Health/version routes must resolve consistently.
- Login must authenticate against a protected endpoint, not merely `/health`. Avoid browser localStorage for long-lived raw API keys. Check logout/session invalidation and CSRF controls.
- Forms and tables must handle loading, denied access, empty data and backend failures without leaking secrets.

## CI / release
- PRs touching UI or proxy must run frontend build and Compose smoke checks, not only backend tests.
- Verify actual tests cover the reported defect; reject assertions that pass without executing real functionality.
- Require independent reviewer feedback and operator sign-off before merge. **Do not auto-approve or auto-merge solely from an AI review.**
