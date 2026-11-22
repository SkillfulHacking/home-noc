# home-noc
Home Noc is a tool that is designed for home lab admins to monitor and integrate network devices and services.

## Running locally

```bash
docker compose up -d --build
```

The frontend's Nginx container (port 3000) is the single entry point in this
deployment. It serves the built SPA and proxies `/api/*` to the backend
service on the internal Compose network (see `frontend/nginx.conf`), so the
browser only ever talks to one origin and never needs CORS:

- `GET /api/health` and `GET /api/version` -> backend `/health`, `/version`
- `/api/v1/*` -> backend `/api/v1/*` (path preserved, not stripped)

After the stack is up, verify routing with:

```bash
./scripts/compose-smoke-test.sh
# or, to also exercise a protected scanner dry-run route:
HOME_NOC_API_KEY=<your API_KEY> ./scripts/compose-smoke-test.sh
```

## Testing

See [`docs/testing.md`](docs/testing.md) for the backend, frontend, dependency
audit, image build, and full-stack Compose commands mirrored by CI.
