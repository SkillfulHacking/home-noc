# home-noc frontend

React + TypeScript + Vite SPA, served through Nginx in production (see `nginx.conf`).

## API client (`src/lib/api.ts`, `src/lib/auth.ts`)

- `defaultApiBase()` resolves the API base path used to pre-fill the login form:
  the build-time `VITE_DEFAULT_API_BASE` path if set, otherwise a same-origin
  `/api` path so the production build works through the Nginx proxy
  without CORS. `docker-compose.yml` sets `VITE_DEFAULT_API_BASE=/api` as a
  frontend build arg; without that override it uses the current browser origin
  plus `/api`, matching the same-origin production route.
- API base configuration is restricted to the current browser origin before it
  is stored or used, preventing a mistyped or poisoned value from sending an
  API key to another host.
- Login keeps `{ apiBase, apiKey }` in module memory only. It is never written
  to browser storage, so a reload requires logging in again; M03 will replace
  the temporary API-key flow with a server-managed session.
- Login checks the key against the protected `/v1/devices` route rather than an
  unauthenticated health endpoint.
- `apiGet/apiPost/apiPut/apiPatch/apiDelete` are a typed `fetch` wrapper that
  attach the stored `X-API-Key` header, parse JSON responses, clear stored
  credentials and redirect to `/login` on a `401`, and throw a typed
  `ApiError` (with `status` and the backend's `detail` message when present)
  on failure so UI code can surface readable errors.

## Scripts

```
npm ci
npm run dev      # vite dev server on :5173
npm run build    # production build into dist/
npm run test     # vitest unit tests (src/lib)
```
