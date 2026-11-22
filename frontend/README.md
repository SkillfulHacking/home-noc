# home-noc frontend

React + TypeScript + Vite SPA, served through Nginx in production (see `nginx.conf`).

## API client (`src/lib/api.ts`, `src/lib/auth.ts`)

- `defaultApiBase()` resolves the API base URL used to pre-fill the login form:
  the build-time `VITE_DEFAULT_API_BASE` env var if set, otherwise a same-origin
  `"<origin>/api"` path so the production build works through the Nginx proxy
  without CORS. `docker-compose.yml` sets `VITE_DEFAULT_API_BASE=/api` as a
  frontend build arg; without that override it uses the current browser origin
  plus `/api`, matching the same-origin production route.
- Login saves `{ apiBase, apiKey }` via `setAuth()`; it is kept in
  `sessionStorage` (cleared when the tab closes) rather than `localStorage`,
  to limit how long a raw API key persists in the browser.
- `apiGet/apiPost/apiPut/apiPatch/apiDelete` are a typed `fetch` wrapper that
  attach the stored `X-API-Key` header, parse JSON responses, clear stored
  credentials on a `401`, and throw a typed `ApiError` (with `status` and the
  backend's `detail` message when present) on failure so UI code can surface
  readable errors.

## Scripts

```
npm ci
npm run dev      # vite dev server on :5173
npm run build    # production build into dist/
npm run test     # vitest unit tests (src/lib)
```
