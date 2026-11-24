import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Device,
  Filters,
  INVENTORY_POLL_MS,
  LIST_LIMIT,
  NO_FILTERS,
  FRESHNESS_LABEL,
  ROLES,
  describeInventoryError,
  filterDevices,
  freshness,
  listDevices,
  vendorsOf,
} from "../lib/inventory";
import { usePolling } from "../lib/usePolling";

const STATUS_CLASS: Record<string, string> = {
  recent: "text-emerald-400",
  stale: "text-amber-400",
  never: "text-zinc-400",
};

export default function InventoryPage() {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);

  // Polling keeps scan imports visible without a manual refresh. Filters live
  // in component state, so a refresh never resets them. A failed poll keeps
  // the last good list on screen and shows the error.
  usePolling(async () => {
    try {
      setDevices(await listDevices());
      setError(null);
    } catch (err) {
      setError(describeInventoryError(err, "Could not load the inventory."));
    }
  }, INVENTORY_POLL_MS);

  const set = (patch: Partial<Filters>) => setFilters((f) => ({ ...f, ...patch }));
  const shown = devices ? filterDevices(devices, filters) : [];
  const filtering = JSON.stringify(filters) !== JSON.stringify(NO_FILTERS);
  const input = "rounded bg-zinc-800 p-2 w-full";

  return (
    <main id="app" className="mx-auto max-w-6xl p-4 space-y-4">
      <h1 className="text-xl font-semibold">Inventory</h1>

      <form
        role="search"
        aria-label="Filter devices"
        className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4"
        onSubmit={(e) => e.preventDefault()}
      >
        <label className="block">
          Search
          <input
            type="search"
            className={input}
            value={filters.search}
            placeholder="hostname, IP, MAC, vendor, location"
            onChange={(e) => set({ search: e.target.value })}
          />
        </label>
        <label className="block">
          Role
          <select className={input} value={filters.role} onChange={(e) => set({ role: e.target.value })}>
            <option value="">Any role</option>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          Vendor
          <select className={input} value={filters.vendor} onChange={(e) => set({ vendor: e.target.value })}>
            <option value="">Any vendor</option>
            {vendorsOf(devices ?? []).map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          Status
          <select className={input} value={filters.status} onChange={(e) => set({ status: e.target.value })}>
            <option value="">Any status</option>
            <option value="recent">Recently seen (within the last hour)</option>
            <option value="stale">Stale</option>
            <option value="never">Never seen</option>
          </select>
        </label>
      </form>

      {error && <p role="alert">{error}</p>}

      {devices === null && !error && <p role="status">Loading inventory…</p>}

      {devices !== null && devices.length === 0 && (
        <p role="status">
          No devices yet. Run a scan from the <Link className="underline" to="/scans">Scans</Link> page;
          discovered devices appear here automatically.
        </p>
      )}

      {devices !== null && devices.length > 0 && (
        <>
          <p role="status" className="text-sm">
            Showing {shown.length} of {devices.length} device(s).
          </p>
          {devices.length >= LIST_LIMIT && (
            <p role="status" aria-label="Truncation warning" className="text-sm">
              Only the first {LIST_LIMIT} devices are loaded, so the inventory may be incomplete. Search and
              filters apply only to these loaded records and cannot find devices outside them.
            </p>
          )}
          {shown.length === 0 && filtering && <p>No devices match these filters.</p>}
          {shown.length > 0 && (
            <ul aria-label="Devices" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {shown.map((d) => {
                const status = freshness(d.last_seen);
                return (
                  <li key={d.id} className="rounded-xl border border-zinc-800 bg-zinc-900 p-3 break-words">
                    <Link className="font-medium underline" to={`/inventory/${encodeURIComponent(d.id)}`}>
                      {d.hostname}
                    </Link>
                    <p className={`text-sm ${STATUS_CLASS[status]}`}>{FRESHNESS_LABEL[status]}</p>
                    <p className="text-sm">{d.ip.join(", ") || "no address"}</p>
                    <p className="text-sm text-zinc-400">
                      {[d.vendor, d.roles.join(", ")].filter(Boolean).join(" · ") || "—"}
                    </p>
                  </li>
                );
              })}
            </ul>
          )}
        </>
      )}
    </main>
  );
}
