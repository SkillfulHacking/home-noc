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
  scanTargetsFor,
  sortDevices,
  vendorsOf,
  type SortDir,
  type SortKey,
} from "../lib/inventory";
import { formatTime, utcTime } from "../lib/operations";
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
  const [view, setView] = useState<"table" | "cards">("table");
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: "hostname", dir: "asc" });
  const [selected, setSelected] = useState<Set<string>>(new Set());

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
  const shown = devices ? sortDevices(filterDevices(devices, filters), sort.key, sort.dir) : [];
  const chosen = shown.filter((d) => selected.has(d.id));
  const scanTargets = scanTargetsFor(chosen);
  const toggleSort = (key: SortKey) =>
    setSort((cur) => ({ key, dir: cur.key === key && cur.dir === "asc" ? "desc" : "asc" }));
  const toggleOne = (id: string) =>
    setSelected((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const allShownSelected = shown.length > 0 && shown.every((d) => selected.has(d.id));
  const toggleAll = () =>
    setSelected((cur) => {
      const next = new Set(cur);
      for (const d of shown) {
        if (allShownSelected) next.delete(d.id);
        else next.add(d.id);
      }
      return next;
    });
  const header = (key: SortKey, label: string) => (
    <th scope="col" className="p-2 text-left" aria-sort={sort.key === key ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" className="font-semibold hover:underline" onClick={() => toggleSort(key)}>
        {label}
        {sort.key === key ? (sort.dir === "asc" ? " ▲" : " ▼") : ""}
      </button>
    </th>
  );
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
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <div role="group" aria-label="View">
                <button type="button" aria-pressed={view === "table"} className="rounded-l bg-zinc-800 px-3 py-1 aria-pressed:bg-zinc-600" onClick={() => setView("table")}>Table</button>
                <button type="button" aria-pressed={view === "cards"} className="rounded-r bg-zinc-800 px-3 py-1 aria-pressed:bg-zinc-600" onClick={() => setView("cards")}>Cards</button>
              </div>
              <span>{chosen.length} selected</span>
              {chosen.length > 0 && (
                scanTargets.length > 0 ? (
                  <Link className="rounded bg-zinc-800 px-3 py-1 hover:bg-zinc-700" to={`/scans?targets=${encodeURIComponent(scanTargets.join(","))}`}>
                    Scan selected ({scanTargets.length})
                  </Link>
                ) : (
                  <span className="text-zinc-400">Selected devices have no IPv4 address to scan.</span>
                )
              )}
              {chosen.length > 0 && (
                <button type="button" className="underline" onClick={() => setSelected(new Set())}>Clear selection</button>
              )}
              <span className="text-xs text-zinc-500">
                Scans are previewed and authorized on the Scans page before anything runs.
              </span>
            </div>
          )}
          {shown.length > 0 && view === "table" && (
            <div className="overflow-x-auto rounded-xl border border-zinc-800">
              <table aria-label="Devices" className="w-full text-sm">
                <thead className="bg-zinc-900">
                  <tr>
                    <th scope="col" className="p-2">
                      <input type="checkbox" aria-label="Select all shown devices" checked={allShownSelected} onChange={toggleAll} />
                    </th>
                    {header("hostname", "Name")}
                    {header("ip", "Address")}
                    {header("vendor", "Vendor")}
                    {header("roles", "Roles")}
                    {header("last_seen", "Last seen")}
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {shown.map((d) => {
                    const status = freshness(d.last_seen);
                    return (
                      <tr key={d.id} data-testid="device-row">
                        <td className="p-2">
                          <input type="checkbox" aria-label={`Select ${d.hostname}`} checked={selected.has(d.id)} onChange={() => toggleOne(d.id)} />
                        </td>
                        <td className="p-2">
                          <Link className="font-medium underline" to={`/inventory/${encodeURIComponent(d.id)}`}>{d.hostname}</Link>
                        </td>
                        <td className="p-2">{d.ip.join(", ") || "no address"}</td>
                        <td className="p-2">{d.vendor ?? <span className="text-zinc-500">unknown</span>}</td>
                        <td className="p-2">{d.roles.join(", ") || <span className="text-zinc-500">—</span>}</td>
                        <td className="p-2">
                          <span className={STATUS_CLASS[status]}>{FRESHNESS_LABEL[status]}</span>{" "}
                          <span className="text-xs text-zinc-400" title={utcTime(d.last_seen)}>
                            {d.last_seen ? formatTime(d.last_seen) : ""}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {shown.length > 0 && view === "cards" && (
            <ul aria-label="Devices" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {shown.map((d) => {
                const status = freshness(d.last_seen);
                return (
                  <li key={d.id} className="rounded-xl border border-zinc-800 bg-zinc-900 p-3 break-words" data-testid="device-row">
                    <label className="mr-2 inline-flex items-center gap-1">
                      <input type="checkbox" aria-label={`Select ${d.hostname}`} checked={selected.has(d.id)} onChange={() => toggleOne(d.id)} />
                    </label>
                    <Link className="font-medium underline" to={`/inventory/${encodeURIComponent(d.id)}`}>
                      {d.hostname}
                    </Link>
                    <p className={`text-sm ${STATUS_CLASS[status]}`}>
                      {FRESHNESS_LABEL[status]}
                      {d.last_seen && (
                        <span className="text-zinc-400" title={utcTime(d.last_seen)}> · {formatTime(d.last_seen)}</span>
                      )}
                    </p>
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
