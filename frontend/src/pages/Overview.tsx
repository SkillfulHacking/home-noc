import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { apiGet } from "../lib/api";
import {
  acknowledgeEvent,
  eventTypeLabel,
  fetchEvents,
  fetchFindingsSummary,
  fetchHealth,
  formatTime,
  HEALTH_STATUSES,
  statusClass,
  utcTime,
  type DeviceHealth,
  type EventSeverity,
  type FindingsSummary,
  type HealthResponse,
  type OpEvent,
} from "../lib/operations";
import { usePolling } from "../lib/usePolling";

const REFRESH_MS = 30_000;
type Section = "health" | "events" | "findings" | "system";

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export default function OverviewPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [attention, setAttention] = useState<DeviceHealth[]>([]);
  const [events, setEvents] = useState<OpEvent[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [eventTotal, setEventTotal] = useState(0);
  const [findings, setFindings] = useState<FindingsSummary | null>(null);
  const [system, setSystem] = useState<Record<string, unknown> | null>(null);
  const [errors, setErrors] = useState<Partial<Record<Section, string>>>({});
  const [severity, setSeverity] = useState<EventSeverity | "">("");
  const [onlyUnacked, setOnlyUnacked] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  // The current filter key; responses for an older key are dropped so a slow request from a
  // previous filter can never overwrite the results the operator is looking at.
  const filterKey = `${severity}|${onlyUnacked}`;
  const currentKey = useRef(filterKey);
  useEffect(() => {
    currentKey.current = filterKey; // declared before usePolling, so it runs first
  }, [filterKey]);
  // True once older pages were appended: polling must then merge, not replace.
  const loadedOlder = useRef(false);

  const setError = (section: Section, err: unknown | null) =>
    setErrors((prev) => {
      const next = { ...prev };
      if (err === null) delete next[section];
      else next[section] = errorText(err);
      return next;
    });

  const refresh = useCallback(async () => {
    // Each panel loads independently so one failing API never blanks the dashboard.
    await Promise.all([
      (async () => {
        try {
          const [all, offline, degraded] = await Promise.all([
            fetchHealth(undefined, 1),
            fetchHealth("offline", 10),
            fetchHealth("degraded", 10),
          ]);
          setHealth(all);
          setAttention([...offline.devices, ...degraded.devices]);
          setError("health", null);
        } catch (err) {
          setError("health", err);
        }
      })(),
      (async () => {
        const key = filterKey;
        try {
          const page = await fetchEvents({
            severity: severity || undefined,
            acknowledged: onlyUnacked ? false : undefined,
          });
          if (key !== currentKey.current) return;
          if (loadedOlder.current) {
            // Refresh the head without discarding older pages the operator loaded:
            // fresh rows win by id, the existing cursor is kept.
            setEvents((prev) => {
              const fresh = new Set(page.events.map((e) => e.id));
              return [...page.events, ...prev.filter((e) => !fresh.has(e.id))];
            });
          } else {
            setEvents(page.events);
            setNextCursor(page.next_cursor);
          }
          setEventTotal(page.total);
          setError("events", null);
        } catch (err) {
          setError("events", err);
        }
      })(),
      (async () => {
        try {
          setFindings(await fetchFindingsSummary());
          setError("findings", null);
        } catch (err) {
          setError("findings", err);
        }
      })(),
      (async () => {
        try {
          setSystem(await apiGet<Record<string, unknown>>("/health"));
          setError("system", null);
        } catch (err) {
          setError("system", err);
        }
      })(),
    ]);
  }, [severity, onlyUnacked, filterKey]);

  usePolling(refresh, REFRESH_MS, filterKey);

  const loadMore = async () => {
    if (!nextCursor) return;
    setLoadingMore(true);
    const key = filterKey;
    try {
      const page = await fetchEvents({
        severity: severity || undefined,
        acknowledged: onlyUnacked ? false : undefined,
        cursor: nextCursor,
      });
      if (key !== currentKey.current) return;
      loadedOlder.current = true;
      setEvents((prev) => {
        const have = new Set(prev.map((e) => e.id));
        return [...prev, ...page.events.filter((e) => !have.has(e.id))];
      });
      setNextCursor(page.next_cursor);
      setError("events", null);
    } catch (err) {
      setError("events", err);
    } finally {
      setLoadingMore(false);
    }
  };

  const acknowledge = async (id: string) => {
    try {
      const updated = await acknowledgeEvent(id);
      setEvents((prev) =>
        onlyUnacked ? prev.filter((e) => e.id !== id) : prev.map((e) => (e.id === id ? updated : e))
      );
    } catch (err) {
      setError("events", err);
    }
  };

  const summary = health?.summary;
  return (
    <main id="app" className="mx-auto max-w-6xl p-4">
      <h1 className="text-2xl font-semibold mb-4">Operations overview</h1>

      <section aria-labelledby="health-h" className="mb-6">
        <h2 id="health-h" className="font-medium mb-2">Device health</h2>
        {errors.health && <p role="alert" className="text-red-400">Health unavailable: {errors.health}</p>}
        {summary && (
          <ul className="grid grid-cols-2 gap-3 sm:grid-cols-4" aria-label="Device health summary">
            {HEALTH_STATUSES.map((status) => (
              <li
                key={status}
                className={`rounded-xl border bg-zinc-900 p-3 ${statusClass(status)}`}
                data-testid={`health-${status}`}
              >
                <div className="text-3xl font-semibold">{summary[status]}</div>
                <div className="text-sm capitalize">{status}</div>
              </li>
            ))}
          </ul>
        )}
        {summary && (
          <p className="mt-2 text-sm text-zinc-400">
            {summary.total} devices. Status is derived from recent observations and repeated
            failures; <Link className="underline" to="/inventory">last seen</Link> shows inventory
            freshness separately.
          </p>
        )}
        {attention.length > 0 && (
          <div className="mt-3">
            <h3 className="text-sm font-medium mb-1">Needs attention</h3>
            <ul className="divide-y divide-zinc-800 rounded-xl border border-zinc-800 bg-zinc-900">
              {attention.map((d) => (
                <li key={d.device_id} className="flex flex-wrap items-center gap-2 p-2">
                  <span className={`rounded border px-2 text-xs ${statusClass(d.status)}`}>
                    {d.status}
                  </span>
                  <Link className="underline" to={`/inventory/${d.device_id}`}>{d.hostname}</Link>
                  <span className="text-sm text-zinc-400">{d.reason}</span>
                  <span className="ml-auto text-xs text-zinc-500" title={utcTime(d.status_changed_at)}>
                    since {formatTime(d.status_changed_at)}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {summary && attention.length === 0 && !errors.health && (
          <p className="mt-2 text-sm text-emerald-300">No offline or degraded devices.</p>
        )}
      </section>

      <section aria-labelledby="findings-h" className="mb-6">
        <h2 id="findings-h" className="font-medium mb-2">Findings</h2>
        {errors.findings && (
          <p role="alert" className="text-red-400">Findings unavailable: {errors.findings}</p>
        )}
        {findings && (
          <p>
            <span className="text-2xl font-semibold" data-testid="open-findings">
              {findings.by_status.open}
            </span>{" "}
            open finding(s)
            {findings.by_status.suppressed > 0 && ` (${findings.by_status.suppressed} suppressed)`}.
          </p>
        )}
      </section>

      <section aria-labelledby="events-h" className="mb-6">
        <div className="mb-2 flex flex-wrap items-center gap-3">
          <h2 id="events-h" className="font-medium">Event timeline</h2>
          <label className="text-sm">
            Severity{" "}
            <select
              className="rounded bg-zinc-800 px-1 py-0.5"
              value={severity}
              onChange={(e) => {
                loadedOlder.current = false;
                setSeverity(e.target.value as EventSeverity | "");
              }}
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
            </select>
          </label>
          <label className="text-sm">
            <input
              type="checkbox"
              checked={onlyUnacked}
              onChange={(e) => {
                loadedOlder.current = false;
                setOnlyUnacked(e.target.checked);
              }}
            />{" "}
            Unacknowledged only
          </label>
          <span className="text-xs text-zinc-500">{eventTotal} event(s)</span>
        </div>
        {errors.events && <p role="alert" className="text-red-400">Events unavailable: {errors.events}</p>}
        {events.length === 0 && !errors.events && (
          <p className="text-sm text-zinc-400">No events match.</p>
        )}
        <ol className="divide-y divide-zinc-800 rounded-xl border border-zinc-800 bg-zinc-900">
          {events.map((e) => (
            <li key={e.id} className="flex flex-wrap items-center gap-2 p-2" data-testid="event-row">
              <span
                className={`rounded border px-2 text-xs ${
                  e.severity === "critical"
                    ? "border-red-700 text-red-300"
                    : e.severity === "warning"
                      ? "border-amber-600 text-amber-300"
                      : "border-zinc-600 text-zinc-300"
                }`}
              >
                {e.severity}
              </span>
              <span className="font-medium">{eventTypeLabel(e.type)}</span>
              <span>
                {e.device_id ? (
                  <Link className="underline" to={`/inventory/${e.device_id}`}>
                    {e.hostname ?? e.device_id}
                  </Link>
                ) : (
                  e.hostname
                )}
              </span>
              <span className="text-sm text-zinc-400">{e.summary}</span>
              {e.count > 1 && <span className="text-xs text-zinc-500">×{e.count}</span>}
              <span className="ml-auto text-xs text-zinc-500" title={utcTime(e.last_at)}>
                {formatTime(e.last_at)}
              </span>
              {e.acknowledged_at ? (
                <span className="text-xs text-zinc-500">acknowledged</span>
              ) : (
                <button
                  className="rounded bg-zinc-800 px-2 py-0.5 text-xs hover:bg-zinc-700"
                  onClick={() => void acknowledge(e.id)}
                  aria-label={`Acknowledge ${eventTypeLabel(e.type)} ${e.hostname ?? ""}`}
                >
                  Acknowledge
                </button>
              )}
            </li>
          ))}
        </ol>
        {nextCursor && (
          <button
            className="mt-2 rounded bg-zinc-800 px-3 py-1 hover:bg-zinc-700"
            onClick={() => void loadMore()}
            disabled={loadingMore}
          >
            {loadingMore ? "Loading…" : "Load older events"}
          </button>
        )}
      </section>

      <section aria-labelledby="system-h" className="text-sm text-zinc-400">
        <h2 id="system-h" className="sr-only">System</h2>
        {errors.system ? (
          <p role="alert" className="text-red-400">API health check failed: {errors.system}</p>
        ) : (
          <p>API status: {String(system?.status ?? "checking…")}</p>
        )}
      </section>
    </main>
  );
}
