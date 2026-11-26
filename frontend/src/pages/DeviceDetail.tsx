import { FormEvent, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  Device,
  FRESHNESS_LABEL,
  primaryIPv4,
  serviceLabel,
  INVENTORY_POLL_MS,
  Identity,
  Observation,
  ROLES,
  Role,
  UserEdits,
  describeInventoryError,
  displayIdentity,
  displayObservation,
  editsFrom,
  freshness,
  getDevice,
  getIdentities,
  getObservations,
  sameEdits,
  saveEdits,
} from "../lib/inventory";
import { ApiError } from "../lib/api";
import { formatTime, utcTime } from "../lib/operations";
import { usePolling } from "../lib/usePolling";

const show = (v: string | null | undefined) => (v ? v : "—");
/** Readable local time; the exact UTC instant is in the tooltip. */
function when(v: string | null | undefined) {
  if (!v) return "—";
  return (
    <time dateTime={v} title={utcTime(v)}>
      {formatTime(v)}
    </time>
  );
}

/**
 * Route wrapper. Keying the detail component by device ID forces a fresh
 * instance (state, draft, polling) whenever the route param changes, so
 * nothing from device A can leak into device B.
 */
export default function DeviceDetailPage() {
  const { id = "" } = useParams();
  return <DeviceDetail key={id} id={id} />;
}

function DeviceDetail({ id }: { id: string }) {
  // Responses that arrive after this instance unmounts are discarded.
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const [device, setDevice] = useState<Device | null>(null);
  const [observations, setObservations] = useState<Observation[]>([]);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [gone, setGone] = useState(false);
  // `draft` is null until the operator edits something. While it is set,
  // polling updates the read-only data but never overwrites what is typed.
  const [draft, setDraft] = useState<UserEdits | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  // Bumped when a save begins and again when it settles. A poll records the
  // generation at start and is discarded if it changed or a save is in flight,
  // so a stale GET can never overwrite a freshly saved device.
  const saveGen = useRef(0);
  const saveInFlight = useRef(false);

  usePolling(async () => {
    if (gone) return;
    const startGen = saveGen.current;
    const stale = () =>
      !alive.current || saveInFlight.current || saveGen.current !== startGen;
    if (saveInFlight.current) return;
    try {
      const [dev, obs, ids] = await Promise.allSettled([
        getDevice(id),
        getObservations(id),
        getIdentities(id),
      ]);
      if (stale()) return;
      if (dev.status === "rejected") throw dev.reason;
      setDevice(dev.value);
      if (obs.status === "fulfilled") setObservations(obs.value);
      if (ids.status === "fulfilled") setIdentities(ids.value);
      setError(
        obs.status === "rejected" || ids.status === "rejected"
          ? "Source details could not be refreshed."
          : null
      );
    } catch (err) {
      if (stale()) return;
      if (err instanceof ApiError && err.status === 404) setGone(true);
      setError(describeInventoryError(err, "Could not load this device."));
    }
  }, INVENTORY_POLL_MS);

  if (gone) {
    return (
      <main id="app" className="mx-auto max-w-4xl p-4 space-y-2">
        <p role="alert">{error}</p>
        <Link className="underline" to="/inventory">Back to inventory</Link>
      </main>
    );
  }
  if (!device) {
    return (
      <main id="app" className="mx-auto max-w-4xl p-4 space-y-2">
        {error ? <p role="alert">{error}</p> : <p role="status">Loading device…</p>}
        <Link className="underline" to="/inventory">Back to inventory</Link>
      </main>
    );
  }

  const base = editsFrom(device);
  const edits = draft ?? base;
  const dirty = draft !== null && !sameEdits(draft, base);
  const status = freshness(device.last_seen);

  const change = (patch: Partial<UserEdits>) => {
    setSaved(false);
    setDraft({ ...edits, ...patch });
  };
  const toggleRole = (role: Role, on: boolean) =>
    change({ roles: on ? [...edits.roles, role] : edits.roles.filter((r) => r !== role) });

  async function onSave(e: FormEvent) {
    e.preventDefault();
    if (!draft || saving || saveInFlight.current) return;
    saveInFlight.current = true;
    saveGen.current += 1;
    setSaving(true);
    setSaveError(null);
    const submitted = draft;
    try {
      // `id` is fixed for this instance (keyed by route), so a save can only
      // ever target the device currently on screen.
      const updated = await saveEdits(id, submitted);
      if (!alive.current) return;
      setDevice(updated);
      // Keep anything typed while the request was in flight.
      setDraft((cur) => (cur === submitted ? null : cur));
      setSaved(true);
    } catch (err) {
      if (alive.current) setSaveError(describeInventoryError(err, "Could not save your changes."));
    } finally {
      saveInFlight.current = false;
      saveGen.current += 1;
      if (alive.current) setSaving(false);
    }
  }

  const field = "rounded bg-zinc-800 p-2 w-full";
  const card =
    "min-w-0 rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-1 break-words [overflow-wrap:anywhere]";

  return (
    <main id="app" className="mx-auto max-w-4xl p-4 space-y-4">
      <Link className="underline text-sm" to="/inventory">← Back to inventory</Link>
      <h1 className="text-xl font-semibold break-words [overflow-wrap:anywhere]">{device.hostname}</h1>
      {error && <p role="alert">{error}</p>}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <section aria-label="Identity" className={card}>
          <h2 className="font-semibold">Identity</h2>
          <dl className="text-sm grid grid-cols-[auto_minmax(0,1fr)] gap-x-3">
            <dt>ID</dt><dd className="min-w-0">{device.id}</dd>
            <dt>MAC</dt><dd className="min-w-0">{show(device.mac)}</dd>
            <dt>Vendor</dt><dd className="min-w-0">{show(device.vendor)}</dd>
            <dt>Model</dt><dd className="min-w-0">{show(device.model)}</dd>
            <dt>OS</dt><dd className="min-w-0">{show(device.os)}</dd>
            <dt>Serial</dt><dd className="min-w-0">{show(device.serial)}</dd>
          </dl>
        </section>

        <section aria-label="Addresses" className={card}>
          <h2 className="font-semibold">Addresses</h2>
          {device.ip.length === 0 ? (
            <p className="text-sm">No addresses recorded.</p>
          ) : (
            <ul className="list-disc pl-5 text-sm">
              {device.ip.map((a) => <li key={a}>{a}</li>)}
            </ul>
          )}
        </section>

        <section aria-label="Freshness" className={card}>
          <h2 className="font-semibold">Freshness</h2>
          <p className="text-sm">Status: <strong>{FRESHNESS_LABEL[status]}</strong></p>
          <p className="text-xs text-zinc-400">
            Based on when a source last observed this device; it does not confirm the device is reachable now.
          </p>
          {primaryIPv4(device) && (
            <p className="text-sm">
              <Link className="underline" to={`/scans?targets=${encodeURIComponent(primaryIPv4(device) ?? "")}`}>
                Scan this device
              </Link>{" "}
              <span className="text-xs text-zinc-400">(previewed and authorized on the Scans page first)</span>
            </p>
          )}
          <p className="text-sm">First seen: {when(device.first_seen)}</p>
          <p className="text-sm">Last seen: {when(device.last_seen)}</p>
        </section>

        <section aria-label="Ports" className={card}>
          <h2 className="font-semibold">Ports</h2>
          {device.ports.length === 0 ? (
            <p className="text-sm">No ports recorded.</p>
          ) : (
            <ul className="text-sm">
              {device.ports.map((p) => (
                <li key={`${p.proto}/${p.port}`}>
                  {p.port}/{p.proto} {p.state ?? ""}{" "}
                  {(() => {
                    const label = serviceLabel(p);
                    return label.basis === "inferred" ? (
                      <span title="Guessed from the conventional port number; the service was not verified.">
                        {label.text} <em className="text-xs text-zinc-400">(conventional, not verified)</em>
                      </span>
                    ) : label.basis === "reported" ? (
                      <span>{label.text} <em className="text-xs text-zinc-400">(reported by scanner)</em></span>
                    ) : (
                      <span className="text-zinc-400">{label.text}</span>
                    );
                  })()}
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section aria-label="Sources" className={card}>
        <h2 className="font-semibold">Sources and provenance</h2>
        <p className="text-sm">Discovery method: {show(device.discovery_method)}</p>
        {identities.length > 0 && (
          <ul aria-label="Source identifiers" className="text-sm">
            {identities.map((i) => {
              const v = displayIdentity(i);
              return (
                <li key={i.id} className="min-w-0">
                  {v.source}: {v.value ?? "value hidden (not a recognized hardware identifier)"}
                </li>
              );
            })}
          </ul>
        )}
        {observations.length === 0 ? (
          <p className="text-sm">No source observations recorded.</p>
        ) : (
          <ul aria-label="Observations" className="text-sm">
            {observations.map((o) => {
              const v = displayObservation(o);
              return (
                <li key={o.id} className="min-w-0">
                  {o.observed_at} — {v.source}{v.ref ? ` (${v.ref})` : ""}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <form onSubmit={onSave} aria-label="Your labels" className={card}>
        <h2 className="font-semibold">Your labels</h2>
        <label className="block">
          Location
          <input className={field} value={edits.location} maxLength={255}
            onChange={(e) => change({ location: e.target.value })} />
        </label>
        <fieldset>
          <legend>Roles</legend>
          <div className="flex flex-wrap gap-3">
            {ROLES.map((r) => (
              <label key={r}>
                <input type="checkbox" checked={edits.roles.includes(r)}
                  onChange={(e) => toggleRole(r, e.target.checked)} /> {r}
              </label>
            ))}
          </div>
        </fieldset>
        <label className="block">
          Notes
          <textarea className={field} rows={4} value={edits.notes}
            onChange={(e) => change({ notes: e.target.value })} />
        </label>
        <p className="text-xs text-zinc-400">Notes are stored unencrypted; keep secrets out of them.</p>
        <div className="flex items-center gap-3">
          <button type="submit" className="rounded bg-emerald-800 px-3 py-1 disabled:opacity-50"
            disabled={!dirty || saving}>
            {saving ? "Saving…" : "Save changes"}
          </button>
          {dirty && (
            <button type="button" className="underline" onClick={() => setDraft(null)}>Discard</button>
          )}
          {saved && !dirty && <span role="status">Saved.</span>}
        </div>
        {saveError && <p role="alert">{saveError}</p>}
      </form>
    </main>
  );
}
