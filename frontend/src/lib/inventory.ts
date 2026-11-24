import { ApiError, apiGet, apiPatch } from "./api";

export const ROLES = ["switch", "router", "ap", "server", "camera", "iot", "nas", "printer"] as const;
export type Role = (typeof ROLES)[number];

export interface Port {
  port: number;
  proto: "tcp" | "udp";
  service: string | null;
  state: "open" | "closed" | "filtered" | null;
}

/** Canonical device shape. Credentials are never part of it. */
export interface Device {
  id: string;
  hostname: string;
  ip: string[];
  mac: string | null;
  first_seen: string | null;
  last_seen: string | null;
  discovery_method: string | null;
  vendor: string | null;
  model: string | null;
  os: string | null;
  serial: string | null;
  location: string | null;
  roles: Role[];
  ports: Port[];
  snmp: { enabled: boolean; version: string | null } | null;
  api: { type: string | null; url: string | null } | null;
  notes: string | null;
}

/** Provenance: only these fields of an observation are ever displayed (not `data`). */
export interface Observation {
  id: string;
  source: string;
  source_ref: string | null;
  observed_at: string;
}

export interface Identity {
  id: string;
  source: string;
  external_id: string;
}

export interface UserEdits {
  notes: string;
  location: string;
  roles: Role[];
}

/**
 * How recently a source observed the device. This is NOT a reachability
 * signal: a recent observation does not prove the device is up right now.
 */
export type Freshness = "recent" | "stale" | "never";

export const FRESHNESS_LABEL: Record<Freshness, string> = {
  recent: "Recently seen",
  stale: "Stale",
  never: "Never seen",
};

/** A device last observed within this window is "Recently seen". */
export const RECENT_WINDOW_MS = 60 * 60 * 1000;
/** Backend page-size ceiling; a full page means the list may be truncated. */
export const LIST_LIMIT = 500;
export const INVENTORY_POLL_MS = 5000;

export function freshness(lastSeen: string | null, now: number = Date.now()): Freshness {
  if (!lastSeen) return "never";
  const t = Date.parse(lastSeen);
  if (Number.isNaN(t)) return "never";
  return now - t <= RECENT_WINDOW_MS ? "recent" : "stale";
}

/**
 * Display policy for source-specific identifiers. The backend accepts any
 * `external_id` per source, so a value could accidentally carry a credential.
 * Raw values are shown only for known hardware-identifier sources AND only
 * when they look like a plain identifier; everything else is withheld.
 */
const DISPLAYABLE_IDENTITY_SOURCES = new Set([
  "mac", "mac_address", "serial", "serial_number", "uuid", "chassis_id", "hardware_id",
]);
const SAFE_SOURCE = /^[A-Za-z0-9_.-]{1,40}$/;
const SAFE_VALUE = /^[A-Za-z0-9:._-]{1,128}$/;

export interface IdentityView {
  source: string;
  /** null = withheld by policy */
  value: string | null;
}

export function displayIdentity(i: Identity): IdentityView {
  if (!SAFE_SOURCE.test(i.source)) return { source: "unrecognized source", value: null };
  const ok =
    DISPLAYABLE_IDENTITY_SOURCES.has(i.source.toLowerCase()) && SAFE_VALUE.test(i.external_id);
  return { source: i.source, value: ok ? i.external_id : null };
}

const DISPLAYABLE_REF_SOURCES = new Set(["scan", "import"]);

/** Observation provenance line; never includes `data`, and withholds unvetted references. */
export function displayObservation(o: Observation): { source: string; ref: string | null } {
  if (!SAFE_SOURCE.test(o.source)) return { source: "unrecognized source", ref: null };
  const ref =
    o.source_ref && DISPLAYABLE_REF_SOURCES.has(o.source.toLowerCase()) && SAFE_VALUE.test(o.source_ref)
      ? o.source_ref
      : null;
  return { source: o.source, ref };
}

export interface Filters {
  search: string;
  role: string; // "" = any
  vendor: string; // "" = any
  status: string; // "" = any, else Freshness ("recent" | "stale" | "never")
}

export const NO_FILTERS: Filters = { search: "", role: "", vendor: "", status: "" };

export function filterDevices(devices: Device[], f: Filters, now: number = Date.now()): Device[] {
  const q = f.search.trim().toLowerCase();
  return devices.filter((d) => {
    if (f.role && !d.roles.includes(f.role as Role)) return false;
    if (f.vendor && (d.vendor ?? "") !== f.vendor) return false;
    if (f.status && freshness(d.last_seen, now) !== f.status) return false;
    if (!q) return true;
    const haystack = [d.hostname, d.mac, d.vendor, d.model, d.location, ...d.ip]
      .filter((v): v is string => typeof v === "string")
      .join("\n")
      .toLowerCase();
    return haystack.includes(q);
  });
}

export function vendorsOf(devices: Device[]): string[] {
  return [...new Set(devices.map((d) => d.vendor).filter((v): v is string => !!v))].sort((a, b) =>
    a.localeCompare(b)
  );
}

export function editsFrom(d: Device): UserEdits {
  return { notes: d.notes ?? "", location: d.location ?? "", roles: [...d.roles] };
}

const byName = (items: readonly string[]): string =>
  [...items].sort((x, y) => x.localeCompare(y)).join(",");

export function sameEdits(a: UserEdits, b: UserEdits): boolean {
  return (
    a.notes === b.notes &&
    a.location === b.location &&
    a.roles.length === b.roles.length &&
    byName(a.roles) === byName(b.roles)
  );
}

/** Only user-owned fields are sent, so scanner-owned data can't be clobbered. */
export function toPatch(e: UserEdits): { notes: string | null; location: string | null; roles: Role[] } {
  return {
    notes: e.notes.trim() === "" ? null : e.notes,
    location: e.location.trim() === "" ? null : e.location.trim(),
    roles: e.roles,
  };
}

export function describeInventoryError(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.status === 404) return "Device not found; it may have been removed.";
    if (err.status === 422) return "Those values were rejected by the server.";
    if (err.status === 0) return "Could not reach the server.";
    return err.message || fallback;
  }
  return fallback;
}

export const listDevices = () => apiGet<Device[]>(`/v1/devices?limit=${LIST_LIMIT}`);
export const getDevice = (id: string) => apiGet<Device>(`/v1/devices/${encodeURIComponent(id)}`);
export const getObservations = (id: string) =>
  apiGet<Observation[]>(`/v1/devices/${encodeURIComponent(id)}/observations`);
export const getIdentities = (id: string) =>
  apiGet<Identity[]>(`/v1/devices/${encodeURIComponent(id)}/identities`);
export const saveEdits = (id: string, e: UserEdits) =>
  apiPatch<Device>(`/v1/devices/${encodeURIComponent(id)}`, toPatch(e));
