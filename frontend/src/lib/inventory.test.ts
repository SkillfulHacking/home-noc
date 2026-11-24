import { describe, expect, it } from "vitest";
import {
  Device,
  FRESHNESS_LABEL,
  NO_FILTERS,
  displayIdentity,
  displayObservation,
  editsFrom,
  filterDevices,
  freshness,
  sameEdits,
  toPatch,
  vendorsOf,
} from "./inventory";

const NOW = Date.parse("2026-01-01T12:00:00Z");

function dev(over: Partial<Device>): Device {
  return {
    id: "1", hostname: "h", ip: [], mac: null, first_seen: null, last_seen: null,
    discovery_method: null, vendor: null, model: null, os: null, serial: null,
    location: null, roles: [], ports: [], snmp: null, api: null, notes: null, ...over,
  };
}

describe("freshness", () => {
  it("classifies by last_seen", () => {
    expect(freshness(null, NOW)).toBe("never");
    expect(freshness("garbage", NOW)).toBe("never");
    expect(freshness("2026-01-01T11:30:00Z", NOW)).toBe("recent");
    expect(freshness("2026-01-01T09:00:00Z", NOW)).toBe("stale");
  });
  it("uses non-reachability labels", () => {
    expect(Object.values(FRESHNESS_LABEL)).toEqual(["Recently seen", "Stale", "Never seen"]);
  });
});

describe("display policy", () => {
  it("shows ordinary hardware identifiers", () => {
    expect(displayIdentity({ id: "1", source: "serial", external_id: "SN-123" }).value).toBe("SN-123");
    expect(displayIdentity({ id: "1", source: "mac", external_id: "aa:bb:cc:dd:ee:ff" }).value).not.toBeNull();
  });
  it("withholds unknown sources and odd-looking values but keeps the source", () => {
    expect(displayIdentity({ id: "1", source: "vendor_api", external_id: "abc" })).toEqual({
      source: "vendor_api", value: null,
    });
    expect(displayIdentity({ id: "1", source: "serial", external_id: "Bearer abc def" }).value).toBeNull();
    expect(displayIdentity({ id: "1", source: "serial", external_id: "x".repeat(200) }).value).toBeNull();
    expect(displayIdentity({ id: "1", source: "bad source!", external_id: "a" }).source).toBe("unrecognized source");
  });
  it("only shows vetted observation references", () => {
    const o = { id: "1", observed_at: "t" };
    expect(displayObservation({ ...o, source: "scan", source_ref: "job-1" })).toEqual({ source: "scan", ref: "job-1" });
    expect(displayObservation({ ...o, source: "snmp", source_ref: "job-1" }).ref).toBeNull();
    expect(displayObservation({ ...o, source: "scan", source_ref: "a b" }).ref).toBeNull();
  });
});

describe("filterDevices", () => {
  const a = dev({ id: "a", hostname: "Router", ip: ["10.0.0.1"], vendor: "Acme", roles: ["router"], last_seen: "2026-01-01T11:59:00Z" });
  const b = dev({ id: "b", hostname: "cam", ip: ["10.0.0.2"], vendor: "Other", roles: ["camera"] });
  it("returns everything with no filters", () => {
    expect(filterDevices([a, b], NO_FILTERS, NOW)).toHaveLength(2);
  });
  it("combines filters with AND", () => {
    expect(filterDevices([a, b], { ...NO_FILTERS, role: "router", vendor: "Acme" }, NOW)).toEqual([a]);
    expect(filterDevices([a, b], { ...NO_FILTERS, role: "router", vendor: "Other" }, NOW)).toEqual([]);
  });
  it("searches case-insensitively across addresses", () => {
    expect(filterDevices([a, b], { ...NO_FILTERS, search: "RoUt" }, NOW)).toEqual([a]);
    expect(filterDevices([a, b], { ...NO_FILTERS, search: "10.0.0.2" }, NOW)).toEqual([b]);
  });
  it("filters by status", () => {
    expect(filterDevices([a, b], { ...NO_FILTERS, status: "recent" }, NOW)).toEqual([a]);
    expect(filterDevices([a, b], { ...NO_FILTERS, status: "never" }, NOW)).toEqual([b]);
  });
  it("lists distinct vendors", () => {
    expect(vendorsOf([a, b, a])).toEqual(["Acme", "Other"]);
  });
});

describe("user edits", () => {
  it("detects changes regardless of role order", () => {
    const base = editsFrom(dev({ roles: ["switch", "ap"], notes: "n" }));
    expect(sameEdits(base, { ...base, roles: ["ap", "switch"] })).toBe(true);
    expect(sameEdits(base, { ...base, notes: "x" })).toBe(false);
  });
  it("patches only user-owned fields and nulls blanks", () => {
    expect(toPatch({ notes: "  ", location: " ", roles: [] })).toEqual({
      notes: null, location: null, roles: [],
    });
    expect(Object.keys(toPatch({ notes: "a", location: "b", roles: ["nas"] })).sort()).toEqual([
      "location", "notes", "roles",
    ]);
  });
});
