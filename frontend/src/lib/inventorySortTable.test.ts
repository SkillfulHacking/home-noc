import { describe, expect, it } from "vitest";
import { ipv4Value, primaryIPv4, scanTargetsFor, serviceLabel, sortDevices, type Device } from "./inventory";

const dev = (hostname: string, ip: string[], over: Partial<Device> = {}) =>
  ({ id: hostname, hostname, ip, roles: [], vendor: null, last_seen: null, ...over }) as Device;

describe("numeric IP sorting", () => {
  it("orders 10.0.0.9 before 10.0.0.10 and 10.0.0.100 (not lexicographically)", () => {
    const sorted = sortDevices(
      [dev("c", ["10.0.0.100"]), dev("a", ["10.0.0.9"]), dev("b", ["10.0.0.10"])], "ip", "asc");
    expect(sorted.map((d) => d.hostname)).toEqual(["a", "b", "c"]);
    expect(sortDevices(sorted, "ip", "desc").map((d) => d.hostname)).toEqual(["c", "b", "a"]);
  });

  it("uses the lowest valid IPv4 and puts devices without one last in both directions", () => {
    const list = [dev("none", []), dev("v6", ["fe80::1"]), dev("multi", ["192.168.1.5", "10.0.0.2"]),
      dev("low", ["10.0.0.1"])];
    expect(primaryIPv4(list[2])).toBe("10.0.0.2");
    expect(sortDevices(list, "ip", "asc").map((d) => d.hostname)).toEqual(["low", "multi", "none", "v6"]);
    expect(sortDevices(list, "ip", "desc").map((d) => d.hostname)).toEqual(["multi", "low", "none", "v6"]);
  });

  it("rejects malformed addresses", () => {
    expect(ipv4Value("256.1.1.1")).toBeNull();
    expect(ipv4Value("1.2.3")).toBeNull();
    expect(ipv4Value("1.2.3.4")).toBe(16909060);
  });
});

describe("other sorts", () => {
  it("sorts by name case-insensitively and by last seen with never-seen last", () => {
    const list = [dev("b", [], { last_seen: "2026-01-02T00:00:00Z" }), dev("A", [], { last_seen: null }),
      dev("c", [], { last_seen: "2026-01-03T00:00:00Z" })];
    expect(sortDevices(list, "hostname", "asc").map((d) => d.hostname)).toEqual(["A", "b", "c"]);
    expect(sortDevices(list, "last_seen", "desc").map((d) => d.hostname)).toEqual(["c", "b", "A"]);
    expect(sortDevices(list, "last_seen", "asc").map((d) => d.hostname)).toEqual(["b", "c", "A"]);
  });

  it("does not mutate its input and is stable on ties", () => {
    const list = [dev("x", [], { vendor: "V" }), dev("y", [], { vendor: "V" })];
    const copy = [...list];
    expect(sortDevices(list, "vendor", "asc").map((d) => d.hostname)).toEqual(["x", "y"]);
    expect(list).toEqual(copy);
  });
});

describe("service labels and bulk targets", () => {
  it("marks conventional names as inferred and never invents unknown services", () => {
    expect(serviceLabel({ port: 22, proto: "tcp", state: "open", service: null })).toEqual({ text: "SSH", basis: "inferred" });
    expect(serviceLabel({ port: 22, proto: "tcp", state: "open", service: "openssh" })).toEqual({ text: "openssh", basis: "reported" });
    expect(serviceLabel({ port: 49152, proto: "tcp", state: "open", service: null }).basis).toBe("unknown");
  });

  it("builds de-duplicated, capped scan targets from selected devices", () => {
    const list = [dev("a", ["10.0.0.1"]), dev("b", ["10.0.0.1"]), dev("c", []), dev("d", ["10.0.0.2"])];
    expect(scanTargetsFor(list)).toEqual(["10.0.0.1", "10.0.0.2"]);
    expect(scanTargetsFor(list, 1)).toEqual(["10.0.0.1"]);
  });
});
