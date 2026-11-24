import { describe, expect, it } from "vitest";
import { sameEdits, vendorsOf, type Device } from "./inventory";

const dev = (vendor: string | null) => ({ vendor }) as Device;

describe("deterministic sorting", () => {
  it("vendorsOf returns unique, locale-ordered vendors without blanks", () => {
    expect(vendorsOf([dev("beta"), dev("Alpha"), dev(null), dev("beta"), dev("alpha")])).toEqual(
      ["alpha", "Alpha", "beta"].sort((a, b) => a.localeCompare(b))
    );
  });

  it("sameEdits ignores role order but not role membership", () => {
    const base = { notes: "n", location: "l" };
    expect(sameEdits({ ...base, roles: ["nas", "switch"] }, { ...base, roles: ["switch", "nas"] })).toBe(true);
    expect(sameEdits({ ...base, roles: ["nas", "switch"] }, { ...base, roles: ["nas", "router"] })).toBe(false);
  });
});
