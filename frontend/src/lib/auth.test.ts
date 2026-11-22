import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AUTH_CHANGED_EVENT, clearAuth, defaultApiBase, getAuth, setAuth } from "./auth";

describe("defaultApiBase", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("uses the build-time override when set", () => {
    vi.stubEnv("VITE_DEFAULT_API_BASE", "/internal-api");
    expect(defaultApiBase()).toBe("/internal-api");
  });

  it("trims a configured override", () => {
    vi.stubEnv("VITE_DEFAULT_API_BASE", "  /internal-api/  ");
    expect(defaultApiBase()).toBe("/internal-api");
  });

  it("falls back to a same-origin /api path when unset", () => {
    vi.stubEnv("VITE_DEFAULT_API_BASE", "");
    expect(defaultApiBase()).toBe("/api");
  });

  it("rejects a cross-origin build-time override", () => {
    vi.stubEnv("VITE_DEFAULT_API_BASE", "https://attacker.example/api");
    expect(() => defaultApiBase()).toThrow("same origin");
  });
});

describe("auth state", () => {
  beforeEach(() => {
    clearAuth();
  });

  it("returns null when nothing is stored", () => {
    expect(getAuth()).toBeNull();
  });

  it("round-trips a saved config", () => {
    setAuth({ apiBase: "/api/", apiKey: "secret:/+=@" });
    expect(getAuth()).toEqual({ apiBase: "/api", apiKey: "secret:/+=@" });
  });

  it("omits an empty api key", () => {
    setAuth({ apiBase: "/api", apiKey: "" });
    expect(getAuth()).toEqual({ apiBase: "/api", apiKey: undefined });
  });

  it("clears stored credentials", () => {
    setAuth({ apiBase: "/api", apiKey: "secret" });
    clearAuth();
    expect(getAuth()).toBeNull();
  });

  it("rejects a cross-origin API base before storing credentials", () => {
    expect(() => setAuth({ apiBase: "https://attacker.example/api", apiKey: "secret" })).toThrow(
      "same origin"
    );
    expect(getAuth()).toBeNull();
  });

  it("rejects unsafe API-key characters before storage", () => {
    expect(() => setAuth({ apiBase: "/api", apiKey: "<script>alert(1)</script>" })).toThrow(
      "unsupported characters"
    );
    expect(getAuth()).toBeNull();
  });

  it("notifies mounted routes when authentication changes", () => {
    const listener = vi.fn();
    window.addEventListener(AUTH_CHANGED_EVENT, listener);
    setAuth({ apiBase: "/api", apiKey: "secret" });
    clearAuth();
    window.removeEventListener(AUTH_CHANGED_EVENT, listener);
    expect(listener).toHaveBeenCalledTimes(2);
  });
});
