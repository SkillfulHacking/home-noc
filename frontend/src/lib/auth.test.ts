import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearAuth, defaultApiBase, getAuth, setAuth } from "./auth";

describe("defaultApiBase", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("uses the build-time override when set", () => {
    vi.stubEnv("VITE_DEFAULT_API_BASE", "http://localhost:8000");
    expect(defaultApiBase()).toBe("http://localhost:8000");
  });

  it("trims a configured override", () => {
    vi.stubEnv("VITE_DEFAULT_API_BASE", "  http://localhost:8000  ");
    expect(defaultApiBase()).toBe("http://localhost:8000");
  });

  it("falls back to a same-origin /api path when unset", () => {
    vi.stubEnv("VITE_DEFAULT_API_BASE", "");
    expect(defaultApiBase()).toBe(`${window.location.origin}/api`);
  });
});

describe("auth storage", () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  it("returns null when nothing is stored", () => {
    expect(getAuth()).toBeNull();
  });

  it("round-trips a saved config", () => {
    setAuth({ apiBase: "http://localhost:8000", apiKey: "secret" });
    expect(getAuth()).toEqual({ apiBase: "http://localhost:8000", apiKey: "secret" });
  });

  it("omits an empty api key", () => {
    setAuth({ apiBase: "http://localhost:8000", apiKey: "" });
    expect(getAuth()).toEqual({ apiBase: "http://localhost:8000", apiKey: undefined });
  });

  it("clears stored credentials", () => {
    setAuth({ apiBase: "http://localhost:8000", apiKey: "secret" });
    clearAuth();
    expect(getAuth()).toBeNull();
  });

  it("treats corrupted storage as logged out and wipes it", () => {
    sessionStorage.setItem("home-noc.auth", "{not-json");
    expect(getAuth()).toBeNull();
    expect(sessionStorage.getItem("home-noc.auth")).toBeNull();
  });

  it("rejects a stored entry missing apiBase", () => {
    sessionStorage.setItem("home-noc.auth", JSON.stringify({ apiKey: "secret" }));
    expect(getAuth()).toBeNull();
  });
});
