import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AUTH_CHANGED_EVENT,
  CSRF_COOKIE_NAME,
  clearSession,
  defaultApiBase,
  getSession,
  readCsrfToken,
  setSession,
} from "./auth";

const SESSION = { username: "admin", expiresAt: "2026-12-01T00:00:00+00:00" };

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

  it("falls back safely for a cross-origin build-time override", () => {
    vi.stubEnv("VITE_DEFAULT_API_BASE", "https://attacker.example/api");
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(defaultApiBase()).toBe("/api");
    expect(warn).toHaveBeenCalledOnce();
    warn.mockRestore();
  });
});

describe("session state", () => {
  beforeEach(() => {
    clearSession();
  });

  it("returns null when nothing is cached", () => {
    expect(getSession()).toBeNull();
  });

  it("round-trips a cached session", () => {
    setSession(SESSION);
    expect(getSession()).toEqual(SESSION);
  });

  it("caches no credential of its own", () => {
    setSession(SESSION);
    // Only the identity the server reported; never a password or token.
    expect(Object.keys(getSession() ?? {}).sort()).toEqual(["expiresAt", "username"]);
  });

  it("never writes the session to localStorage or sessionStorage", () => {
    setSession(SESSION);
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("clears the cached session", () => {
    setSession(SESSION);
    clearSession();
    expect(getSession()).toBeNull();
  });

  it("notifies mounted routes when authentication changes", () => {
    const listener = vi.fn();
    window.addEventListener(AUTH_CHANGED_EVENT, listener);
    setSession(SESSION);
    clearSession();
    window.removeEventListener(AUTH_CHANGED_EVENT, listener);
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("does not re-notify when already signed out", () => {
    const listener = vi.fn();
    window.addEventListener(AUTH_CHANGED_EVENT, listener);
    clearSession();
    window.removeEventListener(AUTH_CHANGED_EVENT, listener);
    expect(listener).not.toHaveBeenCalled();
  });
});

describe("readCsrfToken", () => {
  afterEach(() => {
    document.cookie = `${CSRF_COOKIE_NAME}=; Max-Age=0; path=/`;
    document.cookie = "unrelated=; Max-Age=0; path=/";
  });

  it("returns null when the cookie is absent", () => {
    expect(readCsrfToken()).toBeNull();
  });

  it("reads the token the server set", () => {
    document.cookie = `${CSRF_COOKIE_NAME}=token-value; path=/`;
    expect(readCsrfToken()).toBe("token-value");
  });

  it("is not confused by other cookies or by a name prefix match", () => {
    document.cookie = "unrelated=nope; path=/";
    document.cookie = `${CSRF_COOKIE_NAME}=real-token; path=/`;
    expect(readCsrfToken()).toBe("real-token");
  });

  it("decodes a percent-encoded token", () => {
    document.cookie = `${CSRF_COOKIE_NAME}=a%2Bb; path=/`;
    expect(readCsrfToken()).toBe("a+b");
  });
});
