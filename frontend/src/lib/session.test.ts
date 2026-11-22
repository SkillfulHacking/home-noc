import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CSRF_COOKIE_NAME, clearSession, getSession, setSession } from "./auth";
import { fetchSession, login, logout } from "./session";

const PAYLOAD = { username: "admin", expires_at: "2026-12-01T00:00:00+00:00" };
const SESSION = { username: "admin", expiresAt: PAYLOAD.expires_at };

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("session operations", () => {
  beforeEach(() => {
    clearSession();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    clearSession();
    document.cookie = `${CSRF_COOKIE_NAME}=; Max-Age=0; path=/`;
  });

  describe("login", () => {
    it("posts credentials to the backend login endpoint and caches the session", async () => {
      const fetchMock = vi.fn().mockResolvedValue(json(PAYLOAD));
      vi.stubGlobal("fetch", fetchMock);

      const session = await login("admin", "correct horse battery");

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe(`${window.location.origin}/api/v1/auth/login`);
      expect(init.method).toBe("POST");
      expect(init.credentials).toBe("same-origin");
      expect(JSON.parse(init.body)).toEqual({ username: "admin", password: "correct horse battery" });
      expect((init.headers as Headers).has("X-API-Key")).toBe(false);
      expect(session).toEqual(SESSION);
      expect(getSession()).toEqual(SESSION);
    });

    it("does not cache a session or store the password after a 401", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ detail: "Invalid username or password" }, 401)));

      await expect(login("admin", "wrong-password")).rejects.toMatchObject({
        status: 401,
        message: "Invalid username or password",
      });
      expect(getSession()).toBeNull();
      expect(localStorage.length).toBe(0);
      expect(sessionStorage.length).toBe(0);
    });

    it("surfaces a 429 lockout without caching a session", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ detail: "Too many failed sign-in attempts" }, 429)));
      await expect(login("admin", "x")).rejects.toMatchObject({ status: 429 });
      expect(getSession()).toBeNull();
    });

    it("surfaces network errors without caching a session", async () => {
      vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
      await expect(login("admin", "pw")).rejects.toMatchObject({ name: "ApiError", status: 0 });
      expect(getSession()).toBeNull();
    });

    it.each([
      ["an HTML body", new Response("<html>proxy</html>", { status: 200 })],
      ["an empty body", new Response(null, { status: 200 })],
      ["a JSON body missing fields", json({ ok: true })],
      ["a JSON null", json(null)],
    ])("rejects %s instead of treating it as signed in", async (_label, response) => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
      await expect(login("admin", "pw")).rejects.toMatchObject({ name: "ApiError" });
      expect(getSession()).toBeNull();
    });
  });

  describe("fetchSession", () => {
    it("probes the backend session endpoint with a GET and caches the result", async () => {
      const fetchMock = vi.fn().mockResolvedValue(json(PAYLOAD));
      vi.stubGlobal("fetch", fetchMock);

      await expect(fetchSession()).resolves.toEqual(SESSION);

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe(`${window.location.origin}/api/v1/auth/session`);
      expect(init.method).toBe("GET");
      expect(init.credentials).toBe("same-origin");
      expect(getSession()).toEqual(SESSION);
    });

    it("returns null and clears the cache when the session has expired (401)", async () => {
      setSession(SESSION);
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ detail: "Not authenticated" }, 401)));

      await expect(fetchSession()).resolves.toBeNull();
      expect(getSession()).toBeNull();
    });

    it("clears the cache and rethrows on a network error", async () => {
      setSession(SESSION);
      vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));

      await expect(fetchSession()).rejects.toMatchObject({ status: 0 });
      expect(getSession()).toBeNull();
    });

    it("clears the cache and rethrows on a server error", async () => {
      setSession(SESSION);
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ detail: "boom" }, 500)));

      await expect(fetchSession()).rejects.toMatchObject({ status: 500 });
      expect(getSession()).toBeNull();
    });

    it("does not trust a malformed 200 response", async () => {
      setSession(SESSION);
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html></html>", { status: 200 })));

      await expect(fetchSession()).rejects.toMatchObject({ name: "ApiError" });
      expect(getSession()).toBeNull();
    });
  });

  describe("logout", () => {
    it("posts to the backend logout endpoint with the CSRF token and clears the cache", async () => {
      document.cookie = `${CSRF_COOKIE_NAME}=csrf-xyz; path=/`;
      setSession(SESSION);
      const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
      vi.stubGlobal("fetch", fetchMock);

      await logout();

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe(`${window.location.origin}/api/v1/auth/logout`);
      expect(init.method).toBe("POST");
      expect(init.credentials).toBe("same-origin");
      expect((init.headers as Headers).get("X-CSRF-Token")).toBe("csrf-xyz");
      expect(getSession()).toBeNull();
    });

    it("clears the cache even when the server request fails", async () => {
      setSession(SESSION);
      vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));

      await expect(logout()).rejects.toMatchObject({ status: 0 });
      expect(getSession()).toBeNull();
    });

    it("clears the cache when the session had already expired (401)", async () => {
      setSession(SESSION);
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ detail: "Not authenticated" }, 401)));

      await expect(logout()).rejects.toMatchObject({ status: 401 });
      expect(getSession()).toBeNull();
    });
  });
});
