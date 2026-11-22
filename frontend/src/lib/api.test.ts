import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiDelete, apiGet, apiPatch, apiPost, apiPut } from "./api";
import { AUTH_CHANGED_EVENT, CSRF_COOKIE_NAME, clearSession, getSession, setSession } from "./auth";

function jsonResponse(body: unknown, init: { status?: number; statusText?: string } = {}) {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    statusText: init.statusText ?? "OK",
    headers: { "Content-Type": "application/json" },
  });
}

const SESSION = { username: "admin", expiresAt: "2026-12-01T00:00:00+00:00" };

function expireCsrfCookie() {
  document.cookie = `${CSRF_COOKIE_NAME}=; Max-Age=0; path=/`;
}

describe("api client", () => {
  beforeEach(() => {
    clearSession();
    expireCsrfCookie();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    clearSession();
    expireCsrfCookie();
  });

  it("resolves the URL against the configured base and parses JSON", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await apiGet<{ ok: boolean }>("/health");

    expect(result).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledWith(
      `${window.location.origin}/api/health`,
      expect.objectContaining({ method: "GET" })
    );
  });

  it("sends same-origin credentials on every request", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(() => Promise.resolve(jsonResponse({ ok: true })));
    vi.stubGlobal("fetch", fetchMock);

    await apiGet("/health");
    await apiPost("/things", { a: 1 });
    await apiDelete("/things/1");

    for (const [, init] of fetchMock.mock.calls) {
      expect(init.credentials).toBe("same-origin");
    }
  });

  it("never sends the legacy X-API-Key header", async () => {
    document.cookie = `${CSRF_COOKIE_NAME}=csrf-abc; path=/`;
    setSession(SESSION);
    const fetchMock = vi
      .fn()
      .mockImplementation(() => Promise.resolve(jsonResponse({ ok: true })));
    vi.stubGlobal("fetch", fetchMock);

    await apiGet("/health");
    await apiPost("/things", {});
    await apiDelete("/things/1");

    for (const [, init] of fetchMock.mock.calls) {
      expect((init.headers as Headers).has("X-API-Key")).toBe(false);
      expect((init.headers as Headers).has("Authorization")).toBe(false);
    }
  });

  it("does not persist credentials in web storage", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ ok: true })));
    await apiGet("/health");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("echoes the CSRF cookie in X-CSRF-Token on unsafe methods", async () => {
    document.cookie = `${CSRF_COOKIE_NAME}=csrf-abc; path=/`;
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse({ ok: true })));
    vi.stubGlobal("fetch", fetchMock);

    await apiPost("/things", {});
    await apiPut("/things/1", {});
    await apiPatch("/things/1", {});
    await apiDelete("/things/1");

    expect(fetchMock).toHaveBeenCalledTimes(4);
    for (const [, init] of fetchMock.mock.calls) {
      expect((init.headers as Headers).get("X-CSRF-Token")).toBe("csrf-abc");
    }
  });

  it("does not send X-CSRF-Token on safe methods", async () => {
    document.cookie = `${CSRF_COOKIE_NAME}=csrf-abc; path=/`;
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await apiGet("/health");

    const [, init] = fetchMock.mock.calls[0];
    expect((init.headers as Headers).has("X-CSRF-Token")).toBe(false);
  });

  it("omits X-CSRF-Token when the cookie is absent so the server rejects the write", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await apiPost("/things", {});

    const [, init] = fetchMock.mock.calls[0];
    expect((init.headers as Headers).has("X-CSRF-Token")).toBe(false);
  });

  it("keeps a protocol-relative looking path on the same origin", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await apiGet("//attacker.example/steal");

    const [url] = fetchMock.mock.calls[0];
    expect(new URL(url).origin).toBe(window.location.origin);
  });

  it("serializes JSON bodies and sets Content-Type for writes", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ id: "1" }, { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);

    await apiPost("/things", { name: "router" });

    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ name: "router" }));
    expect((init.headers as Headers).get("Content-Type")).toBe("application/json");
  });

  it("raises a readable ApiError using the backend detail message", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(jsonResponse({ detail: "Invalid API key" }, { status: 403, statusText: "Forbidden" }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiGet("/health")).rejects.toMatchObject({
      name: "ApiError",
      status: 403,
      message: "Invalid API key",
    });
  });

  it("falls back to the status text when no detail is present", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("", { status: 500, statusText: "Server Error" })
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiDelete("/things/1")).rejects.toMatchObject({
      status: 500,
      message: "500 Server Error",
    });
  });

  it("clears the cached session and notifies routes on a 401 response", async () => {
    setSession(SESSION);
    const listener = vi.fn();
    window.addEventListener(AUTH_CHANGED_EVENT, listener);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse({ detail: "Not authenticated" }, { status: 401 }))
    );
    listener.mockClear();

    await expect(apiGet("/health")).rejects.toMatchObject({ status: 401, message: "Not authenticated" });
    window.removeEventListener(AUTH_CHANGED_EVENT, listener);

    expect(getSession()).toBeNull();
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("keeps the session on non-401 errors such as 403 and 500", async () => {
    setSession(SESSION);
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(jsonResponse({ detail: "CSRF token invalid" }, { status: 403 }))
        .mockResolvedValueOnce(new Response("boom", { status: 500, statusText: "Server Error" }))
    );

    await expect(apiPost("/things", {})).rejects.toMatchObject({ status: 403 });
    await expect(apiGet("/things")).rejects.toMatchObject({ status: 500 });
    expect(getSession()).toEqual(SESSION);
  });

  it("treats a non-JSON error body as text without crashing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("<html>Bad Gateway</html>", { status: 502, statusText: "Bad Gateway" }))
    );

    await expect(apiGet("/health")).rejects.toMatchObject({
      status: 502,
      message: "502 Bad Gateway",
      body: "<html>Bad Gateway</html>",
    });
  });

  it("ignores a non-string detail field in the error body", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(jsonResponse({ detail: [{ msg: "bad" }] }, { status: 422, statusText: "Unprocessable" }))
    );

    await expect(apiPost("/things", {})).rejects.toMatchObject({ status: 422, message: "422 Unprocessable" });
  });

  it("returns undefined for an empty 204 response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
    await expect(apiPost("/v1/auth/logout")).resolves.toBeUndefined();
  });

  it("wraps network failures in an ApiError instead of throwing raw errors", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiGet("/health")).rejects.toMatchObject({
      name: "ApiError",
      status: 0,
    });
  });
});
