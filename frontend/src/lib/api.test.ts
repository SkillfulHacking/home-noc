import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiDelete, apiGet, apiPost } from "./api";
import { clearAuth, getAuth, setAuth } from "./auth";

function jsonResponse(body: unknown, init: { status?: number; statusText?: string } = {}) {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    statusText: init.statusText ?? "OK",
    headers: { "Content-Type": "application/json" },
  });
}

describe("api client", () => {
  beforeEach(() => {
    sessionStorage.clear();
    setAuth({ apiBase: "/api", apiKey: "secret-key" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    clearAuth();
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

  it("sends the configured API key as a header", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await apiGet("/health");

    const [, init] = fetchMock.mock.calls[0];
    const headers = init.headers as Headers;
    expect(headers.get("X-API-Key")).toBe("secret-key");
  });

  it("omits the API key header when not configured", async () => {
    setAuth({ apiBase: "/api" });
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await apiGet("/health");

    const [, init] = fetchMock.mock.calls[0];
    const headers = init.headers as Headers;
    expect(headers.has("X-API-Key")).toBe(false);
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

  it("clears stored credentials on a 401 response", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ detail: "Invalid API key" }, { status: 401 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiGet("/health")).rejects.toBeInstanceOf(ApiError);
    expect(getAuth()).toBeNull();
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
