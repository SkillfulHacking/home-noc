import { clearAuth, defaultApiBase, getAuth } from "./auth";

export class ApiError extends Error {
  readonly status: number;
  readonly body?: unknown;

  constructor(message: string, status: number, body?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

function resolveUrl(path: string): string {
  const configuredBase = getAuth()?.apiBase ?? defaultApiBase();
  const base = configuredBase.endsWith("/") ? configuredBase.slice(0, -1) : configuredBase;
  const suffix = path.startsWith("/") ? path : `/${path}`;
  const url = new URL(`${base}${suffix}`, window.location.origin);
  if (url.origin !== window.location.origin) {
    throw new ApiError("Refusing to send an API request to another origin", 0);
  }
  return url.toString();
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function extractMessage(data: unknown, fallback: string): string {
  if (data && typeof data === "object" && "detail" in data) {
    const detail = (data as { detail?: unknown }).detail;
    if (typeof detail === "string") return detail;
  }
  return fallback;
}

async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const url = resolveUrl(path);
  const auth = getAuth();

  const headers = new Headers(init.headers);
  if (auth?.apiKey) headers.set("X-API-Key", auth.apiKey);
  if (init.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(url, { ...init, headers });
  } catch (err) {
    throw new ApiError(
      `Network error contacting ${url}: ${err instanceof Error ? err.message : String(err)}`,
      0
    );
  }

  const text = await response.text();
  const data = text ? safeJsonParse(text) : undefined;

  if (response.status === 401) {
    // RequireAuth listens for clearAuth's event and immediately unmounts the
    // protected route, avoiding a hard navigation from the fetch layer.
    clearAuth();
  }

  if (!response.ok) {
    throw new ApiError(
      extractMessage(data, `${response.status} ${response.statusText}`),
      response.status,
      data
    );
  }

  return data as T;
}

export function apiGet<T>(path: string, init?: RequestInit): Promise<T> {
  return apiFetch<T>(path, { ...init, method: "GET" });
}

export function apiPost<T>(path: string, body?: unknown, init?: RequestInit): Promise<T> {
  return apiFetch<T>(path, {
    ...init,
    method: "POST",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

export function apiPut<T>(path: string, body?: unknown, init?: RequestInit): Promise<T> {
  return apiFetch<T>(path, {
    ...init,
    method: "PUT",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

export function apiPatch<T>(path: string, body?: unknown, init?: RequestInit): Promise<T> {
  return apiFetch<T>(path, {
    ...init,
    method: "PATCH",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

export function apiDelete<T>(path: string, init?: RequestInit): Promise<T> {
  return apiFetch<T>(path, { ...init, method: "DELETE" });
}
