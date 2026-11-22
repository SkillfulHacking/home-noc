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
  const base = (getAuth()?.apiBase ?? defaultApiBase()).replace(/\/+$/, "");
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return `${base}${suffix}`;
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
    // Credentials are no longer valid; drop them so the next request
    // doesn't repeat the same failure and the user is routed back to login.
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
