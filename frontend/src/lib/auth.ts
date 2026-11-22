export interface AuthConfig {
  apiBase: string;
  apiKey?: string;
}

export const AUTH_CHANGED_EVENT = "home-noc:auth-changed";
const API_KEY_PATTERN = /^[A-Za-z0-9._~+/=:@-]{1,512}$/;
let currentAuth: AuthConfig | null = null;

function normalizeApiBase(value: string): string {
  const url = new URL(value, window.location.origin);
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.origin !== window.location.origin) {
    throw new Error("API base must use the same origin as Home-NOC");
  }
  if (url.search || url.hash) {
    throw new Error("API base must not contain a query string or fragment");
  }

  let path = url.pathname;
  while (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
  return path;
}

function notifyAuthChanged(): void {
  window.dispatchEvent(new Event(AUTH_CHANGED_EVENT));
}

function normalizeApiKey(value: unknown): string | undefined {
  if (value === undefined || value === "") return undefined;
  if (typeof value !== "string" || !API_KEY_PATTERN.test(value)) {
    throw new Error("API key contains unsupported characters or has an invalid length");
  }
  return value;
}

/**
 * Resolves the API base URL to pre-fill the login form with, in priority order:
 * an explicit build-time override, then a same-origin "/api" path so the
 * production Nginx proxy (see frontend/nginx.conf) works without CORS.
 */
export function defaultApiBase(): string {
  const envBase = import.meta.env.VITE_DEFAULT_API_BASE;
  if (typeof envBase === "string" && envBase.trim()) {
    return normalizeApiBase(envBase.trim());
  }
  return "/api";
}

export function getAuth(): AuthConfig | null {
  return currentAuth ? { ...currentAuth } : null;
}

export function setAuth(config: AuthConfig): void {
  currentAuth = {
    apiBase: normalizeApiBase(config.apiBase),
    apiKey: normalizeApiKey(config.apiKey),
  };
  notifyAuthChanged();
}

export function clearAuth(): void {
  currentAuth = null;
  notifyAuthChanged();
}
