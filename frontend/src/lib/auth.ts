export interface AuthConfig {
  apiBase: string;
  apiKey?: string;
}

const STORAGE_KEY = "home-noc.auth";

/**
 * Resolves the API base URL to pre-fill the login form with, in priority order:
 * an explicit build-time override, then a same-origin "/api" path so the
 * production Nginx proxy (see frontend/nginx.conf) works without CORS.
 */
export function defaultApiBase(): string {
  const envBase = import.meta.env.VITE_DEFAULT_API_BASE;
  if (typeof envBase === "string" && envBase.trim()) {
    return envBase.trim();
  }
  return `${window.location.origin}/api`;
}

export function getAuth(): AuthConfig | null {
  const raw = sessionStorage.getItem(STORAGE_KEY);
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.apiBase === "string" && parsed.apiBase.trim()) {
      return {
        apiBase: parsed.apiBase,
        apiKey: typeof parsed.apiKey === "string" && parsed.apiKey ? parsed.apiKey : undefined,
      };
    }
  } catch {
    // fall through to treat as logged out
  }

  sessionStorage.removeItem(STORAGE_KEY);
  return null;
}

export function setAuth(config: AuthConfig): void {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(config));
}

export function clearAuth(): void {
  sessionStorage.removeItem(STORAGE_KEY);
}
