/**
 * Client-side view of the operator session (M03, issue #6).
 *
 * The browser holds no credential of its own. The session lives in an
 * httpOnly, SameSite=Strict cookie that JavaScript cannot read, so this
 * module only caches *who* the server says we are. The authoritative check
 * is always `GET /v1/auth/session`.
 */
export interface Session {
  username: string;
  expiresAt: string;
}

export const AUTH_CHANGED_EVENT = "home-noc:auth-changed";

/** Readable by JS by design: the SPA must echo it back in a header. */
export const CSRF_COOKIE_NAME = "home_noc_csrf";

let currentSession: Session | null = null;

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

/**
 * Resolves the API base URL, in priority order: an explicit build-time
 * override, then a same-origin "/api" path so the production Nginx proxy
 * (see frontend/nginx.conf) works without CORS. Never operator-supplied,
 * so a hostile value cannot be injected at runtime.
 */
export function defaultApiBase(): string {
  const envBase = import.meta.env.VITE_DEFAULT_API_BASE;
  if (typeof envBase === "string" && envBase.trim()) {
    try {
      return normalizeApiBase(envBase.trim());
    } catch (error) {
      console.warn("Invalid VITE_DEFAULT_API_BASE; using /api", error);
    }
  }
  return "/api";
}

/** The cached session, or null when the SPA believes it is signed out. */
export function getSession(): Session | null {
  return currentSession ? { ...currentSession } : null;
}

export function setSession(session: Session): void {
  currentSession = { username: session.username, expiresAt: session.expiresAt };
  notifyAuthChanged();
}

/**
 * Forget the cached session. This is a UI-state update only: the session is
 * revoked server-side by `POST /v1/auth/logout`, which is what actually
 * invalidates the cookie.
 */
export function clearSession(): void {
  if (currentSession === null) return;
  currentSession = null;
  notifyAuthChanged();
}

/**
 * Read the double-submit CSRF token the server set at login. Returns null
 * when absent, so the caller sends no header and the request is rejected
 * server-side rather than silently succeeding.
 */
export function readCsrfToken(): string | null {
  const prefix = `${CSRF_COOKIE_NAME}=`;
  for (const part of document.cookie.split(";")) {
    const entry = part.trim();
    if (entry.startsWith(prefix)) {
      const value = entry.slice(prefix.length);
      return value ? decodeURIComponent(value) : null;
    }
  }
  return null;
}
