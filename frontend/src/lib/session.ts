/**
 * Session operations against the backend (M03, issue #6).
 *
 * Kept separate from `auth.ts` (pure client state) so the network calls can
 * be exercised independently in tests.
 */
import { ApiError, apiGet, apiPost } from "./api";
import { clearSession, setSession, type Session } from "./auth";

interface SessionPayload {
  username: string;
  expires_at: string;
}

function toSession(payload: unknown): Session {
  // A 2xx with a malformed body (e.g. an HTML page from a misconfigured
  // proxy) must never be mistaken for a signed-in session.
  const candidate = payload as Partial<SessionPayload> | null;
  if (
    !candidate ||
    typeof candidate !== "object" ||
    typeof candidate.username !== "string" ||
    !candidate.username ||
    typeof candidate.expires_at !== "string" ||
    !candidate.expires_at
  ) {
    throw new ApiError("Unexpected session response from the server", 502, payload);
  }
  return { username: candidate.username, expiresAt: candidate.expires_at };
}

/** Sign in, then cache the session the server confirms. */
export async function login(username: string, password: string): Promise<Session> {
  const payload = await apiPost<SessionPayload>("/v1/auth/login", { username, password });
  const session = toSession(payload);
  setSession(session);
  return session;
}

/**
 * Ask the backend who we are. This is the real protected route: a cached
 * session is only trusted after the server confirms it.
 */
export async function fetchSession(): Promise<Session | null> {
  try {
    const payload = await apiGet<SessionPayload>("/v1/auth/session");
    const session = toSession(payload);
    setSession(session);
    return session;
  } catch (error) {
    // 401 means "not signed in", which is an answer rather than a failure.
    // apiFetch has already cleared the cached session for us.
    if (error instanceof ApiError && error.status === 401) return null;
    clearSession();
    throw error;
  }
}

/**
 * Revoke the session server-side, then drop the local cache. The local
 * cache is cleared even if the request fails, so the UI never claims to be
 * signed in after the operator asked to leave.
 */
export async function logout(): Promise<void> {
  try {
    await apiPost<void>("/v1/auth/logout");
  } finally {
    clearSession();
  }
}
