import { Link, NavLink } from "react-router-dom";
import { useEffect, useState } from "react";
import { AUTH_CHANGED_EVENT, getSession } from "../lib/auth";

function usePersistedFlag(key: string, initial = false) {
  const [flag, setFlag] = useState<boolean>(() => {
    const saved = localStorage.getItem(key);
    return saved ? saved === "1" : initial;
  });
  useEffect(() => {
    localStorage.setItem(key, flag ? "1" : "0");
  }, [key, flag]);
  return [flag, setFlag] as const;
}

/** True only while the server has confirmed a session (see lib/auth, RequireAuth). */
function useSignedIn(): boolean {
  const [signedIn, setSignedIn] = useState<boolean>(() => getSession() !== null);
  useEffect(() => {
    const refresh = () => setSignedIn(getSession() !== null);
    window.addEventListener(AUTH_CHANGED_EVENT, refresh);
    refresh();
    return () => window.removeEventListener(AUTH_CHANGED_EVENT, refresh);
  }, []);
  return signedIn;
}

export default function NavBar() {
  const signedIn = useSignedIn();
  const [dark, setDark] = usePersistedFlag("ui.dark", true);
  const [hc, setHc] = usePersistedFlag("ui.hc", false);

  useEffect(() => {
    const html = document.documentElement;
    html.classList.toggle("dark", dark);
  }, [dark]);

  useEffect(() => {
    const html = document.documentElement;
    html.classList.toggle("hc", hc);
  }, [hc]);

  return (
    <header className="border-b border-zinc-800 bg-zinc-900/60 backdrop-blur supports-[backdrop-filter]:bg-zinc-900/40">
      <nav className="mx-auto max-w-6xl flex flex-col items-start gap-2 p-3 sm:flex-row sm:items-center sm:justify-between">
        <Link to="/" className="font-semibold">
          home-noc
        </Link>
        <div className="flex w-full flex-wrap items-center gap-x-3 gap-y-2 sm:w-auto">
          <NavLink to="/" end className="hover:underline">Overview</NavLink>
          <NavLink to="/inventory" className="hover:underline">Inventory</NavLink>
          <NavLink to="/scans"className="hover:underline">Scans</NavLink>
          {/* Shown only to a confirmed session. This is navigation convenience, not
              access control: the backend enforces administrator-only access (403
              admin_required) and the page shows an access-denied message. The app has
              a single administrator account, so no separate role model exists. */}
          {signedIn && <NavLink to="/connectors" className="hover:underline">Connectors</NavLink>}
          {signedIn && (
            <NavLink to="/settings/security/scan-policy" className="hover:underline">
              Scan policy
            </NavLink>
          )}
          <NavLink to="/login" className="hover:underline">Login</NavLink>
          <NavLink to="/logout" className="hover:underline">Logout</NavLink>
          <button
            className="rounded px-2 py-1 bg-zinc-800 hover:bg-zinc-700"
            onClick={() => setDark(d => !d)}
            aria-pressed={dark}
            title="Toggle dark mode"
          >
            {dark ? "🌙" : "☀️"}
          </button>
          <button
            className="rounded px-2 py-1 bg-zinc-800 hover:bg-zinc-700"
            onClick={() => setHc(h => !h)}
            aria-pressed={hc}
            title="Toggle high-contrast"
          >
            HC
          </button>
        </div>
      </nav>
    </header>
  );
}
