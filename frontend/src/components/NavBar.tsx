import { Link, NavLink } from "react-router-dom";
import { useEffect, useState } from "react";

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

export default function NavBar() {
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
          <NavLink to="/" className="hover:underline">Index</NavLink>
          <NavLink to="/inventory" className="hover:underline">Inventory</NavLink>
          <NavLink to="/scans"className="hover:underline">Scans</NavLink>
          {/* Admin-only on the server: a non-admin sees an access-denied message there. */}
          <NavLink to="/settings/security/scan-policy" className="hover:underline">
            Scan policy
          </NavLink>
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
