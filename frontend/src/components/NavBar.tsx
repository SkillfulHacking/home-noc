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
    dark ? html.classList.add("dark") : html.classList.remove("dark");
  }, [dark]);

  useEffect(() => {
    const html = document.documentElement;
    hc ? html.classList.add("hc") : html.classList.remove("hc");
  }, [hc]);

  return (
    <header className="border-b border-zinc-800 bg-zinc-900/60 backdrop-blur supports-[backdrop-filter]:bg-zinc-900/40">
      <nav className="mx-auto max-w-6xl flex items-center justify-between p-3">
        <Link to="/" className="font-semibold">
          home-noc
        </Link>
        <div className="flex items-center gap-3">
          <NavLink to="/" className="hover:underline">Index</NavLink>
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
