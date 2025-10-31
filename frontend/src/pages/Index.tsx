import { useEffect, useState } from "react";
import { apiGet } from "../lib/api";

export default function IndexPage() {
  const [health, setHealth] = useState<null | Record<string, unknown>>(null);
  const [version, setVersion] = useState<null | Record<string, unknown>>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const h = await apiGet<Record<string, unknown>>("/health");
        setHealth(h);
        const v = await apiGet<Record<string, unknown>>("/version");
        setVersion(v);
      } catch (e: any) {
        setError(e.message || String(e));
      }
    })();
  }, []);

  return (
    <main id="app" className="mx-auto max-w-6xl p-4">
      <h1 className="text-2xl font-semibold mb-4">Index</h1>
      {error && <div className="text-red-400 mb-3">Error: {error}</div>}
      <div className="grid md:grid-cols-2 gap-4">
        <section className="card rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <h2 className="font-medium mb-2">Health</h2>
          <pre className="text-sm overflow-auto">{JSON.stringify(health, null, 2)}</pre>
        </section>
        <section className="card rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <h2 className="font-medium mb-2">Version</h2>
          <pre className="text-sm overflow-auto">{JSON.stringify(version, null, 2)}</pre>
        </section>
      </div>
    </main>
  );
}
