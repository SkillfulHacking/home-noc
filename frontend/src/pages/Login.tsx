import { FormEvent, useState } from "react";
import { setAuth, defaultApiBase } from "../lib/auth";

export default function LoginPage() {
  const [apiBase, setApiBase] = useState<string>(defaultApiBase());
  const [apiKey, setApiKey] = useState<string>("");
  const [status, setStatus] = useState<string>("");

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setStatus("Checking…");
    try {
      const r = await fetch(`${apiBase}/health`, {
        headers: apiKey ? { "X-API-Key": apiKey } : {}
      });
      if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
      setAuth({ apiBase, apiKey: apiKey || undefined });
      setStatus("OK — saved. Redirecting…");
      window.location.href = "/";
    } catch (err: any) {
      setStatus(`Failed: ${err.message || String(err)}`);
    }
  }

  return (
    <main id="app" className="mx-auto max-w-lg p-4">
      <h1 className="text-2xl font-semibold mb-4">Login</h1>
      <form onSubmit={onSubmit} className="space-y-4">
        <label className="block">
          <span className="text-sm text-zinc-300">API Base URL</span>
          <input
            className="mt-1 w-full rounded-lg bg-zinc-900 border border-zinc-800 px-3 py-2"
            placeholder="http://localhost:8000"
            value={apiBase}
            onChange={(e) => setApiBase(e.target.value)}
            required
            inputMode="url"
          />
        </label>
        <label className="block">
          <span className="text-sm text-zinc-300">API Key (optional)</span>
          <input
            className="mt-1 w-full rounded-lg bg-zinc-900 border border-zinc-800 px-3 py-2"
            placeholder="(leave blank if not required)"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
          />
        </label>
        <div className="flex items-center gap-3">
          <button
            type="submit"
            className="rounded-lg bg-sky-600 px-4 py-2 font-medium hover:bg-sky-500"
          >
            Save & Test
          </button>
          <span className="text-sm">{status}</span>
        </div>
      </form>
    </main>
  );
}
