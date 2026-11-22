import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../lib/session";

export default function LoginPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [status, setStatus] = useState<string>("");
  const [busy, setBusy] = useState<boolean>(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setStatus("Signing in…");
    try {
      await login(username, password);
      // Never keep the password in component state once it has been sent.
      setPassword("");
      navigate("/", { replace: true });
    } catch (err: unknown) {
      setPassword("");
      setStatus(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main id="app" className="mx-auto max-w-lg p-4">
      <h1 className="text-2xl font-semibold mb-4">Sign in</h1>
      <form onSubmit={onSubmit} className="space-y-4">
        <label className="block">
          <span className="text-sm text-zinc-300">Username</span>
          <input
            className="mt-1 w-full rounded-lg bg-zinc-900 border border-zinc-800 px-3 py-2"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoComplete="username"
            name="username"
          />
        </label>
        <label className="block">
          <span className="text-sm text-zinc-300">Password</span>
          <input
            className="mt-1 w-full rounded-lg bg-zinc-900 border border-zinc-800 px-3 py-2"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
            name="password"
          />
        </label>
        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={busy}
            className="rounded-lg bg-sky-600 px-4 py-2 font-medium hover:bg-sky-500 disabled:opacity-50"
          >
            Sign in
          </button>
          <span className="text-sm" role="status">{status}</span>
        </div>
      </form>
    </main>
  );
}
