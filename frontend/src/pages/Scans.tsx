import { FormEvent, useEffect, useState } from "react";
import { ApiError, apiGet, apiPost } from "../lib/api";

interface Profile {
  name: string;
  description: string;
  intrusive: boolean;
  enabled: boolean;
  max_hosts: number;
}
interface Scope {
  allowed_cidrs: string[];
  allow_public: boolean;
  profiles: Profile[];
}
interface Preview {
  mode: string;
  profile: string;
  resolved_targets: string[];
  resolved_target_count: number;
}

/** Backend scope errors carry `detail: {code, message}`; show the message. */
function describe(err: unknown): string {
  if (!(err instanceof ApiError)) return "Preflight failed";
  const detail = (err.body as { detail?: { message?: unknown } } | undefined)?.detail;
  if (detail && typeof detail === "object" && typeof detail.message === "string") {
    return detail.message;
  }
  return err.message;
}

export default function ScansPage() {
  const [scope, setScope] = useState<Scope | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [targets, setTargets] = useState("");
  const [profile, setProfile] = useState("discovery");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiGet<Scope>("/v1/scans/scope")
      .then(setScope)
      .catch((e: unknown) =>
        setLoadError(e instanceof ApiError ? e.message : "Could not load scan scope")
      );
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setPreview(null);
    setBusy(true);
    try {
      const list = targets.split(/[\s,]+/).filter(Boolean);
      setPreview(await apiPost<Preview>("/v1/scans/preflight", { targets: list, profile }));
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main id="app" className="mx-auto max-w-6xl p-4 space-y-4">
      <h1 className="text-xl font-semibold">Scan preflight</h1>

      <section role="note" className="rounded border border-amber-600 p-3 text-sm">
        <strong>Ownership and acceptable use.</strong> Only scan networks you own or
        have explicit written permission to test. Scans are limited to the allowlist
        configured by the administrator (<code>SCAN_ALLOWED_CIDRS</code>); each
        authorization is logged with your username. The security profile is opt-in and
        may be disabled. Nothing is scanned from this page: it only previews.
      </section>

      {loadError && <p role="alert">{loadError}</p>}
      {scope && (
        <section aria-label="Authorized scope" className="text-sm">
          <h2 className="font-semibold">Authorized scope</h2>
          {scope.allowed_cidrs.length === 0 ? (
            <p>No scope is configured, so all scans are refused.</p>
          ) : (
            <ul className="list-disc pl-5">
              {scope.allowed_cidrs.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          )}
        </section>
      )}

      <form onSubmit={onSubmit} className="space-y-2">
        <label className="block">
          Targets (IPv4 or CIDR, separated by spaces or commas)
          <input
            className="block w-full rounded bg-zinc-800 p-2"
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            required
          />
        </label>
        <label className="block">
          Profile
          <select
            className="block rounded bg-zinc-800 p-2"
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
          >
            {(scope?.profiles ?? []).map((p) => (
              <option key={p.name} value={p.name} disabled={!p.enabled}>
                {p.name} {p.intrusive ? "(opt-in)" : ""} – {p.description}
              </option>
            ))}
          </select>
        </label>
        <button className="rounded bg-zinc-700 px-3 py-1" disabled={busy}>
          {busy ? "Checking…" : "Preview (dry run)"}
        </button>
      </form>

      {error && <p role="alert">{error}</p>}
      {preview && (
        <p role="status">
          Mode: {preview.mode}. Profile: {preview.profile}. Resolved targets:{" "}
          {preview.resolved_target_count} host(s) in {preview.resolved_targets.join(", ")}.
        </p>
      )}
    </main>
  );
}
