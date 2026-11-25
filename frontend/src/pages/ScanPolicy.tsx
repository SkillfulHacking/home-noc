import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../lib/api";
import {
  PolicySaveFailure,
  ScanPolicy,
  classifyPolicyError,
  describeError,
  getScanPolicy,
  parseTargets,
  saveScanPolicy,
} from "../lib/scans";

interface Form {
  privateEnabled: boolean;
  privateStrict: boolean;
  privateList: string;
  publicEnabled: boolean;
  publicList: string;
  exclusions: string;
}

const lines = (items: string[]) => items.join("\n");

function toForm(p: ScanPolicy): Form {
  return {
    privateEnabled: p.private.enabled,
    privateStrict: p.private.strict,
    privateList: lines(p.private.allowlist),
    publicEnabled: p.public.enabled,
    publicList: lines(p.public.allowlist),
    exclusions: lines(p.exclusions),
  };
}

const REASON_TEXT: Record<string, string> = {
  private_enabled: "enables private-network scanning",
  private_strict_disabled: "leaves strict mode (all RFC1918 becomes scannable)",
  private_allowlist_widened: "widens the private allowlist",
  public_enabled: "enables PUBLIC address scanning",
  public_allowlist_widened: "adds public ranges to the allowlist",
  exclusion_removed: "removes an exclusion",
};

type LoadState =
  | { kind: "loading" }
  | { kind: "ready" }
  | { kind: "denied"; message: string }
  | { kind: "error"; message: string };

/** Settings → Security → Scan Policy (M08A). Administrator only; the server enforces it. */
export default function ScanPolicyPage() {
  const [policy, setPolicy] = useState<ScanPolicy | null>(null);
  const [form, setForm] = useState<Form | null>(null);
  const [load, setLoad] = useState<LoadState>({ kind: "loading" });
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<PolicySaveFailure | null>(null);
  const [confirmBroadening, setConfirmBroadening] = useState(false);
  const [confirmPublic, setConfirmPublic] = useState(false);
  const [saved, setSaved] = useState<number | null>(null);

  const [loadAttempt, setLoadAttempt] = useState(0);

  useEffect(() => {
    let active = true;

    void getScanPolicy()
      .then((p) => {
        if (!active) return;
        setPolicy(p);
        setForm(toForm(p));
        setLoad({ kind: "ready" });
      })
      .catch((err: unknown) => {
        if (!active) return;

        const detail = err instanceof ApiError
          ? (err.body as { detail?: { code?: string } } | undefined)?.detail
          : undefined;

        if (err instanceof ApiError &&
            err.status === 403 &&
            detail?.code === "admin_required") {
          setLoad({
            kind: "denied",
            message: "Administrator access is required to view or change the scan policy.",
          });
        } else {
          setLoad({
            kind: "error",
            message: describeError(err, "Could not load the scan policy"),
          });
        }
      });

    return () => {
      active = false;
    };
  }, [loadAttempt]);

  function reload() {
    setLoad({ kind: "loading" });
    setLoadAttempt((attempt) => attempt + 1);
  }

  const dirty = policy !== null && form !== null &&
    JSON.stringify(form) !== JSON.stringify(toForm(policy));

  // Warn before a reload or tab close discards unsaved edits.
  useEffect(() => {
    if (!dirty) return undefined;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [dirty]);

  function edit(patch: Partial<Form>) {
    setForm((f) => (f ? { ...f, ...patch } : f));
    setSaved(null);
    // Edits invalidate any pending confirmation: it applied to different content.
    setFailure((f) => (f && f.kind === "confirmation" ? null : f));
    setConfirmBroadening(false);
    setConfirmPublic(false);
  }

  async function submit(withConfirmation: boolean) {
    if (!policy || !form || saving) return;
    setSaving(true);
    setFailure(null);
    try {
      const next = await saveScanPolicy({
        expected_revision: policy.revision,
        private_enabled: form.privateEnabled,
        private_strict: form.privateStrict,
        private_allowlist: parseTargets(form.privateList),
        public_enabled: form.publicEnabled,
        public_allowlist: parseTargets(form.publicList),
        exclusions: parseTargets(form.exclusions),
        confirm_broadening: withConfirmation && confirmBroadening,
        confirm_public: withConfirmation && confirmPublic,
      });
      setPolicy(next);
      setForm(toForm(next));
      setSaved(next.revision);
      setConfirmBroadening(false);
      setConfirmPublic(false);
    } catch (err) {
      setFailure(classifyPolicyError(err));
    } finally {
      setSaving(false);
    }
  }

  function adoptCurrent(current: ScanPolicy) {
    setPolicy(current);
    setForm(toForm(current));
    setFailure(null);
    setSaved(null);
  }

  if (load.kind === "loading") {
    return (
      <main id="app" className="mx-auto max-w-4xl p-4">
        <p role="status">Loading scan policy…</p>
      </main>
    );
  }
  if (load.kind === "denied" || load.kind === "error" || !policy || !form) {
    const message = load.kind === "ready" ? "Scan policy unavailable" : load.message;
    return (
      <main id="app" className="mx-auto max-w-4xl p-4 space-y-2">
        <h1 className="text-xl font-semibold">Scan policy</h1>
        <p role="alert">{message}</p>
        {load.kind === "error" && (
          <p className="text-sm">Scanning remains disabled while the policy cannot be read.</p>
        )}
        {load.kind === "error" && (
          <button type="button" className="rounded bg-zinc-700 px-3 py-1" onClick={() => void reload()}>
            Retry
          </button>
        )}
      </main>
    );
  }

  const eff = policy.effective;
  const publicBlocked = policy.deployment.public_blocked;
  const fieldError = (field: string) =>
    failure?.kind === "validation" && failure.field === field ? failure.message : null;
  const showOwnership =
    form.publicEnabled || parseTargets(form.publicList).length > 0;

  return (
    <main id="app" className="mx-auto max-w-4xl p-4 space-y-4">
      <h1 className="text-xl font-semibold">Settings · Security · Scan Policy</h1>
      <p className="text-sm">
        Revision {policy.revision}, last changed by {policy.updated_by} at {policy.updated_at}.
        Changes apply immediately, without a restart. See{" "}
        <Link className="underline" to="/scans">Scans</Link>.
      </p>

      <section aria-label="Effective policy" className="rounded border border-zinc-700 p-3 text-sm space-y-1">
        <h2 className="font-semibold">Effective policy (what is authorized right now)</h2>
        <p>
          Private scanning: <strong>{eff.private_scanning ? "enabled" : "disabled"}</strong>
          {eff.private_scanning && ` – ${eff.private_networks.join(", ")}`}
          {eff.special_use_networks.length > 0 && ` (+ environment-listed ${eff.special_use_networks.join(", ")})`}
        </p>
        <p>
          Public scanning: <strong>{eff.public_scanning ? "enabled" : "disabled"}</strong>
          {eff.public_scanning && ` – only ${eff.public_networks.join(", ")}`}
        </p>
        <p>Excluded: {eff.excluded.length ? eff.excluded.join(", ") : "none"}</p>
        <h3 className="font-semibold pt-1">Deployment restrictions (environment, immutable here)</h3>
        <p>
          {policy.deployment.scope_restricted
            ? `SCAN_ALLOWED_CIDRS ceiling: ${policy.deployment.allowed_cidrs.join(", ") || "no usable range (all scans refused)"}`
            : "No SCAN_ALLOWED_CIDRS ceiling is set."}
        </p>
        {publicBlocked && <p>SCAN_ALLOW_PUBLIC=false: public scanning cannot be enabled.</p>}
        <p>
          The security (intrusive) profile is{" "}
          {policy.deployment.security_profile_enabled ? "enabled" : "disabled"} by the deployment;
          this page cannot change it.
        </p>
        <h3 className="font-semibold pt-1">Limits</h3>
        <ul className="list-disc pl-5">
          {policy.limits.profiles.map((p) => (
            <li key={p.name}>
              {p.name}: up to {p.max_hosts} hosts, {p.max_concurrency} concurrent, {p.timeout_seconds}s
            </li>
          ))}
          <li>
            At most {policy.limits.max_target_entries} targets per request and{" "}
            {policy.limits.max_active_jobs} queued/running jobs.
          </li>
        </ul>
        <p>{policy.worker_vantage}</p>
      </section>

      <form
        aria-label="Scan policy"
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          void submit(false);
        }}
      >
        <fieldset className="space-y-2 rounded border border-zinc-700 p-3">
          <legend className="font-semibold">Private networks (RFC1918)</legend>
          <label className="block">
            <input
              type="checkbox"
              checked={form.privateEnabled}
              onChange={(e) => edit({ privateEnabled: e.target.checked })}
            />{" "}
            Allow scanning of private IPv4 targets that an administrator selects
          </label>
          <p className="text-sm">
            Covers exactly {policy.private.rfc1918.join(", ")}. Targets are always chosen
            explicitly; nothing is swept automatically.
          </p>
          <label className="block">
            <input
              type="checkbox"
              checked={form.privateStrict}
              // Leaving strict mode clears the list: the server refuses a list that
              // would not be applied, and leaving it would silently mislead.
              onChange={(e) =>
                edit(e.target.checked ? { privateStrict: true } : { privateStrict: false, privateList: "" })
              }
            />{" "}
            Strict mode: authorize only the listed private ranges
          </label>
          <p className="text-sm">
            Off: every RFC1918 range may be targeted. On with an empty list: nothing is
            authorized. On with ranges: only those. Environment-listed special-use ranges
            (legacy exception) are never authorized in strict mode.
          </p>
          <label className="block">
            Strict private allowlist (one RFC1918 CIDR per line; used only in strict mode)
            <textarea
              className="block w-full rounded bg-zinc-800 p-2 font-mono"
              rows={3}
              value={form.privateList}
              disabled={!form.privateStrict}
              onChange={(e) => edit({ privateList: e.target.value })}
            />
          </label>
          {fieldError("private_allowlist") && <p role="alert">{fieldError("private_allowlist")}</p>}
        </fieldset>

        <fieldset className="space-y-2 rounded border border-zinc-700 p-3">
          <legend className="font-semibold">Public addresses</legend>
          <label className="block">
            <input
              type="checkbox"
              checked={form.publicEnabled}
              disabled={publicBlocked}
              onChange={(e) => edit({ publicEnabled: e.target.checked })}
            />{" "}
            Allow scanning of explicitly listed public IPv4 ranges
          </label>
          <label className="block">
            Public allowlist (one IP or CIDR per line, no wider than /{policy.public.min_prefix})
            <textarea
              className="block w-full rounded bg-zinc-800 p-2 font-mono"
              rows={3}
              value={form.publicList}
              disabled={publicBlocked}
              onChange={(e) => edit({ publicList: e.target.value })}
            />
          </label>
          {fieldError("public_allowlist") && <p role="alert">{fieldError("public_allowlist")}</p>}
          {fieldError("public_enabled") && <p role="alert">{fieldError("public_enabled")}</p>}
          <p className="text-sm">
            The toggle alone authorizes nothing: only the listed ranges can be targeted, and
            only with the gentle discovery and ports profiles.
          </p>
          {showOwnership && (
            <p role="note" className="rounded border border-amber-600 p-2 text-sm">
              <strong>Ownership warning.</strong> Scanning addresses you do not own or have
              written approval to test may be illegal and can harm others. List only
              infrastructure you control.
            </p>
          )}
        </fieldset>

        <fieldset className="space-y-2 rounded border border-zinc-700 p-3">
          <legend className="font-semibold">Exclusions</legend>
          <label className="block">
            Never scan (one IP or CIDR per line; a target overlapping any of these is rejected)
            <textarea
              className="block w-full rounded bg-zinc-800 p-2 font-mono"
              rows={3}
              value={form.exclusions}
              onChange={(e) => edit({ exclusions: e.target.value })}
            />
          </label>
          {fieldError("exclusions") && <p role="alert">{fieldError("exclusions")}</p>}
        </fieldset>

        {failure?.kind === "validation" && !failure.field && (
          <p role="alert">{failure.message}</p>
        )}
        {failure?.kind === "error" && <p role="alert">{failure.message}</p>}
        {failure?.kind === "conflict" && (
          <div role="alert" className="rounded border border-red-700 p-3 space-y-2">
            <p>
              The policy was changed elsewhere (now revision {failure.current.revision}). Your
              edits were not applied.
            </p>
            <button
              type="button"
              className="rounded bg-zinc-700 px-3 py-1"
              onClick={() => adoptCurrent(failure.current)}
            >
              Discard my edits and load the current policy
            </button>
          </div>
        )}
        {failure?.kind === "confirmation" && (
          <div role="alertdialog" aria-label="Confirm broader authorization" className="rounded border border-amber-600 p-3 space-y-2">
            <p>This change authorizes more scanning:</p>
            <ul className="list-disc pl-5">
              {failure.reasons.map((r) => (
                <li key={r}>{REASON_TEXT[r] ?? r}</li>
              ))}
            </ul>
            <label className="block">
              <input
                type="checkbox"
                checked={confirmBroadening}
                onChange={(e) => setConfirmBroadening(e.target.checked)}
              />{" "}
              I understand and want to broaden what can be scanned.
            </label>
            {failure.publicRequired && (
              <label className="block">
                <input
                  type="checkbox"
                  checked={confirmPublic}
                  onChange={(e) => setConfirmPublic(e.target.checked)}
                />{" "}
                I own these public addresses or have written approval to scan them.
              </label>
            )}
            <button
              type="button"
              className="rounded bg-red-900 px-3 py-1 disabled:opacity-50"
              disabled={
                saving || !confirmBroadening || (failure.publicRequired && !confirmPublic)
              }
              onClick={() => void submit(true)}
            >
              Confirm and save
            </button>
          </div>
        )}
        {saved !== null && <p role="status">Saved as revision {saved}. Applied immediately.</p>}
        {dirty && <p role="status">You have unsaved changes.</p>}

        <div className="flex gap-2">
          <button
            type="submit"
            className="rounded bg-emerald-800 px-3 py-1 disabled:opacity-50"
            disabled={!dirty || saving}
          >
            {saving ? "Saving…" : "Save changes"}
          </button>
          <button
            type="button"
            className="rounded bg-zinc-700 px-3 py-1 disabled:opacity-50"
            disabled={!dirty || saving}
            onClick={() => {
              setForm(toForm(policy));
              setFailure(null);
            }}
          >
            Discard changes
          </button>
        </div>
      </form>
    </main>
  );
}
