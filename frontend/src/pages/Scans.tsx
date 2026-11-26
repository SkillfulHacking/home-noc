import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  Job,
  JobEvent,
  MAX_EVENTS_SHOWN,
  Preview,
  Scope,
  cancelScan,
  describeError,
  describeRejection,
  getScope,
  isActive,
  listJobs,
  parseTargets,
  pollJob,
  previewScan,
  startScan,
} from "../lib/scans";

// Only the gentle, non-intrusive modes are offered in this UI. The intrusive
// security profile stays opt-in on the server and is never selectable here.
const MODE_LABEL: Record<string, string> = {
  discovery: "ICMP host discovery (gentle: no port probing)",
  ports: "TCP connect scan (limited: short fixed list of common ports)",
};

function progressText(job: Job): string {
  const { done, total, percent } = job.progress;
  const unit = job.profile === "ports" ? "connection attempts" : "addresses";
  return total ? `${done} / ${total} ${unit} (${percent}%)` : "waiting for progress…";
}

export default function ScansPage() {
  const [scope, setScope] = useState<Scope | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  // Inventory hands selected addresses over as a *prefill only*; nothing runs until the
  // operator previews (server-side scope/authorization) and confirms.
  const [searchParams] = useSearchParams();
  const [targets, setTargets] = useState(() => (searchParams.get("targets") ?? "").slice(0, 2000)
    .split(/[\s,]+/).filter((t) => /^[0-9./]+$/.test(t)).join(", "));
  const [profile, setProfile] = useState("discovery");
  const [confirmed, setConfirmed] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [job, setJob] = useState<Job | null>(null);
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [pollError, setPollError] = useState<string | null>(null);
  const [history, setHistory] = useState<Job[]>([]);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const stopPolling = useRef<(() => void) | null>(null);
  // A response for an earlier target/mode must never authorize edited inputs.
  const previewRevision = useRef(0);
  // Guard against a second click before React has rendered the busy state.
  const startingRef = useRef(false);
  // Id of the job currently displayed; lets async responses detect staleness.
  const watchedId = useRef<string | null>(null);

  const refreshHistory = useCallback(() => {
    return listJobs()
      .then((items) => {
        setHistory(items);
        setHistoryError(null);
        return items;
      })
      .catch((e: unknown) => {
        setHistoryError(describeError(e, "Could not load scan history"));
        return [] as Job[];
      });
  }, []);

  const watch = useCallback(
    (initial: Job) => {
      stopPolling.current?.();
      watchedId.current = initial.id;
      setJob(initial);
      setEvents([]);
      setPollError(null);
      setCancelling(false);
      stopPolling.current = pollJob(initial.id, {
        onJob: setJob,
        onEvents: (fresh) =>
          setEvents((prev) => [...prev, ...fresh].slice(-MAX_EVENTS_SHOWN)),
        onError: setPollError,
        onDone: () => void refreshHistory(),
      });
    },
    [refreshHistory]
  );

  // On load (including after a refresh or a backend restart) read persisted
  // state from the API and resume watching the newest active job, if any.
  useEffect(() => {
    let live = true;
    getScope()
      .then((s) => live && setScope(s))
      .catch((e: unknown) => live && setLoadError(describeError(e, "Could not load scan scope")));
    void refreshHistory().then((items) => {
      if (!live) return;
      const running = items.find((j) => isActive(j.status));
      if (running) watch(running);
    });
    return () => {
      live = false;
      stopPolling.current?.();
    };
  }, [refreshHistory, watch]);

  // Any change to the inputs invalidates the previous preview and consent.
  function invalidate() {
    previewRevision.current += 1;
    setPreview(null);
    setConfirmed(false);
  }

  async function onPreview(e: FormEvent) {
    e.preventDefault();
    setError(null);
    invalidate();
    const revision = previewRevision.current;
    const requestedTargets = parseTargets(targets);
    const requestedProfile = profile;
    setBusy(true);
    try {
      const response = await previewScan(requestedTargets, requestedProfile);
      if (revision === previewRevision.current) setPreview(response);
    } catch (err) {
      if (revision === previewRevision.current) {
        setError(describeRejection(err, "Preflight failed"));
      }
    } finally {
      setBusy(false);
    }
  }

  // A scan is active if the watched job OR any listed job is still active, so
  // viewing a finished job from history cannot unlock a second concurrent start.
  const hasActive =
    (job !== null && isActive(job.status)) || history.some((h) => isActive(h.status));

  // Polling stops when another job is viewed, so keep history fresh while any
  // listed job is active; otherwise a stale "running" row would block starts forever.
  const historyHasActive = history.some((h) => isActive(h.status));
  useEffect(() => {
    if (!historyHasActive) return undefined;
    const timer = setInterval(() => void refreshHistory(), 3000);
    return () => clearInterval(timer);
  }, [historyHasActive, refreshHistory]);

  async function onStart() {
    if (startingRef.current || !preview || !confirmed || busy || hasActive) return;
    startingRef.current = true;
    setError(null);
    setBusy(true);
    try {
      // Start precisely the approved preview snapshot, never mutable form text.
      // The backend independently re-validates scope at enqueue and execution.
      const started = await startScan(preview.resolved_targets, preview.profile);
      invalidate();
      watch(started);
      void refreshHistory();
    } catch (err) {
      setError(describeRejection(err, "Could not start the scan"));
    } finally {
      startingRef.current = false;
      setBusy(false);
    }
  }

  async function onCancel() {
    if (!job) return;
    setError(null);
    setCancelling(true);
    const id = job.id;
    try {
      const updated = await cancelScan(id);
      // Ignore a late response if the operator has since switched to another job.
      if (watchedId.current === id) setJob(updated);
      void refreshHistory();
    } catch (err) {
      if (watchedId.current === id) {
        setError(describeError(err, "Could not cancel the scan"));
        setCancelling(false);
      }
    }
  }

  const profiles = (scope?.profiles ?? []).filter(
    (p) => p.enabled && !p.intrusive && (p.name === "discovery" || p.name === "ports")
  );
  // Fail closed: without a loaded scope, or if the chosen mode is not one of
  // the offered gentle modes, nothing can be previewed or started.
  const modeOffered = profiles.some((p) => p.name === profile);
  const canStart = preview !== null && confirmed && !busy && !hasActive && modeOffered;
  const rawCounts = job?.result?.asset_reconciliation;
  const counts = rawCounts && typeof rawCounts === "object" && !Array.isArray(rawCounts)
    ? (rawCounts as Record<string, unknown>)
    : null;
  const hasCounts = counts !== null && ["created", "merged", "ambiguous", "invalid"].every(
    (key) => typeof counts[key] === "number"
  );

  return (
    <main id="app" className="mx-auto max-w-6xl p-4 space-y-4">
      <h1 className="text-xl font-semibold">Scans</h1>

      <section role="note" className="rounded border border-amber-600 p-3 text-sm">
        <strong>Ownership and acceptable use.</strong> Only scan networks you own or
        have explicit written permission to test. Scans are limited to the scan policy
        configured by the administrator (and any deployment ceiling); each
        authorization is logged with your username. Only gentle modes are offered here;
        the intrusive security profile is not available from this page.
      </section>

      {loadError && <p role="alert">{loadError}</p>}
      {scope?.policy_error && (
        <p role="alert">
          {scope.policy_error.message} Scanning stays disabled until this is resolved.
        </p>
      )}
      {scope?.policy && (
        <section aria-label="Effective scan authorization" className="text-sm space-y-1">
          <h2 className="font-semibold">Effective scan authorization</h2>
          <p>
            Private (RFC1918) scanning:{" "}
            <strong>{scope.policy.effective.private_scanning ? "enabled" : "disabled"}</strong>
            {scope.policy.effective.private_scanning &&
              ` – ${scope.policy.effective.private_networks.join(", ")}`}
          </p>
          <p>
            Public scanning:{" "}
            <strong>{scope.policy.effective.public_scanning ? "enabled" : "disabled"}</strong>
            {scope.policy.effective.public_scanning &&
              ` – only ${scope.policy.effective.public_networks.join(", ")}`}
          </p>
          {scope.policy.effective.excluded.length > 0 && (
            <p>Excluded: {scope.policy.effective.excluded.join(", ")}</p>
          )}
          {scope.policy.deployment.scope_restricted && (
            <p>
              Deployment ceiling (environment, not editable here):{" "}
              {scope.policy.deployment.allowed_cidrs.join(", ")}
            </p>
          )}
          <p>{scope.policy.worker_vantage}</p>
          <p>
            <Link className="underline" to="/settings/security/scan-policy">
              Scan policy settings
            </Link>{" "}
            (administrators)
          </p>
        </section>
      )}
      {scope && !scope.policy && !scope.policy_error && (
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

      <form onSubmit={onPreview} className="space-y-2" aria-label="New scan">
        <h2 className="font-semibold">1. Choose targets and mode</h2>
        <label className="block">
          Targets (IPv4 or CIDR, separated by spaces or commas)
          <input
            className="block w-full rounded bg-zinc-800 p-2"
            value={targets}
            onChange={(e) => {
              setTargets(e.target.value);
              invalidate();
            }}
            required
          />
        </label>
        <fieldset>
          <legend>Mode</legend>
          {profiles.map((p) => (
            <label key={p.name} className="block">
              <input
                type="radio"
                name="mode"
                value={p.name}
                checked={profile === p.name}
                onChange={() => {
                  setProfile(p.name);
                  invalidate();
                }}
              />{" "}
              {MODE_LABEL[p.name] ?? p.name} – up to {p.max_hosts} hosts
            </label>
          ))}
        </fieldset>
        <button
          type="submit"
          className="rounded bg-zinc-700 px-3 py-1 disabled:opacity-50"
          disabled={busy || !modeOffered}
        >
          {busy ? "Working…" : "Preview targets (dry run)"}
        </button>
      </form>

      {error && <p role="alert">{error}</p>}

      {preview && (
        <section aria-label="Preflight preview" className="space-y-2">
          <h2 className="font-semibold">2. Review and start</h2>
          <p role="status">
            Mode: {preview.profile}. {preview.resolved_target_count} host(s) in{" "}
            {preview.resolved_targets.join(", ")}. Limits: at most{" "}
            {preview.limits.max_hosts} hosts, {preview.limits.max_concurrency} concurrent,{" "}
            {preview.limits.timeout_seconds}s timeout.
          </p>
          <label className="block">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />{" "}
            I own these networks or have written permission to scan them.
          </label>
          <button
            type="button"
            className="rounded bg-emerald-800 px-3 py-1 disabled:opacity-50"
            disabled={!canStart}
            onClick={onStart}
          >
            Start scan
          </button>
          {hasActive && <p>A scan is already in progress; wait for it or cancel it.</p>}
        </section>
      )}

      {job && (
        <section aria-label="Current scan" className="space-y-2">
          <h2 className="font-semibold">Scan progress</h2>
          <p role="status">
            {job.profile} scan of {job.targets.join(", ")}: <strong>{job.status}</strong>
            {job.cancel_requested && isActive(job.status) ? " (cancellation requested)" : ""}
          </p>
          <progress
            aria-label="Scan progress"
            max={100}
            value={job.progress.percent}
            className="w-full"
          />
          <p className="text-sm">{progressText(job)}</p>
          {job.error_message && <p role="alert">{job.error_message}</p>}
          {/* 401/404 deliberately stop polling; don't promise a retry. */}
          {pollError && <p role="alert">{pollError}</p>}
          {isActive(job.status) && (
            <button
              type="button"
              className="rounded bg-red-900 px-3 py-1 disabled:opacity-50"
              onClick={onCancel}
              disabled={cancelling || job.status === "cancelling"}
            >
              {cancelling || job.status === "cancelling" ? "Cancelling…" : "Cancel scan"}
            </button>
          )}
          {job.status === "succeeded" && (
            <section aria-label="Scan result summary" className="space-y-1">
              <h3 className="font-semibold">Results</h3>
              {typeof job.result?.hosts_up === "number" && (
                <p>Responsive hosts: {job.result.hosts_up}</p>
              )}
              {hasCounts && counts && (
                <p>
                  Inventory reconciliation: {String(counts.created)} created, {String(counts.merged)}
                  {" "}merged, {String(counts.ambiguous)} ambiguous, {String(counts.invalid)} invalid.
                </p>
              )}
              <p>
                <Link className="underline" to="/inventory">Browse the inventory</Link>
              </p>
            </section>
          )}
          <h3 className="font-semibold">Events</h3>
          <ul aria-label="Scan events" className="max-h-48 overflow-auto text-sm font-mono">
            {events.map((ev) => (
              <li key={ev.id}>
                {ev.at} [{ev.level}] {ev.message}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-label="Scan history" className="space-y-2">
        <h2 className="font-semibold">History</h2>
        {historyError && <p role="alert">{historyError}</p>}
        {history.length === 0 ? (
          <p className="text-sm">No scans yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                <th>Started</th>
                <th>Mode</th>
                <th>Targets</th>
                <th>Status</th>
                <th>Progress</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {history.map((h) => (
                <tr key={h.id}>
                  <td>{h.created_at}</td>
                  <td>{h.profile}</td>
                  <td>{h.targets.join(", ")}</td>
                  <td>{h.status}</td>
                  <td>{h.progress.percent}%</td>
                  <td>
                    <button
                      type="button"
                      className="underline"
                      onClick={() => watch(h)}
                      aria-label={`View scan ${h.id}`}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}
