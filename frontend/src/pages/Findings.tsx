import { useCallback, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import {
  fetchFinding,
  fetchFindings,
  previewVulnPlan,
  SEVERITIES,
  severityClass,
  startVulnScan,
  STATUSES,
  suppressFinding,
  unsuppressFinding,
  vulnErrorMessage,
  type Finding,
  type FindingFilters,
  type FindingHistory,
  type FindingList,
  type VulnPlan,
} from "../lib/findings";
import { formatTime, utcTime } from "../lib/operations";
import { usePolling } from "../lib/usePolling";

const PAGE = 25;
const btn = "rounded bg-zinc-800 px-3 py-1 hover:bg-zinc-700 disabled:opacity-50";
const input = "rounded bg-zinc-800 px-2 py-1";
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

function VulnScanPanel() {
  const [targets, setTargets] = useState("");
  const [plan, setPlan] = useState<VulnPlan | null>(null);
  const [approved, setApproved] = useState(false);
  const [msg, setMsg] = useState<{ text: string; error: boolean; jobId?: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const list = () => targets.split(/[\s,]+/).filter(Boolean);

  const review = async (e: FormEvent) => {
    e.preventDefault();
    setPlan(null);
    setApproved(false);
    setMsg(null);
    if (list().length === 0) return setMsg({ text: "Enter at least one authorized address or CIDR", error: true });
    setBusy(true);
    try {
      setPlan((await previewVulnPlan(list())).plan);
    } catch (err) {
      setMsg({ text: vulnErrorMessage(err), error: true });
    } finally {
      setBusy(false);
    }
  };

  const start = async () => {
    if (!plan || !approved) return;
    setBusy(true);
    try {
      const job = await startVulnScan(list(), plan.approval_digest);
      setMsg({ text: "Vulnerability scan queued.", error: false, jobId: job.id });
      setPlan(null);
      setApproved(false);
    } catch (err) {
      setMsg({ text: vulnErrorMessage(err), error: true });
      setPlan(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="mb-6 rounded-xl border border-zinc-800 bg-zinc-900 p-4" aria-labelledby="vuln-h">
      <h2 id="vuln-h" className="font-medium mb-1">Vulnerability scan (opt-in, approval required)</h2>
      <p className="text-sm text-zinc-400 mb-3">
        Runs a curated, read-only set of Nuclei checks against HTTP services Home-NOC already knows
        on hosts inside your authorized scope. Nothing is guessed or expanded. Only scan systems
        you own or are authorized to test.
      </p>
      <form onSubmit={review} className="flex flex-wrap items-end gap-3">
        <label className="text-sm">
          Targets (addresses or CIDRs)
          <input className={`${input} block w-72`} value={targets} onChange={(e) => setTargets(e.target.value)}
            placeholder="192.168.1.0/28" />
        </label>
        <button className={btn} type="submit" disabled={busy}>Review plan</button>
      </form>
      {plan && (
        <div className="mt-3" data-testid="vuln-plan">
          <h3 className="text-sm font-medium">Plan to approve</h3>
          {plan.urls.length === 0 ? (
            <p className="text-sm text-amber-300">
              No known HTTP services on these targets, so nothing would be scanned. Run a ports scan first.
            </p>
          ) : (
            <>
              <p className="text-sm">{plan.urls.length} URL(s):</p>
              <ul className="text-sm font-mono">
                {plan.urls.map((u) => <li key={u}>{u}</li>)}
              </ul>
              <p className="text-sm mt-1">
                {plan.templates.length} read-only templates · Nuclei {plan.versions.nuclei} · templates{" "}
                {plan.versions.templates} · {plan.limits.rate_limit} req/s · {plan.limits.concurrency} concurrent ·
                time limit {Math.round(plan.limits.timeout_seconds / 60)} min
              </p>
              <label className="mt-2 block text-sm">
                <input type="checkbox" checked={approved} onChange={(e) => setApproved(e.target.checked)} /> I
                approve scanning exactly these URLs with these checks.
              </label>
              <button className={`${btn} mt-2`} disabled={!approved || busy} onClick={() => void start()}>
                Start vulnerability scan
              </button>
            </>
          )}
        </div>
      )}
      {msg && (
        <p role={msg.error ? "alert" : "status"} className={msg.error ? "text-red-400" : "text-emerald-300"}>
          {msg.text} {msg.jobId && <Link className="underline" to="/scans">View in Scans</Link>}
        </p>
      )}
    </section>
  );
}

function Detail({ id, onChanged }: { id: string; onChanged: () => void }) {
  const [data, setData] = useState<(Finding & { history: FindingHistory[] }) | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const load = useCallback(async () => {
    try {
      setData(await fetchFinding(id));
      setError(null);
    } catch (e) {
      setError(errorText(e));
    }
  }, [id]);
  usePolling(load, 60_000, id);

  const act = async (action: () => Promise<unknown>) => {
    try {
      await action();
      setReason("");
      await load();
      onChanged();
    } catch (e) {
      setError(errorText(e));
    }
  };

  if (error) return <p role="alert" className="text-red-400">{error}</p>;
  if (!data) return <p role="status">Loading…</p>;
  return (
    <div className="mt-2 rounded border border-zinc-800 p-3 text-sm" data-testid="finding-detail">
      {data.details.description && <p className="mb-2">{data.details.description}</p>}
      <p className="text-zinc-400">
        Template {data.template_id} (templates {data.template_version ?? "unknown"}, scanner{" "}
        {data.scanner_version ?? "unknown"}) · seen {data.occurrences}× · first{" "}
        <span title={utcTime(data.first_seen)}>{formatTime(data.first_seen)}</span>
      </p>
      {(data.details.cve?.length || data.details.cwe?.length) ? (
        <p className="text-zinc-400">{[...(data.details.cve ?? []), ...(data.details.cwe ?? [])].join(", ")}</p>
      ) : null}
      {data.details.evidence && data.details.evidence.length > 0 && (
        <pre className="mt-1 overflow-auto rounded bg-zinc-950 p-2 text-xs">{data.details.evidence.join("\n")}</pre>
      )}
      {data.status === "suppressed" ? (
        <div className="mt-2">
          <p>Suppressed: {data.suppressed_reason}</p>
          <button className={btn} onClick={() => void act(() => unsuppressFinding(id))}>Unsuppress</button>
        </div>
      ) : (
        <form className="mt-2 flex flex-wrap items-center gap-2"
          onSubmit={(e) => { e.preventDefault(); void act(() => suppressFinding(id, reason.trim())); }}>
          <label>
            <span className="sr-only">Suppression reason</span>
            <input className={`${input} w-64`} value={reason} placeholder="Reason (required, ≥ 3 characters)"
              onChange={(e) => setReason(e.target.value)} />
          </label>
          <button className={btn} type="submit" disabled={reason.trim().length < 3}>Suppress</button>
        </form>
      )}
      <h4 className="mt-3 font-medium">History</h4>
      <ol className="text-xs text-zinc-400">
        {data.history.map((h, i) => (
          <li key={`${h.at}-${i}`}>
            <span title={utcTime(h.at)}>{formatTime(h.at)}</span> — {h.type}
            {h.actor ? ` by ${h.actor}` : ""}{h.note ? `: ${h.note}` : ""}
          </li>
        ))}
      </ol>
    </div>
  );
}

export default function FindingsPage() {
  const [filters, setFilters] = useState<FindingFilters>({ severity: "", status: "open", q: "" });
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<FindingList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await fetchFindings(filters, offset, PAGE));
      setError(null);
    } catch (e) {
      setError(errorText(e));
    }
  }, [filters, offset]);
  usePolling(load, 30_000, `${filters.severity}|${filters.status}|${filters.q}|${offset}`);

  const change = (patch: Partial<FindingFilters>) => {
    setOffset(0);
    setFilters((f) => ({ ...f, ...patch }));
  };

  return (
    <main id="app" className="mx-auto max-w-6xl p-4">
      <h1 className="text-2xl font-semibold mb-4">Findings</h1>
      <VulnScanPanel />
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <label className="text-sm">
          Severity
          <select className={`${input} block`} value={filters.severity}
            onChange={(e) => change({ severity: e.target.value as FindingFilters["severity"] })}>
            <option value="">All</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label className="text-sm">
          Status
          <select className={`${input} block`} value={filters.status}
            onChange={(e) => change({ status: e.target.value as FindingFilters["status"] })}>
            <option value="">All</option>
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label className="text-sm">
          Search
          <input className={`${input} block`} value={filters.q} onChange={(e) => change({ q: e.target.value })} />
        </label>
        {data && (
          <span className="text-sm text-zinc-400" data-testid="finding-counts">
            {data.total} shown · open {data.by_status.open} · resolved {data.by_status.resolved} · suppressed{" "}
            {data.by_status.suppressed}
          </span>
        )}
      </div>
      {error && <p role="alert" className="text-red-400">Findings unavailable: {error}</p>}
      {data && data.findings.length === 0 && !error && (
        <p className="text-sm text-zinc-400">No findings match. Findings appear after an approved vulnerability scan.</p>
      )}
      <ul className="divide-y divide-zinc-800 rounded-xl border border-zinc-800 bg-zinc-900">
        {(data?.findings ?? []).map((f) => (
          <li key={f.id} className="p-2" data-testid="finding-row">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`rounded border px-2 text-xs ${severityClass(f.severity)}`}>{f.severity}</span>
              <span className="font-medium">{f.name}</span>
              <span className="text-xs text-zinc-500">{f.status}</span>
              <Link className="underline text-sm" to={`/inventory/${f.device_id}`}>
                {f.host}:{f.port}
              </Link>
              <span className="ml-auto text-xs text-zinc-500" title={utcTime(f.last_seen)}>
                last seen {formatTime(f.last_seen)}
              </span>
              <button className={btn} aria-expanded={openId === f.id}
                onClick={() => setOpenId(openId === f.id ? null : f.id)}>
                {openId === f.id ? "Hide" : "Details"}
              </button>
            </div>
            {openId === f.id && <Detail id={f.id} onChanged={() => void load()} />}
          </li>
        ))}
      </ul>
      {data && (
        <div className="mt-3 flex gap-2">
          <button className={btn} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
            Previous
          </button>
          <button className={btn} disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>
            Next
          </button>
        </div>
      )}
    </main>
  );
}
