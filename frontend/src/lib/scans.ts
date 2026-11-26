import { ApiError, apiGet, apiPost, apiPut } from "./api";

export interface Profile {
  name: string;
  description: string;
  intrusive: boolean;
  enabled: boolean;
  max_hosts: number;
}

export interface EffectivePolicy {
  private_networks: string[];
  special_use_networks: string[];
  public_networks: string[];
  excluded: string[];
  private_scanning: boolean;
  public_scanning: boolean;
}

/** Runtime scan policy as returned by GET/PUT /v1/scan-policy (M08A). */
export interface ScanPolicy {
  revision: number;
  updated_at: string;
  updated_by: string;
  bootstrap_origin: string;
  private: { enabled: boolean; strict: boolean; allowlist: string[]; rfc1918: string[] };
  public: { enabled: boolean; allowlist: string[]; min_prefix: number };
  exclusions: string[];
  effective: EffectivePolicy;
  deployment: {
    scope_restricted: boolean;
    allowed_cidrs: string[];
    public_blocked: boolean;
    security_profile_enabled: boolean;
  };
  limits: {
    max_target_entries: number;
    max_policy_entries: number;
    max_exclusions: number;
    min_public_prefix: number;
    max_active_jobs: number;
    profiles: {
      name: string;
      intrusive: boolean;
      max_hosts: number;
      timeout_seconds: number;
      max_concurrency: number;
    }[];
  };
  worker_vantage: string;
}

export interface Scope {
  allowed_cidrs: string[];
  allow_public: boolean;
  profiles: Profile[];
  /** Absent on older backends; null when the stored policy is unreadable. */
  policy?: ScanPolicy | null;
  policy_error?: { code: string; message: string } | null;
}

export interface ScanPolicyUpdate {
  expected_revision: number;
  private_enabled: boolean;
  private_strict: boolean;
  private_allowlist: string[];
  public_enabled: boolean;
  public_allowlist: string[];
  exclusions: string[];
  confirm_broadening?: boolean;
  confirm_public?: boolean;
}

export type PolicySaveFailure =
  | { kind: "conflict"; current: ScanPolicy }
  | { kind: "confirmation"; reasons: string[]; publicRequired: boolean }
  | { kind: "validation"; code: string; field: string | null; message: string }
  | { kind: "error"; message: string };

/** Map a failed PUT /v1/scan-policy onto something a form can act on. */
export function classifyPolicyError(err: unknown): PolicySaveFailure {
  if (err instanceof ApiError) {
    const detail = (err.body as { detail?: Record<string, unknown> } | undefined)?.detail;
    if (detail && typeof detail === "object" && !Array.isArray(detail)) {
      if (err.status === 409 && detail.code === "revision_conflict") {
        return { kind: "conflict", current: detail.current as ScanPolicy };
      }
      if (err.status === 409 && detail.code === "confirmation_required") {
        return {
          kind: "confirmation",
          reasons: Array.isArray(detail.reasons) ? (detail.reasons as string[]) : [],
          publicRequired: detail.public_confirmation_required === true,
        };
      }
      if (err.status === 422 && typeof detail.code === "string") {
        return {
          kind: "validation",
          code: detail.code,
          field: typeof detail.field === "string" ? detail.field : null,
          message: typeof detail.message === "string" ? detail.message : "Invalid policy",
        };
      }
    }
  }
  return { kind: "error", message: describeError(err, "Could not save the scan policy") };
}

/** Why the policy refused a target set, in operator language. */
const REJECTION_HELP: Record<string, string> = {
  private_scanning_disabled:
    "Private-network scanning is turned off. An administrator can enable it in Settings → Security → Scan Policy.",
  public_not_allowlisted:
    "Public scanning is on, but this target is not fully inside an explicitly listed public range.",
  excluded_target: "The target is, or includes, an address excluded by the scan policy.",
  mixed_range: "The range mixes authorized and unauthorized space; submit narrower ranges.",
  policy_unavailable: "The scan policy could not be read, so scanning is disabled until it can.",
  policy_missing: "No scan policy is stored (run database migrations); scanning is disabled.",
  policy_invalid: "The stored scan policy is invalid; an administrator must fix it.",
};

/** Like describeError, but appends guidance for known policy rejection codes. */
export function describeRejection(err: unknown, fallback: string): string {
  const base = describeError(err, fallback);
  if (err instanceof ApiError) {
    const code = (err.body as { detail?: { code?: unknown } } | undefined)?.detail?.code;
    if (typeof code === "string" && REJECTION_HELP[code]) {
      return `${base} ${REJECTION_HELP[code]}`;
    }
  }
  return base;
}

export interface Preview {
  mode: string;
  profile: string;
  intrusive: boolean;
  resolved_targets: string[];
  resolved_target_count: number;
  limits: { max_hosts: number; timeout_seconds: number; max_concurrency: number };
}

export type JobStatus =
  | "queued"
  | "running"
  | "cancelling"
  | "succeeded"
  | "failed"
  | "cancelled";

export interface Job {
  id: string;
  profile: string;
  targets: string[];
  status: JobStatus;
  created_by: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  attempts: number;
  max_attempts: number;
  cancel_requested: boolean;
  progress: { done: number; total: number; percent: number };
  error_code: string | null;
  error_message: string | null;
  result: Record<string, unknown> | null;
}

export interface JobEvent {
  id: number;
  at: string;
  level: string;
  type: string;
  message: string;
}

export interface EventPage {
  status: JobStatus;
  terminal: boolean;
  next_after: number;
  events: JobEvent[];
}

const TERMINAL: ReadonlySet<string> = new Set(["succeeded", "failed", "cancelled"]);

export const isTerminal = (status: string): boolean => TERMINAL.has(status);
export const isActive = (status: string): boolean => !isTerminal(status);

/** The poll interval backs off up to this ceiling while the API is failing. */
export const POLL_MS = 2000;
export const MAX_BACKOFF_MS = 15000;
/** Cap of events kept in the browser; the server caps at 500 per job anyway. */
export const MAX_EVENTS_SHOWN = 200;

/** Split operator input into a target list (the backend validates scope). */
export function parseTargets(input: string): string[] {
  return input.split(/[\s,]+/).filter(Boolean);
}

/**
 * Backend scope errors carry `detail: {code, message}`, validation errors
 * carry a list. Always return a short, human-readable string.
 */
export function describeError(err: unknown, fallback: string): string {
  if (!(err instanceof ApiError)) return fallback;
  const detail = (err.body as { detail?: unknown } | undefined)?.detail;
  if (detail && typeof detail === "object" && !Array.isArray(detail)) {
    const message = (detail as { message?: unknown }).message;
    if (typeof message === "string") return message;
  }
  if (Array.isArray(detail) && err.status === 422) {
    return "The request was rejected: check the target list (1–64 IPv4 addresses or CIDRs).";
  }
  return err.message || fallback;
}

export const getScope = () => apiGet<Scope>("/v1/scans/scope");

export const getScanPolicy = () => apiGet<ScanPolicy>("/v1/scan-policy");

export const saveScanPolicy = (update: ScanPolicyUpdate) =>
  apiPut<ScanPolicy>("/v1/scan-policy", update);

export const previewScan = (targets: string[], profile: string) =>
  apiPost<Preview>("/v1/scans/preflight", { targets, profile });

export const startScan = (targets: string[], profile: string) =>
  apiPost<Job>("/v1/scans/jobs", { targets, profile });

export const cancelScan = (id: string) =>
  apiPost<Job>(`/v1/scans/jobs/${encodeURIComponent(id)}/cancel`);

export const getJob = (id: string) =>
  apiGet<Job>(`/v1/scans/jobs/${encodeURIComponent(id)}`);

export const listJobs = (limit = 25) =>
  apiGet<{ items: Job[] }>(`/v1/scans/jobs?limit=${limit}`).then((r) => r.items);

export const getEvents = (id: string, after: number) =>
  apiGet<EventPage>(
    `/v1/scans/jobs/${encodeURIComponent(id)}/events?after=${after}&limit=100`
  );

/** Next delay: the base interval when healthy, doubling (bounded) on failure. */
export function nextDelay(consecutiveFailures: number): number {
  if (consecutiveFailures <= 0) return POLL_MS;
  return Math.min(POLL_MS * 2 ** consecutiveFailures, MAX_BACKOFF_MS);
}

export interface PollHandlers {
  onJob(job: Job): void;
  onEvents(events: JobEvent[]): void;
  /** Called with `null` after a successful poll, with a message after a failure. */
  onError(message: string | null): void;
  onDone?(job: Job): void;
}

/**
 * Poll a persisted job until it reaches a terminal state. State lives in the
 * backend, so calling this again after a reload resumes where the job is now;
 * events are re-read from the start. Returns a stop function.
 */
export function pollJob(id: string, handlers: PollHandlers): () => void {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let cursor = 0;
  let failures = 0;

  const tick = async () => {
    try {
      const job = await getJob(id);
      if (stopped) return;
      // Drain events (the API pages at 100) before reporting, in order.
      for (let pages = 0; pages < 10; pages += 1) {
        const page = await getEvents(id, cursor);
        if (stopped) return;
        if (page.events.length === 0) break;
        cursor = page.next_after;
        handlers.onEvents(page.events);
        if (page.events.length < 100) break;
      }
      failures = 0;
      handlers.onError(null);
      handlers.onJob(job);
      if (isTerminal(job.status)) {
        handlers.onDone?.(job);
        return;
      }
    } catch (err) {
      if (stopped) return;
      if (err instanceof ApiError && (err.status === 404 || err.status === 401)) {
        // Job gone or session ended: retrying cannot help.
        handlers.onError(describeError(err, "Scan job is no longer available"));
        return;
      }
      failures += 1;
      handlers.onError(describeError(err, "Lost contact with the server; retrying…"));
    }
    if (!stopped) timer = setTimeout(tick, nextDelay(failures));
  };

  void tick();
  return () => {
    stopped = true;
    if (timer !== undefined) clearTimeout(timer);
  };
}
