import { ApiError, apiGet, apiPost } from "./api";

export interface Profile {
  name: string;
  description: string;
  intrusive: boolean;
  enabled: boolean;
  max_hosts: number;
}

export interface Scope {
  allowed_cidrs: string[];
  allow_public: boolean;
  profiles: Profile[];
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
