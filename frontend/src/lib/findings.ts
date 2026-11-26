import { ApiError, apiGet, apiPost } from "./api";

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";
export type FindingStatus = "open" | "resolved" | "suppressed";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info", "unknown"];
export const STATUSES: FindingStatus[] = ["open", "resolved", "suppressed"];

export interface Finding {
  id: string;
  device_id: string;
  template_id: string;
  name: string;
  severity: Severity;
  status: FindingStatus;
  host: string;
  port: number;
  scheme: string;
  path: string;
  matcher_name: string | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  suppressed_reason: string | null;
  occurrences: number;
  template_version: string | null;
  scanner_version: string | null;
  details: {
    description?: string | null;
    tags?: string[];
    cve?: string[];
    cwe?: string[];
    evidence?: string[];
  };
}

export interface FindingHistory {
  at: string;
  type: string;
  job_id: string | null;
  actor: string | null;
  note: string | null;
}

export interface FindingList {
  total: number;
  by_status: Record<FindingStatus, number>;
  findings: Finding[];
}

export interface FindingFilters {
  severity: Severity | "";
  status: FindingStatus | "";
  q: string;
}

export function fetchFindings(f: FindingFilters, offset = 0, limit = 25): Promise<FindingList> {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (f.severity) params.set("severity", f.severity);
  if (f.status) params.set("status", f.status);
  if (f.q.trim()) params.set("q", f.q.trim());
  return apiGet<FindingList>(`/v1/findings?${params.toString()}`);
}

export const fetchFinding = (id: string) =>
  apiGet<Finding & { history: FindingHistory[] }>(`/v1/findings/${encodeURIComponent(id)}`);

export const suppressFinding = (id: string, reason: string) =>
  apiPost<Finding>(`/v1/findings/${encodeURIComponent(id)}/suppress`, { reason });

export const unsuppressFinding = (id: string) =>
  apiPost<Finding>(`/v1/findings/${encodeURIComponent(id)}/unsuppress`);

export interface VulnPlan {
  urls: string[];
  templates: string[];
  versions: { nuclei: string | null; templates: string | null };
  limits: { rate_limit: number; concurrency: number; timeout_seconds: number; max_urls: number };
  approval_digest: string;
}

export function previewVulnPlan(targets: string[]): Promise<{ plan: VulnPlan }> {
  return apiPost("/v1/scans/preflight", { targets, profile: "vuln" });
}

export function startVulnScan(targets: string[], approvalDigest: string): Promise<{ id: string }> {
  return apiPost("/v1/scans/jobs", {
    targets,
    profile: "vuln",
    approval_digest: approvalDigest,
  });
}

/** Operator-readable text for the vuln flow's expected failures. */
export function vulnErrorMessage(err: unknown): string {
  if (err instanceof ApiError && err.body && typeof err.body === "object") {
    const detail = (err.body as { detail?: { code?: string; message?: string } }).detail;
    if (detail?.code === "profile_disabled") {
      return "Vulnerability scanning is disabled on this deployment (SCAN_VULN_PROFILE_ENABLED).";
    }
    if (detail?.code === "approval_mismatch") {
      return "The plan changed since you reviewed it. Review it again.";
    }
    if (detail?.message) return detail.message;
  }
  return err instanceof Error ? err.message : String(err);
}

export function severityClass(s: Severity): string {
  switch (s) {
    case "critical":
      return "border-red-600 text-red-300";
    case "high":
      return "border-orange-600 text-orange-300";
    case "medium":
      return "border-amber-600 text-amber-300";
    case "low":
      return "border-sky-700 text-sky-300";
    default:
      return "border-zinc-600 text-zinc-300";
  }
}
