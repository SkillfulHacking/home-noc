import { apiGet, apiPost } from "./api";

export type HealthStatus = "online" | "degraded" | "offline" | "unknown";
export const HEALTH_STATUSES: HealthStatus[] = ["offline", "degraded", "unknown", "online"];

export interface HealthSummary {
  total: number;
  online: number;
  degraded: number;
  offline: number;
  unknown: number;
}

export interface DeviceHealth {
  device_id: string;
  hostname: string;
  status: HealthStatus;
  reason: string;
  last_success_at: string | null;
  last_attempt_at: string | null;
  status_changed_at: string | null;
  last_seen: string | null;
}

export interface HealthResponse {
  summary: HealthSummary;
  devices: DeviceHealth[];
}

export type EventSeverity = "info" | "warning" | "critical";

export interface OpEvent {
  id: string;
  at: string;
  last_at: string;
  type: string;
  severity: EventSeverity;
  device_id: string | null;
  hostname: string | null;
  summary: string;
  count: number;
  acknowledged_at: string | null;
}

export interface EventsResponse {
  total: number;
  events: OpEvent[];
  next_cursor: string | null;
}

export interface FindingsSummary {
  total: number;
  by_status: { open: number; resolved: number; suppressed: number };
}

export const EVENT_TYPE_LABELS: Record<string, string> = {
  device_discovered: "New device",
  address_changed: "New address",
  port_opened: "New open port",
  device_offline: "Device offline",
  device_degraded: "Device degraded",
  device_recovered: "Device recovered",
  managed_device_missing: "Managed device missing",
  finding_opened: "New finding",
};

export function eventTypeLabel(type: string): string {
  return EVENT_TYPE_LABELS[type] ?? type;
}

/** Local, readable time with the exact UTC instant available for tooltips. */
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "never";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "unknown";
  return date.toLocaleString();
}

export function utcTime(iso: string | null | undefined): string | undefined {
  if (!iso) return undefined;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

export function fetchHealth(status?: HealthStatus, limit = 50): Promise<HealthResponse> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (status) params.set("status", status);
  return apiGet<HealthResponse>(`/v1/health/devices?${params.toString()}`);
}

export interface EventQuery {
  severity?: EventSeverity;
  type?: string;
  acknowledged?: boolean;
  cursor?: string | null;
  limit?: number;
}

export function fetchEvents(query: EventQuery = {}): Promise<EventsResponse> {
  const params = new URLSearchParams({ limit: String(query.limit ?? 20) });
  if (query.severity) params.set("severity", query.severity);
  if (query.type) params.set("type", query.type);
  if (query.acknowledged !== undefined) params.set("acknowledged", String(query.acknowledged));
  if (query.cursor) params.set("cursor", query.cursor);
  return apiGet<EventsResponse>(`/v1/events?${params.toString()}`);
}

export function acknowledgeEvent(id: string): Promise<OpEvent> {
  return apiPost<OpEvent>(`/v1/events/${encodeURIComponent(id)}/ack`);
}

export function fetchFindingsSummary(): Promise<FindingsSummary> {
  return apiGet<FindingsSummary>("/v1/findings?status=open&limit=1");
}

/** Tailwind classes per status; colour is never the only signal (a text label is shown). */
export function statusClass(status: HealthStatus): string {
  switch (status) {
    case "online":
      return "border-emerald-700 text-emerald-300";
    case "degraded":
      return "border-amber-600 text-amber-300";
    case "offline":
      return "border-red-700 text-red-300";
    default:
      return "border-zinc-600 text-zinc-300";
  }
}
