import { apiDelete, apiGet, apiPatch, apiPost, apiPut } from "./api";

export interface UniFiSettings {
  name: "unifi";
  enabled: boolean;
  base_url: string | null;
  site: string | null;
  verify_tls: boolean;
  credential_configured: boolean;
  last_status: string | null;
  last_error_code: string | null;
  last_attempt_at: string | null;
  last_success_at: string | null;
  consecutive_failures: number;
  last_summary: Record<string, number> | null;
}

export interface ConnectorResult {
  ok: boolean;
  result?: Record<string, unknown> | null;
  error?: { code: string; message: string } | null;
}

/** Masked credential status as returned by the API: never contains a secret. */
export interface CredentialStatus {
  credential_type: string;
  configured: boolean;
  masked: string | null;
  metadata: Record<string, unknown>;
}

export interface Schedule {
  id: string;
  name: string;
  kind: "scan" | "snmp_poll" | "unifi_sync";
  interval_seconds: number;
  enabled: boolean;
  next_run_at: string;
  last_run_at: string | null;
  last_error_code: string | null;
  consecutive_failures: number;
}

export const SNMP_AUTH_PROTOCOLS = ["SHA", "SHA224", "SHA256", "SHA384", "SHA512"] as const;
export const SNMP_PRIV_PROTOCOLS = ["AES128", "AES192", "AES256"] as const;
export type SnmpAuthProtocol = (typeof SNMP_AUTH_PROTOCOLS)[number];
export type SnmpPrivProtocol = (typeof SNMP_PRIV_PROTOCOLS)[number];

export const fetchUniFi = () => apiGet<UniFiSettings>("/v1/connectors/unifi");

export const saveUniFi = (body: {
  enabled: boolean;
  base_url: string | null;
  site: string | null;
  verify_tls: boolean;
}) => apiPut<UniFiSettings>("/v1/connectors/unifi", body);

export const testUniFi = () => apiPost<ConnectorResult>("/v1/connectors/unifi/test");
export const syncUniFi = () => apiPost<ConnectorResult>("/v1/connectors/unifi/sync");

/** Write-only: the token travels in this request body and is never read back. */
export const putUniFiToken = (token: string, label?: string) =>
  apiPut<CredentialStatus>("/v1/credentials/connectors/unifi/unifi_api_token", {
    secret: { token },
    metadata: label ? { label } : {},
  });

export const deleteUniFiToken = () =>
  apiDelete<void>("/v1/credentials/connectors/unifi/unifi_api_token");

export const fetchDeviceCredentials = (deviceId: string) =>
  apiGet<{ credentials: CredentialStatus[] }>(
    `/v1/credentials/devices/${encodeURIComponent(deviceId)}`
  );

export interface SnmpV3Input {
  username: string;
  authProtocol: SnmpAuthProtocol;
  authPassphrase: string;
  privProtocol: SnmpPrivProtocol;
  privPassphrase: string;
}

/** SNMPv3 authPriv only: both secrets are required and sent in request bodies. */
export async function putSnmpCredentials(deviceId: string, v: SnmpV3Input): Promise<void> {
  const base = `/v1/credentials/devices/${encodeURIComponent(deviceId)}`;
  await apiPut(`${base}/snmpv3_auth`, {
    secret: { password: v.authPassphrase },
    metadata: { username: v.username, protocol: v.authProtocol },
  });
  await apiPut(`${base}/snmpv3_priv`, {
    secret: { password: v.privPassphrase },
    metadata: { protocol: v.privProtocol },
  });
}

export async function deleteSnmpCredentials(deviceId: string): Promise<void> {
  const base = `/v1/credentials/devices/${encodeURIComponent(deviceId)}`;
  await apiDelete(`${base}/snmpv3_auth`);
  await apiDelete(`${base}/snmpv3_priv`);
}

export const testSnmp = (deviceId: string) =>
  apiPost<ConnectorResult>(`/v1/devices/${encodeURIComponent(deviceId)}/snmp/test`, {});
export const pollSnmp = (deviceId: string) =>
  apiPost<ConnectorResult>(`/v1/devices/${encodeURIComponent(deviceId)}/snmp/poll`, {});

export const fetchSchedules = () => apiGet<{ schedules: Schedule[] }>("/v1/schedules");

export const createConnectorSchedule = (
  kind: "snmp_poll" | "unifi_sync",
  name: string,
  intervalSeconds: number
) =>
  apiPost<Schedule>("/v1/schedules", {
    name,
    kind,
    interval_seconds: intervalSeconds,
    targets: [],
  });

export const setScheduleEnabled = (id: string, enabled: boolean) =>
  apiPatch<Schedule>(`/v1/schedules/${encodeURIComponent(id)}`, { enabled });

export const deleteSchedule = (id: string) =>
  apiDelete<void>(`/v1/schedules/${encodeURIComponent(id)}`);

/** Only http(s) controller URLs on an IPv4 literal are accepted server-side; mirror it. */
export function validateControllerUrl(value: string): string | null {
  const v = value.trim();
  if (!v) return "Enter the controller address, for example https://192.168.1.1";
  let url: URL;
  try {
    url = new URL(v);
  } catch {
    return "Not a valid URL";
  }
  if (url.protocol !== "https:") return "Use https://";
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) {
    return "Use the controller's IPv4 address (hostnames are not accepted)";
  }
  if (url.username || url.password || url.search || url.hash || !["", "/"].includes(url.pathname)) {
    return "Enter only https://<IPv4>[:port]";
  }
  return null;
}

export function describeResult(r: ConnectorResult): string {
  if (!r.ok) return `Failed: ${r.error?.message ?? "unknown error"} (${r.error?.code ?? "error"})`;
  const entries = Object.entries(r.result ?? {}).filter(([, v]) => typeof v !== "object");
  return entries.length ? `OK — ${entries.map(([k, v]) => `${k}: ${String(v)}`).join(", ")}` : "OK";
}
