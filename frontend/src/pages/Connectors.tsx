import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import {
  createConnectorSchedule,
  deleteSchedule,
  deleteSnmpCredentials,
  deleteUniFiToken,
  describeResult,
  fetchDeviceCredentials,
  fetchSchedules,
  fetchUniFi,
  pollSnmp,
  putSnmpCredentials,
  putUniFiToken,
  saveUniFi,
  setScheduleEnabled,
  SNMP_AUTH_PROTOCOLS,
  SNMP_PRIV_PROTOCOLS,
  syncUniFi,
  testSnmp,
  testUniFi,
  validateControllerUrl,
  type ConnectorResult,
  type Schedule,
  type SnmpAuthProtocol,
  type SnmpPrivProtocol,
  type UniFiSettings,
} from "../lib/connectors";
import { listDevices, type Device } from "../lib/inventory";
import { formatTime, utcTime } from "../lib/operations";

const card = "rounded-xl border border-zinc-800 bg-zinc-900 p-4 mb-6";
const input = "rounded bg-zinc-800 px-2 py-1 w-full";
const btn = "rounded bg-zinc-800 px-3 py-1 hover:bg-zinc-700 disabled:opacity-50";

type Outcome = { text: string; error: boolean };
const outcome = (r: ConnectorResult): Outcome => ({ text: describeResult(r), error: !r.ok });
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Busy flag + status message + a runner that turns thrown errors into alerts. */
function useRunner() {
  const [msg, setMsg] = useState<Outcome | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (label: string, action: () => Promise<string | Outcome | void>) => {
    setBusy(true);
    setMsg(null);
    try {
      const out = await action();
      if (out && typeof out === "object") setMsg(out);
      else setMsg({ text: out || `${label} done`, error: false });
    } catch (e) {
      setMsg({ text: `${label} failed: ${errorText(e)}`, error: true });
    } finally {
      setBusy(false);
    }
  };
  return { msg, setMsg, busy, run };
}

function Status({ message, error }: { message: string | null; error?: boolean }) {
  if (!message) return null;
  return (
    <p role={error ? "alert" : "status"} className={error ? "text-red-400" : "text-emerald-300"}>
      {message}
    </p>
  );
}

function UniFiCard() {
  const [settings, setSettings] = useState<UniFiSettings | null>(null);
  const [url, setUrl] = useState("");
  const [site, setSite] = useState("");
  const [verify, setVerify] = useState(true);
  const [enabled, setEnabled] = useState(false);
  const [token, setToken] = useState("");
  const { msg, setMsg, busy, run } = useRunner();

  const apply = (s: UniFiSettings) => {
    setSettings(s);
    setUrl(s.base_url ?? "");
    setSite(s.site ?? "");
    setVerify(s.verify_tls);
    setEnabled(s.enabled);
  };

  useEffect(() => {
    fetchUniFi()
      .then(apply)
      .catch((e) => setMsg({ text: errorText(e), error: true }));
  }, [setMsg]);

  const save = (e: FormEvent) => {
    e.preventDefault();
    const problem = url.trim() ? validateControllerUrl(url) : enabled ? "Enter the controller address" : null;
    if (problem) {
      setMsg({ text: problem, error: true });
      return;
    }
    void run("Save", async () => {
      apply(
        await saveUniFi({
          enabled,
          base_url: url.trim() || null,
          site: site.trim() || null,
          verify_tls: verify,
        })
      );
      if (token) {
        // Write-only: sent once, then the field is cleared and never shown again.
        await putUniFiToken(token);
        setToken("");
        apply(await fetchUniFi());
      }
      return "Saved";
    });
  };

  const showResult = async (r: ConnectorResult): Promise<Outcome> => {
    apply(await fetchUniFi());
    return { text: describeResult(r), error: !r.ok };
  };

  return (
    <section className={card} aria-labelledby="unifi-h">
      <h2 id="unifi-h" className="font-medium mb-2">UniFi Network controller</h2>
      <p className="text-sm text-zinc-400 mb-3">
        Read-only import of devices and clients (UniFi Network 9+ API token). Use a view-only token.
      </p>
      {settings && (
        <p className="text-sm mb-3" data-testid="unifi-status">
          Token: <strong>{settings.credential_configured ? "configured" : "not configured"}</strong>
          {" · "}Last sync:{" "}
          <span title={utcTime(settings.last_success_at)}>{formatTime(settings.last_success_at)}</span>
          {settings.last_status === "error" && (
            <span className="text-red-400">
              {" "}· last attempt failed ({settings.last_error_code}), {settings.consecutive_failures} in a row
            </span>
          )}
        </p>
      )}
      <form onSubmit={save} className="grid gap-3 sm:grid-cols-2">
        <label className="text-sm">
          Controller address
          <input className={input} value={url} onChange={(e) => setUrl(e.target.value)}
            placeholder="https://192.168.1.1" inputMode="url" />
        </label>
        <label className="text-sm">
          Site (optional)
          <input className={input} value={site} onChange={(e) => setSite(e.target.value)} />
        </label>
        <label className="text-sm sm:col-span-2">
          API token (write-only)
          <input className={input} type="password" autoComplete="new-password" value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder={settings?.credential_configured ? "•••••••• (leave empty to keep)" : "paste token"} />
        </label>
        <label className="text-sm">
          <input type="checkbox" checked={verify} onChange={(e) => setVerify(e.target.checked)} /> Verify TLS
          certificate
        </label>
        <label className="text-sm">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled
          (allows sync and scheduled polling)
        </label>
        <div className="flex flex-wrap gap-2 sm:col-span-2">
          <button className={btn} type="submit" disabled={busy}>Save</button>
          <button className={btn} type="button" disabled={busy || !settings?.credential_configured}
            onClick={() => void run("Test", () => testUniFi().then(showResult))}>
            Test connection
          </button>
          <button className={btn} type="button" disabled={busy || !settings?.enabled}
            onClick={() => void run("Sync", () => syncUniFi().then(showResult))}>
            Sync now
          </button>
          <button className={btn} type="button" disabled={busy || !settings?.credential_configured}
            onClick={() => {
              if (window.confirm("Remove the stored UniFi token?")) {
                void run("Remove token", async () => {
                  await deleteUniFiToken();
                  apply(await fetchUniFi());
                  return "Token removed";
                });
              }
            }}>
            Remove token
          </button>
        </div>
      </form>
      <Status message={msg?.text ?? null} error={msg?.error} />
    </section>
  );
}

function SnmpCard() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceId, setDeviceId] = useState("");
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [username, setUsername] = useState("");
  const [authProto, setAuthProto] = useState<SnmpAuthProtocol>("SHA256");
  const [authPass, setAuthPass] = useState("");
  const [privProto, setPrivProto] = useState<SnmpPrivProtocol>("AES128");
  const [privPass, setPrivPass] = useState("");
  const { msg, setMsg, busy, run } = useRunner();

  useEffect(() => {
    listDevices()
      .then(setDevices)
      .catch((e) => setMsg({ text: `Could not load devices: ${errorText(e)}`, error: true }));
  }, [setMsg]);

  // The currently selected device; a slow response for a device the operator already
  // moved away from must not set another device's configured flag or username.
  const selected = useRef(deviceId);
  useEffect(() => {
    selected.current = deviceId;
  }, [deviceId]);

  const refreshStatus = useCallback(async (id: string) => {
    if (!id) return setConfigured(null);
    try {
      const { credentials } = await fetchDeviceCredentials(id);
      if (id !== selected.current) return;
      const have = new Set(credentials.filter((c) => c.configured).map((c) => c.credential_type));
      setConfigured(have.has("snmpv3_auth") && have.has("snmpv3_priv"));
      const auth = credentials.find((c) => c.credential_type === "snmpv3_auth");
      if (auth && typeof auth.metadata.username === "string") setUsername(auth.metadata.username);
    } catch (e) {
      if (id !== selected.current) return;
      setConfigured(null);
      setMsg({ text: errorText(e), error: true });
    }
  }, [setMsg]);

  const save = (e: FormEvent) => {
    e.preventDefault();
    if (!deviceId || !username.trim()) return setMsg({ text: "Choose a device and enter the SNMPv3 username", error: true });
    if (authPass.length < 8 || privPass.length < 8) {
      return setMsg({ text: "Authentication and privacy passphrases must be at least 8 characters (authPriv is required)", error: true });
    }
    void run("Save", async () => {
      await putSnmpCredentials(deviceId, {
        username: username.trim(), authProtocol: authProto, authPassphrase: authPass,
        privProtocol: privProto, privPassphrase: privPass,
      });
      setAuthPass("");
      setPrivPass("");
      await refreshStatus(deviceId);
      return "Credentials saved (passphrases are never shown again)";
    });
  };

  return (
    <section className={card} aria-labelledby="snmp-h">
      <h2 id="snmp-h" className="font-medium mb-2">SNMPv3 devices</h2>
      <p className="text-sm text-zinc-400 mb-3">
        SNMPv3 with authentication and privacy only (no v1/v2c). Passphrases are write-only.
      </p>
      <form onSubmit={save} className="grid gap-3 sm:grid-cols-2">
        <label className="text-sm sm:col-span-2">
          Device
          <select className={input} value={deviceId}
            onChange={(e) => {
              selected.current = e.target.value; // before any response can arrive
              setDeviceId(e.target.value);
              // Nothing from the previous device may carry over (it would be saved to the new one).
              setUsername("");
              setConfigured(null);
              setAuthPass("");
              setPrivPass("");
              setMsg(null);
              void refreshStatus(e.target.value);
            }}>
            <option value="">Select a device…</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>{d.hostname} ({d.ip.join(", ") || "no address"})</option>
            ))}
          </select>
        </label>
        {deviceId && configured !== null && (
          <p className="text-sm sm:col-span-2" data-testid="snmp-status">
            SNMPv3 credentials: <strong>{configured ? "configured" : "not configured"}</strong>
          </p>
        )}
        <label className="text-sm">
          Username
          <input className={input} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
        </label>
        <span />
        <label className="text-sm">
          Authentication protocol
          <select className={input} value={authProto} onChange={(e) => setAuthProto(e.target.value as SnmpAuthProtocol)}>
            {SNMP_AUTH_PROTOCOLS.map((p) => <option key={p}>{p}</option>)}
          </select>
        </label>
        <label className="text-sm">
          Authentication passphrase
          <input className={input} type="password" autoComplete="new-password" value={authPass}
            onChange={(e) => setAuthPass(e.target.value)} />
        </label>
        <label className="text-sm">
          Privacy protocol
          <select className={input} value={privProto} onChange={(e) => setPrivProto(e.target.value as SnmpPrivProtocol)}>
            {SNMP_PRIV_PROTOCOLS.map((p) => <option key={p}>{p}</option>)}
          </select>
        </label>
        <label className="text-sm">
          Privacy passphrase
          <input className={input} type="password" autoComplete="new-password" value={privPass}
            onChange={(e) => setPrivPass(e.target.value)} />
        </label>
        <div className="flex flex-wrap gap-2 sm:col-span-2">
          <button className={btn} type="submit" disabled={busy || !deviceId}>Save credentials</button>
          <button className={btn} type="button" disabled={busy || !configured}
            onClick={() => void run("Test", async () => outcome(await testSnmp(deviceId)))}>
            Test connection
          </button>
          <button className={btn} type="button" disabled={busy || !configured}
            onClick={() => void run("Poll", async () => outcome(await pollSnmp(deviceId)))}>
            Poll now
          </button>
          <button className={btn} type="button" disabled={busy || !configured}
            onClick={() => {
              if (window.confirm("Remove the stored SNMPv3 credentials for this device?")) {
                void run("Remove", async () => {
                  await deleteSnmpCredentials(deviceId);
                  await refreshStatus(deviceId);
                  return "Credentials removed";
                });
              }
            }}>
            Remove credentials
          </button>
        </div>
      </form>
      <Status message={msg?.text ?? null} error={msg?.error} />
    </section>
  );
}

function SchedulesCard() {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [kind, setKind] = useState<"snmp_poll" | "unifi_sync">("unifi_sync");
  const [minutes, setMinutes] = useState(15);
  const [msg, setMsg] = useState<{ text: string; error: boolean } | null>(null);

  const load = useCallback(async () => {
    try {
      const { schedules: all } = await fetchSchedules();
      setSchedules(all.filter((s) => s.kind !== "scan"));
    } catch (e) {
      setMsg({ text: errorText(e), error: true });
    }
  }, []);
  useEffect(() => {
    fetchSchedules()
      .then(({ schedules: all }) => setSchedules(all.filter((s) => s.kind !== "scan")))
      .catch((e) => setMsg({ text: errorText(e), error: true }));
  }, []);

  const act = async (action: () => Promise<unknown>) => {
    try {
      await action();
      setMsg(null);
      await load();
    } catch (e) {
      setMsg({ text: errorText(e), error: true });
    }
  };

  return (
    <section className={card} aria-labelledby="sched-h">
      <h2 id="sched-h" className="font-medium mb-2">Polling schedules</h2>
      <ul className="mb-3 divide-y divide-zinc-800">
        {schedules.length === 0 && <li className="text-sm text-zinc-400">No connector schedules.</li>}
        {schedules.map((s) => (
          <li key={s.id} className="flex flex-wrap items-center gap-2 py-1" data-testid="schedule-row">
            <span className="font-medium">{s.kind === "unifi_sync" ? "UniFi sync" : "SNMP poll"}</span>
            <span className="text-sm text-zinc-400">every {Math.round(s.interval_seconds / 60)} min</span>
            <span className="text-xs text-zinc-500" title={utcTime(s.next_run_at)}>next {formatTime(s.next_run_at)}</span>
            {s.last_error_code && <span className="text-xs text-red-400">{s.last_error_code}</span>}
            <span className="ml-auto flex gap-2">
              <button className={btn} onClick={() => void act(() => setScheduleEnabled(s.id, !s.enabled))}>
                {s.enabled ? "Pause" : "Resume"}
              </button>
              <button className={btn} onClick={() => void act(() => deleteSchedule(s.id))}>Delete</button>
            </span>
          </li>
        ))}
      </ul>
      <form className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => { e.preventDefault(); void act(() => createConnectorSchedule(kind,
          kind === "unifi_sync" ? "UniFi sync" : "SNMP poll", minutes * 60)); }}>
        <label className="text-sm">
          Kind
          <select className={input} value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
            <option value="unifi_sync">UniFi sync</option>
            <option value="snmp_poll">SNMP poll (all devices with credentials)</option>
          </select>
        </label>
        <label className="text-sm">
          Every (minutes)
          <input className={input} type="number" min={1} max={10080} value={minutes}
            onChange={(e) => setMinutes(Math.max(1, Number(e.target.value) || 1))} />
        </label>
        <button className={btn} type="submit">Add schedule</button>
      </form>
      <Status message={msg?.text ?? null} error />
    </section>
  );
}

export default function ConnectorsPage() {
  return (
    <main id="app" className="mx-auto max-w-6xl p-4">
      <h1 className="text-2xl font-semibold mb-4">Connectors</h1>
      <p className="mb-4 text-sm text-zinc-400">
        Credentials are stored encrypted and are never displayed. Connectors only contact addresses
        inside the authorized scan policy.
      </p>
      <UniFiCard />
      <SnmpCard />
      <SchedulesCard />
    </main>
  );
}
