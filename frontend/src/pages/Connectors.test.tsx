import { act } from "react";
import { createRoot, Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import ConnectorsPage from "./Connectors";
import { validateControllerUrl } from "../lib/connectors";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const TOKEN = "UNIFI-TOKEN-SECRET-0123456789";
const AUTH = "auth-passphrase-SECRET-1";
const PRIV = "priv-passphrase-SECRET-2";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

function backend() {
  const calls: { method: string; path: string; body?: Record<string, unknown> }[] = [];
  const state = {
    unifi: {
      name: "unifi", enabled: false, base_url: null as string | null, site: null as string | null,
      verify_tls: true, credential_configured: false, last_status: null, last_error_code: null,
      last_attempt_at: null, last_success_at: null, consecutive_failures: 0, last_summary: null,
    },
    snmpConfigured: false,
    schedules: [] as Record<string, unknown>[],
  };
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit = {}) => {
    const u = new URL(url);
    const path = u.pathname.replace("/api", "");
    const method = init.method ?? "GET";
    const body = init.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
    calls.push({ method, path, body });
    if (path === "/v1/connectors/unifi" && method === "GET") return json(state.unifi);
    if (path === "/v1/connectors/unifi" && method === "PUT") {
      Object.assign(state.unifi, body);
      return json(state.unifi);
    }
    if (path === "/v1/credentials/connectors/unifi/unifi_api_token") {
      state.unifi.credential_configured = method === "PUT";
      return method === "PUT" ? json({ configured: true, masked: "********", metadata: {} }) : new Response(null, { status: 204 });
    }
    if (path === "/v1/connectors/unifi/test") return json({ ok: true, result: { application_version: "9.1.0", site_count: 1 } });
    if (path === "/v1/connectors/unifi/sync") return json({ ok: false, error: { code: "timeout", message: "Controller did not respond in time" } });
    if (path === "/v1/devices") return json([{ id: "dev1", hostname: "core-sw", ip: ["10.0.0.2"] }]);
    if (path === "/v1/credentials/devices/dev1" && method === "GET") {
      return json({ credentials: [
        { credential_type: "snmpv3_auth", configured: state.snmpConfigured, masked: state.snmpConfigured ? "********" : null, metadata: state.snmpConfigured ? { username: "monitor" } : {} },
        { credential_type: "snmpv3_priv", configured: state.snmpConfigured, masked: null, metadata: {} },
      ] });
    }
    if (path.startsWith("/v1/credentials/devices/dev1/") && method === "PUT") {
      state.snmpConfigured = true;
      return json({ configured: true, masked: "********", metadata: {} });
    }
    if (path.startsWith("/v1/credentials/devices/dev1/") && method === "DELETE") {
      state.snmpConfigured = false;
      return new Response(null, { status: 204 });
    }
    if (path === "/v1/devices/dev1/snmp/test") return json({ ok: true, result: { sys_name: "core", identity_key: "abc" } });
    if (path === "/v1/schedules" && method === "GET") return json({ schedules: state.schedules });
    if (path === "/v1/schedules" && method === "POST") {
      const s = { id: "s1", name: body?.name, kind: body?.kind, interval_seconds: body?.interval_seconds, enabled: true,
        next_run_at: "2026-01-01T00:00:00Z", last_run_at: null, last_error_code: null, consecutive_failures: 0 };
      state.schedules.push(s);
      return json(s, 201);
    }
    return json({ detail: "not found" }, 404);
  }));
  return { calls, state };
}

let root: Root;
let container: HTMLDivElement;
async function render() {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => { root.render(<MemoryRouter><ConnectorsPage /></MemoryRouter>); });
  await act(async () => { await Promise.resolve(); });
}
afterEach(() => {
  if (root) act(() => root.unmount());
  container?.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const text = () => container.textContent ?? "";
const flush = () => act(async () => { await Promise.resolve(); await Promise.resolve(); });
async function type(el: HTMLInputElement | HTMLSelectElement, value: string) {
  await act(async () => {
    const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
    el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? "change" : "input", { bubbles: true }));
  });
}
const byLabel = (label: string) => {
  const l = Array.from(container.querySelectorAll("label")).find((x) => x.textContent?.includes(label));
  return l?.querySelector("input,select") as HTMLInputElement;
};
const button = (name: string) =>
  Array.from(container.querySelectorAll("button")).find((b) => b.textContent?.includes(name)) as HTMLButtonElement;
const submit = async (name: string) => { await act(async () => { button(name).click(); }); await flush(); await flush(); };

describe("validateControllerUrl", () => {
  it.each([
    ["https://192.168.1.1", null],
    ["https://10.0.0.1:8443/", null],
    ["http://192.168.1.1", "Use https://"],
    ["https://unifi.local", "Use the controller's IPv4 address (hostnames are not accepted)"],
    ["https://u:p@10.0.0.1", "Enter only https://<IPv4>[:port]"],
    ["https://10.0.0.1/x", "Enter only https://<IPv4>[:port]"],
    ["", "Enter the controller address, for example https://192.168.1.1"],
    ["not a url", "Not a valid URL"],
  ])("%s", (value, expected) => expect(validateControllerUrl(value)).toBe(expected));
});

describe("ConnectorsPage secrets", () => {
  it("renders every secret input as a masked, non-autofilled password field", async () => {
    backend();
    await render();
    const secrets = container.querySelectorAll('input[type="password"]');
    expect(secrets).toHaveLength(3);
    secrets.forEach((el) => expect(el.getAttribute("autocomplete")).toBe("new-password"));
  });

  it("saves the UniFi token once, then clears the field and never shows it again", async () => {
    const { calls } = backend();
    await render();
    await type(byLabel("Controller address"), "https://192.168.1.1");
    await type(byLabel("API token"), TOKEN);
    await submit("Save");
    const put = calls.find((c) => c.path.endsWith("unifi_api_token") && c.method === "PUT");
    expect((put?.body?.secret as { token: string }).token).toBe(TOKEN);
    expect(byLabel("API token").value).toBe("");
    expect(container.innerHTML).not.toContain(TOKEN);
    expect(text()).toContain("configured");
    // The settings PUT must never carry the token.
    const settingsPut = calls.find((c) => c.path === "/v1/connectors/unifi" && c.method === "PUT");
    expect(JSON.stringify(settingsPut?.body)).not.toContain(TOKEN);
  });

  it("rejects a hostname controller URL client-side without calling the API", async () => {
    const { calls } = backend();
    await render();
    await type(byLabel("Controller address"), "https://unifi.local");
    await submit("Save");
    expect(text()).toContain("hostnames are not accepted");
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
  });

  it("test and sync report success and failure from the connector", async () => {
    const { state } = backend();
    state.unifi.credential_configured = true;
    state.unifi.enabled = true;
    state.unifi.base_url = "https://192.168.1.1";
    await render();
    await submit("Test connection");
    expect(text()).toContain("application_version: 9.1.0");
    await submit("Sync now");
    expect(text()).toContain("Controller did not respond in time (timeout)");
  });

  it("saves SNMPv3 authPriv credentials, clears passphrases, and shows only a configured flag", async () => {
    const { calls } = backend();
    await render();
    await type(byLabel("Device"), "dev1");
    await flush();
    expect(container.querySelector('[data-testid="snmp-status"]')?.textContent).toContain("not configured");
    await type(byLabel("Username"), "monitor");
    await type(byLabel("Authentication passphrase"), AUTH);
    await type(byLabel("Privacy passphrase"), PRIV);
    await submit("Save credentials");
    const puts = calls.filter((c) => c.method === "PUT" && c.path.startsWith("/v1/credentials/devices/dev1/"));
    expect(puts.map((p) => p.path.split("/").pop())).toEqual(["snmpv3_auth", "snmpv3_priv"]);
    expect(byLabel("Authentication passphrase").value).toBe("");
    expect(byLabel("Privacy passphrase").value).toBe("");
    expect(container.innerHTML).not.toContain(AUTH);
    expect(container.innerHTML).not.toContain(PRIV);
    expect(container.querySelector('[data-testid="snmp-status"]')?.textContent).toContain("configured");
  });

  it("refuses short SNMP passphrases (authPriv is required)", async () => {
    const { calls } = backend();
    await render();
    await type(byLabel("Device"), "dev1");
    await type(byLabel("Username"), "monitor");
    await type(byLabel("Authentication passphrase"), "short");
    await type(byLabel("Privacy passphrase"), "short");
    await submit("Save credentials");
    expect(text()).toContain("at least 8 characters");
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
  });

  it("creates a polling schedule", async () => {
    const { calls } = backend();
    await render();
    await submit("Add schedule");
    const post = calls.find((c) => c.path === "/v1/schedules" && c.method === "POST");
    expect(post?.body).toMatchObject({ kind: "unifi_sync", interval_seconds: 900, targets: [] });
    expect(container.querySelectorAll('[data-testid="schedule-row"]')).toHaveLength(1);
  });
});

describe("ConnectorsPage device switching", () => {
  it("ignores a late credential status from a device that is no longer selected", async () => {
    let releaseA: (r: Response) => void = () => undefined;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      const path = new URL(url).pathname.replace("/api", "");
      if (path === "/v1/connectors/unifi") return Promise.resolve(json({ name: "unifi", enabled: false,
        base_url: null, site: null, verify_tls: true, credential_configured: false, last_status: null,
        last_error_code: null, last_attempt_at: null, last_success_at: null, consecutive_failures: 0,
        last_summary: null }));
      if (path === "/v1/devices") return Promise.resolve(json([
        { id: "devA", hostname: "alpha", ip: ["10.0.0.1"] }, { id: "devB", hostname: "bravo", ip: ["10.0.0.2"] }]));
      if (path === "/v1/credentials/devices/devA") {
        return new Promise<Response>((resolve) => { releaseA = resolve; });
      }
      if (path === "/v1/credentials/devices/devB") {
        return Promise.resolve(json({ credentials: [
          { credential_type: "snmpv3_auth", configured: false, masked: null, metadata: {} },
          { credential_type: "snmpv3_priv", configured: false, masked: null, metadata: {} }] }));
      }
      if (path === "/v1/schedules") return Promise.resolve(json({ schedules: [] }));
      return Promise.resolve(json({ detail: "nope" }, 404));
    }));
    await render();
    await type(byLabel("Device"), "devA"); // response for A stays pending
    await type(byLabel("Device"), "devB");
    await flush();
    expect(container.querySelector('[data-testid="snmp-status"]')?.textContent).toContain("not configured");
    await act(async () => {
      releaseA(json({ credentials: [
        { credential_type: "snmpv3_auth", configured: true, masked: "********", metadata: { username: "alice" } },
        { credential_type: "snmpv3_priv", configured: true, masked: "********", metadata: {} }] }));
      await Promise.resolve();
    });
    await flush();
    expect(container.querySelector('[data-testid="snmp-status"]')?.textContent).toContain("not configured");
    expect(byLabel("Username").value).toBe("");
    expect(button("Test connection").disabled).toBe(true);
  });

  it("clears the username when switching from a configured to an unconfigured device", async () => {
    backend();
    await render();
    await type(byLabel("Device"), "dev1");
    await flush();
    await type(byLabel("Username"), "typed-for-dev1");
    await type(byLabel("Device"), "");
    expect(byLabel("Username").value).toBe("");
  });
});
