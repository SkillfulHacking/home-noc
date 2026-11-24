/**
 * Deterministic, stateful stand-in for the Home-NOC API (M22, issue #25).
 *
 * Every `/api/*` request made by the SPA is fulfilled here, in the browser
 * context, so the tests need no backend and can never reach a real network:
 * any request to a non-loopback origin is aborted and recorded. Tests drive the
 * job lifecycle explicitly (`update`, `addEvent`) instead of relying on timing.
 */
import type { Page, Route } from "@playwright/test";
import type { Job, JobEvent, Scope } from "../../src/lib/scans";
import type { Device, Identity, Observation } from "../../src/lib/inventory";
import { E2E_ORIGIN } from "./constants";

export function makeDevice(over: Partial<Device> = {}): Device {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    hostname: "core-switch",
    ip: ["192.0.2.10"],
    mac: "aa:bb:cc:dd:ee:01",
    first_seen: "2026-01-01T00:00:00Z",
    last_seen: new Date().toISOString(),
    discovery_method: "scan",
    vendor: "Acme",
    model: null,
    os: null,
    serial: null,
    location: null,
    roles: ["switch"],
    ports: [{ port: 22, proto: "tcp", service: "ssh", state: "open" }],
    snmp: null,
    api: null,
    notes: null,
    ...over,
  };
}

/** Not a secret: a fixed value for the JS-readable double-submit CSRF cookie. */
export const CSRF_TOKEN = "e2e-csrf-token";
export const OPERATOR = "e2e-operator";
export const ALLOWED_CIDR = "192.0.2.0/24";

export interface MockOptions {
  authenticated?: boolean;
  scopeFails?: boolean;
}

const JSON_HEADERS = { "content-type": "application/json" };

const DEFAULT_SCOPE: Scope = {
  allowed_cidrs: [ALLOWED_CIDR],
  allow_public: false,
  profiles: [
    { name: "discovery", description: "ICMP host discovery", intrusive: false, enabled: true, max_hosts: 256 },
    { name: "ports", description: "TCP connect scan", intrusive: false, enabled: true, max_hosts: 32 },
    // Present on purpose: the UI must never offer an intrusive profile.
    { name: "security", description: "Intrusive security scan", intrusive: true, enabled: true, max_hosts: 16 },
    // Future server profiles must not be offered without an explicit UI review.
    { name: "experimental", description: "Unreviewed scan mode", intrusive: false, enabled: true, max_hosts: 16 },
  ],
};

/** Count addresses and check scope for the small IPv4/CIDR forms the tests use. */
function inspectTarget(target: string): { inScope: boolean; addresses: number; hosts: number } {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(target);
  if (!match) return { inScope: false, addresses: 0, hosts: 0 };
  const prefix = match[5] === undefined ? 32 : Number(match[5]);
  const inScope =
    `${match[1]}.${match[2]}.${match[3]}` === ALLOWED_CIDR.split("/")[0].split(".").slice(0, 3).join(".") && prefix >= 24 && prefix <= 32;
  const addresses = inScope ? 2 ** (32 - prefix) : 0;
  // The real preflight excludes network/broadcast for prefix lengths below /31.
  // The queued job initially counts all addresses for progress tracking.
  const hosts = prefix >= 31 ? addresses : Math.max(0, addresses - 2);
  return { inScope, addresses, hosts };
}

export class MockApi {
  authenticated: boolean;
  scopeFails: boolean;
  readonly jobs: Job[] = [];
  readonly devices: Device[] = [];
  readonly observations = new Map<string, Observation[]>();
  readonly patchBodies: unknown[] = [];
  /** Device ID each PATCH was addressed to, in order. */
  readonly patchTargets: string[] = [];
  readonly identities = new Map<string, Identity[]>();
  private readonly gates = new Map<string, Promise<void>>();
  readonly calls = { scope: 0, jobList: 0, preflight: 0, startJob: 0, cancel: 0, deviceList: 0 };
  readonly preflightBodies: unknown[] = [];
  readonly startBodies: unknown[] = [];
  /** `X-CSRF-Token` header of every state-changing request, in order. */
  readonly mutationCsrf: (string | undefined)[] = [];
  readonly blockedExternal: string[] = [];
  readonly unmocked: string[] = [];
  private readonly events = new Map<string, JobEvent[]>();

  constructor(options: MockOptions = {}) {
    this.authenticated = options.authenticated ?? true;
    this.scopeFails = options.scopeFails ?? false;
  }

  async install(page: Page): Promise<void> {
    await page.context().addCookies([{ name: "home_noc_csrf", value: CSRF_TOKEN, url: E2E_ORIGIN }]);
    // Anything that is not our own loopback origin is blocked, never forwarded.
    await page.route(
      (url) => url.origin !== E2E_ORIGIN,
      (route) => {
        this.blockedExternal.push(route.request().url());
        return route.abort("blockedbyclient");
      },
    );
    // Registered last, so it takes precedence for API paths only.
    await page.route(
      (url) => url.origin === E2E_ORIGIN && url.pathname.startsWith("/api/"),
      (route) => this.handle(route),
    );
  }

  /** Hold every GET /devices/:id response for this device until the returned release() is called. */
  holdDevice(id: string): () => void {
    let release!: () => void;
    this.gates.set(id, new Promise<void>((resolve) => (release = resolve)));
    return () => {
      this.gates.delete(id);
      release();
    };
  }

  latestJob(): Job {
    const job = this.jobs[this.jobs.length - 1];
    if (!job) throw new Error("no job has been created");
    return job;
  }

  update(id: string, patch: Partial<Job>): void {
    const job = this.jobs.find((j) => j.id === id);
    if (!job) throw new Error(`unknown job ${id}`);
    Object.assign(job, patch);
  }

  addEvent(id: string, level: string, message: string): void {
    const list = this.events.get(id) ?? [];
    const next = list.length + 1;
    list.push({
      id: next,
      at: `2026-01-01T00:00:${String(next).padStart(2, "0")}Z`,
      level,
      type: "log",
      message,
    });
    this.events.set(id, list);
  }

  private async handle(route: Route): Promise<void> {
    const request = route.request();
    const method = request.method();
    const path = new URL(request.url()).pathname.replace(/^\/api/, "");
    const reply = (status: number, body: unknown) =>
      route.fulfill({ status, headers: JSON_HEADERS, body: JSON.stringify(body) });
    const bodyOf = (): Record<string, unknown> => {
      try {
        return (request.postDataJSON() ?? {}) as Record<string, unknown>;
      } catch {
        return {};
      }
    };

    if (method !== "GET") this.mutationCsrf.push(request.headers()["x-csrf-token"]);

    if (method === "POST" && path === "/v1/auth/login") {
      const body = bodyOf();
      if (typeof body.username !== "string" || !body.username || typeof body.password !== "string" || !body.password) {
        return reply(401, { detail: "Invalid credentials" });
      }
      this.authenticated = true;
      return reply(200, { username: OPERATOR, expires_at: "2099-01-01T00:00:00Z" });
    }
    if (method === "GET" && path === "/v1/auth/session") {
      return this.authenticated
        ? reply(200, { username: OPERATOR, expires_at: "2099-01-01T00:00:00Z" })
        : reply(401, { detail: "Not authenticated" });
    }
    if (!this.authenticated) return reply(401, { detail: "Not authenticated" });

    if (method === "GET" && path === "/v1/devices") {
      this.calls.deviceList += 1;
      return reply(200, this.devices);
    }
    const deviceRoute = /^\/v1\/devices\/([^/]+)(?:\/(observations|identities))?$/.exec(path);
    if (deviceRoute) {
      const device = this.devices.find((d) => d.id === decodeURIComponent(deviceRoute[1]));
      if (!device) return reply(404, { detail: "Not found" });
      if (method === "GET" && deviceRoute[2] === "observations") {
        return reply(200, this.observations.get(device.id) ?? []);
      }
      if (method === "GET" && deviceRoute[2] === "identities") {
        return reply(200, this.identities.get(device.id) ?? []);
      }
      if (method === "GET" && deviceRoute[2] === undefined) {
        const gate = this.gates.get(device.id);
        if (gate) await gate;
        return reply(200, device);
      }
      if (method === "PATCH" && deviceRoute[2] === undefined) {
        this.patchTargets.push(device.id);
        this.patchBodies.push(bodyOf());
        Object.assign(device, bodyOf());
        return reply(200, device);
      }
    }

    if (method === "GET" && path === "/v1/scans/scope") {
      this.calls.scope += 1;
      return this.scopeFails
        ? reply(503, { detail: { code: "scope_unavailable", message: "Scan scope is temporarily unavailable." } })
        : reply(200, DEFAULT_SCOPE);
    }

    if (method === "POST" && path === "/v1/scans/preflight") {
      this.calls.preflight += 1;
      const body = bodyOf();
      this.preflightBodies.push(body);
      const profile = DEFAULT_SCOPE.profiles.find((p) => p.name === body.profile);
      if (!profile || profile.intrusive) {
        return reply(403, { detail: { code: "profile_not_allowed", message: "That scan mode is not allowed." } });
      }
      const targets = Array.isArray(body.targets) ? (body.targets as string[]) : [];
      let total = 0;
      for (const target of targets) {
        const { inScope, hosts } = inspectTarget(target);
        if (!inScope) {
          return reply(403, {
            detail: { code: "target_out_of_scope", message: `Target ${target} is outside the authorized scan scope.` },
          });
        }
        total += hosts;
      }
      return reply(200, {
        approved: true,
        mode: "dry-run",
        profile: profile.name,
        intrusive: false,
        resolved_targets: targets,
        resolved_target_count: total,
        limits: { max_hosts: profile.max_hosts, timeout_seconds: 5, max_concurrency: 16 },
      });
    }

    if (method === "POST" && path === "/v1/scans/jobs") {
      this.calls.startJob += 1;
      const body = bodyOf();
      this.startBodies.push(body);
      const targets = (body.targets as string[]) ?? [];
      const total = targets.reduce((sum, t) => sum + inspectTarget(t).addresses, 0);
      const job: Job = {
        id: `00000000-0000-4000-8000-${String(this.jobs.length + 1).padStart(12, "0")}`,
        profile: String(body.profile),
        targets,
        status: "queued",
        created_by: OPERATOR,
        created_at: "2026-01-01T00:00:00Z",
        started_at: null,
        finished_at: null,
        attempts: 0,
        max_attempts: 1,
        cancel_requested: false,
        progress: { done: 0, total, percent: 0 },
        error_code: null,
        error_message: null,
        result: null,
      };
      this.jobs.push(job);
      return reply(202, job);
    }

    if (method === "GET" && path === "/v1/scans/jobs") {
      this.calls.jobList += 1;
      return reply(200, { items: [...this.jobs].reverse() });
    }

    const jobRoute = /^\/v1\/scans\/jobs\/([^/]+)(?:\/(events|cancel))?$/.exec(path);
    if (jobRoute) {
      const job = this.jobs.find((j) => j.id === decodeURIComponent(jobRoute[1]));
      if (!job) return reply(404, { detail: "Scan job not found" });
      const terminal = ["succeeded", "failed", "cancelled"].includes(job.status);

      if (method === "GET" && jobRoute[2] === undefined) return reply(200, job);

      if (method === "GET" && jobRoute[2] === "events") {
        const url = new URL(request.url());
        const after = Number(url.searchParams.get("after") ?? "0");
        const limit = Number(url.searchParams.get("limit") ?? "100");
        const page = (this.events.get(job.id) ?? []).filter((e) => e.id > after).slice(0, limit);
        const nextAfter = page.length ? page[page.length - 1].id : after;
        return reply(200, { status: job.status, terminal, next_after: nextAfter, events: page });
      }

      if (method === "POST" && jobRoute[2] === "cancel") {
        this.calls.cancel += 1;
        if (terminal) {
          return reply(409, { detail: { code: "job_finished", message: "The scan has already finished." } });
        }
        job.status = "cancelling";
        job.cancel_requested = true;
        this.addEvent(job.id, "warning", "Cancellation requested by operator");
        return reply(200, job);
      }
    }

    // Fail loudly (and visibly to the tests) rather than touching anything real.
    this.unmocked.push(`${method} ${path}`);
    return reply(404, { detail: "No mock for this endpoint" });
  }
}
