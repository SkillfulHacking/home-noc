import { act } from "react";
import { createRoot, Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ScansPage from "./Scans";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const SCOPE = {
  allowed_cidrs: ["192.168.1.0/24"],
  allow_public: false,
  profiles: [
    { name: "discovery", description: "d", intrusive: false, enabled: true, max_hosts: 1024 },
    { name: "ports", description: "p", intrusive: false, enabled: true, max_hosts: 256 },
    { name: "security", description: "s", intrusive: true, enabled: true, max_hosts: 16 },
  ],
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function makeJob(status: string, done = 0) {
  return {
    id: "job-1",
    profile: "discovery",
    targets: ["192.168.1.0/30"],
    status,
    created_by: "admin",
    created_at: "2026-01-01T00:00:00Z",
    started_at: null,
    finished_at: null,
    attempts: 1,
    max_attempts: 3,
    cancel_requested: status === "cancelling",
    progress: { done, total: 4, percent: (100 * done) / 4 },
    error_code: null,
    error_message: null,
    result: null,
  };
}

/** Minimal in-memory stand-in for the scan API, recording each request. */
function fakeBackend(initialJobs: ReturnType<typeof makeJob>[] = []) {
  const jobs = [...initialJobs];
  const calls: { method: string; path: string; body?: unknown }[] = [];
  const fetchMock = vi.fn(async (url: string, init: RequestInit = {}) => {
    const path = new URL(url).pathname.replace("/api", "");
    const method = init.method ?? "GET";
    const body = init.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path, body });
    if (path === "/v1/scans/scope") return json(SCOPE);
    if (path === "/v1/scans/preflight") {
      if ((body.targets as string[]).some((t) => !t.startsWith("192.168.1."))) {
        return json(
          { detail: { code: "out_of_scope", message: "Target is outside the authorized scope" } },
          403
        );
      }
      return json({
        mode: "dry-run",
        profile: body.profile,
        intrusive: false,
        resolved_targets: body.targets,
        resolved_target_count: 4,
        limits: { max_hosts: 1024, timeout_seconds: 60, max_concurrency: 8 },
      });
    }
    if (path === "/v1/scans/jobs" && method === "POST") {
      const job = makeJob("queued");
      jobs.unshift(job);
      return json(job, 202);
    }
    if (path === "/v1/scans/jobs") return json({ items: jobs });
    if (path.endsWith("/cancel")) {
      jobs[0] = { ...jobs[0], status: "cancelled" };
      return json(jobs[0]);
    }
    if (path.endsWith("/events")) {
      return json({ status: jobs[0].status, terminal: false, next_after: 1, events: [
        { id: 1, at: "t0", level: "info", type: "queued", message: "Job queued" },
      ] });
    }
    if (path.startsWith("/v1/scans/jobs/")) return json(jobs[0]);
    return json({ detail: "not found" }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, jobs };
}

let container: HTMLDivElement;
let root: Root;

async function settle() {
  await act(async () => {
    for (let i = 0; i < 10; i += 1) await Promise.resolve();
    await new Promise((r) => setTimeout(r, 0));
  });
}

async function mount() {
  await act(async () => {
    root.render(
      <MemoryRouter>
        <ScansPage />
      </MemoryRouter>
    );
  });
  await settle();
}

async function type(input: HTMLInputElement, value: string) {
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function click(el: Element) {
  await act(async () => {
    el.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
  await settle();
}

const button = (label: RegExp) =>
  Array.from(container.querySelectorAll("button")).find((b) => label.test(b.textContent ?? ""))!;

describe("ScansPage", () => {
  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });
  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    vi.unstubAllGlobals();
  });

  it("offers only the gentle modes", async () => {
    fakeBackend();
    await mount();
    const modes = Array.from(container.querySelectorAll('input[name="mode"]')).map(
      (i) => (i as HTMLInputElement).value
    );
    expect(modes).toEqual(["discovery", "ports"]);
  });

  it("fails closed when the scope cannot be loaded", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        new URL(url).pathname.endsWith("/scope")
          ? json({ detail: "boom" }, 500)
          : json({ items: [] })
      )
    );
    await mount();
    expect(container.querySelector('[role="alert"]')?.textContent).toContain("boom");
    expect((button(/Preview targets|Working/) as HTMLButtonElement).disabled).toBe(true);
    expect(button(/Start scan/)).toBeUndefined();
  });

  it("visibly rejects an unsafe target and offers no way to start", async () => {
    const backend = fakeBackend();
    await mount();
    await type(container.querySelector('input[type="text"], input:not([type])')!, "8.8.8.8");
    await click(button(/Preview targets/));

    expect(container.querySelector('[role="alert"]')?.textContent).toBe(
      "Target is outside the authorized scope"
    );
    expect(button(/Start scan/)).toBeUndefined();
    expect(backend.calls.some((c) => c.method === "POST" && c.path === "/v1/scans/jobs")).toBe(false);
  });

  it("requires preview and consent, starts a job, shows progress and cancels it", async () => {
    const backend = fakeBackend();
    await mount();
    await type(container.querySelector('input:not([type])')!, "192.168.1.0/30");
    await click(button(/Preview targets/));

    const start = button(/Start scan/) as HTMLButtonElement;
    expect(start.disabled).toBe(true); // no consent yet
    await click(container.querySelector('input[type="checkbox"]')!);
    expect((button(/Start scan/) as HTMLButtonElement).disabled).toBe(false);
    await click(button(/Start scan/));

    const started = backend.calls.find((c) => c.method === "POST" && c.path === "/v1/scans/jobs");
    expect(started?.body).toEqual({ targets: ["192.168.1.0/30"], profile: "discovery" });
    expect(container.textContent).toContain("queued");
    expect(container.textContent).toContain("Job queued");

    await click(button(/Cancel scan/));
    expect(backend.calls.some((c) => c.path === "/v1/scans/jobs/job-1/cancel")).toBe(true);
    expect(container.querySelector('[aria-label="Current scan"]')?.textContent).toContain("cancelled");
    expect(button(/Cancel scan/)).toBeUndefined();
  });

  it("ignores an approved preview arriving after the operator edits targets", async () => {
    fakeBackend();
    await mount();
    const originalFetch = globalThis.fetch;
    let deliverPreview: (response: Response) => void = () => {
      throw new Error("preflight was never called");
    };
    vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
      if (new URL(url).pathname === "/api/v1/scans/preflight") {
        return new Promise<Response>((resolve) => { deliverPreview = resolve; });
      }
      return originalFetch(url, init);
    });
    const targetInput = container.querySelector<HTMLInputElement>('input:not([type])')!;
    await type(targetInput, "192.168.1.0/30");
    await click(button(/Preview targets/));
    await type(targetInput, "192.168.1.99");
    await act(async () => {
      deliverPreview(json({
        mode: "dry-run", profile: "discovery", intrusive: false,
        resolved_targets: ["192.168.1.0/30"], resolved_target_count: 4,
        limits: { max_hosts: 1024, timeout_seconds: 60, max_concurrency: 8 },
      }));
    });
    await settle();
    expect(container.querySelector('[aria-label="Preflight preview"]')).toBeNull();
    expect(button(/Start scan/)).toBeUndefined();
  });

  it("labels TCP scan progress in connection attempts, not addresses", async () => {
    const portJob = makeJob("running", 2);
    portJob.profile = "ports";
    fakeBackend([portJob]);
    await mount();
    expect(container.querySelector('[aria-label="Current scan"]')?.textContent)
      .toContain("2 / 4 connection attempts (50%)");
  });

  it("a finished job shows results without a broken inventory link", async () => {
    fakeBackend([makeJob("succeeded", 4)]);
    await mount();
    await click(button(/^View$/));
    expect(container.querySelector('[aria-label="Scan result summary"]')?.textContent)
      .toContain("inventory browser will be added in M21");
    expect(Array.from(container.querySelectorAll("a"))
      .some((a) => a.textContent?.includes("View discovered assets"))).toBe(false);
  });

  it("resumes an active persisted job after a page reload", async () => {
    const backend = fakeBackend([makeJob("running", 2)]);
    await mount();
    const current = container.querySelector('[aria-label="Current scan"]');
    expect(current?.textContent).toContain("running");
    expect(current?.textContent).toContain("2 / 4 addresses (50%)");
    expect(button(/Cancel scan/)).toBeDefined();
    // Nothing was started by merely loading the page.
    expect(backend.calls.some((c) => c.method === "POST")).toBe(false);
  });
});
