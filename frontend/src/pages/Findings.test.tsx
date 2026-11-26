import { act } from "react";
import { createRoot, Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import FindingsPage from "./Findings";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const finding = (id: string, over: Record<string, unknown> = {}) => ({
  id, device_id: "d1", template_id: "http-missing-security-headers", name: `Finding ${id}`,
  severity: "medium", status: "open", host: "10.0.0.5", port: 80, scheme: "http", path: "/",
  matcher_name: null, first_seen: "2026-01-01T00:00:00Z", last_seen: "2026-01-02T00:00:00Z",
  resolved_at: null, suppressed_reason: null, occurrences: 3, template_version: "10.5.2",
  scanner_version: "3.11.1",
  details: { description: "Header missing", tags: [], cve: [], cwe: ["cwe-693"], evidence: ["plain"] },
  ...over,
});

const PLAN = {
  urls: ["http://10.0.0.5:80"], templates: ["a", "b"], versions: { nuclei: "3.11.1", templates: "10.5.2" },
  limits: { rate_limit: 10, concurrency: 5, timeout_seconds: 1800, max_urls: 64 }, approval_digest: "a".repeat(64),
};

function backend(opts: { disabled?: boolean; plan?: typeof PLAN; suppressFails?: boolean } = {}) {
  const calls: { method: string; url: string; body?: Record<string, unknown> }[] = [];
  const rows = [finding("f1"), finding("f2", { severity: "critical", name: "Critical thing" })];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit = {}) => {
    const u = new URL(url);
    const path = u.pathname.replace("/api", "");
    const method = init.method ?? "GET";
    const body = init.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
    calls.push({ method, url: path + u.search, body });
    if (path === "/v1/findings") {
      return json({ total: rows.length, by_status: { open: 2, resolved: 0, suppressed: 0 }, findings: rows });
    }
    if (path === "/v1/findings/f1" && method === "GET") {
      return json({ ...rows[0], history: [{ at: "2026-01-01T00:00:00Z", type: "opened", job_id: "j", actor: null, note: null }] });
    }
    if (path === "/v1/findings/f1/suppress") {
      return opts.suppressFails
        ? json({ detail: "Missing or invalid CSRF token" }, 403)
        : json({ ...rows[0], status: "suppressed" });
    }
    if (path === "/v1/scans/preflight") {
      return opts.disabled
        ? json({ detail: { code: "profile_disabled", message: "x" } }, 403)
        : json({ plan: opts.plan ?? PLAN });
    }
    if (path === "/v1/scans/jobs") return json({ id: "job-9" }, 202);
    return json({ detail: "nope" }, 404);
  }));
  return { calls };
}

let root: Root;
let container: HTMLDivElement;
async function render() {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => { root.render(<MemoryRouter><FindingsPage /></MemoryRouter>); });
  await act(async () => { await Promise.resolve(); });
}
afterEach(() => {
  if (root) act(() => root.unmount());
  container?.remove();
  vi.unstubAllGlobals();
});
const text = () => container.textContent ?? "";
const flush = () => act(async () => { await Promise.resolve(); await Promise.resolve(); });
const btn = (name: string) =>
  Array.from(container.querySelectorAll("button")).find((b) => b.textContent?.includes(name)) as HTMLButtonElement;
async function set(el: HTMLInputElement | HTMLSelectElement, value: string) {
  await act(async () => {
    const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
    el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? "change" : "input", { bubbles: true }));
  });
}
const field = (label: string) =>
  Array.from(container.querySelectorAll("label")).find((l) => l.textContent?.includes(label))
    ?.querySelector("input,select") as HTMLInputElement;
const click = async (el: Element) => { await act(async () => { (el as HTMLElement).click(); }); await flush(); };

describe("FindingsPage", () => {
  it("lists findings with severity, asset link and counts, defaulting to open", async () => {
    const { calls } = backend();
    await render();
    expect(container.querySelectorAll('[data-testid="finding-row"]')).toHaveLength(2);
    expect(text()).toContain("10.0.0.5:80");
    expect(container.querySelector('[data-testid="finding-counts"]')?.textContent).toContain("open 2");
    expect(calls.some((c) => c.url.includes("status=open"))).toBe(true);
  });

  it("sends severity and search filters to the API", async () => {
    const { calls } = backend();
    await render();
    await set(field("Severity"), "critical");
    await set(field("Search"), "headers");
    expect(calls.some((c) => c.url.includes("severity=critical"))).toBe(true);
    expect(calls.some((c) => c.url.includes("q=headers"))).toBe(true);
  });

  it("shows detail with history and suppresses with a required reason", async () => {
    const { calls } = backend();
    await render();
    await click(btn("Details"));
    expect(container.querySelector('[data-testid="finding-detail"]')?.textContent).toContain("opened");
    expect(text()).toContain("templates 10.5.2");
    const suppress = btn("Suppress");
    expect(suppress.disabled).toBe(true);
    await set(container.querySelector('input[placeholder^="Reason"]') as HTMLInputElement, "lab only");
    await click(btn("Suppress"));
    const post = calls.find((c) => c.url.endsWith("/suppress"));
    expect(post?.body).toEqual({ reason: "lab only" });
  });

  it("requires reviewing the plan and an explicit approval before starting a vuln scan", async () => {
    const { calls } = backend();
    await render();
    await set(field("Targets"), "10.0.0.0/28");
    await click(btn("Review plan"));
    expect(container.querySelector('[data-testid="vuln-plan"]')?.textContent).toContain("http://10.0.0.5:80");
    const start = btn("Start vulnerability scan");
    expect(start.disabled).toBe(true);
    expect(calls.some((c) => c.url === "/v1/scans/jobs")).toBe(false);
    await click(container.querySelector('[data-testid="vuln-plan"] input[type="checkbox"]')!);
    await click(btn("Start vulnerability scan"));
    const job = calls.find((c) => c.url === "/v1/scans/jobs");
    expect(job?.body).toEqual({ targets: ["10.0.0.0/28"], profile: "vuln", approval_digest: PLAN.approval_digest });
    expect(text()).toContain("Vulnerability scan queued");
  });

  it("says nothing would be scanned when no HTTP services are known and offers no start", async () => {
    backend({ plan: { ...PLAN, urls: [] } });
    await render();
    await set(field("Targets"), "10.0.0.0/28");
    await click(btn("Review plan"));
    expect(text()).toContain("nothing would be scanned");
    expect(btn("Start vulnerability scan")).toBeUndefined();
  });

  it("explains a disabled profile", async () => {
    backend({ disabled: true });
    await render();
    await set(field("Targets"), "10.0.0.0/28");
    await click(btn("Review plan"));
    expect(text()).toContain("disabled on this deployment");
  });

  it("editing the targets after review discards the plan and the approval", async () => {
    const { calls } = backend();
    await render();
    await set(field("Targets"), "10.0.0.0/28");
    await click(btn("Review plan"));
    await click(container.querySelector('[data-testid="vuln-plan"] input[type="checkbox"]')!);
    await set(field("Targets"), "10.9.9.0/28");
    expect(container.querySelector('[data-testid="vuln-plan"]')).toBeNull();
    expect(btn("Start vulnerability scan")).toBeUndefined();
    expect(calls.some((c) => c.url === "/v1/scans/jobs")).toBe(false);
  });

  it("a failed suppress keeps the details visible and shows the error inline", async () => {
    backend({ suppressFails: true });
    await render();
    await click(btn("Details"));
    await set(container.querySelector('input[placeholder^="Reason"]') as HTMLInputElement, "lab only");
    await click(btn("Suppress"));
    const detail = container.querySelector('[data-testid="finding-detail"]');
    expect(detail).not.toBeNull();
    expect(detail?.textContent).toContain("Action failed: Missing or invalid CSRF token");
    expect(detail?.textContent).toContain("History");
    expect((container.querySelector('input[placeholder^="Reason"]') as HTMLInputElement).value).toBe("lab only");
  });

  it("drops a slow response for an earlier search instead of overwriting the current one", async () => {
    const pending: (() => void)[] = [];
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      const u = new URL(url);
      const path = u.pathname.replace("/api", "");
      if (path !== "/v1/findings") return Promise.resolve(json({ detail: "nope" }, 404));
      const q = u.searchParams.get("q");
      const body = (name: string) => json({ total: 1, by_status: { open: 1, resolved: 0, suppressed: 0 },
        findings: [finding("x", { name })] });
      if (q === null) {
        return new Promise<Response>((resolve) => pending.push(() => resolve(body("STALE-RESULT"))));
      }
      return Promise.resolve(body("FRESH-RESULT"));
    }));
    await render();
    await set(field("Search"), "abc");
    await flush();
    expect(text()).toContain("FRESH-RESULT");
    await act(async () => { pending.forEach((release) => release()); await Promise.resolve(); });
    expect(text()).toContain("FRESH-RESULT");
    expect(text()).not.toContain("STALE-RESULT");
  });
});
