import { act } from "react";
import { createRoot, Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import OverviewPage from "./Overview";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const dev = (id: string, hostname: string, status: string, reason: string) => ({
  device_id: id,
  hostname,
  status,
  reason,
  last_success_at: null,
  last_attempt_at: null,
  status_changed_at: "2026-01-01T10:00:00Z",
  last_seen: null,
});

const event = (id: string, over: Record<string, unknown> = {}) => ({
  id,
  at: "2026-01-01T10:00:00Z",
  last_at: "2026-01-01T10:00:00Z",
  type: "device_offline",
  severity: "critical",
  device_id: "d1",
  hostname: "core-sw",
  summary: "Device is offline",
  count: 1,
  acknowledged_at: null,
  ...over,
});

interface Backend {
  fail?: string[];
  events?: ReturnType<typeof event>[];
  secondPage?: ReturnType<typeof event>[];
}

function install(b: Backend = {}) {
  const calls: { method: string; url: string }[] = [];
  const events = b.events ?? [event("e1"), event("e2", { severity: "info", type: "device_recovered" })];
  const fetchMock = vi.fn(async (url: string, init: RequestInit = {}) => {
    const u = new URL(url);
    const path = u.pathname.replace("/api", "");
    calls.push({ method: init.method ?? "GET", url: path + u.search });
    if (b.fail?.some((f) => path.startsWith(f))) return json({ detail: "boom" }, 500);
    if (path === "/v1/health/devices") {
      const status = u.searchParams.get("status");
      const all = [dev("d1", "core-sw", "offline", "no fresh observation"),
                   dev("d2", "ap-1", "degraded", "icmp failing")];
      return json({
        summary: { total: 5, online: 2, degraded: 1, offline: 1, unknown: 1 },
        devices: status ? all.filter((d) => d.status === status) : [],
      });
    }
    if (path === "/v1/events" && init.method !== "POST") {
      if (u.searchParams.get("cursor")) {
        return json({ total: 3, events: b.secondPage ?? [event("e3")], next_cursor: null });
      }
      return json({ total: 3, events, next_cursor: b.secondPage ? "CUR" : null });
    }
    if (path.startsWith("/v1/events/") && path.endsWith("/ack")) {
      const id = path.split("/")[3];
      return json({ ...event(id), acknowledged_at: "2026-01-01T11:00:00Z" });
    }
    if (path === "/v1/findings") {
      return json({ total: 1, by_status: { open: 3, resolved: 0, suppressed: 1 }, findings: [] });
    }
    if (path === "/health") return json({ status: "ok" });
    return json({ detail: "not found" }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls };
}

let root: Root;
let container: HTMLDivElement;

async function render() {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root.render(<MemoryRouter><OverviewPage /></MemoryRouter>);
  });
  await act(async () => {
    await Promise.resolve();
  });
}

const text = () => container.textContent ?? "";
const click = async (el: Element | null) => {
  expect(el).not.toBeNull();
  await act(async () => {
    (el as HTMLElement).click();
  });
};

beforeEach(() => vi.useRealTimers());
afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.unstubAllGlobals();
});

describe("OverviewPage", () => {
  it("shows health counts, attention list, findings and the timeline", async () => {
    install();
    await render();
    expect(container.querySelector('[data-testid="health-online"]')?.textContent).toContain("2");
    expect(container.querySelector('[data-testid="health-offline"]')?.textContent).toContain("1");
    expect(text()).toContain("Needs attention");
    expect(text()).toContain("no fresh observation");
    expect(text()).toContain("icmp failing");
    expect(container.querySelector('[data-testid="open-findings"]')?.textContent).toBe("3");
    expect(container.querySelectorAll('[data-testid="event-row"]')).toHaveLength(2);
    expect(text()).toContain("Device offline");
    expect(text()).toContain("API status: ok");
  });

  it("asks for findings without a status filter so suppressed counts are real", async () => {
    const { calls } = install();
    await render();
    const finding = calls.find((c) => c.url.startsWith("/v1/findings"));
    expect(finding?.url).toBe("/v1/findings?limit=1");
    expect(text()).toContain("(1 suppressed)");
  });

  it("keeps working when one API fails and says which panel is unavailable", async () => {
    install({ fail: ["/v1/findings"] });
    await render();
    expect(text()).toContain("Findings unavailable");
    expect(container.querySelectorAll('[data-testid="event-row"]')).toHaveLength(2);
    expect(container.querySelector('[data-testid="health-online"]')).not.toBeNull();
  });

  it("acknowledges an event through a CSRF-protected POST and marks it", async () => {
    const { calls } = install();
    await render();
    const button = container.querySelector('button[aria-label^="Acknowledge Device offline"]');
    await click(button);
    expect(calls.some((c) => c.method === "POST" && c.url === "/v1/events/e1/ack")).toBe(true);
    expect(text()).toContain("acknowledged");
  });

  it("filters by severity and by unacknowledged, and sends the filters to the API", async () => {
    const { calls } = install();
    await render();
    const select = container.querySelector("select") as HTMLSelectElement;
    await act(async () => {
      select.value = "critical";
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await act(async () => {
      await Promise.resolve();
    });
    expect(select.value).toBe("critical");
    expect(calls.some((c) => c.url.startsWith("/v1/events?") && c.url.includes("severity=critical")))
      .toBe(true);
    const box = container.querySelector('input[type="checkbox"]') as HTMLInputElement;
    await click(box);
    await act(async () => {
      await Promise.resolve();
    });
    expect(box.checked).toBe(true);
    expect(calls.some((c) => c.url.includes("acknowledged=false") && c.url.includes("severity=critical")))
      .toBe(true);
  });

  it("loads older events with the opaque cursor", async () => {
    const { calls } = install({ secondPage: [event("e3", { summary: "older one" })] });
    await render();
    await click(Array.from(container.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("Load older events")) ?? null);
    expect(calls.some((c) => c.url.includes("cursor=CUR"))).toBe(true);
    expect(text()).toContain("older one");
    expect(container.querySelectorAll('[data-testid="event-row"]')).toHaveLength(3);
  });

  it("keeps loaded older pages when the 30 s refresh runs (merges the head page)", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { calls } = install({ secondPage: [event("e3", { summary: "older one" })] });
    await render();
    await click(Array.from(container.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("Load older events")) ?? null);
    expect(container.querySelectorAll('[data-testid="event-row"]')).toHaveLength(3);
    const before = calls.filter((c) => c.url.startsWith("/v1/events?")).length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(31_000);
    });
    expect(calls.filter((c) => c.url.startsWith("/v1/events?")).length).toBeGreaterThan(before);
    expect(container.querySelectorAll('[data-testid="event-row"]')).toHaveLength(3);
    expect(text()).toContain("older one");
    vi.useRealTimers();
  });

  it("drops a slow response from a previous filter instead of overwriting the new results", async () => {
    const pending: ((r: Response) => void)[] = [];
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      const u = new URL(url);
      const path = u.pathname.replace("/api", "");
      if (path === "/v1/events") {
        calls.push(u.search);
        const sev = u.searchParams.get("severity");
        if (sev === null && calls.length === 1) {
          // The initial (unfiltered) request stays in flight until released below.
          return new Promise<Response>((resolve) => pending.push(() =>
            resolve(json({ total: 1, events: [event("old", { summary: "STALE-ROW" })], next_cursor: null }))));
        }
        return Promise.resolve(json({ total: 1, events: [event("new", { summary: "FRESH-ROW" })], next_cursor: null }));
      }
      if (path === "/v1/health/devices") return Promise.resolve(json({ summary: { total: 0, online: 0, degraded: 0, offline: 0, unknown: 0 }, devices: [] }));
      if (path === "/v1/findings") return Promise.resolve(json({ total: 0, by_status: { open: 0, resolved: 0, suppressed: 0 }, findings: [] }));
      return Promise.resolve(json({ status: "ok" }));
    }));
    await render();
    const select = container.querySelector("select") as HTMLSelectElement;
    await act(async () => {
      select.value = "critical";
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await act(async () => { await Promise.resolve(); });
    expect(text()).toContain("FRESH-ROW");
    await act(async () => { pending.forEach((release) => release(new Response())); await Promise.resolve(); });
    expect(text()).toContain("FRESH-ROW");
    expect(text()).not.toContain("STALE-ROW");
  });

  it("shows a calm empty state", async () => {
    install({ events: [] });
    await render();
    expect(text()).toContain("No events match.");
  });
});
