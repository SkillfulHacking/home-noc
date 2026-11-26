import { act } from "react";
import { createRoot, Root } from "react-dom/client";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import InventoryPage from "./Inventory";
import ScansPage from "./Scans";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const dev = (id: string, hostname: string, ip: string[], over: Record<string, unknown> = {}) => ({
  id, hostname, ip, mac: null, first_seen: null, last_seen: "2026-01-01T12:00:00Z",
  discovery_method: "scan", vendor: null, model: null, os: null, serial: null, location: null,
  roles: [], ports: [], snmp: null, api: null, notes: null, ...over,
});

const DEVICES = [
  dev("a", "alpha", ["10.0.0.100"]),
  dev("b", "bravo", ["10.0.0.9"]),
  dev("c", "charlie", ["10.0.0.10"], { vendor: "Acme" }),
  dev("d", "delta", []),
];

let root: Root;
let container: HTMLDivElement;
function LocationProbe() {
  const loc = useLocation();
  return <output data-testid="loc">{loc.pathname + loc.search}</output>;
}
async function render(initial = "/inventory") {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    const path = new URL(url).pathname.replace("/api", "");
    if (path === "/v1/devices") return json(DEVICES);
    if (path === "/v1/scans/scope") return json({ allowed_cidrs: [], allow_public: false, profiles: [] });
    if (path === "/v1/scans/jobs") return json({ items: [] });
    return json({ detail: "nope" }, 404);
  }));
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root.render(
      <MemoryRouter initialEntries={[initial]}>
        <LocationProbe />
        <Routes>
          <Route path="/inventory" element={<InventoryPage />} />
          <Route path="/scans" element={<ScansPage />} />
        </Routes>
      </MemoryRouter>
    );
  });
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
}
afterEach(() => {
  if (root) act(() => root.unmount());
  container?.remove();
  vi.unstubAllGlobals();
});
const names = () =>
  Array.from(container.querySelectorAll('[data-testid="device-row"] a')).map((a) => a.textContent);
const click = async (el: Element | null | undefined) => {
  expect(el).toBeTruthy();
  await act(async () => { (el as HTMLElement).click(); });
};
const header = (label: string) =>
  Array.from(container.querySelectorAll("th button")).find((b) => b.textContent?.startsWith(label));

describe("Inventory table", () => {
  it("is a dense table by default, sorted by name", async () => {
    await render();
    expect(container.querySelector("table")).not.toBeNull();
    expect(names()).toEqual(["alpha", "bravo", "charlie", "delta"]);
  });

  it("sorts addresses numerically in both directions with address-less devices last", async () => {
    await render();
    await click(header("Address"));
    expect(names()).toEqual(["bravo", "charlie", "alpha", "delta"]);
    expect(container.querySelector('th[aria-sort="ascending"]')?.textContent).toContain("Address");
    await click(header("Address"));
    expect(names()).toEqual(["alpha", "charlie", "bravo", "delta"]);
  });

  it("shows each device's addresses once and local time with the UTC instant in a tooltip", async () => {
    await render();
    const row = container.querySelector('[data-testid="device-row"]') as HTMLElement;
    expect((row.textContent?.match(/10\.0\.0\.100/g) ?? []).length).toBe(1);
    expect(container.querySelector('[title="2026-01-01T12:00:00.000Z"]')).not.toBeNull();
  });

  it("switches to cards and keeps the selection", async () => {
    await render();
    await click(container.querySelector('input[aria-label="Select bravo"]'));
    await click(Array.from(container.querySelectorAll("button")).find((b) => b.textContent === "Cards"));
    expect(container.querySelector("table")).toBeNull();
    expect(container.querySelector('ul[aria-label="Devices"]')).not.toBeNull();
    expect((container.querySelector('input[aria-label="Select bravo"]') as HTMLInputElement).checked).toBe(true);
  });

  it("bulk selection hands de-duplicated addresses to the Scans page as a prefill only", async () => {
    await render();
    await click(container.querySelector('input[aria-label="Select all shown devices"]'));
    expect(container.textContent).toContain("4 selected");
    const link = Array.from(container.querySelectorAll("a")).find((a) => a.textContent?.startsWith("Scan selected"));
    expect(link?.textContent).toBe("Scan selected (3)");
    expect(link?.getAttribute("href")).toBe("/scans?targets=10.0.0.100%2C10.0.0.9%2C10.0.0.10");
    await click(link);
    expect(container.querySelector('[data-testid="loc"]')?.textContent).toContain("/scans?targets=");
    const input = container.querySelector('form[aria-label="New scan"] input') as HTMLInputElement;
    expect(input.value).toBe("10.0.0.100, 10.0.0.9, 10.0.0.10");
    // Nothing was started: only scope/history reads, no preview or job creation.
    const calls = (fetch as unknown as { mock: { calls: [string, RequestInit?][] } }).mock.calls;
    expect(calls.filter(([, init]) => init?.method === "POST")).toHaveLength(0);
  });

  it("explains when selected devices have nothing scannable", async () => {
    await render();
    await click(container.querySelector('input[aria-label="Select delta"]'));
    expect(container.textContent).toContain("no IPv4 address to scan");
  });

  it("filters scan prefill to address-like tokens", async () => {
    await render("/scans?targets=10.0.0.1%2C%3Cscript%3E%2C192.168.0.0%2F24");
    const input = container.querySelector('form[aria-label="New scan"] input') as HTMLInputElement;
    expect(input.value).toBe("10.0.0.1, 192.168.0.0/24");
  });
});
