import { expect, test } from "@playwright/test";
import { MockApi, makeDevice } from "./support/mockApi";

const STALE = "2020-01-01T00:00:00Z";

test("empty inventory explains how to populate it", async ({ page }) => {
  const api = new MockApi();
  await api.install(page);
  await page.goto("/inventory");
  await expect(page.getByText("No devices yet.")).toBeVisible();
  expect(api.unmocked).toEqual([]);
});

test("shows an error when the inventory cannot load", async ({ page }) => {
  const api = new MockApi({ authenticated: true });
  await api.install(page);
  await page.route(/\/api\/v1\/devices\?/, (r) => r.fulfill({ status: 500, body: "{}" }));
  await page.goto("/inventory");
  await expect(page.getByRole("alert")).toBeVisible();
});

test("filters by search, role, vendor and status", async ({ page }) => {
  const api = new MockApi();
  api.devices.push(
    makeDevice(),
    makeDevice({ id: "2", hostname: "nas-1", ip: ["192.0.2.20"], vendor: "Other", roles: ["nas"], last_seen: STALE }),
  );
  await api.install(page);
  await page.goto("/inventory");
  const list = page.getByRole("table", { name: "Devices" });
  await expect(list.getByTestId("device-row")).toHaveCount(2);

  await page.getByLabel("Search").fill("192.0.2.20");
  await expect(list.getByTestId("device-row")).toHaveCount(1);
  await expect(list).toContainText("nas-1");
  await page.getByLabel("Search").fill("");

  await page.getByLabel("Role").selectOption("switch");
  await expect(list).toContainText("core-switch");
  await expect(list).not.toContainText("nas-1");
  await page.getByLabel("Role").selectOption("");

  await page.getByLabel("Vendor").selectOption("Other");
  await expect(list).toContainText("nas-1");
  await page.getByLabel("Vendor").selectOption("");

  await page.getByLabel("Status").selectOption("stale");
  await expect(list).toContainText("nas-1");
  await expect(list).not.toContainText("core-switch");
});

test("new scan imports appear without a manual refresh", async ({ page }) => {
  const api = new MockApi();
  await api.install(page);
  await page.goto("/inventory");
  await expect(page.getByText("No devices yet.")).toBeVisible();
  api.devices.push(makeDevice({ hostname: "imported-host" }));
  await expect(page.getByRole("link", { name: "imported-host" })).toBeVisible({ timeout: 15_000 });
});

test("detail shows provenance and user edits survive polling", async ({ page }) => {
  const api = new MockApi();
  const device = makeDevice();
  api.devices.push(device);
  api.observations.set(device.id, [
    { id: "o1", source: "scan", source_ref: "job-1", observed_at: "2026-01-01T00:00:00Z" },
  ]);
  await api.install(page);
  await page.goto(`/inventory/${device.id}`);
  await expect(page.getByRole("heading", { name: "core-switch" })).toBeVisible();
  await expect(page.getByRole("list", { name: "Observations" })).toContainText("scan (job-1)");
  await expect(page.getByText("22/tcp")).toBeVisible();

  await page.getByLabel("Notes").fill("typed but unsaved");
  // A background refresh with changed server data must not clobber the draft.
  device.model = "X1";
  await expect(page.getByText("X1")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByLabel("Notes")).toHaveValue("typed but unsaved");

  await page.getByLabel("Location").fill("Rack 2");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Saved.")).toBeVisible();
  expect(api.patchBodies).toEqual([
    { notes: "typed but unsaved", location: "Rack 2", roles: ["switch"] },
  ]);
});

test("a stale poll that finishes after a save never reverts saved labels", async ({ page }) => {
  const api = new MockApi();
  const device = makeDevice();
  api.devices.push(device);
  await api.install(page);
  await page.goto(`/inventory/${device.id}`);
  await expect(page.getByRole("heading", { name: "core-switch" })).toBeVisible();

  // Hold the next poll's GET; it snapshots the pre-save (stale) device.
  const release = api.holdDevice(device.id);
  await expect.poll(() => api.heldDeviceGets, { timeout: 20_000 }).toBeGreaterThan(0);

  await page.getByLabel("Location").fill("Rack 9");
  await page.getByLabel("Notes").fill("first note");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Saved.")).toBeVisible();

  // Deliver the stale response only after the save completed.
  const stale = page.waitForResponse(
    (r) => r.request().method() === "GET" && new URL(r.url()).pathname.endsWith(`/devices/${device.id}`),
  );
  release();
  await stale;
  await page.waitForTimeout(300);

  await expect(page.getByLabel("Location")).toHaveValue("Rack 9");
  await expect(page.getByLabel("Notes")).toHaveValue("first note");
  await expect(page.getByText("Saved.")).toBeVisible();

  // A second edit must be based on the saved values, not the stale ones.
  await page.getByLabel("Notes").fill("second note");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect.poll(() => api.patchBodies.length).toBe(2);
  expect(api.patchBodies).toEqual([
    { notes: "first note", location: "Rack 9", roles: ["switch"] },
    { notes: "second note", location: "Rack 9", roles: ["switch"] },
  ]);
});

test("detail is usable on a narrow screen and hides credentials", async ({ page }) => {
  const api = new MockApi();
  const device = makeDevice({ api: { type: "rest", url: "https://192.0.2.10/api" } });
  api.devices.push(device);
  await api.install(page);
  await page.setViewportSize({ width: 360, height: 740 });
  await page.goto(`/inventory/${device.id}`);
  await expect(page.getByRole("heading", { name: "core-switch" })).toBeVisible();
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(overflow).toBe(false);
  await expect(page.locator("body")).not.toContainText(/password|community|token/i);
});

test("long unbroken identifiers do not overflow a 360px viewport", async ({ page }) => {
  const api = new MockApi();
  const long = "X".repeat(120); // synthetic; within the display policy's length limit
  const device = makeDevice({ serial: long, hostname: "H".repeat(90), mac: "aa:".repeat(40) + "aa" });
  api.devices.push(device);
  api.identities.set(device.id, [{ id: "i1", source: "serial", external_id: long }]);
  api.observations.set(device.id, [
    { id: "o1", source: "scan", source_ref: "R".repeat(120), observed_at: "2026-01-01T00:00:00Z" },
  ]);
  await api.install(page);
  await page.setViewportSize({ width: 360, height: 740 });
  await page.goto(`/inventory/${device.id}`);
  await expect(page.getByRole("list", { name: "Source identifiers" })).toContainText(long);
  await expect(page.getByRole("list", { name: "Observations" })).toContainText("R".repeat(120));
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(overflow).toBe(false);
  for (const name of ["Identity", "Sources"]) {
    const fits = await page
      .getByRole("region", { name })
      .evaluate((el) => el.scrollWidth <= el.clientWidth);
    expect(fits).toBe(true);
  }
});

test("credential canaries in identities and observation data are never rendered", async ({ page }) => {
  const api = new MockApi();
  const device = makeDevice();
  api.devices.push(device);
  const idCanary = "CANARY-IDENTITY-0001";
  const dataCanary = "CANARY-OBSERVATION-0002";
  const refCanary = "CANARY-REF-0003";
  api.identities.set(device.id, [
    { id: "i1", source: "vendor_api", external_id: idCanary },
    { id: "i2", source: "serial", external_id: "SN-12345" },
    { id: "i3", source: "serial", external_id: `has spaces ${idCanary}` },
  ]);
  api.observations.set(device.id, [
    {
      id: "o1", source: "snmp", source_ref: refCanary, observed_at: "2026-01-01T00:00:00Z",
      data: { community: dataCanary },
    } as never,
  ]);
  await api.install(page);
  await page.goto(`/inventory/${device.id}`);
  const ids = page.getByRole("list", { name: "Source identifiers" });
  await expect(ids).toContainText("SN-12345"); // ordinary hardware identifier is shown
  await expect(ids).toContainText("vendor_api"); // provenance stays useful
  await expect(page.getByRole("list", { name: "Observations" })).toContainText("snmp");
  const html = await page.content();
  const text = await page.locator("body").innerText();
  for (const canary of [idCanary, dataCanary, refCanary]) {
    expect(text).not.toContain(canary);
    expect(html).not.toContain(canary);
  }
});

test("status labels say recently seen / stale / never seen, not online", async ({ page }) => {
  const api = new MockApi();
  api.devices.push(
    makeDevice(),
    makeDevice({ id: "2", hostname: "old", last_seen: STALE }),
    makeDevice({ id: "3", hostname: "ghost", last_seen: null }),
  );
  await api.install(page);
  await page.goto("/inventory");
  const list = page.getByRole("table", { name: "Devices" });
  await expect(list).toContainText("Recently seen");
  await expect(list).toContainText("Stale");
  await expect(list).toContainText("Never seen");
  await expect(page.locator("body")).not.toContainText(/online/i);
  await page.getByLabel("Status").selectOption("recent");
  await expect(list.getByTestId("device-row")).toHaveCount(1);
  await expect(list).toContainText("core-switch");
  await page.getByLabel("Status").selectOption("never");
  await expect(list).toContainText("ghost");
});

test("full page warns that filters only cover loaded records", async ({ page }) => {
  const api = new MockApi();
  for (let n = 0; n < 500; n++) {
    api.devices.push(makeDevice({ id: `d-${n}`, hostname: `host-${n}`, ip: [] }));
  }
  await api.install(page);
  await page.goto("/inventory");
  await expect(page.getByRole("status", { name: "Truncation warning" })).toContainText(
    "apply only to these loaded records",
  );
});

/** Client-side route change that keeps the app (and router) mounted. */
async function spaNavigate(page: import("@playwright/test").Page, path: string) {
  await page.evaluate((p) => {
    window.history.pushState({}, "", p);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, path);
}

const ID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ID_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

test("switching device A to B resets state, drops late A responses and saves to B", async ({ page }) => {
  const api = new MockApi();
  api.devices.push(
    makeDevice({ id: ID_A, hostname: "device-a", notes: "notes of A" }),
    makeDevice({ id: ID_B, hostname: "device-b" }),
  );
  await api.install(page);
  await page.goto(`/inventory/${ID_A}`);
  await expect(page.getByRole("heading", { name: "device-a" })).toBeVisible();
  await page.getByLabel("Notes").fill("draft for A");
  await page.evaluate(() => ((window as unknown as { __mounted: boolean }).__mounted = true));

  // A's next refresh will be slow; switch to B while it is pending.
  const release = api.holdDevice(ID_A);
  await spaNavigate(page, `/inventory/${ID_B}`);
  await expect(page.getByRole("heading", { name: "device-b" })).toBeVisible();
  await expect(page.getByLabel("Notes")).toHaveValue("");
  release();
  await page.waitForTimeout(500);
  await expect(page.getByRole("heading", { name: "device-b" })).toBeVisible();
  await expect(page.getByText("device-a")).toHaveCount(0);

  await page.getByLabel("Notes").fill("note for B");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Saved.")).toBeVisible();
  expect(api.patchTargets).toEqual([ID_B]);

  // The page was never reloaded: the same app instance handled both routes.
  expect(await page.evaluate(() => (window as unknown as { __mounted?: boolean }).__mounted)).toBe(true);
});

test("a 404 for one device does not carry over to the next", async ({ page }) => {
  const api = new MockApi();
  api.devices.push(makeDevice({ id: ID_B, hostname: "device-b" }));
  await api.install(page);
  await page.goto(`/inventory/${ID_A}`); // unknown
  await expect(page.getByRole("alert")).toContainText("not found");
  await spaNavigate(page, `/inventory/${ID_B}`);
  await expect(page.getByRole("heading", { name: "device-b" })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("missing device shows an error", async ({ page }) => {
  const api = new MockApi();
  await api.install(page);
  await page.goto("/inventory/does-not-exist");
  await expect(page.getByRole("alert")).toContainText("not found");
});


test("table sorts addresses numerically and bulk selection prefills (not starts) a scan", async ({ page }) => {
  const api = new MockApi();
  api.devices.push(
    makeDevice({ id: "1", hostname: "c", ip: ["192.0.2.100"] }),
    makeDevice({ id: "2", hostname: "a", ip: ["192.0.2.9"] }),
    makeDevice({ id: "3", hostname: "b", ip: ["192.0.2.10"] }),
  );
  await api.install(page);
  await page.goto("/inventory");
  await page.getByRole("button", { name: /^Address/ }).click();
  await expect(page.getByTestId("device-row").locator("a")).toHaveText(["a", "b", "c"]);
  await page.getByLabel("Select all shown devices").check();
  await page.getByRole("link", { name: /Scan selected \(3\)/ }).click();
  await expect(page).toHaveURL(/\/scans\?targets=/);
  await expect(page.getByLabel(/Targets/)).toHaveValue("192.0.2.9, 192.0.2.10, 192.0.2.100");
  expect(api.calls.preflight).toBe(0);
  expect(api.calls.startJob).toBe(0);
});

test("navigation offers Login or Logout, never both", async ({ page }) => {
  const api = new MockApi();
  await api.install(page);
  await page.goto("/inventory");
  await expect(page.getByRole("link", { name: "Logout" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Login" })).toHaveCount(0);
});
