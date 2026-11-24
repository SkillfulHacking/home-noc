import type { Page } from "@playwright/test";
import { CSRF_TOKEN } from "./support/mockApi";
import type { MockApi } from "./support/mockApi";
import { expect, test } from "./support/fixtures";

const TARGET = "192.168.50.0/30"; // 4 addresses, 2 usable hosts, inside the allowed /24

async function openScans(page: Page) {
  await page.goto("/scans");
  await expect(page.getByRole("radio", { name: /ICMP host discovery/ })).toBeChecked();
}

async function preview(page: Page, targets = TARGET) {
  await page.getByLabel(/^Targets/).fill(targets);
  await page.getByRole("button", { name: /Preview targets/ }).click();
}

async function previewConfirmAndStart(page: Page) {
  await preview(page);
  await expect(page.getByRole("region", { name: "Preflight preview" })).toBeVisible();
  await page.getByRole("checkbox", { name: /I own these networks/ }).check();
  await page.getByRole("button", { name: "Start scan" }).click();
  await expect(page.getByRole("region", { name: "Current scan" })).toBeVisible();
}

function running(api: MockApi, done: number) {
  api.update(api.latestJob().id, {
    status: "running",
    started_at: "2026-01-01T00:00:01Z",
    progress: { done, total: 4, percent: (done / 4) * 100 },
  });
}

test.describe("preflight and ownership confirmation", () => {
  test("an out-of-scope target is refused and cannot be started", async ({ page, api }) => {
    await openScans(page);
    await preview(page, "8.8.8.8");

    await expect(page.getByRole("alert")).toContainText("outside the authorized scan scope");
    await expect(page.getByRole("region", { name: "Preflight preview" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Start scan" })).toHaveCount(0);
    expect(api.calls.startJob).toBe(0);
  });

  test("start stays disabled until ownership is confirmed, and edits revoke consent", async ({ page, api }) => {
    await openScans(page);
    await preview(page);

    const review = page.getByRole("region", { name: "Preflight preview" });
    await expect(review.getByRole("status")).toContainText("2 host(s) in 192.168.50.0/30");
    expect(api.preflightBodies).toEqual([{ targets: [TARGET], profile: "discovery" }]);

    const start = page.getByRole("button", { name: "Start scan" });
    const consent = page.getByRole("checkbox", { name: /I own these networks/ });
    await expect(start).toBeDisabled();
    await consent.check();
    await expect(start).toBeEnabled();

    // Editing the targets discards the approved preview and the consent.
    await page.getByLabel(/^Targets/).fill("192.168.50.0/29");
    await expect(review).toHaveCount(0);

    // A fresh preview starts unchecked again.
    await page.getByRole("button", { name: /Preview targets/ }).click();
    await expect(page.getByRole("checkbox", { name: /I own these networks/ })).not.toBeChecked();
    await expect(page.getByRole("button", { name: "Start scan" })).toBeDisabled();
    expect(api.calls.startJob).toBe(0);
  });
});

test.describe("scan lifecycle", () => {
  test("shows progress and events, then reconciliation counts on success", async ({ page, api }) => {
    await openScans(page);
    await previewConfirmAndStart(page);

    // Exactly the approved snapshot was submitted, with the CSRF header.
    expect(api.calls.startJob).toBe(1);
    expect(api.startBodies).toEqual([{ targets: [TARGET], profile: "discovery" }]);
    expect(api.mutationCsrf.every((token) => token === CSRF_TOKEN)).toBe(true);

    const current = page.getByRole("region", { name: "Current scan" });
    const id = api.latestJob().id;
    running(api, 2);
    api.addEvent(id, "info", "Probing 192.168.50.0/30");

    await expect(current.getByRole("status")).toContainText("running");
    await expect(current).toContainText("2 / 4 addresses (50%)");
    await expect(current.getByRole("progressbar", { name: "Scan progress" })).toHaveJSProperty("value", 50);
    await expect(current.getByRole("list", { name: "Scan events" })).toContainText("Probing 192.168.50.0/30");
    await expect(current.getByRole("button", { name: "Cancel scan" })).toBeVisible();
    await expect(current.getByRole("region", { name: "Scan result summary" })).toHaveCount(0);

    api.addEvent(id, "info", "Scan finished");
    api.update(id, {
      status: "succeeded",
      finished_at: "2026-01-01T00:00:09Z",
      progress: { done: 4, total: 4, percent: 100 },
      result: {
        hosts_up: 3,
        asset_reconciliation: { created: 2, merged: 1, ambiguous: 0, invalid: 0 },
      },
    });

    const summary = current.getByRole("region", { name: "Scan result summary" });
    await expect(summary).toContainText("Responsive hosts: 3");
    await expect(summary).toContainText(/Inventory reconciliation: 2 created, 1\s+merged, 0 ambiguous, 0 invalid\./);
    await expect(current.getByRole("list", { name: "Scan events" }).getByRole("listitem")).toHaveCount(2);
    await expect(current.getByRole("button", { name: "Cancel scan" })).toHaveCount(0);
    await expect(
      page.getByRole("region", { name: "Scan history" }).getByRole("row", { name: /succeeded/ }),
    ).toHaveCount(1);
  });

  test("cancellation is requested, then the cancelled state is terminal", async ({ page, api }) => {
    await openScans(page);
    await previewConfirmAndStart(page);
    const id = api.latestJob().id;
    running(api, 1);

    const current = page.getByRole("region", { name: "Current scan" });
    await expect(current.getByRole("status")).toContainText("running");
    await current.getByRole("button", { name: "Cancel scan" }).click();

    expect(api.calls.cancel).toBe(1);
    await expect(current.getByRole("status")).toContainText("cancelling");
    await expect(current.getByRole("button", { name: "Cancelling…" })).toBeDisabled();

    api.update(id, { status: "cancelled", finished_at: "2026-01-01T00:00:05Z" });
    await expect(current.getByRole("status")).toContainText("cancelled");
    await expect(current.getByRole("status")).not.toContainText("cancellation requested");
    await expect(current.getByRole("button", { name: /Cancel/ })).toHaveCount(0);
    await expect(current.getByRole("region", { name: "Scan result summary" })).toHaveCount(0);
    await expect(current.getByRole("list", { name: "Scan events" })).toContainText("Cancellation requested");
    await expect(
      page.getByRole("region", { name: "Scan history" }).getByRole("row", { name: /cancelled/ }),
    ).toHaveCount(1);
  });

  test("a failed scan shows its error, offers no cancel and no results", async ({ page, api }) => {
    await openScans(page);
    await previewConfirmAndStart(page);
    const id = api.latestJob().id;
    running(api, 1);
    api.update(id, {
      status: "failed",
      finished_at: "2026-01-01T00:00:04Z",
      error_code: "scan_failed",
      error_message: "The scan failed before completing.",
    });

    const current = page.getByRole("region", { name: "Current scan" });
    await expect(current.getByRole("status")).toContainText("failed");
    await expect(current.getByRole("alert")).toContainText("The scan failed before completing.");
    await expect(current.getByRole("button", { name: /Cancel/ })).toHaveCount(0);
    await expect(current.getByRole("region", { name: "Scan result summary" })).toHaveCount(0);
  });

  test("a double click submits exactly one job", async ({ page, api }) => {
    await openScans(page);
    await preview(page);
    await page.getByRole("checkbox", { name: /I own these networks/ }).check();

    // Two synchronous clicks, before React can re-render the disabled state.
    await page.getByRole("button", { name: "Start scan" }).evaluate((el) => {
      (el as HTMLButtonElement).click();
      (el as HTMLButtonElement).click();
    });
    await expect(page.getByRole("region", { name: "Current scan" })).toBeVisible();
    expect(api.calls.startJob).toBe(1);
    expect(api.jobs).toHaveLength(1);
  });
});

test.describe("refresh recovery", () => {
  test("reloading resumes the active job without submitting another", async ({ page, api }) => {
    await openScans(page);
    await previewConfirmAndStart(page);
    const id = api.latestJob().id;
    running(api, 2);
    api.addEvent(id, "info", "Probing 192.168.50.0/30");
    api.addEvent(id, "info", "2 of 4 addresses checked");

    const current = page.getByRole("region", { name: "Current scan" });
    await expect(current).toContainText("2 / 4 addresses (50%)");
    expect(api.calls.startJob).toBe(1);

    await page.reload();

    // State comes back from the API: same job, events replayed exactly once.
    await expect(current.getByRole("status")).toContainText("running");
    await expect(current).toContainText("2 / 4 addresses (50%)");
    await expect(current.getByRole("list", { name: "Scan events" }).getByRole("listitem")).toHaveCount(2);
    await expect(current.getByRole("button", { name: "Cancel scan" })).toBeVisible();

    // The approved preview does not survive a reload, so nothing can resubmit.
    await expect(page.getByRole("button", { name: "Start scan" })).toHaveCount(0);
    expect(api.calls.startJob).toBe(1);
    expect(api.jobs).toHaveLength(1);

    // The resumed watcher still reaches the terminal state.
    api.update(id, {
      status: "succeeded",
      finished_at: "2026-01-01T00:00:09Z",
      progress: { done: 4, total: 4, percent: 100 },
      result: { hosts_up: 4, asset_reconciliation: { created: 4, merged: 0, ambiguous: 0, invalid: 0 } },
    });
    await expect(current.getByRole("region", { name: "Scan result summary" })).toContainText(
      /4 created, 0\s+merged, 0 ambiguous, 0 invalid/,
    );
    expect(api.calls.startJob).toBe(1);
    expect(api.unmocked).toEqual([]);
  });
});
