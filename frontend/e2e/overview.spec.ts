import { expect, test } from "./support/fixtures";

const row = (id: string, hostname: string, status: string, reason: string) => ({
  device_id: id, hostname, status, reason, last_success_at: null, last_attempt_at: null,
  status_changed_at: "2026-01-01T10:00:00Z", last_seen: null,
});
const ev = (id: string, severity: string, summary: string) => ({
  id, at: "2026-01-01T10:00:00Z", last_at: "2026-01-01T10:00:00Z", type: "device_offline", severity,
  device_id: "d1", hostname: "core-sw", summary, count: 1, acknowledged_at: null,
});

test.describe("operations overview", () => {
  test("distinguishes online, degraded, offline and unknown and lists what needs attention",
    async ({ page, api }) => {
      api.opsHealth = [
        row("d1", "core-sw", "offline", "no fresh observation; snmp failed repeatedly"),
        row("d2", "ap-1", "degraded", "icmp failing; snmp still responding"),
        row("d3", "nas", "online", "fresh snmp observation"),
        row("d4", "printer", "unknown", "never observed successfully"),
      ];
      api.opsEvents = [ev("e1", "critical", "Device is offline")];
      api.findings = [{ id: "f1", status: "open" }, { id: "f2", status: "open" }];
      await page.goto("/");
      await expect(page.getByRole("heading", { name: "Operations overview" })).toBeVisible();
      for (const status of ["online", "degraded", "offline", "unknown"]) {
        await expect(page.getByTestId(`health-${status}`)).toContainText("1");
      }
      await expect(page.getByText("Needs attention")).toBeVisible();
      await expect(page.getByText("snmp failed repeatedly")).toBeVisible();
      await expect(page.getByTestId("open-findings")).toHaveText("2");
      await expect(page.getByTestId("event-row")).toHaveCount(1);
    });

  test("acknowledging an event sends a CSRF-protected request and updates the row",
    async ({ page, api }) => {
      api.opsEvents = [ev("e1", "critical", "Device is offline")];
      await page.goto("/");
      await page.getByRole("button", { name: /Acknowledge Device offline/ }).click();
      await expect(page.getByText("acknowledged", { exact: true })).toBeVisible();
      expect(api.acked).toEqual(["e1"]);
      expect(api.mutationCsrf.at(-1)).toBeTruthy();
    });

  test("severity filter narrows the timeline", async ({ page, api }) => {
    api.opsEvents = [ev("e1", "critical", "Device is offline"), ev("e2", "info", "Device recovered")];
    await page.goto("/");
    await expect(page.getByTestId("event-row")).toHaveCount(2);
    await page.getByLabel("Severity").selectOption("critical");
    await expect(page.getByTestId("event-row")).toHaveCount(1);
  });

  test("an empty network shows calm empty states, not errors", async ({ page, api }) => {
    expect(api.opsHealth).toEqual([]);
    await page.goto("/");
    await expect(page.getByText("No events match.")).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
  });
});
