import { expect, test } from "./support/fixtures";

const finding = (id: string, severity: string, name: string, status = "open") => ({
  id, device_id: "11111111-1111-4111-8111-111111111111", template_id: "tpl", name, severity, status,
  host: "192.0.2.10", port: 80, scheme: "http", path: "/", matcher_name: null,
  first_seen: "2026-01-01T00:00:00Z", last_seen: "2026-01-02T00:00:00Z", resolved_at: null,
  suppressed_reason: null, occurrences: 2, template_version: "10.5.2", scanner_version: "3.11.1",
  details: { description: "Explains the problem", tags: [], cve: [], cwe: [], evidence: [] },
});

test.describe("findings", () => {
  test("filters by severity and suppresses with a reason", async ({ page, api }) => {
    api.findings = [finding("f1", "medium", "Missing headers"), finding("f2", "critical", "Exposed config")];
    await page.goto("/findings");
    await expect(page.getByTestId("finding-row")).toHaveCount(2);
    await page.getByLabel("Severity").selectOption("critical");
    await expect(page.getByTestId("finding-row")).toHaveCount(1);
    await expect(page.getByText("Exposed config")).toBeVisible();
    await page.getByRole("button", { name: "Details" }).click();
    await expect(page.getByTestId("finding-detail")).toContainText("Explains the problem");
    await page.getByPlaceholder(/Reason/).fill("accepted: lab only");
    await page.getByRole("button", { name: "Suppress", exact: true }).click();
    // It leaves the default "open" view; it is findable under "suppressed" with its reason.
    await expect(page.getByTestId("finding-row")).toHaveCount(0);
    await page.getByLabel("Status").selectOption("suppressed");
    // The row was expanded before; its details stay open when it reappears.
    await expect(page.getByTestId("finding-detail")).toContainText("Suppressed: accepted: lab only");
    expect(api.mutationCsrf.at(-1)).toBeTruthy();
  });

  test("a vulnerability scan needs a reviewed plan and an explicit approval", async ({ page, api }) => {
    await page.goto("/findings");
    await page.getByLabel("Targets (addresses or CIDRs)").fill("192.0.2.0/28");
    await page.getByRole("button", { name: "Review plan" }).click();
    await expect(page.getByTestId("vuln-plan")).toContainText("http://192.0.2.10:80");
    const start = page.getByRole("button", { name: "Start vulnerability scan" });
    await expect(start).toBeDisabled();
    expect(api.vulnStarts).toHaveLength(0);
    await page.getByLabel(/I approve scanning exactly/).check();
    await start.click();
    await expect(page.getByText("Vulnerability scan queued.")).toBeVisible();
    expect(api.vulnStarts).toEqual([{ targets: ["192.0.2.0/28"], profile: "vuln", approval_digest: "b".repeat(64) }]);
  });

  test("no known HTTP services means no start button", async ({ page, api }) => {
    api.vulnPlanUrls = [];
    await page.goto("/findings");
    await page.getByLabel("Targets (addresses or CIDRs)").fill("192.0.2.0/28");
    await page.getByRole("button", { name: "Review plan" }).click();
    await expect(page.getByText(/nothing would be scanned/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Start vulnerability scan" })).toHaveCount(0);
  });
});
