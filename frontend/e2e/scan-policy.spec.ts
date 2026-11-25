import { expect, test } from "./support/fixtures";

test.describe("scan policy settings", () => {
  test("is reachable from the navigation and shows the effective policy", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("link", { name: "Scan policy" }).click();
    await expect(page).toHaveURL(/\/settings\/security\/scan-policy$/);
    await expect(page.getByRole("heading", { name: /Scan Policy/ })).toBeVisible();
    await expect(page.getByRole("region", { name: "Effective policy" })).toContainText(
      "Private scanning: enabled",
    );
  });

  test("saves exclusions with the CSRF header and the current revision", async ({ page, api }) => {
    await page.goto("/settings/security/scan-policy");
    await page.getByLabel(/Never scan/).fill("192.168.1.10/32");
    await expect(page.getByText("You have unsaved changes.")).toBeVisible();
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText("Saved as revision 2")).toBeVisible();
    expect(api.policyPuts[0]).toMatchObject({ expected_revision: 1, exclusions: ["192.168.1.10/32"] });
    expect(api.mutationCsrf.at(-1)).toBeTruthy();
  });

  test("public enablement needs both confirmations", async ({ page, api }) => {
    await page.goto("/settings/security/scan-policy");
    await page.getByLabel(/explicitly listed public IPv4 ranges/).check();
    await page.getByLabel(/Public allowlist/).fill("8.8.8.0/24");
    await page.getByRole("button", { name: "Save changes" }).click();
    const confirm = page.getByRole("button", { name: "Confirm and save" });
    await expect(confirm).toBeDisabled();
    await page.getByLabel(/understand and want to broaden/).check();
    await expect(confirm).toBeDisabled();
    await page.getByLabel(/own these public addresses/).check();
    await confirm.click();
    await expect(page.getByText("Saved as revision 2")).toBeVisible();
    expect(api.policyPuts[1]).toMatchObject({ confirm_broadening: true, confirm_public: true });
  });

  test("a stale revision is reported and nothing is applied", async ({ page, api }) => {
    await page.goto("/settings/security/scan-policy");
    api.policy.revision = 7; // someone else saved meanwhile
    await page.getByLabel(/Never scan/).fill("10.1.1.1/32");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText(/now revision 7/)).toBeVisible();
    expect(api.policy.exclusions).toEqual([]);
  });

  test("shows server-side validation errors", async ({ page }) => {
    await page.goto("/settings/security/scan-policy");
    await page.getByLabel(/Strict private allowlist/).fill("8.8.8.0/24");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText("Entry is not RFC1918")).toBeVisible();
  });

  test.describe("non-administrator", () => {
    test("sees an access-denied message and no editor", async ({ page, api }) => {
      api.policyDenied = true;
      await page.goto("/settings/security/scan-policy");
      await expect(page.getByText(/Administrator access is required/)).toBeVisible();
      await expect(page.getByRole("form", { name: "Scan policy" })).toHaveCount(0);
    });
  });
});
