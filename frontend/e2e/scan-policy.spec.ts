import { expect, test } from "./support/fixtures";

const PAGE = "/settings/security/scan-policy";

// Every test requests the lazy `api` fixture: it installs the mocked session and
// policy routes and, at teardown, asserts nothing tried to leave the loopback origin.

test.describe("scan policy settings (administrator)", () => {
  test("is reachable from the navigation and shows the effective policy", async ({ page, api }) => {
    await page.goto("/");
    await page.getByRole("link", { name: "Scan policy" }).click();
    await expect(page).toHaveURL(/\/settings\/security\/scan-policy$/);
    await expect(page.getByRole("heading", { name: /Scan Policy/ })).toBeVisible();
    await expect(page.getByRole("region", { name: "Effective policy" })).toContainText(
      "Private scanning: enabled",
    );
    expect(api.policyGets).toBeGreaterThan(0);
    expect(api.policyPuts).toHaveLength(0);
  });

  test("saves exclusions with the CSRF header and the current revision", async ({ page, api }) => {
    await page.goto(PAGE);
    await expect(page.getByText(/^Revision 1,/)).toBeVisible();
    await page.getByLabel(/Never scan/).fill("192.168.1.10/32");
    await expect(page.getByText("You have unsaved changes.")).toBeVisible();
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText("Saved as revision 2")).toBeVisible();
    expect(api.policyPuts).toHaveLength(1);
    expect(api.policyPuts[0]).toMatchObject({
      expected_revision: 1,
      exclusions: ["192.168.1.10/32"],
      private_strict: false,
    });
    expect(api.mutationCsrf.at(-1)).toBeTruthy();
    expect(api.policy.exclusions).toEqual(["192.168.1.10/32"]);
  });

  test("public enablement needs both confirmations", async ({ page, api }) => {
    await page.goto(PAGE);
    await expect(page.getByText(/^Revision 1,/)).toBeVisible();
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
    expect(api.policyPuts).toHaveLength(2);
    expect(api.policyPuts[0]).toMatchObject({ confirm_broadening: false, confirm_public: false });
    expect(api.policyPuts[1]).toMatchObject({ confirm_broadening: true, confirm_public: true });
    expect(api.policy.public.enabled).toBe(true);
  });

  test("a stale revision is reported with the current revision and nothing is applied", async ({
    page,
    api,
  }) => {
    await page.goto(PAGE);
    // Wait for the editor at revision 1 *before* another administrator "saves".
    await expect(page.getByText(/^Revision 1,/)).toBeVisible();
    await expect(page.getByRole("form", { name: "Scan policy" })).toBeVisible();
    api.policy.revision = 7;
    await page.getByLabel(/Never scan/).fill("10.1.1.1/32");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText(/now revision 7/)).toBeVisible();
    await expect(page.getByText(/Your edits were not applied/)).toBeVisible();
    expect(api.policyPuts[0]).toMatchObject({ expected_revision: 1 });
    expect(api.policy.exclusions).toEqual([]);
    expect(api.policy.revision).toBe(7);
  });

  test("shows server-side validation errors without applying anything", async ({ page, api }) => {
    await page.goto(PAGE);
    await expect(page.getByText(/^Revision 1,/)).toBeVisible();
    await page.getByLabel(/Strict mode/).check();
    await page.getByLabel(/Strict private allowlist/).fill("8.8.8.0/24");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText("Entry is not RFC1918")).toBeVisible();
    expect(api.policyPuts).toHaveLength(1);
    expect(api.policyPuts[0]).toMatchObject({
      private_strict: true,
      private_allowlist: ["8.8.8.0/24"],
    });
    expect(api.policy.revision).toBe(1);
  });
});

test.describe("scan policy settings (not the administrator)", () => {
  test("sees an access-denied message and no editor", async ({ page, api }) => {
    api.policyDenied = true;
    await page.goto(PAGE);
    await expect(page.getByText(/Administrator access is required/)).toBeVisible();
    await expect(page.getByRole("form", { name: "Scan policy" })).toHaveCount(0);
    expect(api.policyPuts).toHaveLength(0);
  });
});

test.describe("anonymous visitor", () => {
  test.use({ mockOptions: { authenticated: false } });

  test("is sent to login, sees no scan-policy link and triggers no policy request", async ({
    page,
    api,
  }) => {
    await page.goto(PAGE);
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.getByRole("link", { name: "Scan policy" })).toHaveCount(0);
    expect(api.policyGets).toBe(0);
  });
});
