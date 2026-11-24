import { randomUUID } from "node:crypto";
import { ALLOWED_CIDR } from "./support/mockApi";
import { expect, test } from "./support/fixtures";

test.describe("unauthenticated visitor", () => {
  test.use({ mockOptions: { authenticated: false } });

  test("is redirected to login and no scan API is queried", async ({ page, api }) => {
    await page.goto("/scans");
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Scans" })).toHaveCount(0);
    expect(api.calls.scope).toBe(0);
    expect(api.calls.jobList).toBe(0);
  });
});

test.describe("authenticated operator", () => {
  test.use({ mockOptions: { authenticated: false } });

  test("signs in and reaches /scans through the navigation", async ({ page, api }) => {
    await page.goto("/login");
    await page.getByLabel("Username").fill("operator");
    // A throwaway value: the mocked login accepts any non-empty password.
    await page.getByLabel("Password").fill(randomUUID());
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(/\/$/);

    await page.getByRole("link", { name: "Scans" }).click();
    await expect(page).toHaveURL(/\/scans$/);
    await expect(page.getByRole("heading", { name: "Scans", level: 1 })).toBeVisible();
    expect(api.authenticated).toBe(true);
  });
});

test.describe("scans page with an authorized session", () => {
  test("shows the ownership notice, scope and only gentle modes", async ({ page, api }) => {
    await page.goto("/scans");
    await expect(page.getByRole("heading", { name: "Scans", level: 1 })).toBeVisible();
    await expect(page.getByRole("note")).toContainText("Only scan networks you own");

    const scope = page.getByRole("region", { name: "Authorized scope" });
    await expect(scope.getByRole("listitem")).toHaveText([ALLOWED_CIDR]);

    // The mocked scope advertises an intrusive profile; the UI must not offer it.
    await expect(page.getByRole("radio")).toHaveCount(2);
    await expect(page.getByRole("radio", { name: /ICMP host discovery/ })).toBeChecked();
    await expect(page.getByRole("radio", { name: /TCP connect scan/ })).not.toBeChecked();
    await expect(page.getByRole("radio", { name: /security/i })).toHaveCount(0);
    expect(api.unmocked).toEqual([]);
  });
});

test.describe("authorization scope cannot load", () => {
  test.use({ mockOptions: { scopeFails: true } });

  test("fails closed: error shown, no modes, no preflight possible", async ({ page, api }) => {
    await page.goto("/scans");
    await expect(page.getByRole("alert")).toContainText("Scan scope is temporarily unavailable.");
    await expect(page.getByRole("region", { name: "Authorized scope" })).toHaveCount(0);
    await expect(page.getByRole("radio")).toHaveCount(0);

    const preview = page.getByRole("button", { name: /Preview targets/ });
    await expect(preview).toBeDisabled();

    // Neither the button nor implicit form submission (Enter) may reach preflight.
    const targets = page.getByLabel(/^Targets/);
    await targets.fill("192.0.2.0/30");
    await targets.press("Enter");
    await expect(page.getByRole("region", { name: "Preflight preview" })).toHaveCount(0);
    expect(api.calls.preflight).toBe(0);
    expect(api.calls.startJob).toBe(0);
  });
});
