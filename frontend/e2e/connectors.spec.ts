import { randomUUID } from "node:crypto";
import { makeDevice } from "./support/mockApi";
import { expect, test } from "./support/fixtures";

test.describe("connector setup", () => {
  test("UniFi token field stays masked and the token is never rendered back", async ({ page, api }) => {
    const token = `tok-${randomUUID()}`;
    await page.goto("/connectors");
    await expect(page.getByRole("heading", { name: "Connectors", level: 1 })).toBeVisible();
    const field = page.getByLabel("API token (write-only)");
    await expect(field).toHaveAttribute("type", "password");
    await page.getByLabel("Controller address").fill("https://192.0.2.1");
    await field.fill(token);
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByTestId("unifi-status")).toContainText("configured");
    await expect(field).toHaveValue("");
    expect(await page.content()).not.toContain(token);
    expect(api.secretBodies).toHaveLength(1);
    expect(JSON.stringify(api.secretBodies[0].body)).toContain(token); // sent once, in the body
    expect(api.mutationCsrf.every(Boolean)).toBe(true);
    const unifi = page.getByRole("region", { name: "UniFi Network controller" });
    await unifi.getByRole("button", { name: "Test connection" }).click();
    await expect(page.getByRole("status").filter({ hasText: "application_version: 9.1.0" })).toBeVisible();
  });

  test("SNMPv3 authPriv credentials: both passphrases masked, cleared after save, not echoed",
    async ({ page, api }) => {
      api.devices.push(makeDevice());
      const auth = `auth-${randomUUID()}`;
      const priv = `priv-${randomUUID()}`;
      await page.goto("/connectors");
      await page.getByLabel(/^Device/).selectOption({ index: 1 });
      await expect(page.getByTestId("snmp-status")).toContainText("not configured");
      await expect(page.getByLabel("Authentication passphrase")).toHaveAttribute("type", "password");
      await expect(page.getByLabel("Privacy passphrase")).toHaveAttribute("type", "password");
      await page.getByLabel("Username").fill("monitor");
      await page.getByLabel("Authentication passphrase").fill(auth);
      await page.getByLabel("Privacy passphrase").fill(priv);
      await page.getByRole("button", { name: "Save credentials" }).click();
      await expect(page.getByTestId("snmp-status")).toContainText("configured");
      await expect(page.getByLabel("Authentication passphrase")).toHaveValue("");
      await expect(page.getByLabel("Privacy passphrase")).toHaveValue("");
      const html = await page.content();
      expect(html).not.toContain(auth);
      expect(html).not.toContain(priv);
      expect(api.secretBodies.map((b) => b.path.split("/").pop())).toEqual(["snmpv3_auth", "snmpv3_priv"]);
    });

  test("a hostname controller address is rejected before any request", async ({ page, api }) => {
    await page.goto("/connectors");
    await page.getByLabel("Controller address").fill("https://unifi.local");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("hostnames are not accepted");
    expect(api.secretBodies).toHaveLength(0);
  });
});
