import { defineConfig, devices } from "@playwright/test";
import { E2E_ORIGIN } from "./e2e/support/constants";

// Browser tests run the production build against a deterministic, intercepted
// API (see e2e/support/mockApi.ts). No backend is started and no network
// traffic leaves the loopback interface, so nothing real is ever scanned.
export default defineConfig({
  testDir: "./e2e",
  testMatch: "**/*.spec.ts",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: E2E_ORIGIN,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    // Build first so the test always exercises the current production bundle.
    command: `npm run build && npm run preview:e2e`,
    url: E2E_ORIGIN,
    // Never adopt whatever happens to be listening on the fixed port.
    reuseExistingServer: false,
    timeout: 180_000,
  },
});
