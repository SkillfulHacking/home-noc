import { test as base, expect } from "@playwright/test";
import { MockApi, type MockOptions } from "./mockApi";

interface Fixtures {
  /** Override per describe block with `test.use({ mockOptions: {...} })`. */
  mockOptions: MockOptions;
  api: MockApi;
}

export const test = base.extend<Fixtures>({
  mockOptions: [{}, { option: true }],
  api: async ({ page, mockOptions }, use) => {
    const api = new MockApi(mockOptions);
    await api.install(page);
    await use(api);
    // Safety net: a test must never have tried to leave the loopback origin.
    expect(api.blockedExternal, "requests to non-loopback origins").toEqual([]);
  },
});

export { expect };
