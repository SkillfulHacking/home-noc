import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Regression guard for the M02 routing bug: `location /api/ { proxy_pass
// http://backend:8000/; }` (trailing slash) strips the /api/ prefix, so
// /api/v1/devices reached the backend as /v1/devices and 404'd even though
// the backend only ever mounts routes at /api/v1/*. Parsing nginx.conf here
// catches a reintroduced trailing slash without needing a running container.

const nginxConfPath = resolve(dirname(fileURLToPath(import.meta.url)), "../nginx.conf");

function readConf(): string {
  return readFileSync(nginxConfPath, "utf-8");
}

describe("frontend/nginx.conf routing", () => {
  it("forwards /api/ to the backend without a URI component, preserving the full request path", () => {
    const conf = readConf();
    const match = conf.match(/location\s+\/api\/\s*\{([^}]*)\}/);
    expect(match, "expected a `location /api/ { ... }` block").not.toBeNull();
    const block = match![1];
    expect(block).toMatch(/proxy_pass\s+http:\/\/backend:8000;/);
    // A trailing slash/path here would strip the /api/ prefix and break
    // /api/v1/* routes.
    expect(block).not.toMatch(/proxy_pass\s+http:\/\/backend:8000\/[^;]*;/);
  });

  it("proxies /api/health and /api/version explicitly to the backend's unprefixed routes", () => {
    const conf = readConf();
    expect(conf).toMatch(/location\s+=\s+\/api\/health\s*\{[^}]*proxy_pass\s+http:\/\/backend:8000\/health;/);
    expect(conf).toMatch(/location\s+=\s+\/api\/version\s*\{[^}]*proxy_pass\s+http:\/\/backend:8000\/version;/);
  });
});
