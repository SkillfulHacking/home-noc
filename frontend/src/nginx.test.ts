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

  it("sets browser hardening headers for every response and bounds request bodies", () => {
    const conf = readConf();
    const header = (name: string) => conf.match(new RegExp(`add_header\\s+${name}\\s+"([^"]*)"\\s+always;`))?.[1];
    const csp = header("Content-Security-Policy");
    expect(csp, "CSP header").toBeDefined();
    for (const directive of ["default-src 'self'", "script-src 'self'", "connect-src 'self'",
      "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'"]) {
      expect(csp).toContain(directive);
    }
    expect(csp).not.toMatch(/script-src[^;]*'unsafe-(inline|eval)'/);
    expect(csp).not.toContain("*");
    expect(header("X-Content-Type-Options")).toBe("nosniff");
    expect(header("X-Frame-Options")).toBe("DENY");
    expect(header("Referrer-Policy")).toBe("no-referrer");
    expect(conf).toMatch(/server_tokens\s+off;/);
    expect(conf).toMatch(/client_max_body_size\s+\d+[kKmM];/);
  });

  it("does not let a location override the server-level headers", () => {
    // nginx drops inherited add_header directives when a location defines its own.
    const locations = conf_locations();
    for (const block of locations) expect(block).not.toMatch(/add_header/);
  });
});

function conf_locations(): string[] {
  return [...readConf().matchAll(/location[^{]*\{([^}]*)\}/g)].map((m) => m[1]);
}
