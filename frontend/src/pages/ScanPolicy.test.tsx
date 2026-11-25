import { act } from "react";
import { createRoot, Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ScanPolicyPage from "./ScanPolicy";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function policy(over: Record<string, unknown> = {}) {
  return {
    revision: 1,
    updated_at: "2026-01-01T00:00:00Z",
    updated_by: "migration",
    bootstrap_origin: "fresh",
    private: {
      enabled: true,
      allowlist: [],
      rfc1918: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    },
    public: { enabled: false, allowlist: [], min_prefix: 16 },
    exclusions: [],
    effective: {
      private_networks: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
      special_use_networks: [],
      public_networks: [],
      excluded: [],
      private_scanning: true,
      public_scanning: false,
    },
    deployment: {
      scope_restricted: false,
      allowed_cidrs: [],
      public_blocked: false,
      security_profile_enabled: false,
    },
    limits: {
      max_target_entries: 64,
      max_policy_entries: 64,
      max_exclusions: 256,
      min_public_prefix: 16,
      max_active_jobs: 5,
      profiles: [{ name: "discovery", intrusive: false, max_hosts: 1024, timeout_seconds: 300, max_concurrency: 16 }],
    },
    worker_vantage: "Scans run from the worker container's network position.",
    ...over,
  };
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

type Handler = (body: Record<string, unknown>) => Response;

function backend(get: () => Response, put?: Handler) {
  const puts: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit = {}) => {
      const path = new URL(url).pathname.replace("/api", "");
      if (path !== "/v1/scan-policy") return json({ detail: "nf" }, 404);
      if ((init.method ?? "GET") === "PUT") {
        const body = JSON.parse(String(init.body));
        puts.push(body);
        return put ? put(body) : json(policy());
      }
      return get();
    })
  );
  return puts;
}

let container: HTMLDivElement;
let root: Root;

async function settle() {
  await act(async () => {
    for (let i = 0; i < 10; i += 1) await Promise.resolve();
    await new Promise((r) => setTimeout(r, 0));
  });
}

async function mount() {
  await act(async () => {
    root.render(
      <MemoryRouter>
        <ScanPolicyPage />
      </MemoryRouter>
    );
  });
  await settle();
}

async function setText(el: HTMLTextAreaElement, value: string) {
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function click(el: Element) {
  await act(async () => {
    el.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
  await settle();
}

const button = (label: RegExp) =>
  Array.from(container.querySelectorAll("button")).find((b) => label.test(b.textContent ?? ""))!;
const area = (label: RegExp) =>
  Array.from(container.querySelectorAll("label"))
    .find((l) => label.test(l.textContent ?? ""))!
    .querySelector("textarea") as HTMLTextAreaElement;
const checkbox = (label: RegExp) =>
  Array.from(container.querySelectorAll("label"))
    .find((l) => label.test(l.textContent ?? ""))!
    .querySelector('input[type="checkbox"]') as HTMLInputElement;

describe("ScanPolicyPage", () => {
  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });
  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    vi.unstubAllGlobals();
  });

  it("shows RFC1918, effective policy, ceilings and limits", async () => {
    backend(() =>
      json(policy({ deployment: { ...policy().deployment, scope_restricted: true, allowed_cidrs: ["192.168.1.0/24"], public_blocked: true } }))
    );
    await mount();
    const text = container.textContent ?? "";
    expect(text).toContain("10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16");
    expect(text).toContain("Private scanning: enabled");
    expect(text).toContain("Public scanning: disabled");
    expect(text).toContain("SCAN_ALLOWED_CIDRS ceiling: 192.168.1.0/24");
    expect(text).toContain("public scanning cannot be enabled");
    expect(text).toContain("up to 1024 hosts");
    expect(checkbox(/public IPv4 ranges/).disabled).toBe(true); // immutable ceiling
  });

  it("denies non-administrators and fails closed when the policy is unreadable", async () => {
    backend(() => json({ detail: { code: "admin_required", message: "x" } }, 403));
    await mount();
    expect(container.textContent).toContain("Administrator access is required");
    expect(container.querySelector("form")).toBeNull();

    await act(async () => root.unmount());
    root = createRoot(container);
    backend(() => json({ detail: { code: "policy_invalid", message: "The stored scan policy is invalid." } }, 503));
    await mount();
    expect(container.textContent).toContain("The stored scan policy is invalid.");
    expect(container.textContent).toContain("Scanning remains disabled");
    expect(container.querySelector("form")).toBeNull();
  });

  it("tracks unsaved state and saves exclusions with the current revision", async () => {
    const puts = backend(() => json(policy()), () =>
      json(policy({ revision: 2, exclusions: ["192.168.1.10/32"] }))
    );
    await mount();
    expect((button(/save changes/i) as HTMLButtonElement).disabled).toBe(true);
    await setText(area(/Never scan/), "192.168.1.10/32");
    expect(container.textContent).toContain("unsaved changes");
    await click(button(/save changes/i));
    expect(puts[0]).toMatchObject({
      expected_revision: 1,
      exclusions: ["192.168.1.10/32"],
      private_enabled: true,
      confirm_broadening: false,
    });
    expect(container.textContent).toContain("Saved as revision 2");
    expect(container.textContent).not.toContain("unsaved changes");
  });

  it("requires explicit confirmation, including ownership, before broadening to public", async () => {
    const puts = backend(
      () => json(policy()),
      (body) =>
        body.confirm_broadening && body.confirm_public
          ? json(policy({ revision: 2 }))
          : json(
              {
                detail: {
                  code: "confirmation_required",
                  message: "m",
                  reasons: ["public_enabled"],
                  public_confirmation_required: true,
                },
              },
              409
            )
    );
    await mount();
    await click(checkbox(/public IPv4 ranges/));
    await setText(area(/Public allowlist/), "8.8.8.0/24");
    expect(container.textContent).toContain("Ownership warning");
    await click(button(/save changes/i));
    expect(container.textContent).toContain("enables PUBLIC address scanning");
    const confirm = button(/confirm and save/i) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    await click(checkbox(/understand and want to broaden/));
    expect((button(/confirm and save/i) as HTMLButtonElement).disabled).toBe(true); // ownership too
    await click(checkbox(/own these public addresses/));
    await click(button(/confirm and save/i));
    expect(puts).toHaveLength(2);
    expect(puts[1]).toMatchObject({ confirm_broadening: true, confirm_public: true });
    expect(container.textContent).toContain("Saved as revision 2");
  });

  it("shows validation errors next to the field and keeps the edit", async () => {
    backend(() => json(policy()), () =>
      json({ detail: { code: "not_rfc1918", message: "8.8.8.0/24 is not RFC1918", field: "private_allowlist" } }, 422)
    );
    await mount();
    await setText(area(/Strict private allowlist/), "8.8.8.0/24");
    await click(button(/save changes/i));
    expect(container.textContent).toContain("8.8.8.0/24 is not RFC1918");
    expect(area(/Strict private allowlist/).value).toBe("8.8.8.0/24");
  });

  it("handles a revision conflict without applying the edit", async () => {
    backend(() => json(policy()), () =>
      json(
        { detail: { code: "revision_conflict", message: "m", current: policy({ revision: 5, exclusions: ["10.1.1.1/32"] }) } },
        409
      )
    );
    await mount();
    await setText(area(/Never scan/), "10.9.9.9/32");
    await click(button(/save changes/i));
    expect(container.textContent).toContain("now revision 5");
    expect(container.textContent).toContain("Your edits were not applied");
    await click(button(/discard my edits and load/i));
    expect(area(/Never scan/).value).toBe("10.1.1.1/32");
    expect(container.textContent).toContain("Revision 5");
  });

  it("surfaces generic save failures", async () => {
    backend(() => json(policy()), () => json({ detail: { code: "policy_unavailable", message: "Store down" } }, 503));
    await mount();
    await click(checkbox(/private IPv4 targets/));
    await click(button(/save changes/i));
    expect(container.querySelector('[role="alert"]')?.textContent).toBeTruthy();
  });
});
