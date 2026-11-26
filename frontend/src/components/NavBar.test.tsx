import { act } from "react";
import { createRoot, Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { clearSession, setSession } from "../lib/auth";
import NavBar from "./NavBar";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

const hasPolicyLink = () =>
  container.querySelector('a[href="/settings/security/scan-policy"]') !== null;

describe("NavBar scan policy link", () => {
  beforeEach(async () => {
    clearSession();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    await act(async () => {
      root.render(
        <MemoryRouter>
          <NavBar />
        </MemoryRouter>
      );
    });
  });
  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearSession();
  });

  it("is hidden for an anonymous visitor", () => {
    expect(hasPolicyLink()).toBe(false);
  });

  it("appears for a confirmed session and disappears again on sign-out", async () => {
    await act(async () => setSession({ username: "admin", expiresAt: "2099-01-01T00:00:00Z" }));
    expect(hasPolicyLink()).toBe(true);
    await act(async () => clearSession());
    expect(hasPolicyLink()).toBe(false);
  });

  it("offers Login to visitors and Logout to signed-in users, never both", async () => {
    const link = (href: string) => container.querySelector(`a[href="${href}"]`) !== null;
    expect(link("/login")).toBe(true);
    expect(link("/logout")).toBe(false);
    await act(async () => setSession({ username: "admin", expiresAt: "2099-01-01T00:00:00Z" }));
    expect(link("/login")).toBe(false);
    expect(link("/logout")).toBe(true);
    await act(async () => clearSession());
    expect(link("/login")).toBe(true);
    expect(link("/logout")).toBe(false);
  });
});
