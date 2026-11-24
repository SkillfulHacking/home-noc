import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "./api";
import {
  Job,
  MAX_BACKOFF_MS,
  POLL_MS,
  describeError,
  nextDelay,
  parseTargets,
  pollJob,
} from "./scans";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function job(status: string, done = 0, total = 256): Job {
  return {
    id: "j1",
    profile: "discovery",
    targets: ["192.168.1.0/24"],
    status,
    created_by: "admin",
    created_at: "2026-01-01T00:00:00Z",
    started_at: null,
    finished_at: null,
    attempts: 0,
    max_attempts: 3,
    cancel_requested: false,
    progress: { done, total, percent: Math.floor((100 * done) / total) },
    error_code: null,
    error_message: null,
    result: null,
  } as Job;
}

const page = (ids: number[], status = "running") => ({
  status,
  terminal: status === "succeeded",
  next_after: ids.length ? ids[ids.length - 1] : 0,
  events: ids.map((id) => ({ id, at: "t", level: "info", type: "x", message: `e${id}` })),
});

describe("scan helpers", () => {
  it("splits targets on whitespace and commas", () => {
    expect(parseTargets(" 10.0.0.1, 10.0.0.0/30\n192.168.1.5 ")).toEqual([
      "10.0.0.1",
      "10.0.0.0/30",
      "192.168.1.5",
    ]);
    expect(parseTargets("  ,, ")).toEqual([]);
  });

  it("shows the backend's scope message for a rejected target", () => {
    const err = new ApiError("x", 403, {
      detail: { code: "out_of_scope", message: "Target is outside the authorized scope" },
    });
    expect(describeError(err, "fallback")).toBe("Target is outside the authorized scope");
  });

  it("summarises validation (422 list) errors without dumping raw input", () => {
    const err = new ApiError("x", 422, { detail: [{ loc: ["body"], msg: "bad", input: "secret" }] });
    const text = describeError(err, "fallback");
    expect(text).not.toContain("secret");
    expect(text).toMatch(/target list/);
  });

  it("falls back for non-API errors", () => {
    expect(describeError(new Error("boom"), "fallback")).toBe("fallback");
  });

  it("backs off on failures with a ceiling", () => {
    expect(nextDelay(0)).toBe(POLL_MS);
    expect(nextDelay(1)).toBe(POLL_MS * 2);
    expect(nextDelay(20)).toBe(MAX_BACKOFF_MS);
  });
});

describe("pollJob", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  function route(handler: (url: string) => Response) {
    const fetchMock = vi.fn(async (url: string) => handler(url));
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("polls until terminal, passes the event cursor and stops", async () => {
    const jobs = [job("running", 10), job("succeeded", 256)];
    const pages = [page([1, 2]), page([3], "succeeded")];
    let j = 0;
    let p = 0;
    const urls: string[] = [];
    route((url) => {
      urls.push(url);
      if (url.includes("/events")) return json(pages[Math.min(p++, pages.length - 1)]);
      return json(jobs[Math.min(j++, jobs.length - 1)]);
    });
    const seen: string[] = [];
    const messages: string[] = [];
    const done = vi.fn();

    pollJob("j1", {
      onJob: (x) => seen.push(x.status),
      onEvents: (e) => messages.push(...e.map((x) => x.message)),
      onError: () => undefined,
      onDone: done,
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(seen).toEqual(["running"]);
    await vi.advanceTimersByTimeAsync(POLL_MS);

    expect(seen).toEqual(["running", "succeeded"]);
    expect(messages).toEqual(["e1", "e2", "e3"]);
    expect(done).toHaveBeenCalledTimes(1);
    expect(urls.some((u) => u.includes("/events?after=2"))).toBe(true);

    const calls = urls.length;
    await vi.advanceTimersByTimeAsync(POLL_MS * 5);
    expect(urls.length).toBe(calls); // no polling after a terminal state
  });

  it("keeps retrying through a backend restart, then recovers", async () => {
    let fail = true;
    route((url) => {
      if (fail) throw new TypeError("Failed to fetch");
      return url.includes("/events") ? json(page([])) : json(job("running", 5));
    });
    const errors: (string | null)[] = [];
    const seen: string[] = [];
    const stop = pollJob("j1", {
      onJob: (x) => seen.push(x.status),
      onEvents: () => undefined,
      onError: (m) => errors.push(m),
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(errors[0]).toMatch(/Network error/);
    expect(seen).toEqual([]);

    fail = false;
    await vi.advanceTimersByTimeAsync(POLL_MS * 2);
    expect(seen).toEqual(["running"]);
    expect(errors[errors.length - 1]).toBeNull();
    stop();
  });

  it("gives up when the job no longer exists", async () => {
    const fetchMock = route(() => json({ detail: "Scan job not found" }, 404));
    const errors: (string | null)[] = [];
    pollJob("j1", {
      onJob: () => undefined,
      onEvents: () => undefined,
      onError: (m) => errors.push(m),
    });
    await vi.advanceTimersByTimeAsync(0);
    const calls = fetchMock.mock.calls.length;
    await vi.advanceTimersByTimeAsync(MAX_BACKOFF_MS * 2);
    expect(errors).toEqual(["Scan job not found"]);
    expect(fetchMock.mock.calls.length).toBe(calls);
  });

  it("stop() halts polling", async () => {
    const fetchMock = route((url) =>
      url.includes("/events") ? json(page([])) : json(job("running"))
    );
    const stop = pollJob("j1", {
      onJob: () => undefined,
      onEvents: () => undefined,
      onError: () => undefined,
    });
    await vi.advanceTimersByTimeAsync(0);
    stop();
    const calls = fetchMock.mock.calls.length;
    await vi.advanceTimersByTimeAsync(POLL_MS * 5);
    expect(fetchMock.mock.calls.length).toBe(calls);
  });
});
