import { useEffect, useRef } from "react";

/**
 * Run `task` now and then every `ms` until unmount. Never overlaps runs, skips
 * ticks while the tab is hidden, and keeps going after failures (the task is
 * responsible for recording its own errors). Stops on unmount.
 */
export function usePolling(task: () => Promise<void>, ms: number): void {
  const taskRef = useRef(task);
  useEffect(() => {
    taskRef.current = task;
  });

  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const run = async () => {
      if (!document.hidden) {
        try {
          await taskRef.current();
        } catch {
          /* the task reports its own failures */
        }
      }
      if (!stopped) timer = setTimeout(run, ms);
    };
    void run();
    return () => {
      stopped = true;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [ms]);
}
