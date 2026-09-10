// One request at a time per panel. Visibility and filter changes cancel stale work.
export function visiblePoller(task, intervalMs, {
  document: visibility = globalThis.document,
  setTimer = globalThis.setTimeout,
  clearTimer = globalThis.clearTimeout,
  timeoutMs = 15000,
  maxDelayMs = 600000
} = {}) {
  let timer;
  let current;
  let pending = false;
  let failures = 0;
  let stopped = false;

  function clearScheduled() {
    clearTimer(timer);
    timer = undefined;
  }

  async function run() {
    if (stopped || visibility.hidden || current) return;
    clearScheduled();
    pending = false;
    const controller = new AbortController();
    current = controller;
    const deadline = setTimer(() => {
      controller.abort(new DOMException("Refresh timed out", "TimeoutError"));
    }, timeoutMs);
    let ok = false;
    try {
      ok = await task(controller.signal) !== false;
    } catch {
      // The panel renders its own error. Repeated failures slow automatic reads.
    } finally {
      clearTimer(deadline);
      current = undefined;
      const cancelled = controller.signal.aborted && controller.signal.reason?.name !== "TimeoutError";
      if (!cancelled) failures = ok && !controller.signal.aborted ? 0 : Math.min(failures + 1, 10);
      if (!stopped && !visibility.hidden) {
        if (pending) void run();
        else timer = setTimer(run, Math.min(intervalMs * 2 ** failures, maxDelayMs));
      }
    }
  }

  function refresh() {
    if (stopped) return;
    pending = true;
    clearScheduled();
    if (current) current.abort(new DOMException("Refresh superseded", "AbortError"));
    else void run();
  }

  function onVisibility() {
    if (visibility.hidden) {
      clearScheduled();
      current?.abort(new DOMException("Page hidden", "AbortError"));
    } else refresh();
  }

  visibility.addEventListener("visibilitychange", onVisibility);
  return {
    refresh,
    stop() {
      stopped = true;
      clearScheduled();
      current?.abort(new DOMException("Polling stopped", "AbortError"));
      visibility.removeEventListener("visibilitychange", onVisibility);
    }
  };
}
