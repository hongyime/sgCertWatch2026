export class SafeError extends Error {
  constructor(code, { status = 0, retryAt = 0, ambiguous = false } = {}) {
    super(code);
    this.code = code;
    this.status = status;
    this.retryAt = retryAt;
    this.ambiguous = ambiguous;
  }
}

export function safeCode(error) {
  return error instanceof SafeError ? error.code : "internal_failure";
}

export function retryTime(headers, now, failures = 1, seconds = 0) {
  const retry = headers.get("retry-after");
  const retryAt = retry && /^\d+(\.\d+)?$/.test(retry)
    ? now + Number(retry) * 1000 : Date.parse(retry || "");
  const reset = headers.get("x-ratelimit-remaining") === "0"
    ? Number(headers.get("x-ratelimit-reset")) * 1000 : 0;
  // No sleeps: persist the server's full minimum wait, with capped local backoff.
  return Math.max(now + Math.min(3600000, 60000 * 2 ** Math.min(failures - 1, 6)),
    Number.isFinite(retryAt) ? retryAt : 0, Number.isFinite(reset) ? reset : 0,
    now + (Number.isFinite(seconds) ? Math.max(0, seconds) * 1000 : 0));
}

async function readJson(response, maxBytes) {
  if (response.status === 204) return null;
  if (!response.body) throw new SafeError("invalid_response");
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new SafeError("response_too_large");
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    try { return JSON.parse(new TextDecoder().decode(bytes)); }
    catch { throw new SafeError("invalid_json"); }
  } finally {
    void reader.cancel().catch(() => {});
  }
}

// The deadline covers headers AND body, even when a fake/upstream ignores abort.
export async function boundedJson(fetcher, url, init = {}, timeoutMs = 5000, maxBytes = 131072, expectJson = true, readErrorJson = false) {
  const controller = new AbortController();
  let timer;
  let response;
  const operation = (async () => {
    response = await fetcher(url, { ...init, redirect: "manual", signal: controller.signal });
    if (controller.signal.aborted) {
      void response.body?.cancel().catch(() => {});
      throw new SafeError("request_timeout", { ambiguous: init.method === "POST" });
    }
    // Generic error bodies can reflect credentials; only Telegram's 429 metadata is needed.
    if (!response.ok) {
      // Telegram puts its minimum 429 delay in a JSON parameters object.
      if (readErrorJson && response.status === 429) {
        let data = null;
        try { data = await readJson(response, maxBytes); } catch { /* Only headers remain usable. */ }
        return { status: response.status, headers: response.headers, data };
      }
      void response.body?.cancel().catch(() => {});
      return { status: response.status, headers: response.headers, data: null };
    }
    if (!expectJson) {
      void response.body?.cancel().catch(() => {});
      return { status: response.status, headers: response.headers, data: null };
    }
    const data = await readJson(response, maxBytes);
    return { status: response.status, headers: response.headers, data };
  })();
  try {
    return await Promise.race([operation, new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        // Abort terminates native fetch streams; the race also bounds nonnative mocks.
        reject(new SafeError("request_timeout", { ambiguous: init.method === "POST" }));
      }, timeoutMs);
    })]);
  } catch (error) {
    // A stalled error body cannot erase an already received rate-limit response.
    if (response && !response.ok) return { status: response.status, headers: response.headers, data: null };
    if (error instanceof SafeError) {
      if (init.method === "POST") error.ambiguous = true;
      throw error;
    }
    throw new SafeError("network_failure", { ambiguous: init.method === "POST" });
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}
