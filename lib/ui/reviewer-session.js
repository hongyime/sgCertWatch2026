/**
 * lib/ui/reviewer-session.js
 *
 * Browser-side reviewer session helper (Task 9, password-auth variant).
 *
 * State is memory-only: the access token is never written to localStorage,
 * sessionStorage, IndexedDB or a cookie.  A refresh past the tab lifetime
 * ends the session — this is intentional to keep the free-tier surface small
 * and to avoid leaking analyst tokens.
 *
 * A monotonically increasing "generation" counter is exposed so callers can
 * discard responses from in-flight requests that outlive a signOut() / new
 * signIn().  Include the generation on every private request:
 *
 *     const gen = reviewerSession.generation();
 *     const res = await fetch(`/api/reviews?finding_id=${id}`, {
 *       headers: { Authorization: `Bearer ${reviewerSession.currentToken()}` },
 *     });
 *     if (reviewerSession.generation() !== gen) return;   // discard stale
 *
 * TRIAGE_TOKEN is never sent to the browser and never handled here.
 */

export function createReviewerSession({ fetchImpl } = {}) {
  const doFetch = fetchImpl ?? ((...args) => fetch(...args));

  let token     = null;
  let user      = null;   // { id }
  let expiresAt = null;   // ms epoch
  let generation = 0;
  const listeners = new Set();

  function emit() {
    const snapshot = state();
    for (const cb of listeners) {
      try { cb(snapshot); } catch { /* subscriber errors must not break auth */ }
    }
  }

  function clear() {
    token = null;
    user = null;
    expiresAt = null;
    generation += 1;
  }

  function state() {
    return {
      signedIn: Boolean(token && expiresAt && Date.now() < expiresAt),
      user: user ? { id: user.id } : null,
      expiresAt,
      generation,
    };
  }

  async function signIn(email, password) {
    if (typeof email !== "string" || typeof password !== "string") {
      throw new Error("invalid_credentials");
    }
    generation += 1;
    const startGen = generation;
    const resp = await doFetch("/api/reviewer-session", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (generation !== startGen) {
      throw new Error("auth_stale");
    }
    if (!resp.ok) {
      let err = "auth_unavailable";
      try {
        const body = await resp.json();
        if (typeof body?.error === "string") err = body.error;
      } catch { /* ignore */ }
      if (generation !== startGen) {
        throw new Error("auth_stale");
      }
      generation += 1;
      throw new Error(err);
    }
    const body = await resp.json();
    if (generation !== startGen) {
      throw new Error("auth_stale");
    }
    if (!body?.access_token || !body?.user?.id || !body?.expires_at) {
      generation += 1;
      throw new Error("auth_unavailable");
    }
    const parsedExpires = Date.parse(body.expires_at);
    if (!Number.isFinite(parsedExpires) || parsedExpires <= Date.now()) {
      generation += 1;
      throw new Error("auth_unavailable");
    }
    token = body.access_token;
    user = { id: body.user.id };
    expiresAt = parsedExpires;
    generation += 1;
    emit();
    return { user: { id: user.id }, expiresAt, generation };
  }

  async function signOut() {
    const t = token;
    clear();
    emit();
    if (!t) return;
    try {
      await doFetch("/api/reviewer-session", {
        method: "DELETE",
        credentials: "same-origin",
        headers: { Authorization: `Bearer ${t}` },
      });
    } catch { /* best effort */ }
  }

  function currentToken() {
    if (!token || !expiresAt || Date.now() >= expiresAt) return null;
    return token;
  }

  function currentUser() {
    if (!currentToken()) return null;
    return user ? { id: user.id } : null;
  }

  function onChange(cb) {
    if (typeof cb !== "function") return () => {};
    listeners.add(cb);
    return () => listeners.delete(cb);
  }

  return {
    signIn,
    signOut,
    currentToken,
    currentUser,
    generation: () => generation,
    onChange,
    // Test-only helper.  Exposed but named with an underscore so callers do
    // not treat it as public API.
    _clear: clear,
  };
}

// A module-level default session for the shipping UI.  Tests create their
// own instance via createReviewerSession() to inject a fake fetch.
export const reviewerSession = createReviewerSession();
