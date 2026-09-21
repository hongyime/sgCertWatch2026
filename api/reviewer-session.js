/**
 * api/reviewer-session.js
 *
 * Same-origin reviewer login / logout endpoint (Task 9).
 *
 *   POST   /api/reviewer-session   body: { email, password }
 *      200 { access_token, user: { id }, expires_at }
 *      400 invalid_body
 *      401 invalid_credentials | not_a_reviewer
 *      503 reviewer_not_configured
 *
 *   DELETE /api/reviewer-session   header: Authorization: Bearer <access_token>
 *      204 on success (best-effort revoke)
 *      401 invalid_token
 *      503 reviewer_not_configured
 *
 * The server proxies the Supabase password grant with bounded body + timeout
 * so the browser never talks to the auth host directly.  This preserves the
 * existing connect-src 'self' CSP and keeps the anon key server-side.
 *
 * NEVER logs passwords, access tokens or refresh tokens.
 * NEVER returns the refresh token.  The browser session is memory-only.
 * NEVER accepts a signup, PAT-based override or custom password store.
 */

import { verifyReviewer } from "../lib/reviewer-auth.js";
import { respondIfStorageRecovery } from "../lib/storage-recovery.js";

const MAX_BODY_BYTES  = 4 * 1024;   // 4 KiB
const EMAIL_MAX_LEN   = 254;
const PASSWORD_MAX_LEN = 200;
const UPSTREAM_TIMEOUT_MS = 8_000;

function json(res, status, body) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json");
  res.status(status).json(body);
}

function noContent(res) {
  res.setHeader("Cache-Control", "no-store");
  res.status(204).end();
}

/**
 * Read request body as JSON with a hard byte cap.
 * Handles the two common Vercel / Node adapters:
 *   - request.body already parsed (framework-decoded)
 *   - request is an async iterable of chunks
 */
async function readJsonBody(request) {
  if (request.body && typeof request.body === "object" && !Buffer.isBuffer(request.body)) {
    const s = JSON.stringify(request.body);
    if (Buffer.byteLength(s, "utf8") > MAX_BODY_BYTES) throw new Error("body_too_large");
    return request.body;
  }
  if (typeof request.body === "string") {
    if (Buffer.byteLength(request.body) > MAX_BODY_BYTES) throw new Error("body_too_large");
    return JSON.parse(request.body);
  }
  if (request[Symbol.asyncIterator]) {
    let total = 0;
    const chunks = [];
    for await (const chunk of request) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.length;
      if (total > MAX_BODY_BYTES) throw new Error("body_too_large");
      chunks.push(buf);
    }
    if (total === 0) return {};
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  }
  return {};
}

async function upstreamFetch(url, init = {}) {
  const ctrl = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS);
  return fetch(url, { ...init, signal: init.signal ? AbortSignal.any([init.signal, ctrl]) : ctrl });
}

export default async function handler(request, response) {
  if (!["POST", "DELETE"].includes(request.method)) {
    response.setHeader("Allow", "POST, DELETE");
    return json(response, 405, { error: "method_not_allowed" });
  }
  if (respondIfStorageRecovery(response)) return;

  const supabaseUrl = process.env.SUPABASE_URL;
  const anonKey     = process.env.SUPABASE_ANON_KEY;
  if (!supabaseUrl || !anonKey) {
    return json(response, 503, { error: "reviewer_not_configured" });
  }

  if (request.method === "POST") return handleLogin(request, response, supabaseUrl, anonKey);
  return handleLogout(request, response, supabaseUrl, anonKey);
}

async function handleLogin(request, response, supabaseUrl, anonKey) {
  let body;
  try {
    body = await readJsonBody(request);
  } catch (err) {
    if (err?.message === "body_too_large") return json(response, 400, { error: "body_too_large" });
    return json(response, 400, { error: "invalid_json" });
  }

  const email    = typeof body?.email    === "string" ? body.email.trim()    : "";
  const password = typeof body?.password === "string" ? body.password        : "";
  if (!email || email.length > EMAIL_MAX_LEN || !email.includes("@")) {
    return json(response, 400, { error: "invalid_body", field: "email" });
  }
  if (!password || password.length < 8 || password.length > PASSWORD_MAX_LEN) {
    return json(response, 400, { error: "invalid_body", field: "password" });
  }

  let grantResp;
  try {
    grantResp = await upstreamFetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: {
        apikey: anonKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
    });
  } catch {
    return json(response, 502, { error: "auth_unavailable" });
  }

  if (grantResp.status === 400 || grantResp.status === 401 || grantResp.status === 422) {
    // Do not echo Supabase error text; do not distinguish invalid email vs bad password.
    return json(response, 401, { error: "invalid_credentials" });
  }
  if (!grantResp.ok) {
    return json(response, 502, { error: "auth_unavailable" });
  }

  let grant;
  try {
    grant = await grantResp.json();
  } catch {
    return json(response, 502, { error: "auth_unavailable" });
  }

  const accessToken = typeof grant?.access_token === "string" ? grant.access_token : "";
  const expiresIn   = Number(grant?.expires_in);
  const userId      = typeof grant?.user?.id === "string" ? grant.user.id : "";
  if (!accessToken || !userId) {
    return json(response, 502, { error: "auth_unavailable" });
  }


  // Enforce the reviewer allowlist.  A valid login is not sufficient.
  const auth = await verifyReviewer(accessToken);
  if (!auth.ok) {
    // Revoke the just-issued session before returning.
    upstreamFetch(`${supabaseUrl}/auth/v1/logout`, {
      method: "POST",
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
    }).catch(() => {});
    if (auth.reason === "reviewer_not_configured" || auth.reason === "server_misconfigured") {
      return json(response, 503, { error: "reviewer_not_configured" });
    }
    return json(response, 401, { error: "not_a_reviewer" });
  }

  const ttl = Number.isFinite(expiresIn) && expiresIn > 0 ? expiresIn : 3600;
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
  return json(response, 200, {
    access_token: accessToken,
    user: { id: auth.userId },
    expires_at: expiresAt,
  });
}

async function handleLogout(request, response, supabaseUrl, anonKey) {
  const header = request?.headers?.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token || token.length > 4096) return json(response, 401, { error: "invalid_token" });

  // Verify the token before revoking so a random attacker cannot force
  // arbitrary Supabase Auth calls.
  const auth = await verifyReviewer(token);
  if (!auth.ok) {
    if (auth.reason === "reviewer_not_configured" || auth.reason === "server_misconfigured") {
      return json(response, 503, { error: "reviewer_not_configured" });
    }
    return json(response, 401, { error: "invalid_token" });
  }

  try {
    await upstreamFetch(`${supabaseUrl}/auth/v1/logout`, {
      method: "POST",
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
  } catch {
    // Best-effort revoke; the memory-only browser session is already gone.
  }
  return noContent(response);
}
