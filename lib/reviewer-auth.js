/**
 * lib/reviewer-auth.js
 *
 * Server-side reviewer authentication using Supabase Auth.
 * Validates a Supabase access token and checks the user UUID
 * against the server-only REVIEWER_USER_IDS allowlist.
 *
 * Never exposes the TRIAGE_TOKEN to the browser.
 * Never grants reviewer access based on a valid login alone.
 */

// Read env vars at call time so tests can inject them.

/**
 * Parse the reviewer UUID allowlist from the environment.
 * REVIEWER_USER_IDS is a comma-separated list of Supabase user UUIDs.
 * Returns an empty Set if not configured (reviewer access closed).
 */
function reviewerIds() {
  const raw = process.env.REVIEWER_USER_IDS ?? "";
  return new Set(
    raw.split(",")
       .map((s) => s.trim())
       .filter((s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s))
  );
}

/**
 * Verify a Supabase access token and check reviewer permission.
 *
 * @param {string} token  Bearer token from Authorization header
 * @returns {Promise<{ ok: boolean, userId?: string, reason?: string }>}
 */
export async function verifyReviewer(token) {
  if (!token) return { ok: false, reason: "missing_token" };
  const supabaseUrl = process.env.SUPABASE_URL;
  const anonKey = process.env.SUPABASE_ANON_KEY;
  if (!supabaseUrl || !anonKey) return { ok: false, reason: "server_misconfigured" };

  const allowed = reviewerIds();
  if (allowed.size === 0) return { ok: false, reason: "reviewer_not_configured" };

  try {
    const resp = await fetch(`${supabaseUrl}/auth/v1/user`, {
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${token}`,
      },
    });
    if (!resp.ok) return { ok: false, reason: "token_invalid" };
    const user = await resp.json();
    const userId = user?.id;
    if (!userId) return { ok: false, reason: "token_invalid" };
    if (!allowed.has(userId)) return { ok: false, reason: "not_a_reviewer" };
    return { ok: true, userId };
  } catch {
    return { ok: false, reason: "auth_unavailable" };
  }
}

/**
 * Extract the Bearer token from a request's Authorization header.
 * @param {object} req
 * @returns {string|null}
 */
export function extractBearerToken(req) {
  const header = req?.headers?.authorization ?? "";
  if (!header.startsWith("Bearer ")) return null;
  return header.slice(7).trim() || null;
}
