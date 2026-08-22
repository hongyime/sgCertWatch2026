import { timingSafeEqual } from "node:crypto";

export function checkBearer(req, expected) {
  if (!expected || expected.length < 32) {
    // Fail closed: a missing or weak secret is a misconfiguration, not an open door.
    return { ok: false, reason: "server_misconfigured" };
  }
  const header = req?.headers?.authorization || "";
  if (!header.startsWith("Bearer ")) return { ok: false, reason: "missing_bearer" };
  const given = Buffer.from(header.slice(7));
  const want = Buffer.from(expected);
  if (given.length !== want.length) return { ok: false, reason: "bad_secret" };
  if (!timingSafeEqual(given, want)) return { ok: false, reason: "bad_secret" };
  return { ok: true };
}
