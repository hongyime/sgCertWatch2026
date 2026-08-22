import psl from "psl";
import { domainToASCII, domainToUnicode } from "node:url";

/**
 * Normalise a DNS name from a certificate.
 * - lowercases
 * - strips a trailing dot
 * - strips a leading "*." (wildcard) and reports it separately
 * Returns null for names that are not parseable as hostnames.
 */
export function normaliseName(raw) {
  if (typeof raw !== "string" || raw.length === 0) return null;
  let name = raw.trim().toLowerCase();
  if (name.endsWith(".")) name = name.slice(0, -1);
  let wildcard = false;
  if (name.startsWith("*.")) {
    wildcard = true;
    name = name.slice(2);
  }
  if (name.length === 0 || name.includes(" ") || name.includes("/") || name.includes(":")) return null;
  try {
    const ascii = domainToASCII(name);
    if (!ascii) return null;
    return { name: ascii, unicode: domainToUnicode(ascii), wildcard };
  } catch (_err) {
    return null;
  }
}

/**
 * Registrable domain (eTLD+1) via the Public Suffix List.
 * Returns null when the name IS a public suffix (e.g. "com.sg") or is invalid.
 */
export function registrableDomain(asciiName) {
  if (typeof asciiName !== "string" || asciiName.length === 0) return null;
  const parsed = psl.parse(asciiName);
  if (parsed.error) return null;
  if (!parsed.domain) return null; // name is itself a public suffix
  return parsed.domain;
}

/**
 * Labels to the LEFT of the registrable domain, as an array, outermost first.
 * "a.b.dbs.com.sg" -> ["a", "b"]
 */
export function subdomainLabels(asciiName) {
  const reg = registrableDomain(asciiName);
  if (!reg) return [];
  if (asciiName === reg) return [];
  const prefix = asciiName.slice(0, asciiName.length - reg.length - 1);
  return prefix.length ? prefix.split(".") : [];
}
