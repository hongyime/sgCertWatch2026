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

const PSL_CACHE = new Map();
const MAX_CACHE_SIZE = 150000;

const FLAT_GTLDS = new Set([
  "com", "net", "org", "xyz", "top", "online", "site", "shop", "tech", "app",
  "info", "live", "store", "club", "pro", "biz", "asia", "cloud", "vip", "space",
  "fit", "icu", "lat", "quest", "monster", "tokyo", "link", "press", "fund",
  "agency", "click", "rest", "buzz", "cfd", "sbs", "bank", "finance"
]);

const MULTI_PART_EXCEPTIONS = new Set([
  "us.com", "uk.com", "de.com", "eu.com", "cn.com", "sa.com", "ru.com",
  "za.com", "br.com", "jpn.com", "qc.com", "uy.com", "se.com", "hu.com",
  "kr.com", "no.com", "gr.com", "ar.com", "co.com", "mex.com", "eu.org"
]);

/**
 * Registrable domain (eTLD+1) via the Public Suffix List.
 * Returns null when the name IS a public suffix (e.g. "com.sg") or is invalid.
 */
export function registrableDomain(asciiName) {
  if (typeof asciiName !== "string" || asciiName.length === 0) return null;
  const cached = PSL_CACHE.get(asciiName);
  if (cached !== undefined) return cached;

  const lastDot = asciiName.lastIndexOf(".");
  if (lastDot === -1) {
    PSL_CACHE.set(asciiName, null);
    return null;
  }

  const tld = asciiName.slice(lastDot + 1).toLowerCase();
  if (FLAT_GTLDS.has(tld)) {
    const prevDot = asciiName.lastIndexOf(".", lastDot - 1);
    if (prevDot === -1) {
      PSL_CACHE.set(asciiName, asciiName);
      return asciiName;
    }
    const lastTwo = asciiName.slice(prevDot + 1).toLowerCase();
    if (!MULTI_PART_EXCEPTIONS.has(lastTwo)) {
      const reg = asciiName.slice(prevDot + 1);
      if (PSL_CACHE.size >= MAX_CACHE_SIZE) PSL_CACHE.clear();
      PSL_CACHE.set(asciiName, reg);
      return reg;
    }
  }

  let domain = null;
  try {
    domain = psl.get(asciiName);
  } catch (_err) {
    domain = null;
  }

  if (PSL_CACHE.size >= MAX_CACHE_SIZE) {
    PSL_CACHE.clear();
  }
  PSL_CACHE.set(asciiName, domain);
  return domain;
}

/**
 * Labels to the LEFT of the registrable domain, as an array, outermost first.
 * "a.b.dbs.com.sg" -> ["a", "b"]
 */
export function subdomainLabels(asciiName, knownRegistrable = null) {
  const reg = knownRegistrable !== null ? knownRegistrable : registrableDomain(asciiName);
  if (!reg) return [];
  if (asciiName === reg) return [];
  const prefix = asciiName.slice(0, asciiName.length - reg.length - 1);
  return prefix.length ? prefix.split(".") : [];
}
