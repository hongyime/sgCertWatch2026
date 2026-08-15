import crypto from "node:crypto";

const TWO_PART_SUFFIXES = new Set([
  "com.sg",
  "net.sg",
  "org.sg",
  "gov.sg",
  "edu.sg",
  "per.sg"
]);

function normalizeHost(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^\*\./, "")
    .replace(/\.$/, "");
}

function compact(value) {
  return normalizeHost(value).replace(/[^a-z0-9]/g, "");
}

function registrableDomain(hostname) {
  const host = normalizeHost(hostname);
  const parts = host.split(".").filter(Boolean);
  if (parts.length <= 2) return host;

  const suffix = parts.slice(-2).join(".");
  if (TWO_PART_SUFFIXES.has(suffix) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
}

function suffixOfRegistrable(registrable) {
  const parts = normalizeHost(registrable).split(".");
  if (parts.length < 2) return "";
  const lastTwo = parts.slice(-2).join(".");
  if (TWO_PART_SUFFIXES.has(lastTwo) && parts.length >= 3) return lastTwo;
  return parts.at(-1) || "";
}

function editDistanceAtMost(a, b, maxDistance) {
  if (Math.abs(a.length - b.length) > maxDistance) return false;
  if (a === b) return true;
  if (maxDistance === 0) return false;

  let previous = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i += 1) {
    const current = [i];
    let rowMin = current[0];
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const value = Math.min(
        previous[j] + 1,
        current[j - 1] + 1,
        previous[j - 1] + cost
      );
      current[j] = value;
      rowMin = Math.min(rowMin, value);
    }
    if (rowMin > maxDistance) return false;
    previous = current;
  }

  return previous[b.length] <= maxDistance;
}

function extractDomains(entry) {
  const candidates = [
    entry?.domain,
    entry?.common_name,
    entry?.subject?.common_name,
    entry?.leaf_cert?.subject?.CN,
    ...(entry?.dns_names || []),
    ...(entry?.domains || []),
    ...(entry?.leaf_cert?.all_domains || []),
    ...String(entry?.name_value || "").split(/\s+/)
  ];

  return [...new Set(candidates.map(normalizeHost).filter((value) => value.includes(".")))];
}

function issuerName(entry) {
  return entry?.issuer?.aggregated
    || entry?.issuer?.CN
    || entry?.leaf_cert?.issuer?.aggregated
    || entry?.leaf_cert?.issuer?.CN
    || "";
}

function severity(score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  if (score > 0) return "low";
  return "none";
}

function brandSignals(domain, data) {
  const signals = [];
  const hostCompact = compact(domain);
  const labels = normalizeHost(domain).split(".").map(compact);
  const registrable = registrableDomain(domain);
  const tld = suffixOfRegistrable(registrable);

  for (const brand of data.watchlist.brands) {
    const contextHit = !brand.require_context
      || brand.context_tokens?.some((token) => hostCompact.includes(compact(token)));
    if (!contextHit) continue;

    for (const token of brand.tokens || []) {
      const tokenCompact = compact(token);
      const exact = hostCompact.includes(tokenCompact);
      const fuzzy = labels.some((label) => editDistanceAtMost(label, tokenCompact, brand.max_edit_distance || 0));
      if (!exact && !fuzzy) continue;

      signals.push({
        type: exact ? "brand:exact" : "brand:fuzzy",
        brand: brand.id,
        display: brand.display,
        token,
        points: exact ? 35 : 25
      });

      if (brand.known_tlds?.length && !brand.known_tlds.includes(tld)) {
        signals.push({
          type: "tld:mismatch",
          brand: brand.id,
          expected: brand.known_tlds,
          actual: tld,
          points: 15
        });
      }
      break;
    }
  }

  return signals;
}

function keywordSignals(domain, data) {
  const hostCompact = compact(domain);
  const hits = [];
  for (const keyword of data.keywords.keywords) {
    if (hostCompact.includes(compact(keyword.token))) {
      hits.push({
        type: "kw",
        token: keyword.token,
        category: keyword.category,
        points: data.keywords.scoring.per_keyword
      });
    }
  }

  const cap = data.keywords.scoring.cap;
  let used = 0;
  return hits.map((hit) => {
    const points = Math.max(0, Math.min(hit.points, cap - used));
    used += points;
    return { ...hit, points };
  }).filter((hit) => hit.points > 0);
}

function schemeSignals(domain, data) {
  const hostCompact = compact(domain);
  const signals = [];
  for (const scheme of data.schemes.schemes) {
    for (const token of scheme.tokens || []) {
      if (!hostCompact.includes(compact(token))) continue;
      signals.push({
        type: "scheme",
        scheme: scheme.id,
        display: scheme.display,
        token,
        points: data.schemes.scoring.base_weight
      });
      break;
    }
  }
  return signals;
}

function isAllowlisted(domain, data) {
  const registrable = registrableDomain(domain);
  return data.allowlist.entries.some((entry) => entry.verified && entry.registrable === registrable);
}

function scoreDomain(domain, data) {
  const registrable = registrableDomain(domain);
  if (isAllowlisted(domain, data)) {
    return {
      domain: normalizeHost(domain),
      registrable,
      score: 0,
      severity: "none",
      suppressed: true,
      signals: [{ type: "allowlist", registrable, points: 0 }]
    };
  }

  const signals = [
    ...brandSignals(domain, data),
    ...keywordSignals(domain, data),
    ...schemeSignals(domain, data)
  ];
  const score = signals.reduce((total, signal) => total + signal.points, 0);

  return {
    domain: normalizeHost(domain),
    registrable,
    score,
    severity: severity(score),
    suppressed: false,
    signals
  };
}

function findingId(entry, topDomain) {
  if (entry?.cert_fingerprint) {
    return crypto
      .createHash("sha256")
      .update(`${entry.cert_fingerprint}|${topDomain.registrable}`)
      .digest("hex")
      .slice(0, 32);
  }

  const stable = [
    topDomain.domain,
    topDomain.registrable,
    issuerName(entry),
    entry?.not_before || entry?.leaf_cert?.not_before || entry?.seen || entry?.data?.seen || ""
  ].join("|");
  return crypto.createHash("sha256").update(stable).digest("hex").slice(0, 32);
}

function scoreCertificate(entry, data) {
  const domains = extractDomains(entry);
  const scoredDomains = domains.map((domain) => scoreDomain(domain, data));
  const active = scoredDomains.filter((item) => !item.suppressed && item.score > 0);
  if (!active.length) return null;

  active.sort((a, b) => b.score - a.score);
  const top = active[0];
  const signals = active.flatMap((item) => item.signals.map((signal) => ({ ...signal, domain: item.domain })));
  const matchedBrands = [...new Set(signals.map((signal) => signal.brand).filter(Boolean))];
  const matchedSchemes = [...new Set(signals.map((signal) => signal.scheme).filter(Boolean))];

  return {
    id: findingId(entry, top),
    observed_at: new Date((entry?.seen || entry?.data?.seen || Date.now() / 1000) * 1000).toISOString(),
    certificate_not_before: entry?.not_before || entry?.leaf_cert?.not_before || null,
    registrable: top.registrable,
    domains,
    score: top.score,
    severity: top.severity,
    signals,
    matched_brands: matchedBrands,
    matched_schemes: matchedSchemes,
    issuer: issuerName(entry),
    suppressed: false,
    source: {
      name: entry?.source || null,
      label: entry?.source_label || null,
      cert_index: entry?.cert_index || entry?.data?.cert_index || null,
      cert_link: entry?.cert_link || entry?.data?.cert_link || null,
      source_ref: entry?.source_ref || null,
      fingerprint: entry?.cert_fingerprint || null,
      log_name: entry?.log_name || null,
      log_operator: entry?.log_operator || null
    }
  };
}

export {
  extractDomains,
  registrableDomain,
  scoreCertificate,
  scoreDomain
};
