import crypto from "node:crypto";
import psl from "psl";
import defaultScoringConfig from "../scoring.json" with { type: "json" };
import { normaliseName, registrableDomain, subdomainLabels } from "./domain/registrable.js";

function getScoringConfig(data) {
  return data?.scoring || defaultScoringConfig;
}

function normalizeHost(value) {
  const norm = normaliseName(value);
  return norm ? norm.name : String(value || "").trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
}

function compact(value) {
  return normalizeHost(value).replace(/[^a-z0-9]/g, "");
}

function suffixOfRegistrable(registrable) {
  const parsed = psl.parse(normalizeHost(registrable));
  if (parsed.error || !parsed.tld) return "";
  return parsed.tld;
}

function decomposeLabel(label, affixKeywords) {
  const forms = new Set([label]);
  for (const kw of affixKeywords) {
    if (label.startsWith(kw) && label.length > kw.length) {
      forms.add(label.slice(kw.length));
    }
    if (label.endsWith(kw) && label.length > kw.length) {
      forms.add(label.slice(0, label.length - kw.length));
    }
  }
  return [...forms];
}

function editDistanceAtMost(a, b, maxDistance) {
  if (Math.abs(a.length - b.length) > maxDistance) return false;
  if (a === b) return true;
  if (maxDistance === 0) return false;

  const la = a.length;
  const lb = b.length;
  const d = Array.from({ length: la + 1 }, () => new Array(lb + 1).fill(0));

  for (let i = 0; i <= la; i++) d[i][0] = i;
  for (let j = 0; j <= lb; j++) d[0][j] = j;

  for (let i = 1; i <= la; i++) {
    let rowMin = d[i][0];
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1,       // deletion
        d[i][j - 1] + 1,       // insertion
        d[i - 1][j - 1] + cost // substitution
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1); // transposition
      }
      rowMin = Math.min(rowMin, d[i][j]);
    }
    if (rowMin > maxDistance) return false;
  }

  return d[la][lb] <= maxDistance;
}

function substringEditDistanceAtMost(label, token, maxDistance) {
  if (!label || !token) return false;
  const tokenLen = token.length;
  const labelLen = label.length;
  if (maxDistance <= 0) return label.includes(token);
  if (labelLen < tokenLen - maxDistance) return false;

  const minWindow = Math.max(1, tokenLen - maxDistance);
  const maxWindow = Math.min(labelLen, tokenLen + maxDistance);

  for (let w = minWindow; w <= maxWindow; w++) {
    for (let i = 0; i <= labelLen - w; i++) {
      const windowStr = label.slice(i, i + w);
      if (editDistanceAtMost(windowStr, token, maxDistance)) {
        return true;
      }
    }
  }
  return false;
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

function severity(score, thresholds = defaultScoringConfig.thresholds) {
  if (score >= thresholds.alert_min) return "critical";
  if (score >= thresholds.digest_min) return "high";
  if (score >= thresholds.dashboard_min) return "medium";
  if (score > 0) return "low";
  return "none";
}

function brandSignals(domain, data) {
  const cfg = getScoringConfig(data);
  const w = cfg.weights;
  const signals = [];
  const host = normalizeHost(domain);
  const hostCompact = compact(domain);
  const registrable = registrableDomain(host);
  const tld = suffixOfRegistrable(registrable);
  const subLabels = subdomainLabels(host).map(compact);
  const allLabels = host.split(".").map(compact);
  const affixKeywords = (data?.keywords?.keywords || []).filter((k) => k.affix).map((k) => compact(k.token));

  for (const brand of data?.watchlist?.brands || []) {
    const contextHit = !brand.require_context
      || brand.context_tokens?.some((token) => hostCompact.includes(compact(token)));
    if (!contextHit) continue;

    const isBrandAllowlisted = (data?.allowlist?.entries || []).some(
      (entry) => entry.verified && entry.brand === brand.id && entry.registrable === registrable
    );

    for (const token of brand.tokens || []) {
      const tokenCompact = compact(token);
      const candidateLabels = brand.allow_affix
        ? allLabels.flatMap((l) => decomposeLabel(l, affixKeywords))
        : allLabels;
      const subCandidateLabels = brand.allow_affix
        ? subLabels.flatMap((l) => decomposeLabel(l, affixKeywords))
        : subLabels;

      const effectiveMaxDist = tokenCompact.length <= 2 ? 0 : (tokenCompact.length <= 5 ? Math.min(brand.max_edit_distance ?? 1, 1) : (brand.max_edit_distance ?? 2));
      const exact = hostCompact.includes(tokenCompact) || candidateLabels.includes(tokenCompact);
      const fuzzy = !exact && candidateLabels.some((label) => substringEditDistanceAtMost(label, tokenCompact, effectiveMaxDist));
      if (!exact && !fuzzy) continue;

      signals.push({
        type: exact ? "brand:exact" : "brand:fuzzy",
        brand: brand.id,
        display: brand.display,
        token,
        points: exact ? w["brand:exact"] : w["brand:fuzzy"]
      });

      // High-precision phishing pattern: dbs.com.sg.secure-login.xyz contains the exact brand/domain in a subdomain prefix
      const subSquat = subCandidateLabels.some(
        (l) => l === tokenCompact || substringEditDistanceAtMost(l, tokenCompact, effectiveMaxDist)
      );
      if (!isBrandAllowlisted && subSquat) {
        signals.push({
          type: "subdomain_brand_squat",
          brand: brand.id,
          display: brand.display,
          token,
          points: w["subdomain:brand_squat"]
        });
      }

      // Brand in path position: full legitimate registrable domain appears as a subdomain prefix
      const brandAllowlistedRegs = (data?.allowlist?.entries || [])
        .filter((e) => e.verified && e.brand === brand.id)
        .map((e) => e.registrable);
      const pathPositionMatch = brandAllowlistedRegs.some(
        (reg) => host.startsWith(`${reg}.`) || host.includes(`.${reg}.`)
      );
      if (!isBrandAllowlisted && pathPositionMatch) {
        signals.push({
          type: "brand_in_path_position",
          brand: brand.id,
          display: brand.display,
          token,
          points: w["brand_in_path_position"]
        });
      }

      if (brand.known_tlds?.length && !brand.known_tlds.includes(tld)) {
        signals.push({
          type: "tld:mismatch",
          brand: brand.id,
          expected: brand.known_tlds,
          actual: tld,
          points: w["tld:mismatch"]
        });
      }
      break;
    }
  }

  return signals;
}

function keywordSignals(domain, data) {
  const cfg = getScoringConfig(data);
  const w = cfg.weights;
  const perKeyword = w["kw"] ?? data?.keywords?.scoring?.per_keyword ?? 10;
  const cap = w["keyword_cap"] ?? data?.keywords?.scoring?.cap ?? 25;
  const hostCompact = compact(domain);
  const hits = [];

  for (const keyword of data?.keywords?.keywords || []) {
    if (hostCompact.includes(compact(keyword.token))) {
      hits.push({
        type: "kw",
        token: keyword.token,
        category: keyword.category,
        points: perKeyword
      });
    }
  }

  let used = 0;
  return hits.map((hit) => {
    const points = Math.max(0, Math.min(hit.points, cap - used));
    used += points;
    return { ...hit, points };
  }).filter((hit) => hit.points > 0);
}

function schemeSignals(domain, data, now = new Date()) {
  const cfg = getScoringConfig(data);
  const w = cfg.weights;
  const baseWeight = w["scheme"] ?? data?.schemes?.scoring?.base_weight ?? 45;
  const seasonalBoost = w["scheme_seasonal_boost"] ?? data?.schemes?.scoring?.seasonal_boost ?? 15;
  const hostCompact = compact(domain);
  const signals = [];

  for (const scheme of data?.schemes?.schemes || []) {
    const maxDist = scheme.max_edit_distance || 0;
    for (const token of scheme.tokens || []) {
      const tokenCompact = compact(token);
      const exact = hostCompact.includes(tokenCompact);
      const fuzzy = !exact && substringEditDistanceAtMost(hostCompact, tokenCompact, maxDist);
      if (!exact && !fuzzy) continue;

      signals.push({
        type: "scheme",
        scheme: scheme.id,
        display: scheme.display,
        token,
        points: baseWeight
      });

      if (scheme.active_window?.start && scheme.active_window?.end) {
        const start = new Date(scheme.active_window.start).getTime();
        const end = new Date(scheme.active_window.end).getTime();
        const currentTime = typeof now === "number" ? now : new Date(now).getTime();
        if (currentTime >= start && currentTime <= end) {
          signals.push({
            type: "scheme_seasonal_boost",
            scheme: scheme.id,
            display: scheme.display,
            token,
            points: seasonalBoost
          });
        }
      }
      break;
    }
  }
  return signals;
}

function isAllowlisted(domain, data) {
  const norm = normaliseName(domain);
  const ascii = norm ? norm.name : normalizeHost(domain);
  const reg = registrableDomain(ascii);
  return reg !== null && (data?.allowlist?.entries || []).some((entry) => entry.verified && entry.registrable === reg);
}

function scoreDomain(domain, data, now = new Date()) {
  const cfg = getScoringConfig(data);
  const registrable = registrableDomain(domain);
  if (isAllowlisted(domain, data)) {
    return {
      domain: normalizeHost(domain),
      registrable,
      score: 0,
      scoring_version: cfg.version,
      severity: "none",
      suppressed: true,
      signals: [{ type: "allowlist", registrable, points: 0 }]
    };
  }

  const brandSigs = brandSignals(domain, data);
  const kwSigs = keywordSignals(domain, data);
  const schemeSigs = schemeSignals(domain, data, now);

  const signals = [
    ...brandSigs,
    ...kwSigs,
    ...schemeSigs
  ];

  const hasBrand = brandSigs.some((s) => s.type.startsWith("brand:"));
  const hasScheme = schemeSigs.some((s) => s.type === "scheme");
  const hasKw = kwSigs.some((s) => s.type === "kw");

  const comboWithBrandWeight = cfg.weights["combo_brand_keyword"] ?? data?.keywords?.scoring?.combo_with_brand ?? 25;
  const comboWithSchemeWeight = cfg.weights["combo_scheme_keyword"] ?? data?.keywords?.scoring?.combo_with_scheme ?? 25;

  if (hasBrand && hasKw) {
    signals.push({
      type: "combo_brand_keyword",
      points: comboWithBrandWeight
    });
  } else if (hasScheme && hasKw) {
    signals.push({
      type: "combo_scheme_keyword",
      points: comboWithSchemeWeight
    });
  }

  const rawScore = signals.reduce((total, signal) => total + signal.points, 0);
  const maxCap = cfg.caps?.total ?? 100;
  const score = Math.min(rawScore, maxCap);

  return {
    domain: normalizeHost(domain),
    registrable,
    score,
    scoring_version: cfg.version,
    severity: severity(score, cfg.thresholds),
    suppressed: false,
    signals
  };
}

function findingId(entry, topDomain) {
  if (entry?.cert_issuer_dn_sha256 && entry?.cert_serial) {
    return crypto
      .createHash("sha256")
      .update(`${entry.cert_issuer_dn_sha256}|${entry.cert_serial}|${topDomain.registrable}`)
      .digest("hex")
      .slice(0, 32);
  }

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
  const cfg = getScoringConfig(data);
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
    scoring_version: top.scoring_version ?? cfg.version,
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
    cert_serial: entry?.cert_serial || null,
    cert_issuer_dn_sha256: entry?.cert_issuer_dn_sha256 || null,
    entry_types: entry?.entry_types || (entry?.entry_type ? [entry.entry_type] : ["x509"]),
    san_count: entry?.san_count || domains.length,
    is_wildcard: Boolean(entry?.is_wildcard),
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
