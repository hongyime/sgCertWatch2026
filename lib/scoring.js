import crypto from "node:crypto";
import psl from "psl";
import defaultScoringConfig from "../scoring.json" with { type: "json" };
import { normaliseName, registrableDomain, subdomainLabels } from "./domain/registrable.js";
import { decodeIdn, unicodeSkeleton, isMixedScript, asciiHomoglyphs } from "./domain/confusables.js";

function getScoringConfig(data) {
  return data?.scoring || defaultScoringConfig;
}

function normalizeHost(value) {
  const norm = normaliseName(value);
  return norm ? norm.name : String(value || "").trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
}

function compact(value) {
  const norm = normalizeHost(value);
  const key = norm;
  const cached = COMPACT_CACHE.get(key);
  if (cached !== undefined) return cached;
  const out = unicodeSkeleton(norm).replace(/[^a-z0-9]/g, "");
  if (COMPACT_CACHE.size >= 100000) COMPACT_CACHE.clear();
  COMPACT_CACHE.set(key, out);
  return out;
}

const COMPACT_CACHE = new Map();
const DECOMPOSE_CACHE = new Map();
const LEET_CACHE = new Map();

function leetCached(label) {
  const cached = LEET_CACHE.get(label);
  if (cached !== undefined) return cached;
  const out = asciiHomoglyphs(label);
  if (LEET_CACHE.size >= 100000) LEET_CACHE.clear();
  LEET_CACHE.set(label, out);
  return out;
}
function charMask(str) {
  let l = 0;
  let d = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c >= 97 && c <= 122) l |= 1 << (c - 97);
    else if (c >= 48 && c <= 57) d |= 1 << (c - 48);
  }
  return { l, d };
}

function popcount32(x) {
  x = x - ((x >> 1) & 0x55555555);
  x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
  return (((x + (x >> 4)) & 0x0f0f0f0f) * 0x01010101) >> 24;
}

function maskSubset(mask, hostMask) {
  return ((mask.l & ~hostMask.l) === 0 && (mask.d & ~hostMask.d) === 0);
}

function suffixOfRegistrable(registrable) {
  if (!registrable) return "";
  const firstDot = registrable.indexOf(".");
  return firstDot === -1 ? "" : registrable.slice(firstDot + 1);
}

function decomposeLabel(label, affixKeywords) {
  const cacheKey = label;
  const cached = DECOMPOSE_CACHE.get(cacheKey);
  if (cached) return cached;
  const forms = new Set([label]);
  const MAX_FORMS = 64;
  let frontier = [label];
  while (frontier.length > 0 && forms.size < MAX_FORMS) {
    const next = [];
    for (const form of frontier) {
      for (const kw of affixKeywords) {
        if (form.startsWith(kw) && form.length - kw.length >= 2) {
          const stripped = form.slice(kw.length);
          if (!forms.has(stripped)) {
            forms.add(stripped);
            next.push(stripped);
          }
        }
        if (form.endsWith(kw) && form.length - kw.length >= 2) {
          const stripped = form.slice(0, form.length - kw.length);
          if (!forms.has(stripped)) {
            forms.add(stripped);
            next.push(stripped);
          }
        }
      }
    }
    frontier = next;
  }
  const out = [...forms];
  if (DECOMPOSE_CACHE.size >= 100000) DECOMPOSE_CACHE.clear();
  DECOMPOSE_CACHE.set(cacheKey, out);
  return out;
}

const GENERIC_MORPHEMS = ["bank", "group", "express", "post", "pay"];

function editDistanceAtMost(a, b, maxDistance) {
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > maxDistance) return false;
  if (a === b) return true;
  if (maxDistance === 0) return false;

  if (la === lb && maxDistance === 1) {
    let diff = 0;
    let diffIdx = -1;
    for (let i = 0; i < la; i++) {
      if (a[i] !== b[i]) {
        diff++;
        if (diff > 2) return false;
        if (diff === 1) diffIdx = i;
        else if (diff === 2) {
          if (diffIdx !== i - 1 || a[diffIdx] !== b[i] || a[i] !== b[diffIdx]) {
            return false;
          }
        }
      }
    }
    return diff === 1 || (diff === 2 && a[diffIdx] === b[diffIdx + 1] && a[diffIdx + 1] === b[diffIdx]);
  }

  const prevRow = new Array(lb + 1);
  const currRow = new Array(lb + 1);
  const prevPrevRow = new Array(lb + 1);
  for (let j = 0; j <= lb; j++) prevRow[j] = j;

  for (let i = 1; i <= la; i++) {
    currRow[0] = i;
    let rowMin = i;
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let val = Math.min(
        prevRow[j] + 1,
        currRow[j - 1] + 1,
        prevRow[j - 1] + cost
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        val = Math.min(val, prevPrevRow[j - 2] + 1);
      }
      currRow[j] = val;
      if (val < rowMin) rowMin = val;
    }
    if (rowMin > maxDistance) return false;
    for (let j = 0; j <= lb; j++) {
      prevPrevRow[j] = prevRow[j];
      prevRow[j] = currRow[j];
    }
  }

  return prevRow[lb] <= maxDistance;
}

function damerauLevenshteinDistance(a, b) {
  const la = a.length;
  const lb = b.length;
  if (a === b) return 0;
  if (la === 0) return lb;
  if (lb === 0) return la;

  const d = [];
  for (let i = 0; i <= la; i++) {
    d[i] = new Array(lb + 1);
    d[i][0] = i;
  }
  for (let j = 0; j <= lb; j++) d[0][j] = j;

  for (let i = 1; i <= la; i++) {
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1,
        d[i][j - 1] + 1,
        d[i - 1][j - 1] + cost
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[la][lb];
}

const SUBSTR_ED_CACHE = new Map();

function minSubstringEditDistance(label, token, maxDistance) {
  if (!label || !token) return -1;
  const cacheKey = maxDistance + "|" + token + "|" + label;
  const cached = SUBSTR_ED_CACHE.get(cacheKey);
  if (cached !== undefined) return cached;
  const tokenLen = token.length;
  const labelLen = label.length;
  let result;
  if (label.includes(token)) {
    result = 0;
  } else if (maxDistance <= 0 || labelLen < tokenLen - maxDistance) {
    result = -1;
  } else {
    const minWindow = Math.max(1, tokenLen - maxDistance);
    const maxWindow = Math.min(labelLen, tokenLen + maxDistance);
    let bestDist = maxDistance + 1;
    for (let w = minWindow; w <= maxWindow && bestDist > 1; w++) {
      for (let i = 0; i <= labelLen - w; i++) {
        const windowStr = label.slice(i, i + w);
        if (Math.abs(w - tokenLen) <= maxDistance) {
          const d = damerauLevenshteinDistance(windowStr, token);
          if (d <= maxDistance && d < bestDist) {
            bestDist = d;
            if (bestDist === 1) break;
          }
        }
      }
    }
    result = bestDist <= maxDistance ? bestDist : -1;
  }
  if (SUBSTR_ED_CACHE.size >= 300000) SUBSTR_ED_CACHE.clear();
  SUBSTR_ED_CACHE.set(cacheKey, result);
  return result;
}

function maxEditDistanceForLength(tokenLength, configuredMaxDist = 2, requireContext = false) {
  if (tokenLength <= 2) return 0;
  if (tokenLength === 3) return requireContext ? Math.min(configuredMaxDist, 1) : 0;
  if (tokenLength <= 6) return Math.min(configuredMaxDist, 1);
  return Math.min(configuredMaxDist, 2);
}

function substringEditDistanceAtMost(label, token, maxDistance) {
  if (!label || !token) return false;
  if (maxDistance <= 0) return label.includes(token);
  return minSubstringEditDistance(label, token, maxDistance) >= 0;
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
  if (typeof entry?.issuer === "string") return entry.issuer;
  if (typeof entry?.leaf_cert?.issuer === "string") return entry.leaf_cert.issuer;
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

function brandSignals(domain, data, passedHost = null, passedRegistrable = null) {
  const cfg = getScoringConfig(data);
  const w = cfg.weights;
  const signals = [];
  const host = passedHost || normalizeHost(domain);
  const idn = decodeIdn(domain);
  const hostCompact = compact(domain);
  const skeletonCompact = idn.skeleton ? compact(idn.skeleton) : "";
  const registrable = passedRegistrable !== null ? passedRegistrable : registrableDomain(host);
  const tld = suffixOfRegistrable(registrable);
  const subLabels = subdomainLabels(host, registrable).map(compact);
  const allLabels = host.split(".").map(compact);

  const skelLabels = idn.skeleton ? idn.skeleton.split(".").map(compact) : [];
  const leetLabels = allLabels.flatMap(leetCached).map(compact);
  const combinedLabels = [...new Set([...allLabels, ...skelLabels, ...leetLabels])];

  const combinedSubSet = new Set(subLabels);

  const affixKeywords = data?.affixKeywords || (data?.keywords?.keywords || []).filter((k) => k.affix).map((k) => compact(k.token));
  const candidateLabelsWithAffix = combinedLabels.flatMap((l) => decomposeLabel(l, affixKeywords));
  const candidateSet = new Set(candidateLabelsWithAffix);

  const keywordTokens = (data?.keywords?.keywords || []).map((k) => compact(k.token)).filter(Boolean);
  const hostLabelCount = host.split(".").length;
  const suffixLabelCount = registrable ? suffixOfRegistrable(registrable).split(".").length : 0;
  const rawHostSegments = new Set(
    host
      .split(".")
      .slice(0, Math.max(0, hostLabelCount - suffixLabelCount))
      .flatMap((part) => part.split(/[-_]/))
      .map(compact)
      .filter(Boolean)
  );
  const hostMask = charMask(hostCompact);
  for (const brand of data?.watchlist?.brands || []) {
    const brandTokens = brand._compactTokens || (brand.tokens || []).map(compact);
    if (!brandTokens.length) continue;

    let tokenPossible = false;
    for (let i = 0; i < brandTokens.length; i++) {
      const mask = brand._tokenMasks?.[i];
      if (!mask || maskSubset(mask, hostMask)) {
        tokenPossible = true;
        break;
      }
    }
    if (!tokenPossible) continue;

    const contextHit = !brand.require_context
      || (brand._compactContextTokens || (brand.context_tokens || []).map(compact)).some((tokenCompact) => {
        if (rawHostSegments.has(tokenCompact)) return true;
        return tokenCompact.length >= 4 && (hostCompact.includes(tokenCompact) || skeletonCompact.includes(tokenCompact));
      })
      || brandTokens.some((t) => rawHostSegments.has(t)) && keywordTokens.some((k) => hostCompact.includes(k));
    if (!contextHit) continue;

    const brandAllowlistedRegs = data?.allowlistByBrand?.[brand.id]
      || (data?.allowlist?.entries || []).filter((e) => e.verified && e.brand === brand.id).map((e) => e.registrable);
    const isBrandAllowlisted = registrable !== null && brandAllowlistedRegs.includes(registrable);

    for (let ti = 0; ti < brandTokens.length; ti++) {
      const tokenCompact = brandTokens[ti];
      const tMask = brand._tokenMasks?.[ti];
      if (tMask && !maskSubset(tMask, hostMask)) continue;
      // Anchor-grade exact match: whole delimited component in domain/subdomain position,
      // never raw substring containment and never public-suffix labels.
      let exact = candidateSet.has(tokenCompact)
        || combinedSubSet.has(tokenCompact);
      // Apex-self suppression: a single-label registrable that IS the brand token is the
      // legitimate brand site unless it sits on a TLD the brand disowns AND that TLD carries risk.
      const registrableCore = registrable
        ? compact(registrable.slice(0, Math.max(0, registrable.length - suffixOfRegistrable(registrable).length - 1)))
        : "";
      const tldRiskLists = data?.scoring?.tld_risk || cfg.tld_risk || {};
      const riskyTld = tldRiskLists.high?.includes(tld) || tldRiskLists.medium?.includes(tld);
      const apexBenign = tokenCompact === registrableCore
        && ((brand.known_tlds?.length && brand.known_tlds.includes(tld)) || !riskyTld);
      if (exact && apexBenign) {
        exact = false;
      }
      let matchType = null;
      let matchDist = 0;

      if (exact) {
        matchType = "brand:exact";
        matchDist = 0;
      } else {
        let effectiveMaxDist = maxEditDistanceForLength(tokenCompact.length, brand.max_edit_distance ?? 1, brand.require_context);
        if (effectiveMaxDist > 0) {
          for (const label of candidateLabelsWithAffix) {
            const digitCount = (label.match(/\d/g) || []).length;
            const digitHeavy = label.length > 0 && digitCount / label.length > 0.34;
            const nearLength = label.length <= tokenCompact.length + effectiveMaxDist + 1;
            if (digitHeavy || !nearLength) continue;
            const labelMask = charMask(label);
            if (tMask && popcount32(tMask.l & ~labelMask.l) + popcount32(tMask.d & ~labelMask.d) > effectiveMaxDist) continue;
            let cmpLabel = label;
            let cmpToken = tokenCompact;
            for (const morph of GENERIC_MORPHEMS) {
              if (label.endsWith(morph) && tokenCompact.endsWith(morph) && label !== morph && tokenCompact !== morph) {
                cmpLabel = label.slice(0, -morph.length);
                cmpToken = tokenCompact.slice(0, -morph.length);
                break;
              }
            }
            if (cmpToken !== tokenCompact) {
              effectiveMaxDist = Math.min(
                effectiveMaxDist,
                maxEditDistanceForLength(cmpToken.length, brand.max_edit_distance ?? 1, brand.require_context)
              );
            }

            const dist = minSubstringEditDistance(cmpLabel, cmpToken, effectiveMaxDist);
            if (dist > 0) {
              matchType = dist === 1 ? "brand:edit_distance_1" : "brand:edit_distance_2";
              matchDist = dist;
              break;
            }
          }
        }
      }

      // Squat detection is independent of brand-match: a whole hyphen/underscore-delimited
      // segment of a subdomain label equals the brand token or sits within the edit band of
      // it as a WHOLE string. No sliding windows: partial containment inside long random
      // labels is the dominant false-positive pump.
      const subEffectiveMaxDist = Math.min(
        1,
        maxEditDistanceForLength(tokenCompact.length, brand.max_edit_distance ?? 1, brand.require_context)
      );
      const apexSelf = tokenCompact === registrableCore;
      const squatSegments = [...rawHostSegments];
      const hasExplicitContext = (brand.context_tokens || []).some((ct) => hostCompact.includes(compact(ct)));
      const subSquat = squatSegments.some((seg) => {
        if (brand.id === "carousell" && seg.includes("carousel") && !seg.includes("carousell") && !hasExplicitContext) return false;
        if (seg === tokenCompact) return !apexBenign;
        if (subEffectiveMaxDist === 0) return false;
        if (Math.abs(seg.length - tokenCompact.length) > subEffectiveMaxDist) return false;
        return editDistanceAtMost(seg, tokenCompact, subEffectiveMaxDist);
      });

      if (!matchType && !subSquat) continue;

      if (matchType) {
        const points = matchType === "brand:exact"
          ? (w["brand:exact"] ?? 35)
          : (matchType === "brand:edit_distance_1"
            ? (w["brand:edit_distance_1"] ?? w["brand:fuzzy"] ?? 30)
            : (w["brand:edit_distance_2"] ?? 20));

        signals.push({
          type: matchType,
          brand: brand.id,
          display: brand.display,
          token: brand.tokens[ti],
          distance: matchDist,
          points
        });
      }

      if (!isBrandAllowlisted && subSquat) {
        signals.push({
          type: "subdomain_brand_squat",
          brand: brand.id,
          display: brand.display,
          token: brand.tokens[ti],
          points: w["subdomain:brand_squat"]
        });
      }

      // Brand in path position: full legitimate registrable domain appears as a subdomain prefix
      const pathPositionMatch = brandAllowlistedRegs.some(
        (reg) => host.startsWith(`${reg}.`) || host.includes(`.${reg}.`)
      );
      if (!isBrandAllowlisted && pathPositionMatch) {
        signals.push({
          type: "brand_in_path_position",
          brand: brand.id,
          display: brand.display,
          token: brand.tokens[ti],
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

function homoglyphSignals(domain, data, passedHost = null, passedRegistrable = null) {
  const cfg = getScoringConfig(data);
  const w = cfg.weights;
  const signals = [];
  const host = passedHost || normalizeHost(domain);
  const idn = decodeIdn(domain);

  if (idn.hasMixedScript) {
    signals.push({
      type: "mixed_script_label",
      points: w["mixed_script_label"] ?? 30
    });
  }

  const skeletonCompact = idn.skeleton ? compact(idn.skeleton) : "";
  const hostCompact = compact(host);

  // Check if punycode or Unicode skeleton matches a watched brand
  if (idn.isPunycode || (idn.skeleton && idn.skeleton !== host)) {
    for (const brand of data?.watchlist?.brands || []) {
      for (const token of brand.tokens || []) {
        const tokenCompact = compact(token);
        if (skeletonCompact.includes(tokenCompact)) {
          if (idn.isPunycode) {
            signals.push({
              type: "punycode_brand_match",
              brand: brand.id,
              display: brand.display,
              token,
              points: w["punycode_brand_match"] ?? 35
            });
          }
          if (idn.skeleton !== host && !hostCompact.includes(tokenCompact)) {
            signals.push({
              type: "confusable_skeleton_match",
              brand: brand.id,
              display: brand.display,
              token,
              skeleton: idn.skeleton,
              points: w["confusable_skeleton_match"] ?? 35
            });
          }
          break;
        }
      }
    }
  }

  // ASCII homoglyphs / Leetspeak matching
  const labels = host.split(".").map(compact);
  for (const label of labels) {
    const digits = (label.match(/\d/g) || []).length;
    if (label.length > 14 || (label.length > 0 && digits / label.length > 0.25)) continue;
    const leetCandidates = asciiHomoglyphs(label);
    for (const leet of leetCandidates) {
      for (const brand of data?.watchlist?.brands || []) {
        for (const token of brand.tokens || []) {
          const tokenCompact = compact(token);
          if (leet.includes(tokenCompact) && !hostCompact.includes(tokenCompact)) {
            signals.push({
              type: "homoglyph:ascii",
              brand: brand.id,
              display: brand.display,
              token,
              transformed: leet,
              points: w["homoglyph:ascii"] ?? 25
            });
            break;
          }
        }
      }
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

function isAllowlisted(domain, data, knownRegistrable = null) {
  const reg = knownRegistrable !== null ? knownRegistrable : registrableDomain(normalizeHost(domain));
  if (!reg) return false;
  if (data?.allowlistSet) return data.allowlistSet.has(reg);
  return (data?.allowlist?.entries || []).some((entry) => entry.verified && entry.registrable === reg);
}

function tldRiskSignals(registrable, data, hasThreatGateway = false) {
  if (!hasThreatGateway || !registrable) return [];
  const cfg = getScoringConfig(data);
  const w = cfg.weights;
  const tldRisk = cfg.tld_risk || defaultScoringConfig.tld_risk;
  const tld = suffixOfRegistrable(registrable).toLowerCase();
  const signals = [];

  if (tldRisk?.high?.includes(tld)) {
    signals.push({
      type: "tld_high_risk",
      tld,
      points: w["tld_high_risk"] ?? 12
    });
  } else if (tldRisk?.medium?.includes(tld)) {
    signals.push({
      type: "tld_medium_risk",
      tld,
      points: w["tld_medium_risk"] ?? 6
    });
  }

  return signals;
}

function domainAgeSignals(metadata, data, now = new Date()) {
  if (!metadata) return [];
  const cfg = getScoringConfig(data);
  const w = cfg.weights;
  const signals = [];

  const createdAt = metadata.created_at || metadata.creation_date || metadata.registration_date;
  let ageDays = metadata.domain_age_days;

  if (ageDays === undefined && createdAt) {
    const createdMs = new Date(createdAt).getTime();
    const nowMs = typeof now === "number" ? now : new Date(now).getTime();
    ageDays = Math.max(0, Math.floor((nowMs - createdMs) / (1000 * 86400)));
  }

  if (typeof ageDays === "number" && !Number.isNaN(ageDays)) {
    if (ageDays < 7) {
      signals.push({
        type: "domain_age_under_7d",
        age_days: ageDays,
        points: w["domain_age_under_7d"] ?? 20
      });
    } else if (ageDays < 30) {
      signals.push({
        type: "domain_age_under_30d",
        age_days: ageDays,
        points: w["domain_age_under_30d"] ?? 10
      });
    }
  }

  return signals;
}

const FREE_DV_ISSUERS = [
  "let's encrypt",
  "zerossl",
  "cpanel",
  "google trust services",
  "gts ca",
  "cloudflare",
  "buypass go",
  "ssl.com dv"
];

function certificateSignals(entry, data, now = new Date()) {
  const cfg = getScoringConfig(data);
  const w = cfg.weights;
  const signals = [];
  const issuer = issuerName(entry).toLowerCase();

  if (FREE_DV_ISSUERS.some((ca) => issuer.includes(ca))) {
    signals.push({
      type: "issuer_free_dv",
      issuer: issuerName(entry),
      points: w["issuer_free_dv"] ?? 8
    });
  }

  const notBeforeStr = entry?.not_before || entry?.leaf_cert?.not_before;
  if (notBeforeStr) {
    const notBeforeMs = new Date(notBeforeStr).getTime();
    const nowMs = typeof now === "number" ? now : new Date(now).getTime();
    const ageMs = nowMs - notBeforeMs;
    if (ageMs >= 0 && ageMs < 3600 * 1000) {
      signals.push({
        type: "cert_age_under_1h",
        points: w["cert_age_under_1h"] ?? 10
      });
    } else if (ageMs >= 0 && ageMs < 24 * 3600 * 1000) {
      signals.push({
        type: "cert_age_under_24h",
        points: w["cert_age_under_24h"] ?? 5
      });
    }
  }

  const sanCount = entry?.san_count || (extractDomains(entry) || []).length;
  if (sanCount > 20) {
    signals.push({
      type: "san_count_over_20",
      san_count: sanCount,
      points: w["san_count_over_20"] ?? 5
    });
  }

  return signals;
}

function scoreDomain(domain, data, now = new Date(), domainMetadata = null) {
  const cfg = getScoringConfig(data);
  const host = normalizeHost(domain);
  const registrable = registrableDomain(host);
  if (isAllowlisted(host, data, registrable)) {
    return {
      domain: host,
      registrable,
      score: 0,
      scoring_version: cfg.version,
      severity: "none",
      suppressed: true,
      signals: [{ type: "allowlist", registrable, points: 0 }]
    };
  }

  const brandSigs = brandSignals(domain, data, host, registrable);
  const homoglyphSigs = homoglyphSignals(domain, data, host, registrable);
  const kwSigs = keywordSignals(domain, data);
  const schemeSigs = schemeSignals(domain, data, now);

  const hasBrand = brandSigs.some((s) => s.type.startsWith("brand:"))
    || homoglyphSigs.some((s) => s.type === "punycode_brand_match" || s.type === "confusable_skeleton_match" || s.type === "homoglyph:ascii");
  const hasScheme = schemeSigs.some((s) => s.type === "scheme");
  const hasKw = kwSigs.some((s) => s.type === "kw");
  const hasThreatGateway = hasBrand || hasScheme || hasKw;

  const tldSigs = tldRiskSignals(registrable, data, hasThreatGateway);
  const ageSigs = domainAgeSignals(domainMetadata, data, now);

  const signals = [
    ...brandSigs,
    ...homoglyphSigs,
    ...kwSigs,
    ...schemeSigs,
    ...tldSigs,
    ...ageSigs
  ];

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
  const maxCap = cfg.caps?.total ?? 150;
  const anchorTypes = Array.isArray(cfg.anchor_signals) ? cfg.anchor_signals : [];
  const hasAnchor = signals.some((s) => anchorTypes.includes(s.type));
  const noAnchorCap = cfg.thresholds?.no_anchor_score_cap;
  let score = Math.min(rawScore, maxCap);
  if (!hasAnchor && typeof noAnchorCap === "number") {
    score = Math.min(score, noAnchorCap);
  }

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

function scoreCertificate(entry, data, now = new Date()) {
  const cfg = getScoringConfig(data);
  const domains = extractDomains(entry);
  const scoredDomains = domains.map((domain) => scoreDomain(domain, data, now, entry?.domain_metadata || entry?.rdap));
  const active = scoredDomains.filter((item) => !item.suppressed && item.score > 0);
  if (!active.length) return null;

  active.sort((a, b) => b.score - a.score);
  const top = active[0];
  const domainSignals = active.flatMap((item) => item.signals.map((signal) => ({ ...signal, domain: item.domain })));
  const certSigs = certificateSignals(entry, data, now);

  const signals = [
    ...domainSignals,
    ...certSigs
  ];

  const matchedBrands = [...new Set(signals.map((signal) => signal.brand).filter(Boolean))];
  const matchedSchemes = [...new Set(signals.map((signal) => signal.scheme).filter(Boolean))];

  const certPoints = certSigs.reduce((tot, s) => tot + (s.points || 0), 0);
  const maxCap = cfg.caps?.total ?? 150;
  const anchorSignals = Array.isArray(cfg.anchor_signals) ? cfg.anchor_signals : [];
  const hasAnchor = signals.some((s) => anchorSignals.includes(s.type));
  const noAnchorCap = cfg.thresholds?.no_anchor_score_cap;
  let totalScore = Math.min(top.score + certPoints, maxCap);
  if (!hasAnchor && typeof noAnchorCap === "number") {
    totalScore = Math.min(totalScore, noAnchorCap);
  }

  return {
    id: findingId(entry, top),
    scoring_version: top.scoring_version ?? cfg.version,
    observed_at: new Date((entry?.seen || entry?.data?.seen || Date.now() / 1000) * 1000).toISOString(),
    certificate_not_before: entry?.not_before || entry?.leaf_cert?.not_before || null,
    registrable: top.registrable,
    domains,
    score: totalScore,
    severity: severity(totalScore, cfg.thresholds),
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
  damerauLevenshteinDistance,
  minSubstringEditDistance,
  maxEditDistanceForLength,
  extractDomains,
  registrableDomain,
  scoreCertificate,
  scoreDomain
};
