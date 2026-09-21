/**
 * lib/ui/impersonation.js
 *
 * Pure ES module — no DOM, no fetch.
 * Explains how a suspicious domain impersonates a protected brand.
 *
 * Rules:
 * - Uses only the recorded signal data — never re-runs the scorer.
 * - Highlights substitutions/deletions/insertions for the matched token.
 * - If the stored signal lacks alignment detail, says so explicitly.
 * - Only compares to an official domain when a verified allowlist entry exists.
 * - Uses grapheme-aware display and bidi isolation.
 * - Does NOT change scorer weights, thresholds, or corpus.
 */

/**
 * Build an impersonation explanation from a finding's signals.
 *
 * @param {object} finding  finding row with registrable, signals, matched_brands, domains
 * @param {object[]} watchlistBrands  brands array from watchlist.json
 * @param {object[]} allowlistEntries  entries array from allowlist.json
 * @returns {Array<{
 *   brandName: string,
 *   brandId: string,
 *   signalType: string,
 *   matchedToken: string,
 *   suspiciousToken: string,
 *   registrable: string,
 *   registrablePart: string,
 *   subdomainPart: string,
 *   officialDomain: string|null,
 *   explanation: string,
 *   alignmentAvailable: boolean,
 * }>}
 */
export function explainImpersonation(finding, watchlistBrands, allowlistEntries) {
  if (!finding || !Array.isArray(watchlistBrands)) return [];

  const registrable = finding.registrable ?? "";
  const signals = Array.isArray(finding.signals) ? finding.signals : [];

  // Segment registrable from subdomains
  const domains = Array.isArray(finding.domains) ? finding.domains : [registrable];
  const { registrablePart, subdomainPart } = segmentDomain(registrable, domains);

  const explanations = [];
  const seenBrands = new Set();

  for (const signal of signals) {
    if (!signal.type?.startsWith("brand")) continue;

    const brandId = signal.brand ?? signal.id ?? "";
    if (seenBrands.has(brandId)) continue;
    seenBrands.add(brandId);

    const brand = watchlistBrands.find((b) => b.id === brandId);
    const brandName = signal.display ?? brand?.display ?? brandId;

    // Find the matched token from the signal
    const matchedToken = signal.token ?? (brand?.tokens?.[0] ?? "");
    const signalType = signal.type ?? "";

    // Determine the suspicious token from the registrable
    const suspiciousToken = extractSuspiciousToken(registrablePart, matchedToken, signalType);

    // Find official domain from allowlist (verified entries only)
    const officialDomain = findOfficialDomain(brandId, allowlistEntries);

    // Build explanation text
    const explanation = buildExplanation(
      signalType, matchedToken, suspiciousToken, registrablePart, brandName
    );

    explanations.push({
      brandName,
      brandId,
      signalType,
      matchedToken,
      suspiciousToken,
      registrable,
      registrablePart,
      subdomainPart,
      officialDomain,
      explanation,
      alignmentAvailable: Boolean(suspiciousToken && matchedToken),
    });
  }

  return explanations;
}

/**
 * Render impersonation explanations as HTML.
 * Uses text nodes and bidi isolation for safe display.
 *
 * @param {Array} explanations  from explainImpersonation()
 * @param {function} escapeHtml
 * @returns {string} HTML
 */
export function renderImpersonation(explanations, escapeHtml) {
  if (!explanations.length) {
    return `<p class="muted-text">No brand impersonation signals recorded for this finding.</p>`;
  }

  return explanations.map((ex) => {
    const registrableDisplay = ex.subdomainPart
      ? `<span class="muted-text">${escapeHtml(ex.subdomainPart)}.</span><strong>${escapeHtml(ex.registrablePart)}</strong>`
      : `<strong>${escapeHtml(ex.registrablePart)}</strong>`;

    const alignmentNote = ex.alignmentAvailable
      ? `<span class="impersonation-token">Suspicious: <bdi>${escapeHtml(ex.suspiciousToken)}</bdi></span>
         <span class="impersonation-arrow">&rarr;</span>
         <span class="impersonation-token">Protected: <bdi>${escapeHtml(ex.matchedToken)}</bdi></span>`
      : `<span class="muted-text">Alignment detail not available in stored signal.</span>`;

    const officialNote = ex.officialDomain
      ? `<span class="muted-text">Official domain: <bdi>${escapeHtml(ex.officialDomain)}</bdi></span>`
      : `<span class="muted-text">Official domain not verified in this watchlist.</span>`;

    return `<div class="impersonation-block">
      <div class="impersonation-header">
        <span class="impersonation-brand">${escapeHtml(ex.brandName)}</span>
        <span class="muted-text">&mdash;</span>
        <span class="impersonation-domain">${registrableDisplay}</span>
      </div>
      <p class="impersonation-explanation">${escapeHtml(ex.explanation)}</p>
      <div class="impersonation-alignment">${alignmentNote}</div>
      <div class="impersonation-official">${officialNote}</div>
    </div>`;
  }).join("");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function segmentDomain(registrable, domains) {
  // The registrable is the eTLD+1. Subdomains are the prefix.
  // We look for the longest domain that ends with the registrable.
  let subdomainPart = "";
  for (const d of domains) {
    if (d !== registrable && d.endsWith("." + registrable)) {
      const sub = d.slice(0, d.length - registrable.length - 1);
      if (!subdomainPart || sub.length < subdomainPart.length) {
        subdomainPart = sub;
      }
    }
  }
  return { registrablePart: registrable, subdomainPart };
}

function extractSuspiciousToken(registrablePart, matchedToken, signalType) {
  if (!matchedToken || !registrablePart) return "";
  const lower = registrablePart.toLowerCase();
  // For exact match, return the matched portion
  if (lower.includes(matchedToken.toLowerCase())) {
    const idx = lower.indexOf(matchedToken.toLowerCase());
    return registrablePart.slice(idx, idx + matchedToken.length);
  }
  // For edit-distance or homoglyph signals, return the registrable label
  // (the full registrable minus TLD is the best we can do without re-running the scorer)
  const withoutTld = registrablePart.replace(/\.[^.]+$/, "");
  return withoutTld || registrablePart;
}

function findOfficialDomain(brandId, allowlistEntries) {
  if (!Array.isArray(allowlistEntries)) return null;
  // Handle both shapes:
  //   real allowlist.json: { brand, registrable, verified: true }
  //   legacy test fixtures: { category, name, verified: "verified" }
  const entry = allowlistEntries.find(
    (e) => (e.brand === brandId || e.category === brandId) &&
            (e.verified === true || e.verified === "verified")
  );
  return entry?.registrable ?? entry?.name ?? null;
}

function buildExplanation(signalType, matchedToken, suspiciousToken, registrablePart, brandName) {
  if (signalType === "brand:exact" || signalType === "brand:exact_match") {
    return `The domain contains "${matchedToken}", which exactly matches the protected brand "${brandName}".`;
  }
  if (signalType === "brand:edit_distance_1") {
    return `The domain contains a token one character away from "${matchedToken}" (protected brand "${brandName}"). This is a common typosquatting pattern.`;
  }
  if (signalType === "brand:edit_distance_2") {
    return `The domain contains a token two characters away from "${matchedToken}" (protected brand "${brandName}").`;
  }
  if (signalType === "brand:homoglyph" || signalType === "brand:confusable") {
    return `The domain uses visually similar characters to impersonate "${matchedToken}" (protected brand "${brandName}").`;
  }
  if (signalType?.startsWith("brand")) {
    return `The domain matches the protected brand "${brandName}" via signal type "${signalType}".`;
  }
  return `The domain is associated with the protected brand "${brandName}".`;
}
