/**
 * lib/ui/related-findings.js
 *
 * Pure ES module — no DOM, no fetch.
 * Groups findings by explicit, bounded relationships.
 *
 * Three independently labelled groups:
 *   1. exact-cert: exact nonempty (cert_serial, cert_issuer_dn_sha256) tuple
 *   2. same-registrable: same registrable domain
 *   3. shared-brand: shared matched brand
 *
 * Rules:
 * - Null/missing certificate identifiers never create an identity match.
 * - The issuer fingerprint alone is NOT certificate identity.
 * - Counts are loaded counts, not global campaign totals.
 * - Report related leads, never common attacker or inherited intel confidence.
 */

/**
 * Find findings related to a target finding from a loaded set.
 *
 * @param {object} target  the finding to find relations for
 * @param {object[]} allFindings  the full loaded set (including target)
 * @returns {{
 *   exactCert: object[],
 *   sameRegistrable: object[],
 *   sharedBrand: object[],
 * }}
 */
export function findRelated(target, allFindings) {
  if (!target || !Array.isArray(allFindings)) {
    return { exactCert: [], sameRegistrable: [], sharedBrand: [] };
  }

  const others = allFindings.filter((f) => f.id !== target.id && !f.suppressed);

  // Group 1: exact certificate identity
  // Both cert_serial AND cert_issuer_dn_sha256 must be nonempty and match.
  // The issuer fingerprint alone is not identity.
  const exactCert = (
    target.cert_serial && target.cert_issuer_dn_sha256
      ? others.filter((f) =>
          f.cert_serial &&
          f.cert_issuer_dn_sha256 &&
          f.cert_serial === target.cert_serial &&
          f.cert_issuer_dn_sha256 === target.cert_issuer_dn_sha256
        )
      : []
  );

  // Group 2: same registrable domain
  const sameRegistrable = target.registrable
    ? others.filter((f) => f.registrable === target.registrable && !exactCert.includes(f))
    : [];

  // Group 3: shared matched brand (at least one brand in common)
  const targetBrands = new Set(target.matched_brands ?? []);
  const sharedBrand = targetBrands.size > 0
    ? others.filter((f) =>
        !exactCert.includes(f) &&
        !sameRegistrable.includes(f) &&
        (f.matched_brands ?? []).some((b) => targetBrands.has(b))
      )
    : [];

  return { exactCert, sameRegistrable, sharedBrand };
}

/**
 * Render related findings as HTML sections.
 * Each group is independently labelled.
 * Overlapping findings show multiple reasons.
 *
 * @param {object} target
 * @param {object[]} allFindings
 * @param {function} escapeHtml  HTML escaping function
 * @returns {string} HTML
 */
export function renderRelated(target, allFindings, escapeHtml) {
  const { exactCert, sameRegistrable, sharedBrand } = findRelated(target, allFindings);

  const total = new Set([
    ...exactCert.map((f) => f.id),
    ...sameRegistrable.map((f) => f.id),
    ...sharedBrand.map((f) => f.id),
  ]).size;

  if (total === 0) {
    return `<p class="muted-text">No related findings in loaded results.</p>
<p class="muted-text">Use "Find in stored history" to search the full database.</p>`;
  }

  // Build a merged list with reasons
  const byId = new Map();
  for (const f of exactCert) {
    if (!byId.has(f.id)) byId.set(f.id, { finding: f, reasons: [] });
    byId.get(f.id).reasons.push("Same certificate (serial + issuer)");
  }
  for (const f of sameRegistrable) {
    if (!byId.has(f.id)) byId.set(f.id, { finding: f, reasons: [] });
    byId.get(f.id).reasons.push("Same registrable domain");
  }
  for (const f of sharedBrand) {
    if (!byId.has(f.id)) byId.set(f.id, { finding: f, reasons: [] });
    byId.get(f.id).reasons.push("Shared matched brand");
  }

  const items = [...byId.values()].map(({ finding: f, reasons }) => {
    const reasonList = reasons.map((r) => `<span class="related-reason">${escapeHtml(r)}</span>`).join(" ");
    return `<li class="related-finding">
      <strong>${escapeHtml(f.registrable)}</strong>
      <span class="severity ${escapeHtml(f.severity)}">${escapeHtml(f.severity)} ${escapeHtml(f.score ?? 0)}</span>
      <div class="related-reasons">${reasonList}</div>
      <p class="muted-text">These are investigative leads, not evidence of a shared attacker.</p>
    </li>`;
  }).join("");

  return `<p class="muted-text">In loaded results (${total} finding${total === 1 ? "" : "s"}):</p>
<ul class="related-list">${items}</ul>
<p class="muted-text">Use "Find in stored history" to search beyond the loaded set.</p>`;
}
