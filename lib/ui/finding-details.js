/**
 * lib/ui/finding-details.js
 *
 * Pure ES module — no DOM access, no fetch.
 * Exports the dialog body HTML renderer so it can be tested and reused
 * independently of the DOM manipulation in openFindingDetails (app.js).
 */

/**
 * Render the inner HTML for the triage dialog body.
 *
 * All helper functions must be passed in so this module stays pure.
 * The returned string is identical to the body.innerHTML assignment
 * inside openFindingDetails() in app.js.
 *
 * @param {object} finding
 * @param {{
 *   escapeHtml: function,
 *   formatTime: function,
 *   signalText: function,
 *   renderPriority: function,
 *   renderIntelEvidence: function,
 *   intelEvidence: function,
 *   intelProviderUrl: function,
 *   intelHitCount: function,
 *   priorityScore: function,
 *   sourceLabel: function,
 *   intelVerdict: function,
 * }} helpers
 * @returns {string} HTML string
 */
export function renderDialogBody(finding, {
  escapeHtml,
  formatTime,
  signalText,
  renderPriority,
  renderIntelEvidence,
  intelEvidence,
  intelProviderUrl,
  intelHitCount,
  priorityScore,
  sourceLabel,
  intelVerdict,
}) {
  const signalsRows = (finding.signals || []).map((s) => `
    <tr>
      <td><code>${escapeHtml(s.type)}</code></td>
      <td><strong>+${escapeHtml(s.points || 0)}</strong></td>
      <td>${escapeHtml(signalText(s))}</td>
    </tr>
  `).join("");

  return `
    <div class="dialog-header">
      <div>
        <p class="eyebrow dark">Triage Investigation</p>
        <h2 id="finding-dialog-title">${escapeHtml(finding.registrable)}</h2>
      </div>
      <button type="button" class="btn-close" id="close-dialog-btn" aria-label="Close finding details">&times;</button>
    </div>

    <div class="dialog-summary">
      <div class="summary-badge severity ${escapeHtml(finding.severity)}">
        CT ${escapeHtml(finding.severity).toUpperCase()} (${escapeHtml(finding.score)} pts)
      </div>
      <div class="summary-info">
        <span>Observed: ${escapeHtml(formatTime(finding.observed_at))}</span>
        <span>Issuer: ${escapeHtml(finding.issuer || "Unknown CA")}</span>
        <span>SANs: ${escapeHtml((finding.domains || []).length)}</span>
      </div>
    </div>

    ${renderPriority(finding)}
    ${renderIntelEvidence(finding)}

    <section class="dialog-section">
      <h3>Analyst Actions</h3>
      <div class="dialog-actions">
        <button type="button" id="copy-triage-btn" class="btn-secondary">Copy Triage Report</button>
        <button type="button" id="print-report-btn" class="btn-secondary">Print report</button>
      </div>
      <p class="muted-text">Live probing is performed by analysts off-platform; this dashboard never fetches a suspected hostile host from production.</p>
    </section>

    <section class="dialog-section">
      <h3>Triggered Scoring Signals</h3>
      <table class="signals-table">
        <thead>
          <tr><th>Signal</th><th>Points</th><th>Detail</th></tr>
        </thead>
        <tbody>
          ${signalsRows || "<tr><td colspan='3'>No signals recorded</td></tr>"}
        </tbody>
      </table>
    </section>

    <section class="dialog-section">
      <h3>Certificate Identity & SANs</h3>
      <p><strong>Domains:</strong> <code>${escapeHtml((finding.domains || []).join(", "))}</code></p>
      <p><strong>Serial:</strong> <code>${escapeHtml(finding.cert_serial || "N/A")}</code></p>
      <p><strong>Issuer DN SHA256:</strong> <code>${escapeHtml(finding.cert_issuer_dn_sha256 || "N/A")}</code></p>
    </section>
  `;
}
