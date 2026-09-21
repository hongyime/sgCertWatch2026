# sgCertWatch Design System

Extracted from `styles.css` and `app.js`. This document is the single source of
truth for visual decisions. Every colour, font size, spacing value and component
pattern used in the dashboard is catalogued here.

---

## §1 Identity

### Palette — CSS custom properties (`:root`)

| Token | Value | Usage |
|---|---|---|
| `--ink` | `#17212b` | Default body text |
| `--muted` | `#667381` | Secondary / meta text |
| `--paper` | `#ffffff` | Card and dialog backgrounds |
| `--soft` | `#f4f6f2` | Page background |
| `--line` | `#dce3e8` | Borders, dividers |
| `--teal` | `#0f8b8d` | Primary accent, active states |
| `--teal-soft` | `#dff5f1` | Status badge backgrounds |
| `--amber` | `#a66516` | Medium/low severity, warnings |
| `--red` | `#b73845` | High/critical severity, primary-feed accent |
| `--navy` | `#122033` | Top bar background, skip-link background |
| `--blue` | `#2f5f98` | Review-feed accent, promoted-priority text, evidence links |

Supplementary literal colours used in components (not tokens):
- `#9ddfd5` — eyebrow text on dark backgrounds
- `#d6e3ea` — tagline and inactive nav button text
- `#f9fbfc` — top-bar text and skip-link foreground
- `#405064` — secondary content labels, priority text
- `#3d4a58` — card paragraph text
- `#edf3f7` — token-list span background

### Font stack

```css
font-family: "Aptos", "Segoe UI", ui-sans-serif, system-ui, sans-serif;
```

Applied at `:root`; inherited everywhere. No remote fonts loaded.

---

## §2 Typography

| Element | Size | Weight | Line-height | Notes |
|---|---|---|---|---|
| `h1` | 34 px | default (400) | 1.1 | Top-bar product name |
| `h2` | 22 px | default | 1.15 | Section headings, dialog title |
| `h3` (dialog sections) | 14 px | default | — | Uppercase, `color: var(--navy)` |
| `h3` (Intel health) | 16 px | default | — | Non-uppercase |
| Body / `p` | 14–15 px | 400 | 1.45 | Card paragraphs at 14 px, tagline at 15 px |
| `.eyebrow` | 12 px | 800 | — | Uppercase, letter-spacing 0 |
| `.eyebrow.dark` | 12 px | 800 | — | `color: var(--teal)` |
| Meta / labels | 12–13 px | 700 | — | `.watch-meta`, status tiles |
| Nav buttons | 14 px | 800 | — | Height 38 px, border-radius 6 px |
| Severity badge | 11 px | 800 | — | Uppercase |

---

## §3 Spacing

### Global layout

| Token | Value | Applied to |
|---|---|---|
| Top-bar horizontal padding | `clamp(18px, 4vw, 48px)` | `.topbar` |
| Main horizontal padding | `clamp(16px, 3vw, 40px)` | `main` |
| Main bottom padding | 44 px | `main` |
| Main max-width | 1400 px | `main` |

### Components

| Pattern | Value | Applied to |
|---|---|---|
| Card padding | 14 px | `.watch-card` |
| Section / feed padding | 18 px | `.feed`, `.readiness`, `.watch-hero`, `.config-explorer` |
| Dialog inner padding | 24 px (16 px at ≤ 760 px) | `.dialog-content` |
| Section-heading margin-bottom | 14 px | `.section-heading` |
| Watch-list gap | 10 px | `.watch-list` |
| Topbar grid gap | 18 px | `.topbar` |
| Watch-card-head gap | 10 px | `.watch-card-head` |
| Watch-meta gap | 8 px × 12 px | `.watch-meta` |
| Token-list gap | 6 px | `.token-list` |
| Intel-badges gap | 6 px | `.intel-badges` |
| Finding-priority margin | 10 px top + bottom | `.finding-priority` |
| Attention-grid gap | 18 px | `.attention-grid` |
| Status-grid gap | 10 px | `.status-grid` |

---

## §4 Components

### `.watch-card`

Base card for both finding alerts and manual-review entries.

```
padding: 14px
border: 1px solid #e3e8ed
border-radius: 8px
background: #fbfcfd
```

Variants:
- `.finding-card` — `border-left: 4px solid var(--red)`
- `.review-card` — `border-left: 4px solid var(--blue)`
- `.interactive-card` — adds `cursor: pointer`, hover lift (`translateY(-1px)`), teal border-color on hover

### `.severity` badges

Inline label rendered inside `.watch-card-head`.

```
display: inline-block
padding: 3px 7px
border-radius: 4px
font-size: 11px
font-weight: 800
text-transform: uppercase
color: #ffffff
```

Colour by severity level:

| Class | Background |
|---|---|
| `.severity.critical` | `var(--red)` |
| `.severity.high` | `var(--red)` |
| `.severity.medium` | `var(--amber)` |
| `.severity.low` | `var(--amber)` |
| default | `#405064` |

### `.review-badge`

Same shape as `.severity`; uses `var(--amber)` background. Variant `.review-badge.ok` uses `var(--teal)`.

### `.intel-badges`

Flex row of source attribution badges inside a finding card.

```
display: flex; flex-wrap: wrap; align-items: center; gap: 6px; font-size: 12px
```

- `.intel-count` — muted label (`color: #405064; font-weight: 700`)
- `.intel-source-badge` — pill with `border: 1px solid var(--line); background: #edf3f7`
- `.intel-verdict` — same shape; `.intel-verdict.phishing` and `.malware` use `#fff1f3` background / `#902b37` text

### `.finding-priority`

Score breakdown line below the card heading.

```
display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px 12px
margin: 10px 0; font-size: 13px; color: #405064
```

- `.finding-priority.promoted` — text colour `var(--blue)`
- `.promotion-label` — `font-weight: 700`

### `.token-list`

Pill-shaped keyword list used in card reasons and watchlist table cells.

```
display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px
```

Each `<span>`: `padding: 3px 7px; background: #edf3f7; border-radius: 999px; font-size: 12px`

### `.btn-secondary`

Secondary action button (Export JSON / CSV, Copy Triage Report).

```
padding: 6px 12px; min-height: 40px; font-size: 13px; font-weight: 600
border-radius: 6px; background: var(--soft); color: var(--navy)
border: 1px solid var(--line)
```

Hover: `background: #e6ebef`

### `.btn-close`

Dialog close button (×).

```
background: none; border: none; font-size: 24px; cursor: pointer
color: var(--muted); flex: 0 0 36px; width: 36px; height: 36px
```

Hover: `color: var(--ink)`

---

## §5 Primitives

Two rendering modules live in `lib/ui/`. They are pure ES modules with no DOM
access and no `fetch` calls; all helpers they need are either defined locally or
passed in as parameters.

### `lib/ui/findings-list.js`

| Export | Signature | Description |
|---|---|---|
| `renderFindingCard` | `(finding, index) → string` | Renders a `<li class="watch-card finding-card interactive-card">` for the live alerts list. |
| `renderReviewCard` | `(entry) → string` | Renders a `<li class="watch-card review-card">` for the manual-review list. |
| `filteredFindings` | `(state) → Array` | Filters and sorts a findings array; takes `state` as a parameter so the function is pure. |

Internal helpers bundled in the module (verbatim copies from `app.js`):
`escapeHtml`, `unique`, `tokenList`, `sourceLabel`, `intelEvidence`,
`intelHitCount`, `intelVerdict`, `priorityScore`, `renderPriority`,
`renderIntelBadges`, `signalText`, `renderReasons`, `formatTime`.

### `lib/ui/finding-details.js`

| Export | Signature | Description |
|---|---|---|
| `renderDialogBody` | `(finding, helpers) → string` | Returns the full inner HTML for `#dialog-body` — identical to the `body.innerHTML` assignment in `openFindingDetails()` in `app.js`. |

`helpers` is a destructured object: `{ escapeHtml, formatTime, signalText, renderPriority, renderIntelEvidence, intelEvidence, intelProviderUrl, intelHitCount, priorityScore, sourceLabel, intelVerdict }`.

`app.js` imports both modules via dynamic `import()` inside the call-site
functions (`renderFindingList`, `renderSummary`) to avoid the fixture allowlist
constraint in Playwright workbench tests.

---

## §6 Accessibility

### Skip-to-main link

A visually-hidden-until-focused anchor is the first child of `<body>`:

```html
<a href="#main-content" class="skip-link">Skip to main content</a>
```

`<main>` carries `id="main-content"` as the skip target.

CSS pattern:

```css
.skip-link {
  position: absolute;
  top: -40px;
  left: 0;
  padding: 8px 16px;
  background: var(--navy);
  color: #f9fbfc;
  font-size: 14px;
  font-weight: 700;
  text-decoration: none;
  z-index: 100;
  transition: top 0.2s;
}
.skip-link:focus {
  top: 0;
}
```

### `aria-current` on the active navigation button

`setView(view)` in `app.js` sets `aria-current="page"` on the active
`[data-view]` button and removes it from all others. This gives screen readers a
reliable current-page signal without requiring a separate ARIA live region.

### Focus ring

Existing `:focus-visible` rule on `.interactive-card`:

```css
.interactive-card:focus-visible {
  outline: 2px solid var(--teal);
  outline-offset: 2px;
}
```

Interactive finding cards carry `tabindex="0" role="button"` so they are
keyboard-reachable. `Enter` or `Space` on a card fires the click handler.

### Dialog

`<dialog id="finding-dialog">` uses the native `showModal()` / `close()` API,
which manages focus trap and `Escape` dismissal automatically.
`aria-labelledby="finding-dialog-title"` links the dialog to its `<h2>`.

---

## §7 Responsive

| Breakpoint | Changes |
|---|---|
| `max-width: 1050px` | `.topbar` collapses to single column; `.primary-nav` becomes full-width scrollable; `.status-grid` and `.summary` become 3-column; `.attention-grid` becomes single column |
| `max-width: 800px` | `.monitor-metrics` becomes 2-column (4 → 2) |
| `max-width: 760px` | `.topbar`, `.section-heading`, `.config-heading` stack vertically; `.status-grid`, `.source-list`, `.summary`, `.toolbar` become single column; `.mode-tabs` left-aligns and wraps; `.intel-health .source-list` becomes single column; `.triage-select` expands to full width; `.dialog-content` padding reduces to 16 px; `.evidence-facts > div` stacks to single column |

---

## §8 Print

`@media print` hides chrome and reveals triage content for printed reports:

Elements hidden:
`.topbar`, `.primary-nav`, `.triage-toolbar`, `.coverage-strip`,
`.triage-dialog .dialog-actions`, `.btn-close`, `.site-footer`,
`#export-json-btn`, `#export-csv-btn`

Elements forced visible:
- `.triage-dialog { display: block !important; }` — shows dialog content inline
- `.dialog-content { width: 100% !important; max-width: none !important; }`
