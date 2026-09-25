# WCAG 2.2 AA Accessibility Audit — Harpocrates Frontend

**Scope:** Evidence Studio, Verification Portal, landing page, navigation, and all shared UI  
**Standard:** WCAG 2.2 Level AA  
**Date:** 2026-07-24  
**Status:** Implemented and verified

---

## Overview

This document records the accessibility implementation for the Harpocrates frontend (`frontend/src`). It covers the WCAG 2.2 AA success criteria addressed, the implementation approach, privacy constraints on operational signals, local verification steps, deployment impact, rollback notes, and known limitations.

---

## Success Criteria Addressed

### Perceivable

| Criterion | Implementation |
|-----------|----------------|
| 1.1.1 Non-text Content | SVG workflow diagram has `<title>` and `aria-labelledby`; decorative icons use `aria-hidden="true"`; EvilEye WebGL canvas container is `aria-hidden="true"` |
| 1.3.1 Info and Relationships | Nav uses `<nav aria-label="Site navigation">`; tier tabs use `role="group"`; seed inputs have explicit `<label htmlFor>`; `<dl>` has `aria-label`; event list uses `role="list"` with `role="listitem"` |
| 1.3.3 Sensory Characteristics | Selected tier indicated by `aria-pressed` (not colour alone); active tier tab also has `box-shadow` border, not just background colour |
| 1.4.1 Use of Colour | Tier tab active state adds `box-shadow: inset 0 0 0 1px rgba(255,255,255,0.38)` in addition to background change |
| 1.4.3 Contrast (Minimum) | Data-list `dt` raised from 0.38 to 0.62 opacity (~4.5:1 on dark background); `dd` raised to 0.92; page header sub-text raised to 0.72; lede text raised to 0.78; rail block headings raised to 0.62 |
| 1.4.4 Resize Text | Layout uses `clamp()`, relative units, and flexbox/grid — no fixed-pixel text containers that clip at 200% zoom |
| 1.4.10 Reflow | Workspace grid collapses to single column at 980 px; secret-grid collapses to single column at 680 px |
| 1.4.11 Non-text Contrast | Focus ring is 2 px solid `#4a9eff` (blue on dark ≥ 3:1); skip-link has white background with 2 px `#4a9eff` outline |
| 1.4.13 Content on Hover/Focus | No content appears exclusively on hover without keyboard equivalent |

### Operable

| Criterion | Implementation |
|-----------|----------------|
| 2.1.1 Keyboard | All interactive elements are native `<button>`, `<a>`, or `<input>` — fully keyboard accessible; no `tabIndex` traps |
| 2.1.2 No Keyboard Trap | Skip-link and standard DOM order; no modal overlays trapping focus |
| 2.4.1 Bypass Blocks | Skip-to-content link (`<a href="#main-content" class="skip-link">`) is the first focusable element; it renders visibly on focus |
| 2.4.3 Focus Order | View transitions move focus to the target view's `<h2>` via `studioHeadingRef` / `verifyHeadingRef` + `setTimeout(focus, 50)` |
| 2.4.4 Link Purpose | Download link has `aria-label` that includes the filename; nav buttons have descriptive text |
| 2.4.6 Headings and Labels | `<h1>` on hero, `<h2>` on Evidence Studio and Verify Artifact, `<h3>` on each rail block; all inputs have explicit labels |
| 2.4.7 Focus Visible | `:focus-visible` rule adds 2 px solid `#4a9eff` ring to all interactive elements |
| 2.4.11 Focus Appearance | Focus indicator is ≥ 2 px solid enclosing the component |
| 2.5.3 Label in Name | Visible button labels match their accessible names |
| 2.5.8 Target Size | `.tier-tab` and `.navlinks button` have `min-height: 44px` |

### Understandable

| Criterion | Implementation |
|-----------|----------------|
| 3.2.1 On Focus | No context changes on focus alone |
| 3.2.2 On Input | File inputs trigger processing on change (expected, disclosed in label) |
| 3.3.1 Error Identification | Errors set `alertMessage` into an `aria-live="assertive"` region; network mismatch banner has `role="alert"` |
| 3.3.2 Labels or Instructions | Seed inputs have `aria-describedby="seed-hint"` pointing to a `.sr-only` paragraph explaining they are never transmitted |

### Robust

| Criterion | Implementation |
|-----------|----------------|
| 4.1.2 Name, Role, Value | All interactive elements use native HTML semantics; `aria-pressed` on wallet button and tier tabs; `aria-current="page"` on active nav button; `aria-busy` on studio section and register button during processing |
| 4.1.3 Status Messages | Progress messages use `aria-live="polite"` in both the `.sr-only` live region and the visible `#studio-status` paragraph; errors use `aria-live="assertive"` in the `.sr-only` alert region |

---

## Architecture

### `src/hooks/useA11y.ts`

Four exported hooks:

```
useLiveRegion(politeness?)  →  { message, announce }
useA11yStage(stage)         →  { statusLabel, isBusy }
useFocusReturn(ref, bool)   →  void (side-effect: returns focus on false)
useSkipLink()               →  { mainRef, handleSkip }
```

`useLiveRegion.announce` runs every message through `sanitizeAnnouncement` before storing it in state. The sanitiser applies four regex passes in order:

1. Stellar base32 addresses (`G`/`C` + 55 base32 chars) → `[address]`
2. Hex strings > 8 chars → `[redacted]`
3. Unix file paths (two or more `/segment`) → `[path]`
4. Windows file paths (`C:\...`) → `[path]`

Order matters: the Stellar regex runs first so that base32 strings containing hex-valid characters are caught as addresses before the hex pass fires.

### Live regions in `App.tsx`

Two hidden live regions are rendered unconditionally before `<main>`:

```html
<div role="status" aria-live="polite"   aria-atomic="true" class="sr-only">{liveMessage}</div>
<div role="alert"  aria-live="assertive" aria-atomic="true" class="sr-only">{alertMessage}</div>
```

- Progress messages (hashing, embedding, proving, ready) → `liveStatus.announce()` → polite region  
- Error messages (network, steganography, registration, wallet) → `liveAlert.announce()` → assertive region  
- The visible status `<p>` in the studio header also carries `role="status" aria-live="polite" aria-atomic="true"` as a secondary announcement path

---

## Privacy Constraints on Operational Signals

Assistive technology reads live region content aloud. The sanitiser ensures the following are never spoken:

| Data type | Pattern removed | Replacement |
|-----------|-----------------|-------------|
| SHA-256 / proof / nullifier hashes | Hex strings > 8 chars | `[redacted]` |
| Stellar public keys (G...) | 56-char base32 starting with G | `[address]` |
| Soroban contract IDs (C...) | 56-char base32 starting with C | `[address]` |
| File system paths | `/segment/segment` or `C:\...` | `[path]` |

Status messages that pass through `announce` are short operational strings like:
- `"Hashing video locally in the browser."`
- `"Embedding portable Harpocrates metadata into the video."`
- `"Generating Noir UltraHonk proof in this browser."`
- `"Registration submitted with Stellar status: PENDING."`

No evidence file names, video hash values, proof bytes, wallet addresses, or seed material appear in any live region text.

---

## Local Verification Workflow

### Offline local verification mode

The Verification Portal can verify a received video entirely in the browser
with zero network calls via the **Offline local check** toggle (a focusable
`<button type="button">` with `aria-pressed="true"` when active, next to the
dropzone):

- The received file is hashed locally and its embedded Harpocrates envelope is
  extracted with the same `stego.extractMetadata` loader the online flow and
  the batch workspace use — never a second protocol truth.
- Embedded metadata is structurally validated against the backend envelope
  grammar; when the envelope carries a video hash, the file is bound to it
  (`bound` / `tampered` / `unavailable`). Envelopes carrying secret-shaped keys
  are rejected and rendered as null.
- Offline mode is only a *local check*: it never produces a confirmed trust
  decision, never produces a shareable verification link, and never queries a
  chain, registry, database, or event source. Chain Status reads
  "Not checked (offline)".

Accessibility notes for offline mode:

- The toggle is keyboard reachable, has `aria-pressed`, disabled while a
  verification is in flight, and keeps a 44px touch target (`.mode-toggle`).
- Offline rail blocks announce the reduced trust boundary through
  `role="status"` regions ("On-chain status was not checked in offline mode.",
  "NeonDB events were not queried in offline mode.").
- Offline status copy contains no file names, video hashes, or secret material.

### 1. Start the dev server

```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

### 2. Automated unit tests

```bash
cd frontend
npm test
# Expected: 8 test files, 96 tests, all pass
```

The `useA11y.test.ts` file contains 27 tests covering:
- `useLiveRegion`: empty message, safe passthrough, hex redaction, Stellar key/contract ID redaction, path redaction, empty string, multi-value, politeness param
- `useA11yStage`: all 7 Stage values, reactivity on stage change
- `useFocusReturn`: true→false focus, false→false no-op, false→true no-op, null-safe
- `useSkipLink`: presence, preventDefault + focus, tabIndex=-1, null-safe

### 3. Manual keyboard audit checklist

Open `http://localhost:5173` and test with keyboard only (Tab / Shift+Tab / Enter / Space):

- [ ] First Tab press reveals the skip-to-content link at the top of the viewport
- [ ] Activating the skip link moves focus to `#main-content`
- [ ] Tab from `#main-content` enters the nav; focus ring is visible on each nav button
- [ ] Evidence and Verify buttons show `aria-current="page"` in browser DevTools when active
- [ ] Clicking "Begin evidence flow" moves focus to the Evidence Studio `<h2>`
- [ ] Clicking "Verify an artifact" moves focus to the Verify Artifact `<h2>`
- [ ] All three tier tab buttons are reachable and show `aria-pressed` toggling in DevTools
- [ ] Credential Seed and Nullifier Seed inputs are reachable; their labels are spoken by VoiceOver/NVDA
- [ ] The "Register proof" button shows `aria-busy="true"` during processing stages
- [ ] The verify page file input is reachable by keyboard and labelled
- [ ] The "Offline local check" toggle is reachable and shows `aria-pressed` toggling in DevTools

### 4. Screen reader smoke test (macOS VoiceOver)

1. Open `http://localhost:5173` in Safari
2. Enable VoiceOver (`Cmd+F5`)
3. Press Tab — VoiceOver should announce "Skip to main content, link"
4. Navigate to Evidence Studio; VoiceOver should announce "Evidence Studio, heading level 2" on arrival
5. Upload a file — VoiceOver should announce the hashing/embedding progress via polite live region
6. On error — VoiceOver should immediately announce the error via assertive live region

### 5. Contrast check

Use browser DevTools Accessibility panel or the [WebAIM Contrast Checker](https://webaim.org/resources/contrastchecker/):

| Element | Foreground | Background | Ratio | Pass AA |
|---------|-----------|------------|-------|---------|
| Data-list dt labels | rgba(255,255,255,0.62) ≈ #9E9EA5 | #0A0A0C | ~6.8:1 | ✓ |
| Data-list dd values | rgba(255,255,255,0.92) ≈ #EAEAEC | #0A0A0C | ~12.4:1 | ✓ |
| Lede text | rgba(255,255,255,0.78) ≈ #C7C7CC | #030305 | ~10.2:1 | ✓ |
| Page sub-text | rgba(255,255,255,0.72) ≈ #B8B8BE | #0A0A0C | ~8.4:1 | ✓ |

---

## Deployment Impact

- No backend changes. This is a pure frontend concern.
- No API contract changes.
- No Soroban contract changes.
- No new runtime dependencies (the hooks use only React built-ins).
- Bundle size impact: ~2 KB for `useA11y.ts` (minified + gzipped ≈ 0.7 KB).
- The `.sr-only` elements and live regions add ~5 DOM nodes unconditionally; no performance impact.
- Offline verification (`offlineVerification.ts`) is a pure client module with an injectable extractor and adds no runtime dependencies; its dynamic `stego` import is code-split so the online-only bundle is unaffected.

---

## Migration / Rollback

This change is additive — it only adds ARIA attributes, live regions, focus management hooks, and CSS. To roll back:

1. Revert `src/App.tsx` to the pre-change commit.
2. Revert `src/App.css` to the pre-change commit.
3. Delete `src/hooks/useA11y.ts` and `src/hooks/useA11y.test.ts`.
4. Run `npm test` — the 69 original tests must still pass.

No data migrations, localStorage schema changes, or contract state changes are involved.

For the offline local verification mode specifically: delete
`frontend/src/offlineVerification.ts` and its test, revert
`frontend/src/hooks/useVerification.ts`, `frontend/src/views/VerifyView.tsx`,
and `frontend/src/App.css`, and the portal ships with the online-only flow.
Offline mode persists nothing and writes no storage, so rollback is lossless.

---

## Operational Signals

| Signal | Where | Politeness | Privacy |
|--------|-------|-----------|---------|
| Hashing started | `#live-status` + `#studio-status` | polite | safe |
| Embedding started | `#live-status` + `#studio-status` | polite | safe |
| Proving started | `#live-status` + `#studio-status` | polite | safe |
| Evidence ready | `#live-status` + `#studio-status` | polite | safe |
| Registration submitted | `#live-status` + `#studio-status` | polite | safe (status code only) |
| Offline check started | verify progress region | polite | safe |
| Offline result (local check only) | verify result region | polite | safe (never a confirm framing) |
| Offline dependency unavailable | verify result region | assertive | safe ("No trust decision was made.") |
| Wallet connected | `#live-status` | polite | safe (no key in message) |
| Network mismatch | `#live-alert` + banner `role="alert"` | assertive | safe |
| Any error | `#live-alert` | assertive | sanitised |

---

## Known Limitations

1. **Drag-and-drop:** The `.dropzone` `<label>` wraps a hidden `<input type="file">`. Drag-and-drop works for mouse users but is not exposed as a drag target to AT. Keyboard users activate the native file picker via the label, which is fully accessible. A future enhancement could add `role="button"` and drag-event ARIA live announcements.

2. **Proof progress granularity:** The Noir UltraHonk proof generation in `noirClient.ts` is a single async call with no intermediate progress events. The live region announces "Generating Noir UltraHonk proof in this browser." once at the start but cannot report sub-step completion. A future enhancement could add a `ReadableStream`-based progress reporter.

3. **Freighter wallet extension:** The wallet connection UX depends on the Freighter browser extension injecting its own UI. That UI is outside the scope of this audit.

4. **No automated axe integration:** `axe-core` / `jest-axe` is not in the test suite. The unit tests cover hook logic and DOM semantics via Testing Library queries. A future CI step could run `@axe-core/playwright` against the running dev server for full rule coverage.

5. **Colour contrast on animations:** The WebGL EvilEye background and prismatic veil are `aria-hidden` and decorative. Their colours are not subject to contrast requirements. Reduced-motion users see them frozen or at 1 ms duration.

---

## On-Screen Status

Each stage has two announcement paths:

1. **Visible status paragraph** (`<p role="status" aria-live="polite" aria-atomic="true">`) — shown in the page header, readable by all users.
2. **Hidden polite region** (`<div role="status" aria-live="polite" aria-atomic="true" class="sr-only">`) — duplicated in the `statusLabel` from `useA11yStage` for screen reader announcement.

This dual-path ensures sighted users see the message while AT hears a distinct, stage-specific label.

## Focus Management

On view transition (`landing → studio`, `landing → verify`), focus moves to the view's `<h2>` heading after a 50ms `setTimeout` delay (allows the DOM to settle):

- Studio heading: `<h2 id="studio-heading" tabIndex={-1}>Evidence Studio</h2>`
- Verify heading: `<h2 id="verify-heading" tabIndex={-1}>Verify Artifact</h2>`

Focus is not moved on every stage transition — only on deliberate view changes.

## aria-busy

The `<section id="studio">` has `aria-busy` set to `true` during processing stages (`hashing`, `embedding`, `proving`). The "Register proof" button also carries `aria-busy` during these stages, and its CSS cursor becomes `wait` via `.primary-action[aria-busy="true"]`.

## aria-pressed on Tier Tabs

Each tier tab button has `aria-pressed` reflecting the selected state. This replaces a purely visual active class with a proper accessibility state.

## aria-label on Data List

The evidence data `<dl>` has `aria-label="Evidence data"` so screen readers can identify the list.

## aria-current on Nav Buttons

Each nav button (`Evidence`, `Verify`, `Batch Workspace`) has `aria-current="page"` when its view is active.

---

## Files Changed

| File | Change |
|------|--------|
| `src/hooks/useA11y.ts` | Existing: four accessibility hooks with privacy-safe sanitiser |
| `src/hooks/useA11y.test.ts` | Existing: 27 unit tests for hook logic and negative paths |
| `src/App.tsx` | Updated: aria-live regions, skip link, focus management, aria-current on nav, aria-label on nav |
| `src/App.css` | Existing: skip-link, sr-only, focus-visible rings, touch targets, contrast, reduced-motion |
| `src/views/StudioView.tsx` | Updated: aria-busy on section, role="status" on status p, aria-pressed on tier tabs, aria-label on data-list, aria-label on studio section, aria-label on download link, visible sr-only statusLabel region |
| `src/App.test.tsx` | Updated: 8 new integration tests for accessibility features |
