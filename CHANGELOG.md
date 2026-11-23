# Changelog

All notable changes to PromptVeil are documented in this file.

## [2.3.0] - 2026-11-23

### Pro Checkout, Owner Pro-Code Console & Seamless MV3 Extension Activation
- **Dedicated Pro Checkout & Activation Pages (`R1`):**
  - Added bilingual static checkout & activation routes `/pro/` (`app/static/pro/index.html`, `<html lang="ru">`) and `/en/pro/` (`app/static/en/pro/index.html`, `<html lang="en">`) with `hreflang` alternates, `app/static/sitemap.xml` coverage, Spark Admin light/dark theme (`app/static/js/theme.js`), `390x844` mobile layout (`>= 44px` tap targets, zero horizontal overflow, zero `100vw`), and strict CSP (`script-src 'self'`, `connect-src 'self'`, zero inline scripts/styles, zero `innerHTML`/`fetch`).
  - Implemented `app/static/js/pro-checkout.js` and `app/static/css/pro-checkout.css`: 4 tariff options (`pro-monthly`, `pro-annual`, `pro-lifetime`, `team-pack`), 3 payment methods (`card`, `sbp`, `invoice`, zero raw card PAN/CVV inputs), buyer form validation, RAM-only `PV-ORD-...` order receipt with copy/download actions, and an always-visible Ed25519 Activation & Validation Terminal (`#code=PV1...` fragment hydration, `.pvkey`/`.txt` file upload with `256 KB` size checks, claim viewer, `.pvkey` download, and immediate `/downloads/promptveil-pro-extension.zip` unlock).
  - Connected `/pro/` and `/en/pro/` from `#pricing-pro-checkout-link` on `/` & `/en/`, footer navigation, and `app/static/404.html` while preserving all existing modal hooks (`#open-pro-modal-btn`, `#pricing-activate-pro-btn`, `#modal-plan-request`), achieving 100% RU/EN i18n key and placeholder parity (`615/615` keys); extended `scripts/build.mjs` for multi-entry `esbuild` (`app.js` + `pro-checkout.js`, `splitting: true`) and `app/static/sw.js` precaching of `/pro/` and `/en/pro/`.
- **Transparent Owner Pro-Code CLI & Local Loopback Console (`R2`):**
  - Extended `app/static/js/pro-license.js` with `extractProToken()`, `formatPvKeyFileContent()`, `decodeProTokenPayloadUnsafe()`, `inspectProLicenseToken()`, and fail-closed `nowMs` bounds while preserving `PRO_PUBLIC_KEY_B64U` and `promptveil_pro_license_v1`.
  - Upgraded `scripts/issue-pro-key.mjs` with full payload schema + `exp` + `--now` verification, `PRO_PUBLIC_KEY_B64U` mismatch guard (`--pub` override), `--plan` presets, batch issuance (`--count`, `--prefix`), `--order` references, `.pvkey`/table exports, ledger appending, `--inspect-bundle`, `--verify-bundle`, `--redact`, `--json`, and strict `VALUE_FLAGS` validation.
  - Added local-only `127.0.0.1` Owner Web Console (`scripts/owner-console.mjs`) outside `app/static/` for visual single/batch key issuance, order-to-key fulfillment, `#code=PV1...` activation link generation, `.pvkey` export, and token validation/inspection under strict `OWNER_CONSOLE_CSP` and `Host`/Origin/Referer CSRF guards (keeping all private signing keys strictly offline outside Git).
- **PromptVeil Pro MV3 Extension v2.2.0 & Deterministic Packaging (`R3`):**
  - Updated `extension/` (`manifest.json` `"2.2.0"`, keeping minimal `["storage", "activeTab"]` permissions, zero `host_permissions`, zero `localStorage`, and exact 6 `content_scripts` hosts): added smart `PV1.` extraction, 1-click **Paste & Activate** (`#popup-pro-paste-btn`), `.pvkey`/`.txt` file import (`#popup-pro-file-input`, `256 KB` pre/post-read guard, NUL/UTF-8 checks), `#popup-pro-verify-btn` + `#popup-pro-diagnostics`, actionable locked-feature focus hints, async race-sequence guards, `chrome.storage.local` + `onChanged` synchronization, and interactive `.pv-tier-chip` diagnostics in Shadow DOM `content.js`.
  - Rebuilt deterministic web bundles, `sw.js`, `modulepreload` HTML tags, `extension/dist/*.bundle.js`, and 9-file `app/static/downloads/promptveil-pro-extension.zip` via `npm run build`.
- **E2E Alignment, Tier 5 Hardening & Verification Expansion (`R4`):**
  - Added narrow same-origin `/favicon.svg` & `/favicon.ico` exemption in `e2e_tests/monitors.py` (guarded by 4 negative leak checks in `e2e_tests/run_e2e.py`) and hardened `pro-checkout.js` / `pro-license.js` (`inspectSeq` & `licenseMutationSeq` race guards, `saveStoredProLicenseToken` quota/storage warning, `claims.tier` & `exp` UTC formatting), `owner-console.mjs` (loopback `Origin`+`Referer` validation, `//`/`/\` path rejection, `/favicon.ico` `204`, path-free ledger errors), `issue-pro-key.mjs` (bundle array/empty checks, generic ledger `409` errors), and `extension/src/popup.js` (external `storage.onChanged` inspection/feedback reset).
  - Expanded automated verification to `28` pytest server/CSP checks, `110` web JS unit tests (`21` suites), `27` extension JS unit tests, and `292` Playwright E2E tests (`221` Tiers 1–4 + `53` Tier 5 + `18` Acceptance) across both FastAPI (`--start-server`) and Netlify-parity (`--static-only`) modes.

## [2.2.0] - 2026-11-22

### PromptVeil Pro Suite, Persistent AI Bar & Gemini Launcher
- **Persistent Step 1 & Step 2 AI Launchers + Gemini (`R1`):** Hoisted `#ai-launchers-bar` outside `#panel-sanitize` into `<main id="main-workbench">` after `#panel-rehydrate` so quick AI pills remain accessible on both Sanitize and Restore steps, flushed pending live masking on tab switch, and added **Gemini** (`https://gemini.google.com/app`, `data-testid="ai-launcher-gemini"`).
- **Offline Ed25519 Pro Licensing (`R2`):** Added `app/static/js/pro-license.js` (`PV1.<payload>.<sig>` verifier with WebCrypto Ed25519 + pure-JS RFC 8032 & SHA-512 fallback, stored in `promptveil_pro_license_v1` and allowlisted in `privacy-proof.js`), `#open-pro-license-btn`, `<template id="tpl-modal-pro-license">`, and offline issuance CLI `scripts/issue-pro-key.mjs` (public key only in Git/client code; private signing keys kept offline).
- **Local Batch & Office/PDF Scrubber (`R3`):** Added `app/static/js/pro-documents.js` parsing `.docx`, `.pdf`, and `.xlsx` up to **50 MB** per file completely in browser RAM (`DecompressionStream` + pure-JS RFC 1951/1950 inflate, `DOMParser` + pure-JS XML fallback, PDF `FlateDecode`/`ToUnicode` CMap decoding, zip-bomb & encrypted-PDF rejection, scanned-PDF warning), batch queue UI (`#batch-queue-panel`), `.txt`/`.zip` download, and Step 2 batch rehydration, while preserving Free 2 MB single-file text handling with friendly upgrade prompts.
- **Manifest V3 Browser Extension & Deterministic Packaging (`R4`):** Added `extension/` (`manifest.json`, Shadow DOM `content.js`, `popup.js`, site `adapters.js`, `storage-ext.js`, `i18n-ext.js`) across `chatgpt.com`, `claude.ai`, `gemini.google.com`, `chat.deepseek.com`, `giga.chat`, and `alice.yandex.ru`; extended `scripts/build.mjs` to bundle `extension/dist/*` and emit deterministic `/downloads/promptveil-pro-extension.zip`, served with `application/zip` and CSP/COOP/CORP headers in `app/main.py` and `netlify.toml`, plus `<template id="tpl-modal-pro-downloads">`.
- **Multi-Project Rulebook Profiles, Extended Packs & 1-Click Templates (`R5`):** Added `promptveil_profiles_v1` in `storage.js` (create/rename/switch/delete/import/export with prototype-pollution and Free-tier guards, exempted alongside `RULES_STORAGE_KEY` in `privacy-proof.js`), `PRO_INDUSTRY_WORD_PACKS` (`corporate_ma`, `devsecops`, `banking_fintech`, `crossborder_nda`), and `PROMPT_TEMPLATES` (`#prompt-templates-bar`).
- **Security Hardening & Verification Expansion:** Completed adversarial hardening across `detector.js`, `pipeline.js`, `pro-documents.js`, `pro-license.js`, and `extension/src/adapters.js`, expanding verification to `27` server/CSP pytest checks, `86` web JS + `16` extension JS unit tests, and `252` Playwright E2E tests (FastAPI & Static-Only), and added `"test:ext"` + extension test CI step in `.github/workflows/ci.yml`.

## [2.1.0] - 2026-11-20

### Stage E — Safe Growth Features (Items 28, 31–34, 36)
- **One-Click Copy & Open AI (Item 28):** Delegated click handler on `#ai-launchers-bar .ai-launcher-pill` synchronously flushes pending live sanitization (`ensureFreshSanitizedOutput()`), copies `sanitizedText` to clipboard, displays a status banner, and preserves native `<a target="_blank" rel="noopener noreferrer">` navigation with zero external URLs in JS.
- **Plan Request Telegram Copy & Email Fallback (Items 31–32):** Added `#plan-req-telegram-link` (`https://t.me/supv1rus`) inside `#tpl-modal-plan-request` to copy the generated inquiry summary and show a status banner above the modal, plus `.plan-fallback-box` (`kilkauciha@gmail.com`, `@supv1rus`, copy buttons) and `.footer-contact-note`.
- **How It Works & Honest Limits (Item 33):** Added `#how-it-works` (3-step static HTML + Spark-palette inline SVG diagram) and `#honest-limits` (honest boundary cards + `#limits-open-rulebook-btn` opening `#drawer-rulebook`) with full RU/EN and dark-theme parity.
- **Sensitivity Mode & Detection Reason Tooltips (Item 34):** Added Step 1 `"Обычный / Строгий"` (`Normal / Strict`) switcher synced with `#detect-uuid-toggle`; extended `Strict` mode in `detector.js` for `UUID`, unquoted `RU_ORG`, broader 2-word `RU_FIO`, and `16+` char `HIGH_ENTROPY`; added `reasonKey` metadata across `detector.js`, `vault.js`, `i18n.js`, and `.vault-reason` + `title`/`data-reason` in `render-workbench.js`.
- **Industry Custom Word Packs (Item 36):** Added 4 one-click deduplicating packs (`legal`, `hr`, `medical`, `accounting`) in `presets.js`, `pipeline.js`, and `#drawer-rulebook` (outside `#rulebook-list`).
- **Deferred / Rejected Decisions:** Documented `#29` browser extension (Pro roadmap), `#30` custom domain (out of scope), `#35` `.docx`/`.pdf` parsing (Pro roadmap / CSP & zip-bomb risk), and `#37` cookie-free analytics (rejected under `connect-src 'self'` and zero-tracker guarantee).

### Stage D — Performance, Security Headers, Hygiene & CI (Items 19–26)
- **CSS & JS Bundling (`esbuild`):** Eliminated the 6-file CSS `@import` chain by bundling and minifying `app/static/styles.css` and code-split ESM `app/static/js/app.js` into content-hashed files under `app/static/dist/` via `scripts/build.mjs`, with immutable `Cache-Control: public, max-age=31536000, immutable` in `netlify.toml`.
- **Lazy i18n & `<template>` Modals:** Split `i18n.js` into lazy ES modules (`i18n-ru.js`, `i18n-en.js`) loaded on demand via dynamic `import()` (zero `fetch()`), and moved `#modal-privacy-proof`, `#modal-plan-request`, `#modal-privacy-policy`, and `#modal-terms` into `<template>` elements hydrated via `document.importNode()` on first open.
- **Service Worker & Update Banner:** Updated `app/static/sw.js` to network-first HTML navigations, cache-first `/dist/*` bundles, stale-while-revalidate static assets, deterministic build-hash cache names, and user-confirmed `SKIP_WAITING` activation with `#sw-update-banner`.
- **Security Headers:** Added `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin` in both `app/main.py` and `netlify.toml`.
- **Modularization & Dead Code Removal:** Removed unused `billingCycle` / `renderPricingSection()` / `_cycle` in `pricing.js` and `app.js`; extracted `notifications.js` and `pipeline.js` from `app.js`.
- **Hygiene, Tests & CI:** Added `.gitattributes`, `CHANGELOG.md`, expanded `tests/js/*.test.mjs` unit suites, updated `tests/test_server.py`, and added `.github/workflows/ci.yml`.

### Stage C — Mobile UX (`390×844`, Items 14–18)
- Compacted mobile top header (`<= 64px`) with `44×44` zero-retention lock+dot badge, single RU/EN toggle (`#lang-mobile-toggle`), and `⋯` overflow menu (`#mobile-more-btn`).
- Shortened mobile Step 2 tab label (`2. Вернуть` / `2. Restore`), enforced `>= 44px` tap targets, added collapsible `"Что скрыто"` vault + sticky mobile CTA bar (`#mobile-sticky-cta`), and replaced `100vw` with `100%` in drawers/modals.

### Stage B — State, Validation & i18n Parity (Items 6–13)
- Synchronized masked counts (`Скрыто: N`, `Все M`, Step 2 badge) across category, item, and custom-word toggles.
- Reset `#modal-plan-request` state on open/plan switch, elevated `#global-status-banner` (`z-index: 80`) above modal backdrops, fixed `aria-pressed` on `#toggle-reveal-btn`, added `novalidate` validation in `"Свои слова"`, and cleared copy feedback on `"Очистить"` / session reset.
- Applied `pluralizeRu` / `pluralizeEn` across all Proof modal metrics, added static `/en/index.html` with `hreflang` + `sitemap.xml`, localized EN Free tier (`$0`), and synced meta/OG/Twitter tags and theme button `aria-label` on language switch.

### Stage A — Privacy Detection & Zero-Retention Trust (Items 1–5)
- Added `RU_ORG` (`ООО`, `АО`, `ПАО`, `ЗАО`, `ОАО`, `НКО`, `ИП`), two-word declined `RU_FIO`, `POSSIBLE_CARD` (context-triggered without Luhn), opt-in `UUID` detection (`#detect-uuid-toggle`), and `RU_ADDRESS` city prefix capture.
- Configured `Content-Type: application/manifest+json; charset=utf-8` in `netlify.toml`, clarified Proof modal CSP wording, added MIT `LICENSE`, bilingual `README.md`, and RAM-only default for the audit journal with opt-in persistence (`#audit-persist-toggle`).

## [2.0.0] - 2026-11-20
- Added 7 Russian PII/credential detectors (`RU_INN`, `RU_SNILS`, `RU_PASSPORT`, `RU_OGRN`, `RU_BIK`, `RU_ACCOUNT`, `RU_OMS`), `RU_AUTO_PLATE`, `RU_FIO`, `RU_ADDRESS`, `URL_TOKEN`.
- Added offline PWA Service Worker (`sw.js`), AI launcher links, dark theme (`[data-theme="dark"]`), SEO/OG metadata, and modularized `app.js` into `clipboard.js`, `pricing.js`, and `modals.js`.

## [1.0.0] - 2026-11-19
- Initial release of PromptVeil: 100% client-side AI prompt scrubber with AVL overlap resolution, reversible `SessionVault`, SHA-256 hash-only audit receipts, Zero-Retention Proof modal, FastAPI CSP server, and Netlify deployment.
