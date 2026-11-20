# Changelog

All notable changes to PromptVeil are documented in this file.

## [2.1.0] - 2026-11-20

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
