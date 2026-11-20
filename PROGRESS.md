# Project Progress — PromptVeil

**Checkpoint Date:** 2026-11-20T17:56Z (`20:56+03:00`)  
**Session Status:** v2 Audit Remediation — Stage E / Milestone M5 (Safe Growth Features, Items 28, 31–34, 36) COMPLETE  
**Exact Stop Point:** Stage E / M5 (Items 28, 31–34, 36 + documentation for deferred/rejected items 29, 30, 35, 37) implemented, Gate-verified (Gate PASS: Forensic Auditor `CLEAN`, 2/2 Reviewers `APPROVE`, 2/2 Challengers `APPROVE`; deterministic `esbuild` bundle `7d1ffd0739`, `48/48` `node:test`, `25/25` `pytest`, `172` E2E self-test, `16/16` targeted live E2E), and committed locally (`checkpoint: stage E safe growth features`). Stage A (`5636cd9`), E2E Alignment (`664f816`), Stage B (`2d91890`), Stage C (`3c6fb1f`), and Stage D (`4d944a4`) are preserved below; `e2e_tests/` remains untouched by M5. Next planned stage: `Milestone M6` (fix `T5_32` SW hook + full `--tier all` verification gate) -> `Milestone M7` (Netlify deploy, live browser & Lighthouse, completion email).

---

## 1. Current Architecture (Option A — 100% Client-Side Public Web Product)
- **Zero-Egress Browser Privacy Engine (`app/static/js/`):**
  - `detector.js`: 11 deterministic categories (`API_KEY`, `JWT`, `CREDIT_CARD` Luhn, `IBAN` ISO 7064, `SSN`, `ENV_SECRET`, `CUSTOM` Unicode/Cyrillic with `ruleCategory` tag preservation, `EMAIL`, `PHONE` RU/CIS/intl, `IPV4`, `HIGH_ENTROPY`).
  - `vault.js`: RAM-only `SessionVault` (`[PREFIX_N]` reversible tokens, transient live-typing evolution, category/item toggles, clean reset on empty input, single-pass longest-token `rehydrate`).
  - `storage.js`: Per-browser `localStorage` custom rules (`promptveil_rules_v1`), SHA-256 hash-only audit log (`promptveil_audit_v1`), and language preference (`promptveil_lang_v1`, default `"ru"`) with in-memory fallback.
  - `privacy-proof.js`: Passive live self-test verifying `0` server text requests (`connect-src 'self'`), `0` bytes stored texts/secrets (`sessionStorage`, `cookies`, audit/unknown storage keys), `0` trackers, and transport protocol status (`HTTPS / TLS` vs local host).
  - `contacts.js`: Centralized frozen owner contacts (`@supv1rus`, `kilkauciha@gmail.com`, `github.com/Aquanti`, author `SupV1rus`) + safe `mailto:` builder without external `http(s)://` literals.
- **UI & Spark Admin Design System (`app/static/`):**
  - `index.html` (`lang="ru"`), `favicon.svg`, `styles.css`, and modular CSS (`css/{tokens,layout,components,drawers,sections,modals}.css`) using Spark Admin palette (`#051C12`, `#072F1F`, `#B4F105`, `#FFFFFF`, `#F4F6F5`, `#E2E8DF`) and geometric prism/veil monogram.
  - Modular ES6 UI controllers: `js/{i18n,dom,presets,clipboard,pricing,modals,render-workbench,render-drawers,privacy-proof,contacts,app}.js` + `sw.js` (`promptveil-static-v2`) with full `RU | EN` coverage, Step 1/2 Paste + Copy-and-Go-Step-2 UX, `"Открыть в ИИ"` 5-LLM bar, instant `resetSessionToZero()` + `pagehide` scrub, Honest Waitlist Pricing (`Free 0 ₽ / навсегда`, `Pro`, `Team` without prices), Dark Theme (`promptveil_theme_v1`), and Trust Footer + `#modal-privacy-policy` + `#modal-terms`.
- **Local Preview & Static Cloud Hosting (`app/`, `netlify.toml`):**
  - `app/main.py`, `app/config.py`, `app/schemas.py`: FastAPI static host (`http://127.0.0.1:8000`) + `/health` + strict CSP & security headers.
  - `netlify.toml`: Static deployment config (`publish = "app/static"`) with matching security and cache headers.

---

## 2. Pre-Release R1–R6 Summary
1. **R1 Brand Emblem & Favicon:** Replaced shield+checkmark SVGs in `app/static/favicon.svg` and `app/static/index.html` (header `.brand-emblem` and footer `.footer-brand-emblem`) with a geometric prism/veil polygon monogram in `#051C12`, `#072F1F`, `#B4F105`, `#FFFFFF`.
2. **R2 Zero-Retention Proof & Copy Cleanup:** Removed `"Только в браузере"`, `"Все проверки выполняются локально в вашем браузере"`, and `"ничего не отправляется на сервер"` across `index.html` & `i18n.js`; converted `[data-testid="brand-badge"]` into `#open-proof-btn` (`"Гарантия 0 хранения • Проверить"` / `"Zero-Retention • Verify"`) alongside `#footer-open-proof-btn`; implemented `#modal-privacy-proof`, `privacy-proof.js`, `resetSessionToZero()`, and `pagehide` RAM/DOM scrub.
3. **R3 UX Speedups:** Added `readTextFromClipboard()` in `dom.js` with Ctrl/Cmd+V fallback guidance, `#paste-raw-btn` & `#paste-rehydrate-btn`, and `#copy-goto-step2-btn` (`"Скопировать и перейти к шагу 2 →"`).
4. **R4 Pricing & Client-Only Requests:** Added `#pricing-section` (`#nav-pricing-link` on desktop, Month/Year −20% toggle, Free `0 ₽`/`$0`, Pro `490/390 ₽`/`$6/$5`, Team `1 990/1 590 ₽`/`$24/$19`) and `#modal-plan-request` (client-side validation, copyable formatted summary, `mailto:kilkauciha@gmail.com`).
5. **R5 Trust Footer & Real Contacts:** Added 3-column Trust Footer with security badges, centralized `contacts.js`, copyable `@supv1rus` / `kilkauciha@gmail.com` / `github.com/Aquanti`, `© 2026 PromptVeil • Автор проекта: SupV1rus`, `#modal-privacy-policy`, strict CSP/XSS hygiene, and RU purity (`Эл. почта`).
6. **R6 Tests, E2E & Repo Hygiene:** Updated `.gitignore` (`.agents/`), `tests/test_server.py` (`20/20` PASS), `e2e_tests/{locators,monitors,run_e2e,test_acceptance,README}.py` and `e2e_tests/fixtures/smoke_contract.{html,js}`.

---

## 3. Verification Status
- **Active background processes / local servers / subagents:** `0` (port `8000` free).
- **`py_compile` across `app/`, `tests/`, `e2e_tests/`:** Exit `0` (all Python files, `0` syntax errors).
- **`pytest tests/test_server.py -v`:** **`22 passed`** (`1.19s`, exit `0`, including Stage 1 SEO/PWA and Stage 2 SW/AI-launcher/Dark-theme contract checks).
- **`e2e_tests/run_e2e.py --mode self-test`:** **`ALL CHECKS PASSED`** (`109` Tier 1–4 + `29` Tier 5 + `12` Acceptance = `150` unique tests, exit `0`).
- **`e2e_tests/run_e2e.py --mode live --base-url http://127.0.0.1:8000 --start-server --tier all`:** **`150 passed`** (`323.51s` on modular Stage 3A, exit `0`, `0` failed, `0` skipped, `0` console/page/CSP errors).
- **Lighthouse Audit (`http://127.0.0.1:8000`, Chrome Headless):**
  - Desktop (`--preset=desktop`): Performance **`100`**, Accessibility **`100`**, Best Practices **`100`**, SEO **`100`**.
  - Mobile (default): Performance **`98`**, Accessibility **`100`**, Best Practices **`100`**, SEO **`100`**.
- **Visual Inspection (`e2e_tests/artifacts/acceptance/*.png`):** Inspected `1440×900` & `390×844` light and dark screenshots (`acc_desktop_dark_1440x900.png`, `acc_mobile_dark_390x844.png`, `acc_desktop_pricing_footer_1440x900.png`) — zero overlaps, zero clipping, zero horizontal overflow, WCAG AA contrast, mobile `.top-rail <= 64px`.

---

## 4. Public Launch & Hosting Record
- **Live Public URL:** `https://promptveil.netlify.app` (renamed from `promtveil` on 2026-11-20)
- **Netlify Project:** `promptveil` (`siteId: 12775486-f2aa-4d79-90c2-a85446c2b7a8`, `teamSlug: kil-ka-uchikha`, `plan: nf_team_dev` / Free)
- **Latest Production Deploy:** `6b0064d917c8d8fd558f0da9` (`buildId: 6b0064d817c8d8fd558f0da7`, state `ready`, verified live via `browser` subagent `0516d1c8-c381-4bed-b722-87c7572182d7`: HTTPS 200 `47/47`, 0 app CSP/JS errors, 14/14 RU preset roundtrip, `0 запросов` / `0 байт` / `0 трекеров • HTTPS / TLS`, `Офлайн готов • SW активен`, 5 AI launchers, Dark Theme verified in `final_step_14.png`, Waitlist cards, clickable `@supv1rus` & `github.com/Aquanti`, `#modal-terms`).


---

## 5. v2 Audit Remediation — Stage A (Milestone M1: Privacy Detection & Zero-Retention Trust, Items 1–5)

### Completed Items (Items 1–5)
1. **Item 1 — Detection Engine P0 Upgrades (`app/static/js/detector.js`, `vault.js`, `app.js`, `i18n.js`, `index.html`):**
   - Added `RU_ORG` (priority `68`, `< CUSTOM: 80`) covering quoted legal forms (`ООО`/`АО`/`ПАО`/`ЗАО`/`НКО`/`АНО`/`ФГБОУ`/`МУП`/`ГУП`/`ТСЖ`) and `ИП <Surname> <Initials/Name>` forms.
   - Extended `RU_FIO` (priority `64`) with 2-word `FirstName + Surname` and `Surname + FirstName` detection using `RU_FIRST_NAME_FORMS`, `hasRuSurnameSuffix`, `isRuPatronymic` (including instrumental/feminine forms), `RU_FIO_STOPWORDS`, and multi-word street lookback guards.
   - Added `POSSIBLE_CARD` (priority `84`, `< CREDIT_CARD: 90`) for context-labeled 13–19 digit card sequences (`карта`/`карты`/`карточк*`/`card`/`№карты`) even when Luhn fails, suppressing shifted `CREDIT_CARD` sub-spans inside `POSSIBLE_CARD` matches.
   - Added optional `UUID` detector (priority `58`, `secondary: true`, off by default) controlled by `#detect-uuid-toggle` (`data-testid="detect-uuid-toggle"`) or `sensitivity === "strict"`.
   - Extended `RU_ADDRESS` to capture preceding city tokens (`г. X`, `город/пос./пгт./с.`, major RU city list, or capitalized city before `ул./пр./пер.` and `<StreetName> <StreetType>` forms, with Unicode-aware `STREET_TYPE_WORD_GUARD`).
2. **Item 2 — Netlify Hosting Decision & CSP Wording (`app/static/js/i18n.js`, `privacy-proof.js`):**
   - Kept Netlify Free hosting (`siteId: 12775486-f2aa-4d79-90c2-a85446c2b7a8`; no Free-plan badge toggle or Cloudflare account available) and clarified proof modal CSP text to `"нарушений CSP в документе приложения: 0"` (RU) / `"CSP violations in app document: 0"` (EN).
3. **Item 3 — Web Manifest MIME Header (`netlify.toml`):**
   - Configured `/manifest.webmanifest` with `Content-Type = "application/manifest+json; charset=utf-8"` in `netlify.toml`.
4. **Item 4 — Open Source License, Bilingual Docs & Repository Links (`LICENSE`, `README.md`, `app/static/index.html`, `contacts.js`, `i18n.js`):**
   - Added MIT `LICENSE` (`Copyright (c) 2026 SupV1rus`), dual-language RU+EN `README.md`, and `https://github.com/Aquanti/promptveil` links in the footer and `#modal-privacy-proof`.
5. **Item 5 — Audit Journal RAM-Only Default (`app/static/js/storage.js`, `app.js`, `index.html`, `i18n.js`):**
   - Switched audit journal (`auditLog`) to tab-memory-only by default (no `localStorage` write to `promptveil_audit_v1` unless explicitly enabled via `#audit-persist-toggle` / `data-testid="audit-persist-toggle"` in `#drawer-audit`; unchecking clears `promptveil_audit_v1`).

### Stage A Verification Results (`master @ 5636cd9`)
- **Gate Iteration 2 Result:** **PASS** (Forensic Auditor CLEAN, 2/2 Reviewers APPROVE, 2/2 Challengers CONFIRM).
- **`pytest tests\test_server.py -v`:** **`22 passed`** (`0` failures).
- **`node --test tests\js\detector.test.mjs`:** **`11 passed, 0 failed`** (`2` suites).
- **`node --check` (`app/static/js/*.js`):** **`14/14` JS files OK** (`0` syntax errors).

---

## 5a. E2E Testing Track & Stage B (`M2`) Status (`2026-11-20T16:25Z` / `19:25+03:00`)

### Completed (`Stage A / M1` + `E2E_TRACK` + `Stage B / M2`)
- **Stage A / M1 (`master @ 5636cd9`):** Items 1–5 complete (`22/22` `pytest`, `11/11` JS unit tests).
- **E2E Testing Track (`e2e_tests/`):**
  - `172` unique Playwright E2E tests (`127` Tier 1–4 + `32` Tier 5 + `13` Acceptance) aligned to Stages A–E audit remediation contracts (`e2e_tests/{conftest,locators,monitors,run_e2e,test_acceptance,test_tier1_features,test_tier2_boundaries,test_tier3_combinations,test_tier4_scenarios,test_tier5_adversarial}.py` and `test_cases.json`).
  - Added Linux CI portability in `e2e_tests/conftest.py`.
  - **`.\e2e_tests\.venv_e2e\Scripts\python.exe e2e_tests\run_e2e.py --mode self-test`:** **`ALL CHECKS PASSED`** (exit `0`; `py_compile OK` 10 files, `pytest --collect-only OK` 172 unique tests, smoke/isolation/negative monitor checks OK).
  - *(Note: `e2e_tests/` modifications remain unstaged in the working tree outside M2 commit ownership.)*

---

## 6. v2 Audit Remediation — Stage B (Milestone M2: State, Validation & i18n Parity, Items 6–13)

### Completed Items (Items 6–13)
1. **Item 6 — Counter Sync (`app/static/js/app.js`, `render-workbench.js`):**
   - Synchronized `#sanitized-metrics` (`[data-testid="telemetry-masked-count"]`, `data-count`), `[data-category="ALL"]`, `#rehydrate-ready-badge`, and `#vault-ready-meta` to active `result?.maskedCount ?? 0` across category, item, custom-word, and UUID toggles while preserving `countsByCategory` per category chip and `hasVaultEntries` for Step 2 rehydration.
2. **Items 7 & 8 — Plan Modal Reset & Toast Layering (`app/static/js/pricing.js`, `app/static/css/components.css`):**
   - Added `clearPlanRequestResult(state)` and reset `#plan-req-name`, `#plan-req-contact`, `#plan-req-note`, `#plan-req-seats` (`"10"`), `#plan-req-copy-btn` copy feedback, `#plan-request-alert`, and `#plan-request-result` on every modal open/plan switch and prior to validation on submit.
   - Updated `.status-banner` (`#global-status-banner`) to `position: fixed; z-index: 80` with opaque `--bg-surface` layering (above `.modal-dialog` `z-index: 60` and `.drawer-backdrop` `z-index: 40`) so plan-request and `"Сессия очищена в 0"` toasts render cleanly above modal backdrops on desktop and mobile (`390×844`).
3. **Items 9, 10 & 11 — `aria-pressed`, Custom Words Validation & Copy-State Reset (`app/static/js/render-workbench.js`, `app.js`, `dom.js`, `modals.js`, `index.html`):**
   - Fixed inverted `aria-pressed` on `#toggle-reveal-btn` (`"false"` when visible, `"true"` when hidden).
   - Added `novalidate` on `#add-rule-form` and `aria-required="true"` on `#rule-term-input`; focused `#rule-term-input` on `errorEmpty`/`errorDuplicate` and cleared stale `rulebook-alert` on input, category/case toggle, rule deletion, and drawer close.
   - Added `clearCopyFeedback()` in `dom.js` (with disabled-button guard in `showCopyFeedback`) and cleared `"Скопировано ✓"` immediately on `"Очистить"`, `resetSessionToZero()`, and empty output.
4. **Item 12 — `pluralizeRu` & EN Pluralization in Proof Modal (`app/static/js/i18n.js`, `modals.js`):**
   - Split unit nouns into `{unit}` / `{sessionUnit}` / `{prefUnit}` placeholders and added `pluralizeEn` + `pluralizeCount` alongside `pluralizeRu` for trackers, service keys, storage keys, requests, and bytes.
5. **Item 13 — EN Parity, `/en/index.html`, `hreflang` & Tracker Selector Fix (`app/static/en/index.html`, `app/static/index.html`, `app/static/sitemap.xml`, `app/static/js/{i18n,modals,storage,privacy-proof}.js`, `tests/test_server.py`):**
   - Added static English route `app/static/en/index.html` (`<html lang="en">`, root-relative `/...` assets, canonical `/en/`), `hreflang="ru"` / `hreflang="en"` / `hreflang="x-default"` alternates, and `sitemap.xml` `xhtml:link` alternates.
   - Synced meta description, Open Graph, Twitter tags, and `#theme-toggle-btn` `aria-label`/`title` on language switch; prioritized `/^\/en(?:\/|$)/i` in `loadLanguage()`; registered `"/sw.js"`; removed RU-only INN/SNILS/OGRN/BIK/OMS items from EN Free tier copy.
   - Applied the 1-line `:not([rel="alternate"])` fix in `app/static/js/privacy-proof.js:108` (`'script[src], link[href]:not([rel="canonical"]):not([rel="alternate"]), img[src], iframe[src]'`) so `hreflang` alternate links are not miscounted as external DOM trackers.

### Stage B Verification Results
- **Gate Iteration 1 Result:** **PASS** (Forensic Auditor `CLEAN`, 2/2 Reviewers `APPROVE`, 2/2 Challengers `CONFIRM`).
- **`pytest tests\test_server.py -v`:** **`23/23` passed** (`0` failures).
- **`node --test tests\js\*.test.mjs`:** **`23/23` passed** (`6` suites across `detector.test.mjs` and `state-i18n.test.mjs`, `0` failures).
- **`node --check` (8 modified JS modules):** **`8/8` OK** (`0` syntax errors).

---

## 6a. v2 Audit Remediation — Stage C (Milestone M3: Mobile UX `390×844`, Items 14–18)

### Completed Items (Items 14–18)
1. **Item 14 — Compact Mobile Header (`app/static/index.html`, `app/static/en/index.html`, `app/static/css/{layout,components}.css`, `app/static/js/{i18n,app}.js`):**
   - Compacted `header.top-rail` to `56.25px` (`<= 64.5px`) at `390×844`: converted `#open-proof-btn` into a `44×44` geometric padlock + lime-dot badge (`.brand-badge-lock`, `.brand-badge-dot`, `.sr-only` on `.brand-badge-text`, preserving SVG across `applyLanguage()` switches).
   - Added single `44×44` `[data-testid="lang-mobile-toggle"]` (`RU` / `EN`) and `"⋯"` overflow menu (`#mobile-more-btn`, `#mobile-more-menu`) hosting `"Свои слова"` (`#mobile-open-rulebook-btn` + `#mobile-rulebook-count`), `"Журнал"` (`#mobile-open-audit-btn` + `#mobile-audit-count`), and `"Тарифы"` (`#mobile-pricing-btn`), with Escape/outside-click/resize-to-desktop dismissal and focus restoration.
   - Enforced `@media (min-width: 640px)` cascade override at the end of `app/static/css/components.css` hiding `.lang-mobile-toggle`, `.mobile-more-wrap`, `.mobile-more-btn`, `.vault-collapse-btn`, and `.mobile-sticky-cta` on desktop (`>= 640px`), guarded by regression assertions in `tests/test_server.py::test_stage_c_mobile_ux_contracts`.
2. **Item 15 — Mobile Step 2 Tab Label (`app/static/index.html`, `app/static/en/index.html`, `app/static/css/components.css`, `app/static/js/i18n.js`):**
   - Split `[data-i18n="nav.step2"]` into `.tab-label-short` (`"2. Вернуть"` / `"2. Restore"`) and `.tab-label-tail` (`" в ответ ИИ"` / `" in AI Reply"`), hiding `.tab-label-tail` at `<= 639px` so Step 2 stays single-line with zero wrapping or clipping.
3. **Item 16 — Mobile Tap Targets `>= 44px` (`app/static/css/{layout,components,sections}.css`):**
   - Enforced `min-height: 44px` across mobile header buttons, `.ai-launcher-pill`, `.footer-nav-link`, `.footer-link-btn`, `.footer-proof-btn`, `a.footer-contact-value`, and `.btn-copy-xs`, plus `padding-bottom: 5.25rem` on `.site-footer` so bottom footer controls clear `#mobile-sticky-cta`.
4. **Item 17 — Collapsible Vault & Sticky Bottom CTA (`app/static/index.html`, `app/static/en/index.html`, `app/static/css/{layout,components}.css`, `app/static/js/{app,render-workbench,i18n}.js`):**
   - Added RAM-only `state.mobileVaultExpanded` (default `false` on mobile, preserving the 5-key `localStorage` allowlist), `#vault-collapse-btn`, and `#vault-collapsible-body`, auto-expanding and centering (`block: "center"` + `html { scroll-padding-bottom: 5.25rem; }`) on `scrollToVaultItem(token)` so scrolled items stay clear above `#mobile-sticky-cta`.
   - Added `#mobile-sticky-cta` / `#mobile-sticky-copy-btn` (`"Скопировать → открыть ИИ"` / `"Copy → open AI"`) inside `#panel-sanitize` (auto-hidden on Step 2, disabled when empty, synchronized with `clearCopyFeedback()`).
5. **Item 18 — Drawer & Modal Viewport Width Fix (`app/static/css/{drawers,modals}.css`):**
   - Replaced all `100vw` declarations with `100%` (`min(460px, 100%)`, `min(600px, calc(100% - 1.5rem))`, `calc(100% - 1rem)`), eliminating scrollbar-induced left-edge overflow on `390×844` and `360×800`.

### Stage C Verification Results (Iteration 2 Gate PASS)
- **Gate Iteration 2 Result:** **PASS** (Forensic Auditor `CLEAN`, 2/2 Reviewers `APPROVE`, 2/2 Challengers `APPROVE`).
- **`node --check` (`app.js`, `modals.js`, `render-workbench.js`, `i18n.js`):** Exit `0` (`0` syntax errors).
- **`node --test tests\js\*.test.mjs`:** **`25/25` passed** (`7` suites, `0` failures).
- **`pytest tests\test_server.py -v`:** **`24/24` passed** (`0` failures).
- **Targeted Live Playwright E2E (`ACC_01`, `ACC_02`, `ACC_04`, `ACC_06`, `ACC_12`, `T4_05`, `T4_06`):** **`7/7` passed** (`0` failures).
- **Live Viewport & Adversarial Playwright Probes (`/` & `/en/`, light & dark across `390×844`, `360×800`, `639×844`, `640×800`, `1440×900`):** **`548/548`** Challenger 1 checks + **`92/92 + 3/3`** Challenger 2 edge checks passed (`0` horizontal overflow, `0` console/page/CSP errors, `0` unallowed `localStorage` keys, `scrollToVaultItem` and footer clear above `#mobile-sticky-cta`).

---

## 6b. v2 Audit Remediation — Stage D (Milestone M4: Performance, Security Headers, Hygiene & CI, Items 19–26)

### Completed Items (Items 19–26)
1. **Items 19 & 20 — CSS `@import` Elimination, `esbuild` Bundling & Immutable Cache (`package.json`, `package-lock.json`, `scripts/build.mjs`, `app/static/dist/`, `app/static/{index.html,en/index.html,404.html}`, `netlify.toml`):**
   - Added `scripts/build.mjs` (`esbuild@^0.25.12`) generating deterministic content-hashed build `25408dc9ec` in `app/static/dist/` (`styles.V6OENGR4.css` with 0 `@import`, `app.G2JSUUFJ.js`, `i18n-ru-K33PTIXV.js`, `i18n-en-4AZRN63R.js`), injecting root-relative `/dist/*` links into `index.html`, `en/index.html`, and `404.html` while keeping `app/static/js/*.js` intact for unit/E2E tests.
   - Configured `[[headers]] for = "/dist/*"` in `netlify.toml` with `Cache-Control = "public, max-age=31536000, immutable"`.
2. **Item 21 — Lazy i18n Dictionaries & `<template>` Modals (`app/static/js/{i18n,i18n-ru,i18n-en,modals,pricing,app}.js`, `app/static/{index,en/index}.html`):**
   - Split `i18n-ru.js` and `i18n-en.js` for on-demand dynamic `import()` in `i18n.js` (`pendingLoads` + `applySeq` race protection, zero `fetch()`), paired with `<link rel="modulepreload">` for the alternate language chunk to preserve zero interactive egress.
   - Moved all 4 modals (`#modal-privacy-proof`, `#modal-plan-request`, `#modal-privacy-policy`, `#modal-terms`) into `<template id="tpl-modal-...">` elements hydrated on first open via `document.importNode(tpl.content, true)` (zero `innerHTML`).
3. **Item 22 — Service Worker Strategy & Update Banner (`app/static/sw.js`, `app/static/js/modals.js`, `app/static/css/components.css`, `app/static/{index,en/index}.html`):**
   - Updated `sw.js` (`CACHE_NAME = "promptveil-build-25408dc9ec"`) with network-first HTML navigation, cache-first `/dist/*`, stale-while-revalidate for other same-origin GET assets, `message` handler for `{ type: "SKIP_WAITING" }`, and `#sw-update-banner` / `#sw-update-btn` / `#sw-update-dismiss-btn` reload flow.
4. **Item 23 — COOP & CORP Headers (`app/main.py`, `netlify.toml`):**
   - Added `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin` in both `app/main.py` and `netlify.toml`.
5. **Items 24 & 25 — Dead Code Removal & `app.js` Modularization (`app/static/js/{pricing,notifications,pipeline,app}.js`):**
   - Removed dead pricing code (`billingCycle`, `_cycle`, and empty `renderPricingSection()`).
   - Extracted `notifications.js` (96 lines) and `pipeline.js` (405 lines) from `app.js`, reducing `app.js` to `686` lines (`< 750`).
6. **Item 26 — JS Unit Tests, Repo Hygiene & CI (`.gitattributes`, `CHANGELOG.md`, `README.md`, `.github/workflows/ci.yml`, `tests/js/*.test.mjs`, `tests/test_server.py`, `.gitignore`):**
   - Added `.gitattributes`, `CHANGELOG.md`, updated `README.md`, `.gitignore` (`node_modules/`), and `.github/workflows/ci.yml`.
   - Expanded `tests/js/*.test.mjs` (`detector.test.mjs`, `detector-core.test.mjs`, `state-i18n.test.mjs`, `notifications-pipeline.test.mjs`, `storage.test.mjs`, `vault.test.mjs`) and `tests/test_server.py` (scanning both `js/` and `dist/`).

### Stage D Verification Results (Gate PASS)
- **Gate Iteration 1 Result:** **PASS** (Forensic Auditor `CLEAN`, 2/2 Reviewers `APPROVE`, 2/2 Challengers `APPROVE`).
- **`npm run build`:** Deterministic build `25408dc9ec` (`100%` identical SHA-256 hashes across `index.html`, `en/index.html`, `404.html`, `sw.js`, and 4 `dist/*` bundles on re-run).
- **`node --test tests\js\*.test.mjs`:** **`44/44` passed** (`12` suites, `0` failures).
- **`pytest tests\test_server.py -v`:** **`24/24` passed** (`0` failures).
- **`e2e_tests/run_e2e.py --mode self-test`:** **`ALL CHECKS PASSED`** (`172` tests collected).
- **Targeted Live Playwright E2E (`ACC_01`, `ACC_02`, `ACC_04`, `ACC_06`, `ACC_08`, `ACC_11`, `ACC_12`, `T4_05`, `T4_06`, `T5_08`, `T5_28`, `T5_29`) + Real HTTP SW Update Probe:** **`12/12` passed** (`0` failures) + ephemeral HTTP probe verified full `#sw-update-banner` -> `SKIP_WAITING` -> reload cycle (`SW_PROBE_OK`).
- **Operational Note for `E2E_TRACK` / M6 (`T5_32`):** In `e2e_tests/test_tier5_adversarial.py`, `T5_32` parts 1–3 (`COOP`/`CORP`, `/dist/*` 200, 4 `<template>` modals, `sw_ready`) pass, while line 1945 (`#sw-update-banner`) times out under `page.context.route("**/sw.js", ...)` because Chromium's browser-process `ServiceWorkerRegistration.update()` bypasses context route interception. Route to `E2E_TRACK` / M6 (use a test-server `/sw.js` version-bump hook) before running full `--tier all` / CI.

---

## 6c. v2 Audit Remediation — Stage E (Milestone M5: Safe Growth Features, Items 28, 31–34, 36)

### Completed Items (Items 28, 31–34, 36)
1. **Item 28 — One-Click Copy & Open AI (`app/static/js/app.js`, `app/static/{index,en/index}.html`):**
   - Added delegated click handling on `#ai-launchers-bar` (`a.ai-launcher-pill`) without `event.preventDefault()`, synchronously flushing pending live sanitization via `pipeline.ensureFreshSanitizedOutput()`, copying `sanitizedText` to the clipboard, and showing `#global-status-banner` (`banner.copiedForAi` / `banner.copyFailed`) while preserving allowlisted `<a target="_blank" rel="noopener noreferrer">` links and zero external `http(s)://` literals in JS.
2. **Items 31 & 32 — Plan Request Telegram Copy & Email Fallback (`app/static/{index,en/index}.html`, `app/static/js/{pricing,modals}.js`, `app/static/css/{modals,sections}.css`):**
   - Added `#plan-req-telegram-link` (`data-testid="plan-req-telegram-link"`, `https://t.me/supv1rus`) inside `#tpl-modal-plan-request` (`#plan-request-result`) to copy the generated inquiry summary synchronously and display `#global-status-banner` (`z-index: 80` above modal backdrop `z-index: 60`) with `!ok` clipboard error fallback.
   - Added `.plan-fallback-box` (`data-testid="plan-fallback-box"`) with `kilkauciha@gmail.com` (`#plan-req-email-direct`, `#plan-req-copy-email-btn`), `@supv1rus` (`#plan-req-tg-handle`, `#plan-req-copy-tg-btn`), `.footer-contact-note`, `SITE_CONTACTS` sync in `modals.js`, and `>= 44px` mobile tap targets.
3. **Item 33 — Static HTML+SVG "Как это работает" & Honest "Что мы пока НЕ ловим" (`app/static/{index,en/index}.html`, `app/static/js/modals.js`, `app/static/css/sections.css`, `app/static/js/i18n-{ru,en}.js`):**
   - Added `#how-it-works` (`data-testid="how-it-works-section"`, 3 `.how-step-card` blocks with Spark-palette inline `<svg aria-hidden="true">` diagrams, zero `style=`/`<style>`) and `#honest-limits` (`data-testid="honest-limits-section"`, 4 honest boundary cards + `#limits-open-rulebook-btn` wired in `modals.js` to open `#drawer-rulebook`, keeping `app.js` at `728` lines `< 750`) with full RU/EN and dark-theme parity.
4. **Item 34 — Sensitivity Mode `"Обычный / Строгий"` & `"почему это скрыто"` Tooltips (`app/static/js/{app,pipeline,detector,vault,i18n,i18n-ru,i18n-en,render-workbench}.js`, `app/static/css/components.css`, `app/static/{index,en/index}.html`):**
   - Added Step 1 sensitivity toggle (`#sensitivity-normal-btn`, `#sensitivity-strict-btn`, default `"normal"`), syncing `#detect-uuid-toggle` (`checked` + `disabled` in `"strict"` mode without mutating `state.detectUuid`) and re-running sanitization immediately on switch.
   - Extended `"strict"` mode in `detector.js` for `UUID`, unquoted `RU_ORG`, broader 2-word `RU_FIO` (with short-name/stopword/non-adjective guards), and `16+` char `HIGH_ENTROPY` (`minEntropy: 3.45`, semver/date guards), and attached `reasonKey` metadata across `detector.js`, `vault.js`, `i18n.js`, `render-workbench.js` (`title`, `data-reason`, and `.vault-reason` `[data-testid="vault-reason"]`).
5. **Item 36 — 4 Industry Custom Word Packs in `"Свои слова"` (`app/static/js/{presets,pipeline,render-drawers}.js`, `app/static/{index,en/index}.html`):**
   - Added `INDUSTRY_WORD_PACKS` (`legal`, `hr`, `medical`, `accounting`, 6 localized RU/EN terms per pack, zero `localStorage` writes on load) in `presets.js`, `.word-packs-box` (`[data-testid="word-pack-*"]`) inside `#drawer-rulebook` outside `#rulebook-list`, deduplicated addition via `makeRuleDedupKey` + immediate re-sanitize in `pipeline.js`, and `data-term` on `.rule-term-text` in `render-drawers.js`.
6. **Documented Deferred / Rejected Stage E Items (`README.md`, `CHANGELOG.md`):**
   - `#29` Browser extension: Deferred to Pro roadmap (separate MV3 project).
   - `#30` Custom domain: Out of scope (environment limit — no registrar/DNS access).
   - `#35` `.docx` / `.pdf` parsing: Deferred to Pro roadmap (`pdf.js` / `.docx` parsers conflict with CSP/bundle budget and zip-bomb/encoding safety).
   - `#37` Cookie-free analytics: Rejected (violates `connect-src 'self'`, `"0 трекеров"`, and zero-paid-analytics constraint).
7. **Bundle Rebuild & Tests (`scripts/build.mjs`, `app/static/dist/*`, `app/static/sw.js`, `app/static/{index,en/index,404}.html`, `tests/js/*.test.mjs`, `tests/test_server.py`):**
   - Rebuilt deterministic `esbuild` production bundle (`7d1ffd0739`) generating `app/static/dist/styles.OSO7ZGEU.css`, `app/static/dist/app.7ZFZXPFV.js`, `app/static/dist/i18n-en-DA7RUS5J.js`, and `app/static/dist/i18n-ru-XC3DQG4V.js`, and updated `app/static/sw.js` (`CACHE_NAME = "promptveil-build-7d1ffd0739"` + `PRECACHE_URLS`).

### Stage E Verification Results (Gate PASS)
- **Gate Iteration 1 Result:** **PASS** (Forensic Auditor `CLEAN`, 2/2 Reviewers `APPROVE`, 2/2 Challengers `APPROVE`).
- **`npm run build`:** Deterministic build `7d1ffd0739` (`styles.OSO7ZGEU.css`, `app.7ZFZXPFV.js`, `i18n-en-DA7RUS5J.js`, `i18n-ru-XC3DQG4V.js`; `sw.js` `CACHE_NAME = "promptveil-build-7d1ffd0739"`).
- **`node --test tests\js\*.test.mjs`:** **`48/48` passed** (`13` suites, `0` failures).
- **`pytest tests\test_server.py -v`:** **`25/25` passed** (`0` failures, including `test_stage_e_growth_contracts`).
- **`e2e_tests/run_e2e.py --mode self-test`:** **`ALL CHECKS PASSED`** (`172` tests collected).
- **Targeted Live Playwright E2E:** **`16/16` passed** (`T1_F1_21`, `T1_F4_06`, `T1_F8_07`, `T1_F8_08`, `T1_F8_09`, `T1_F8_10`, `T3_09`, `ACC_01`, `ACC_02`, `ACC_04`, `ACC_06`, `ACC_12`, `ACC_13`, `T4_05`, `T4_06`, `T5_28`, `0` failures) + independent Challenger Node ESM & Playwright desktop/mobile/dark-mode/SW probes passed.

---

## 7. GitHub Remote & Push Instructions (Item 4)
No GitHub credentials or `origin` remote are configured in this local environment. Once ready to publish the repository to `https://github.com/Aquanti/promptveil`, run:

```powershell
git remote add origin https://github.com/Aquanti/promptveil.git
git branch -M master
git push -u origin master
```

*(Note: If the GitHub repository's default branch is `main` instead of `master`, run `git push -u origin master:main`.)*

---

## 8. Next Steps
1. **Next Planned Stage — `Milestone M6: Final Verification Gate`:** Fix `T5_32` `/sw.js` update harness (replacing `page.context.route("**/sw.js")` with a real HTTP version-bump hook), then run `pytest tests\test_server.py -v`, `node --test tests\js\*.test.mjs`, `run_e2e.py --mode self-test`, and `run_e2e.py --mode live --base-url http://127.0.0.1:8000 --start-server --tier all` (`0` failures, port `8000` free) + `PROGRESS.md` checkpoint.
2. **`Milestone M7: Production Netlify Deploy & Delivery`:** Deploy via `netlify_netlify` MCP + confirm via `netlify-open-deployments`, verify live `https://promptveil.netlify.app` in browser, run Desktop & Mobile Lighthouse outside the repo, update `PROGRESS.md` + commit, and send completion email to `kilkauciha@gmail.com`.
