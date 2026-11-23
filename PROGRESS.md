# Project Progress — PromptVeil

**Checkpoint Date:** 2026-11-23T16:53Z  
**Session Status:** v2.3.0 RELEASED & DEPLOYED — PRO CHECKOUT (`/pro/`, `/en/pro/`), OWNER CLI & LOOPBACK CONSOLE, MV3 EXTENSION v2.2.0, FULL 292-TEST VERIFICATION, NETLIFY PRODUCTION DEPLOY & GMAIL REPORT COMPLETE  
**Exact Stop Point:** Completed Milestones M1–M4, release commit `ad4b1f5` on `master`, Netlify production deploy (`deployId: 6b046f223f001957c8c2ca5c`, `buildId: 6b046f213f001957c8c2ca5a`) verified live on `https://promptveil.netlify.app` (`200 OK`, strict CSP, `.zip` SHA-256 `ACE82CF96E717AA9581D10DCBE4984AD56B60AA48D9EB2A7456DBC8BE6710E66`), and final Russian summary email sent to `kilkauciha@gmail.com` (`ID=1a2095306951e73c`).

---

## 1. Current Architecture (Option A — 100% Client-Side Public Web & MV3 Product)
- **Zero-Egress Browser Privacy Engine (`app/static/js/`):**
  - `detector.js`: **25** deterministic categories (`API_KEY`, `URL_TOKEN`, `JWT`, `IBAN` ISO 7064, `RU_ACCOUNT` BIK key, `RU_OMS` Luhn, `CREDIT_CARD` Luhn, `RU_SNILS`, `RU_INN` 10/12, `RU_OGRN`/OGRNIP, `RU_PASSPORT`, `RU_BIK`, `POSSIBLE_CARD` context-labeled fallback, `SSN`, `ENV_SECRET`, `CUSTOM` Unicode/Cyrillic, `EMAIL`, `PHONE` RU/CIS/intl, `RU_ORG`, `RU_AUTO_PLATE`, `RU_FIO` 2–3 words + cases, `RU_ADDRESS` + city capture, `IPV4`, opt-in `UUID`, `HIGH_ENTROPY`) with `"normal"` / `"strict"` sensitivity modes and per-match `reasonKey` explanations.
  - `vault.js`: RAM-only `SessionVault` (`[PREFIX_N]` reversible tokens, transient live-typing evolution, category/item toggles, clean reset on empty input or batch-aware `{ resetOnEmpty: false }`, single-pass longest-token `rehydrate`).
  - `storage.js`: Per-browser `localStorage` multi-project Rulebook profiles (`promptveil_profiles_v1` + legacy `promptveil_rules_v1`), language preference (`promptveil_lang_v1`), dark/light theme (`promptveil_theme_v1`), opt-in audit persistence toggle (`promptveil_audit_persist_v1`), and **RAM-only by default** SHA-256 hash-only audit receipts (`promptveil_audit_v1` written only when opted in).
  - `pro-license.js`: Offline asymmetric Ed25519 key verifier (`PV1.<payload>.<sig>`, WebCrypto Ed25519 + pure-JS RFC 8032/SHA-512 fallback, `promptveil_pro_license_v1`), plus shared `extractProToken()`, `formatPvKeyFileContent()`, `decodeProTokenPayloadUnsafe()`, `inspectProLicenseToken()`, and fail-closed `nowMs` bounds; public key only in client JS, private signing key & issued keys kept strictly offline outside Git.
  - `pro-checkout.js` + `theme.js`: RAM-only tariff (`pro-monthly`, `pro-annual`, `pro-lifetime`, `team-pack`) and payment (`card`, `sbp`, `invoice`, zero PAN/CVV inputs) checkout controller, buyer form validation, `PV-ORD-...` order receipt & `.pvkey` export, and in-page Ed25519 Activation & Validation Terminal (`#code=PV1...` fragment hydration, `.pvkey`/`.txt` upload, claim viewer, `.zip` unlock).
  - `pro-documents.js` (lazily code-split chunk): 100% browser-local `.docx`, `.pdf`, `.xlsx` parser & deterministic PKZIP builder up to 50 MB per file (`DecompressionStream` + pure-JS RFC 1951/1950 inflate, `DOMParser` + pure-JS XML fallback, PDF `FlateDecode` / `ToUnicode` CMap decoding, zip-bomb & encrypted-PDF rejection, scanned-PDF warning).
  - `privacy-proof.js`: Passive live self-test verifying `0` server text requests (`connect-src 'self'`), `0` bytes stored texts/secrets (`sessionStorage`, `cookies`, audit/unknown storage keys), `0` trackers, `"нарушений CSP в документе приложения: 0"`, and transport protocol status (`HTTPS / TLS` vs local host).
  - `contacts.js`: Centralized frozen owner contacts (`@supv1rus`, `kilkauciha@gmail.com`, `github.com/Aquanti/promptveil`, author `SupV1rus`) + safe `mailto:` builder without external `http(s)://` literals.
- **UI, Production Bundle, MV3 Extension & Spark Admin Design System (`app/static/`, `extension/`, `scripts/`):**
  - Routes: `index.html` (`lang="ru"`, `/`), `en/index.html` (`lang="en"`, `/en/`), `pro/index.html` (`lang="ru"`, `/pro/`), `en/pro/index.html` (`lang="en"`, `/en/pro/`), and `404.html` (`noindex`, `/` + `/en/` + Pro checkout links) with root-relative assets, `hreflang`, `og:image:alt`, PWA `manifest.webmanifest` (`any` + `maskable` icon entries), `robots.txt`, `sitemap.xml`, and PNG/SVG icons.
  - `esbuild` multi-entry deterministic `charset: "utf8"` (`splitting: true`) build (`caae73027c`) into `app/static/dist/` (`styles.33F4J2G4.css` `74.3 KB`, `app.2WRYAKBR.js` `127.1 KB`, `pro-checkout.F3FLKHD7.js` `20.2 KB`, `chunk-QGSFLC2X.js` `4.6 KB`, `chunk-WTZKIRLZ.js` `28.2 KB`, lazy `i18n-ru-5KBQW4ZO.js` `58.7 KB`, lazy `i18n-en-MGIBIQSQ.js` `37.7 KB`, lazy `pro-documents-CVYJF6MZ.js` `31.2 KB`), 6 `<template>` modals hydrated on open, and Service Worker `sw.js` (`promptveil-build-caae73027c`, precaching `/`, `/en/`, `/pro/`, `/en/pro/`, `/404.html`, manifest, icons, and `/dist/*` while caching `/downloads/promptveil-pro-extension.zip` and `/og-image.png` on demand).
  - `extension/` (`manifest.json` MV3 `v2.2.0`, minimal `["storage", "activeTab"]` permissions, interactive Shadow DOM `content.js` tier pill, seamless `popup.js` activation with clipboard paste, `.pvkey`/`.txt` import, diagnostics, and site `adapters.js` across ChatGPT, Claude, Gemini, DeepSeek, GigaChat, Alice/YandexGPT): bundled deterministically via `esbuild` (`content.bundle.js` `97.4 KB` + `popup.bundle.js` `80.7 KB`) and packaged into exact 9-file `app/static/downloads/promptveil-pro-extension.zip` (`79.3 KB`, SHA-256 `ACE82CF96E717AA9581D10DCBE4984AD56B60AA48D9EB2A7456DBC8BE6710E66`).
  - `scripts/issue-pro-key.mjs` & `scripts/owner-console.mjs`: Offline Ed25519 CLI and local loopback `127.0.0.1` Owner Pro-Code Web Console (strictly outside `app/static/` and Git) reading the gitignored offline key bundle for single/batch issuance, order-to-key fulfillment, `.pvkey` export, and bundle/token verification.
  - Persistent Step 1 & Step 2 `#ai-launchers-bar` with 6 AI assistants (including `Gemini`), 1-click Copy+Open AI launchers, `Normal / Strict` sensitivity, Rulebook multi-project profiles + Free/Pro word packs, 1-click Prompt Templates, Honest Waitlist/Pro Licensing Pricing + `/pro/` & `/en/pro/` checkout links, `#how-it-works` / `#honest-limits`, and Trust Footer.
- **Local Preview, CI & Static Cloud Hosting (`app/`, `netlify.toml`, `pytest.ini`, `.github/workflows/ci.yml`):**
  - `app/main.py`, `app/config.py`, `app/schemas.py`: FastAPI static host (`http://127.0.0.1:8000`, `app_version == "1.0.0"` invariant preserved) + `/health` + strict CSP, `COOP: same-origin`, `CORP: same-origin`, and `/downloads/*.zip` (`application/zip`).
  - `netlify.toml`: `[build] command = "npm run build"`, `publish = "app/static"`, exact 9 `[[headers]]` blocks (strict CSP/COOP/CORP headers, `immutable` cache on `/dist/*`, `no-cache` on `/sw.js`, `application/manifest+json` on `/manifest.webmanifest`, and `application/zip` on `/downloads/*.zip`).
  - Repo hygiene: MIT `LICENSE`, bilingual RU+EN `README.md`, `CHANGELOG.md` (`2.3.0`), `.gitattributes`, `package.json` (`2.3.0`, `build`, `test:js`, `test:ext`), `pytest.ini` (`testpaths = tests`), and GitHub Actions CI.

---

## 2. Pre-Release R1–R6 Summary
1. **R1 Brand Emblem & Favicon:** Replaced shield+checkmark SVGs in `app/static/favicon.svg` and `app/static/index.html` (header `.brand-emblem` and footer `.footer-brand-emblem`) with a geometric prism/veil polygon monogram in `#051C12`, `#072F1F`, `#B4F105`, `#FFFFFF`.
2. **R2 Zero-Retention Proof & Copy Cleanup:** Removed `"Только в браузере"`, `"Все проверки выполняются локально в вашем браузере"`, and `"ничего не отправляется на сервер"` across `index.html` & `i18n.js`; converted `[data-testid="brand-badge"]` into `#open-proof-btn` (`"Гарантия 0 хранения • Проверить"` / `"Zero-Retention • Verify"`) alongside `#footer-open-proof-btn`; implemented `#modal-privacy-proof`, `privacy-proof.js`, `resetSessionToZero()`, and `pagehide` RAM/DOM scrub.
3. **R3 UX Speedups:** Added `readTextFromClipboard()` in `dom.js` with Ctrl/Cmd+V fallback guidance, `#paste-raw-btn` & `#paste-rehydrate-btn`, and `#copy-goto-step2-btn` (`"Скопировать и перейти к шагу 2 →"`).
4. **R4 Pricing & Client-Only Requests:** Added `#pricing-section` (`#nav-pricing-link` on desktop, Month/Year −20% toggle, Free `0 ₽`/`$0`, Pro `490/390 ₽`/`$6/$5`, Team `1 990/1 590 ₽`/`$24/$19`) and `#modal-plan-request` (client-side validation, copyable formatted summary, `mailto:kilkauciha@gmail.com`).
5. **R5 Trust Footer & Real Contacts:** Added 3-column Trust Footer with security badges, centralized `contacts.js`, copyable `@supv1rus` / `kilkauciha@gmail.com` / `github.com/Aquanti`, `© 2026 PromptVeil • Автор проекта: SupV1rus`, `#modal-privacy-policy`, strict CSP/XSS hygiene, and RU purity (`Эл. почта`).
6. **R6 Tests, E2E & Repo Hygiene:** Updated `.gitignore` (`.agents/`), `tests/test_server.py` (`20/20` PASS), `e2e_tests/{locators,monitors,run_e2e,test_acceptance,README}.py` and `e2e_tests/fixtures/smoke_contract.{html,js}`.

---

## 3. Verification Status (Post-Crash Full Re-Verification — 2026-11-21)
- **Active background processes / local servers / subagents:** `0` (`PORT_8000_LISTEN_COUNT=0`).
- **`npm run build`:** Deterministic build `7d1ffd0739` (`app/static/dist/*`, `0` git diffs).
- **`py_compile` across `app/`, `tests/`, `e2e_tests/`:** Exit `0` (`0` syntax errors).
- **`pytest tests/test_server.py -v`:** **`25 passed`** (`1.64s`, exit `0`).
- **`node --test tests/js/*.test.mjs`:** **`48 passed, 0 failed`** (`13` suites, `202ms`).
- **`e2e_tests/run_e2e.py --mode self-test`:** **`ALL CHECKS PASSED`** (`127` Tier 1–4 + `32` Tier 5 + `13` Acceptance = `172` unique tests, exit `0`).
- **`e2e_tests/run_e2e.py --mode live --base-url http://127.0.0.1:8000 --start-server --tier all`:** **`172 passed, 0 failed, 0 skipped`** (`413.08s`).
- **`e2e_tests/run_e2e.py --mode live --static-only --tier all`:** **`172 passed, 0 failed, 0 skipped`** (`404.59s`).
- **Live Lighthouse Audit (`https://promptveil.netlify.app`, Chrome Headless, saved in conversation scratch `lh-live-v3-{desktop,mobile}.json`):**
  - Desktop (`--preset=desktop`): Performance **`100`**, Accessibility **`100`**, Best Practices **`92`** (Netlify Free HUD `about:srcdoc` only; `0` app CSP violations), SEO **`100`** (`FCP 0.6 s`, `LCP 0.6 s`, `TBT 0 ms`, `CLS 0`, `SI 1.1 s`).
  - Mobile: Performance **`96`**, Accessibility **`100`**, Best Practices **`92`** (Netlify Free HUD `about:srcdoc` only; `0` app CSP violations), SEO **`100`** (`FCP 1.3 s`, `LCP 1.3 s`, `TBT 220 ms`, `CLS 0`, `SI 2.2 s`).
- **Live Visual & Functional Inspection (`browser` subagent `f2d75639` on `https://promptveil.netlify.app`):** Verified desktop `1440×900` (`/` & `/en/`) and mobile `390×844` dark theme screenshots (`final_step_32.png`, `step_30_shot_1_mobile_dark_390x844.png`) — `56.25px` mobile header, `>= 44px` tap targets, `0` horizontal overflow, `0` app errors, headers & detections confirmed.

---

## 4. Public Launch & Hosting Record
- **Live Public URL:** `https://promptveil.netlify.app` (RU), `https://promptveil.netlify.app/en/` (EN), and `https://promptveil.netlify.app/404.html`
- **GitHub Repository:** `https://github.com/Aquanti/promptveil` (`PUBLIC`, branch `master`, CI runs `45014109542`, `45016566078`, `45016724655` = `success`)
- **Netlify Project:** `promptveil` (`siteId: 12775486-f2aa-4d79-90c2-a85446c2b7a8`, `teamSlug: kil-ka-uchikha`, `plan: nf_team_dev` / Free)
- **Latest Production Deploy:** `6b02d335ed70fe705d106966` (`buildId: 6b02d334ed70fe705d106964`, state `ready` on 2026-11-22; prior deploys `6b02cf70b2ca4d46428d6ab1` and `6b02c869e5377eeb5918fb54`).
- **Completion & Pro Keys Email:** Delivered to `kilkauciha@gmail.com` (`Sent: ID=1a2030ce9bc9ab27`).


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

## 6d. v2 Audit Remediation — Milestone M6 (Final Verification Gate: 100% pass)

### Completed E2E Alignment (`e2e_tests/` only; `app/` and `tests/` untouched)
1. **`T5_32` Real HTTP `/sw.js` Update Harness (`e2e_tests/conftest.py`, `e2e_tests/test_tier5_adversarial.py`):**
   - Added `sw_body_provider` hook to `_StaticAppRequestHandler` / `start_static_dir_server` (plus `/manifest.webmanifest` `Cache-Control: public, max-age=300` parity) and updated `test_T5_32_stage_d_headers_template_modals_and_sw_update_banner` Part B to serve rotated `/sw.js` payloads from an isolated `127.0.0.1:0` HTTP origin with full security headers, `NetworkMonitor`, and `ConsoleErrorMonitor`.
2. **Suite Contract Alignments (`e2e_tests/test_tier1_features.py`, `e2e_tests/test_tier2_boundaries.py`, `e2e_tests/test_tier5_adversarial.py`):**
   - `T1_F8_01`: Branched on `--static-only` to assert HTTP `404` on `/health` in static Netlify-parity mode (matching `ACC_05`) and `200` JSON in FastAPI mode.
   - `T2_F4_06`: Updated valid rule addition assertion to check `role="status"` + `inline-alert--success` (`pipeline.js:324`) while preserving `novalidate`, empty-submit focus, and `role="alert"` error checks.
   - `T5_25`: Updated post-collapse `get_telemetry_masked_count()` assertions from `"1"` to `"2"` per M2 `result.maskedCount` contract while keeping unique vault collapse (`len(rows) == 1`) checks intact.

### Milestone M6 Gate Verification Results (Gate PASS)
- **Gate Result:** **PASS** (Forensic Auditor `CLEAN`, 2/2 Reviewers `APPROVE`, 2/2 Challengers `APPROVE`; `0` listening/active sockets on port `8000`).
- **`npm run build`:** `Built PromptVeil dist (7d1ffd0739)` (deterministic, `app/` clean).
- **`.\.venv\Scripts\python.exe -m pytest tests\test_server.py -v`:** **`25 passed, 0 failed`**.
- **`"C:\Program Files\nodejs\node.exe" --test tests\js\*.test.mjs`:** **`48 passed, 0 failed`** (`13` suites across `6` files).
- **`.\e2e_tests\.venv_e2e\Scripts\python.exe e2e_tests\run_e2e.py --mode self-test`:** **`ALL CHECKS PASSED`** (`172` unique tests).
- **`.\e2e_tests\.venv_e2e\Scripts\python.exe e2e_tests\run_e2e.py --mode live --base-url http://127.0.0.1:8000 --start-server --tier all`:** **`172 passed, 0 failed, 0 skipped`**.
- **`.\e2e_tests\.venv_e2e\Scripts\python.exe e2e_tests\run_e2e.py --mode live --static-only --tier all`:** **`172 passed, 0 failed, 0 skipped`**.

---

## 6e. v2 Audit Remediation — Milestone M7 (Production Deploy, Live Browser Verification & Lighthouse)

### Production Deploy & Live Verification
- **Production Deploy (Netlify MCP `netlify-deploy-services-updater`, confirmed `ready` via `netlify-open-deployments` & `get-deploy`):**
  - `siteId`: `12775486-f2aa-4d79-90c2-a85446c2c6a8`
  - `deployId`: `6b009726fbb09a4a4c3fc4e3`
  - `buildId`: `6b009724fbb09a4a4c3fc4e1`
  - Live URL: `https://promptveil.netlify.app`
- **Live Browser Verification (`teamwork_challenger_m7_live`):**
  - **`80/80` checks PASSED (`0` failed)** across `/`, `/en/`, and `390×844` mobile (`0` app CSP/console/`pageerror`/egress violations).
  - Verified `/manifest.webmanifest` `Content-Type: application/manifest+json; charset=utf-8`, `/dist/*` `Cache-Control: public,max-age=31536000,immutable`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`.
  - Verified all P0 detection & round-trip cases (`Алексей Смирнов`, `Иван Петров`, `ООО «Вектор»`, `АО «ТехноСфера»`, `ПАО «ТестБанк»`, `карта 4276 3800 1234 5678`, `Москва, ул. Ленина, д. 5`, `UUID` toggle, RAM-only audit default), plus Stage B–E UI/mobile (`56.25px` header, `>= 44px` tap targets, `390×844` drawers)/SW/growth checks live.
- **Live Lighthouse (`https://promptveil.netlify.app`, reports saved outside repo at `C:\Users\User\.gemini\antigravity\scratch\teamwork\3e50616b-ac3e-43ee-a409-1c9ac6dc2c6a\lighthouse\`):**
  - **Desktop (`lighthouse_desktop.report.{html,json}`):** Performance **`100`**, Accessibility **`100`**, Best Practices **`92`** (Netlify Free HUD `about:srcdoc` only; `0` app CSP errors), SEO **`100`** | FCP `0.5 s`, LCP `0.5 s`, TBT `0 ms`, CLS `0`, SI `0.9 s`.
  - **Mobile (`lighthouse_mobile.report.{html,json}`):** Performance **`100`**, Accessibility **`100`**, Best Practices **`92`** (Netlify Free HUD `about:srcdoc` only; `0` app CSP errors), SEO **`100`** | FCP `1.3 s`, LCP `1.3 s`, TBT `70 ms`, CLS `0`, SI `1.8 s`.
- **Final Automated Verification Summary:**
  - `.\.venv\Scripts\python.exe -m pytest tests\test_server.py -v`: **`25/25` passed**.
  - `"C:\Program Files\nodejs\node.exe" --test tests\js\*.test.mjs`: **`48/48` passed**.
  - `.\e2e_tests\.venv_e2e\Scripts\python.exe e2e_tests\run_e2e.py --mode self-test`: **PASS** (`172` unique tests).
  - `.\e2e_tests\.venv_e2e\Scripts\python.exe e2e_tests\run_e2e.py --mode live --base-url http://127.0.0.1:8000 --start-server --tier all`: **`172/172` passed**.
  - `.\e2e_tests\.venv_e2e\Scripts\python.exe e2e_tests\run_e2e.py --mode live --static-only --tier all`: **`172/172` passed**.
- **Completion Email Status (`kilkauciha@gmail.com`):**
  - **Sent (2026-11-21):** Completion report `completion_email_v3.md` sent via `gmail mutate send` (`Sent: ID=1a1fd8f07328cc77`, `Thread=1a1fd8f07328cc77`).
  - *(Historical worker note: during the earlier 2026-11-20 subagent run, direct worker attempts hit `oauth2.googleapis.com/token: Bad Gateway`; resolved cleanly after session re-initialization.)*

---

## 7. GitHub Remote & Publication (`Aquanti/promptveil`)
- **Public Repository:** `https://github.com/Aquanti/promptveil` (`visibility: PUBLIC`, default branch `master`, homepage `https://promptveil.netlify.app`).
- **Topics:** `privacy`, `pii`, `llm`, `prompt-engineering`, `zero-retention`, `pwa`, `manifest-v3`.
- **CI Workflow:** `.github/workflows/ci.yml` (`ubuntu-latest`, Node `24`, Python `3.13`, `npm run build`, `pytest`, `test:js`, `test:ext`, E2E `--mode self-test` + `--mode live --static-only --tier all`).

---

## 8. Final Handover & Security Posture
1. **GitHub Public Repo:** `https://github.com/Aquanti/promptveil` published with zero tracked secrets (`0` leaks across tracked files and Git history; synthetic E2E Slack test string sanitized to non-secret format).
2. **Production Live URL:** `https://promptveil.netlify.app` (RU `/` and EN `/en/`, with branded `404.html`).
3. **Private Ed25519 Signing Key & Client Tokens:** Kept exclusively outside Git in local gitignored `.secrets/pro_keys_bundle.json` (plus scratch backup). Use `node scripts/issue-pro-key.mjs --issue --tier pro --key-id <id> --label "<label>"` to mint additional keys offline.

---

## 9. PromptVeil Pro Upgrade — Milestone M1 (R1 + R2)
- **R1 Persistent AI Launchers + Gemini (`index.html`, `en/index.html`, `app.js`, `components.css`, `tests/test_server.py`):**
  - Hoisted `#ai-launchers-bar` out of `#panel-sanitize` into `<main id="main-workbench">` after `#panel-rehydrate` so it remains visible across both Step 1 and Step 2, added `data-testid="ai-launcher-gemini"` (`https://gemini.google.com/app`), flushed pending live sanitization on Step 2 switch so `.is-ready` stays active, and allowlisted Gemini in `tests/test_server.py`.
- **R2 Offline Ed25519 Pro License System (`.gitignore`, `scripts/issue-pro-key.mjs`, `pro-license.js`, `privacy-proof.js`, `modals.js`, `pricing.js`, `i18n-{ru,en}.js`, `tests/js/pro-license.test.mjs`):**
  - Protected `.secrets/`, `*.pem`, `pro_keys*.json` in `.gitignore` prior to key generation; generated Ed25519 keypair + 1 Owner Master Key + 20 Client Pro keys strictly into `.secrets/pro_keys_bundle.json` (plus external scratch backup).
  - Implemented `pro-license.js` (`WebCrypto Ed25519` + pure-JS RFC 8032 Ed25519 & SHA-512 fallback), allowlisted `promptveil_pro_license_v1` in `privacy-proof.js`, added `#open-pro-license-btn` header badge (`>= 44px` mobile, `0` overflow), `<template id="tpl-modal-pro-license">` (`#modal-pro-license`), and key-activated `#pricing-section` Pro card (`#open-pro-modal-btn` + `#pricing-activate-pro-btn`).
- **Verification:** `npm run build` (`878c8c93ef`), `node --test tests\js\*.test.mjs` (`55/55` across `14` suites), `pytest tests\test_server.py -v` (`25/25`), Playwright Chrome smoke check across `1440×900` and `390×844` (`/` & `/en/`), and secret hygiene audit (`0` leaked keys/tokens in Git or `app/static/`).

---

## 10. PromptVeil Pro Upgrade — Milestone M2 (R3)
- **Local Document Parsers & ZIP Engine (`app/static/js/pro-documents.js`):**
  - 100% browser-local ES2022 module (`0` network calls, `0` unsafe HTML sinks, `0` `http(s)://` literals): IEEE 802.3 `crc32`, `DecompressionStream("deflate-raw"|"deflate")` with pure-JS RFC 1951 `inflateRawPureJs` and RFC 1950 `inflateZlibPureJs` fallbacks, PKZIP reader (`readZipEntries` with EOCD/CD/LFH/UTF-8/CRC32/zip-bomb checks) and deterministic Store `.zip` builder (`buildZipArchive`), `.docx` extractor (`word/header*.xml`, `word/document.xml`, `word/footer*.xml` via `DOMParser` + `parseXmlPureJs` fallback), `.xlsx` extractor (`xl/sharedStrings.xml` including rich-text excluding `<rPh>`, `xl/workbook.xml` sheet ordering, `t="s"/"inlineStr"/"b"/numeric`), and binary-safe `.pdf` extractor (`FlateDecode`, `ToUnicode` CMap `bfchar`/`bfrange`, UTF-16BE BOM, WinAnsi/PDFDocEncoding, `BT...ET` `Tj`/`TJ`/`'`/`"`, `/Encrypt` rejection, and `isScannedPdf` detection).
- **Free vs. Pro Limits, Batch Queue & Step 2 Rehydrate (`clipboard.js`, `pipeline.js`, `render-workbench.js`, `app.js`, `index.html`, `en/index.html`, `i18n-{ru,en}.js`, `css/components.css`):**
  - Updated `#file-upload-input` (`accept=".txt,.md,.csv,.json,.log,.env,.docx,.pdf,.xlsx" multiple`), added `#file-pro-upgrade-banner` (`role="status"`, `#file-pro-upgrade-btn` opening `#modal-pro-license`) while preserving Free `> 2 MB` `role="alert"` (`"2 МБ"` / `"2 MB"`) and `.png` unsupported format contracts, and kept `app.js` under `< 750` lines (`728` lines).
  - Added `#batch-queue-panel` (`#batch-queue-list`, `#batch-clear-btn`, `#batch-download-txt-btn`, `#batch-download-zip-btn`, `#batch-rehydrate-btn`) with shared `SessionVault` (`{ resetOnEmpty: false }`), masked previews, honest scanned-PDF notices, and `MutationObserver` sync on `#open-pro-license-btn[data-pro-state]`.
- **Verification:** `npm run build` (`9e9f991fbb`), `node --test tests\js\*.test.mjs` (`64/64` across `17` suites), `pytest tests\test_server.py -v` (`25/25`).

---

## 11. PromptVeil Pro Upgrade — Milestone M3 (R5)
- **Multi-Project Rulebook Profiles & Privacy Proof (`app/static/js/{storage,privacy-proof,render-drawers,pipeline,app}.js`, `app/static/{index,en/index}.html`, `app/static/css/drawers.css`):**
  - Implemented `PROFILES_STORAGE_KEY` (`promptveil_profiles_v1`) in `storage.js` with `loadProfilesStore`, `saveProfilesStore`, `getActiveProfile`, `setActiveProfileRules`, `createProfile`, `renameProfile`, `switchProfile`, `deleteProfile`, `exportProfileRulesJson`, and `importProfileRulesJson`, including legacy `promptveil_rules_v1` migration, corruption recovery (`"{broken"`, `"[null, {}]"`), duplicate/empty/reserved-name validation, default/last-profile delete protection, and Free-tier mutation blocking without writing `localStorage`.
  - Allowlisted `PROFILES_STORAGE_KEY` in `privacy-proof.js` and exempted it alongside `RULES_STORAGE_KEY` in the active secret-needle scan so custom rule keywords in profiles never produce false-positive `leakedSecretBytes`.
  - Added `.profiles-box` (`#profile-select`, `#profile-name-input`, `#profile-create-btn`, `#profile-rename-btn`, `#profile-delete-btn`, `#rulebook-pro-upgrade-banner`) inside `#drawer-rulebook` while preserving single `<input type="file">` (`#import-rules-input`), zero `role="switch"` above `#rulebook-list`, non-closing inline Free upgrade prompts, zero `window.confirm()` on delete, and `app.js` at `719` lines (`< 750`).
- **Extended Pro Word Packs & 1-Click Prompt Templates (`app/static/js/{presets,render-workbench,i18n-ru,i18n-en}.js`, `app/static/css/components.css`, `tests/js/profiles-presets.test.mjs`, `tests/test_server.py`):**
  - Exported `PRO_INDUSTRY_WORD_PACKS` (`corporate_ma`, `devsecops`, `banking_fintech`, `crossborder_nda` — 6 clean literal terms each) and `PROMPT_TEMPLATES` (`contract_review`, `nda_redline`, `code_security_review` — anonymized RU/EN templates) in `presets.js` while keeping `INDUSTRY_WORD_PACKS` intact.
  - Added `#prompt-templates-bar` (`#prompt-template-preview`, `#prompt-template-upgrade-btn`) above `.split-workbench` with Free lock badges/preview and Pro 1-click insert + sanitize, 100% RU/EN dictionary parity (`32` new keys per language, zero RU jargon/dev-codes), and `>= 44px` mobile `390×844` tap targets with zero overflow.
- **Verification:** `npm run build` (`22cecb109f`), `"C:\Program Files\nodejs\node.exe" --test tests\js\*.test.mjs` (`75/75` across `18` suites), `.\.venv\Scripts\python.exe -m pytest tests\test_server.py -v` (`26/26`), `(Get-Content app\static\js\app.js).Count` (`719`), and targeted Playwright E2E (`T1_F13_01..05`, `T1_F8_15`, `T2_F13_01..05`, `T5_11`, `T5_18` — `13/13` passed).

---

## 12. PromptVeil Pro Upgrade — Milestone M4B (R4 + R6 Local Gate)
- **Deterministic Extension Bundling & PKZIP Packaging (`scripts/build.mjs`, `extension/dist/*`, `app/static/downloads/promptveil-pro-extension.zip`, `app/static/sw.js`):**
  - Extended `scripts/build.mjs` to bundle `extension/src/{content,popup}.js` via `esbuild` (`bundle: true, format: "iife", target: ["es2022"], minify: true, legalComments: "none"`), validate extension JS/CSS against unsafe sinks, network APIs, external URL literals, `localStorage`, and `100vw`, and package strictly the 9 allowlisted runtime files (`manifest.json`, `popup.html`, `popup.css`, `content.css`, `dist/content.bundle.js`, `dist/popup.bundle.js`, `icons/icon-{16,48,128}.png`) into a deterministic pure-JS PKZIP archive (`node:zlib` `deflateRawSync` + Store fallback, IEEE 802.3 CRC-32, bytewise-sorted POSIX paths, UTF-8 flag `0x0800`, fixed DOS timestamp `0x0000`/`0x5C21`).
  - Included `downloads/promptveil-pro-extension.zip` in `buildHash` (`bbad93a0d1`) and `"/downloads/promptveil-pro-extension.zip"` in `app/static/sw.js` `PRECACHE_URLS`.
- **Server, Netlify, Pro Downloads Modal & R6 Polish (`app/main.py`, `netlify.toml`, `app/static/{index,en/index}.html`, `app/static/js/{modals,i18n-ru,i18n-en}.js`, `app/static/css/{modals,sections}.css`):**
  - Registered `application/zip` for `.zip` and `Cache-Control: public, max-age=300` on `/downloads/*.zip` in `app/main.py` and `netlify.toml` (keeping all 7 CSP/security headers intact).
  - Added `<template id="tpl-modal-pro-downloads">` (`#modal-pro-downloads`, 1-click `#download-extension-zip-btn`, Chrome / Edge / Яндекс.Браузер / Yandex Browser setup guides), `#open-pro-downloads-btn` in `#pricing-card-pro`, and `#pro-license-downloads-btn` in `#tpl-modal-pro-license`, wired purely inside `modals.js` (keeping `app.js` untouched at `719 < 750` lines) with strict Free gating, mutual modal exclusion, Escape/Tab focus trap, updated `terms.item3*` copy, 100% RU/EN parity, and `>= 44px` mobile `390×844` tap targets with zero `100vw`.
- **Verification:** Double-run `"C:\Program Files\nodejs\npm.cmd" run build` produced identical SHA-256 hashes across `promptveil-pro-extension.zip`, `extension/dist/*`, `app/static/dist/*`, and `app/static/sw.js`; `"C:\Program Files\nodejs\node.exe" --test tests\js\*.test.mjs` (`79/79` across `19` suites), `"C:\Program Files\nodejs\node.exe" --test extension\tests\*.test.mjs` (`14/14`), `.\.venv\Scripts\python.exe -m pytest tests\test_server.py -v` (`27/27`), `app.js` `719` lines, and port `8000` free.

---

## 13. PromptVeil Pro Upgrade — Milestone M5 Phase 1 E2E Fixes (`checkpoint: m5-phase1-fixes`)
- **E2E Test & Page-Object Fixes (`e2e_tests/test_tier1_features.py`, `e2e_tests/locators.py`, `e2e_tests/test_tier4_scenarios.py`):**
  - `test_T1_F8_14_zero_egress_across_full_pro_workflow`: moved 1-click prompt template selection (`ui.click_prompt_template(tid)`) before `ui.upload_files([docx_p, pdf_p])` so template loading does not clear `state.batchItems` and `state.vault` mid-batch before `download_batch_zip` / `click_batch_rehydrate` / `rehydrate_text`.
  - `PromptVeilUI.download_extension_zip`: checked whether `#modal-pro-downloads` was already visible prior to calling `self.open_pro_downloads_modal()` and closed `#modal-pro-downloads` via `self.close_active_modal()` after `download.save_as(...)` when opened by `download_extension_zip()`, preventing `#drawer-backdrop` from intercepting subsequent clicks in `test_T3_14` and `test_ACC_16` while keeping `test_T1_F12_03` and `test_T1_F12_05` passing.
  - `test_T4_09_mobile_390x844_pro_workflow_and_key_deactivation_downgrade`: called `ui.click_clear_input()` before `ui.sanitize_text("Downgraded free.user@example.ru")` on mobile `390×844` so `SessionVault` resets cleanly after the prior Pro batch and deterministically assigns `[EMAIL_1]` post-downgrade.
- **Verification (Sequential):**
  - Deterministic `npm run build` x2: `bbad93a0d1` (`0` unexpected git diffs across `app/static/dist/`, `app/static/downloads/promptveil-pro-extension.zip`, `app/static/sw.js`, and HTML files).
  - `.\.venv\Scripts\python.exe -m py_compile` (`app/*.py`, `tests/*.py`, `e2e_tests/*.py`): exit `0` (`17` files).
  - `.\.venv\Scripts\python.exe -m pytest tests/test_server.py -v`: **`27 passed`**.
  - `node --test tests/js/*.test.mjs`: **`79 passed`** (`19` suites); `node --test extension/tests/*.test.mjs`: **`14 passed`**.
  - `.\e2e_tests\.venv_e2e\Scripts\python.exe e2e_tests\run_e2e.py --mode self-test`: **`ALL CHECKS PASSED`** (`245` unique tests collected).
  - Targeted Live FastAPI (`--base-url http://127.0.0.1:8000 --start-server`) & Static-Only (`--static-only`) for `test_T1_F8_14 or test_T1_F12_03 or test_T1_F12_05 or test_T3_14 or test_T4_09 or test_ACC_16`: **`6 passed` / `6 passed`**, `0` listeners on port `8000`.

---

## 14. PromptVeil v2.2.0 Release, Public GitHub Launch & P0–P2 Optimizations (2026-11-22)
- **M5 Phase 2 Hardening & Full 252-Test Live Verification (`b07f5f9` / `21ecae6`):**
  - Expanded suites to `27` server/CSP pytest checks, `86` web JS unit tests (`19` suites), `16` extension JS unit tests, and `252` Playwright E2E tests (`197` Tier 1–4 + `39` Tier 5 + `16` Acceptance).
  - Re-verified full Live FastAPI E2E (**`252 passed`**, `0` failed/skipped) and full Live Static-Only E2E (**`252 passed`**, `0` failed/skipped).
  - Updated `README.md` (RU + EN), `CHANGELOG.md` (`[2.2.0]`), `package.json` (`2.2.0`, `test:ext`), and `.github/workflows/ci.yml` (`python-version: "3.13"` + extension test step); created & pushed public `https://github.com/Aquanti/promptveil` (`master`).
- **P0–P2 Audit Optimization Pass (`b355565aea`):**
  - **P0 (`charset: "utf8"` & `modulepreload` Fix in `scripts/build.mjs`):** Added `charset: "utf8"` across all 4 `esbuild.build()` calls, shrinking `i18n-ru` from `108,213 B` (`105.68 KB`) to `47,408 B` (`46.30 KB`, `-56.2%`), `extension/dist/content.bundle.js` from `109,652 B` (`107.08 KB`) to `87,395 B` (`85.35 KB`), and `extension/dist/popup.bundle.js` from `82,019 B` (`80.10 KB`) to `60,246 B` (`58.83 KB`); fixed `modulepreload` so `index.html` preloads `i18n-ru-*.js` and `en/index.html` preloads `i18n-en-*.js`.
  - **P1 (Lazy `pro-documents.js` Code-Split):** Moved `getDocumentErrorI18nKey` into `i18n.js` (re-exported by `pro-documents.js`) and switched `clipboard.js` and `pipeline.js` (`downloadBatchZip`) to dynamic `import("./pro-documents.js")`, trimming main entry bundle `app.*.js` from `211,956 B` (`206.99 KB`) to `151,674 B` (`148.12 KB`, `-28.4%`) with `pro-documents-*.js` (`31,179 B` / `30.45 KB`) + shared `chunk-*.js` (`4,317 B` / `4.22 KB`) loaded only when processing files/ZIPs.
  - **P1 (PWA/SW & SEO/404):** Removed `/downloads/promptveil-pro-extension.zip` and `/og-image.png` from eager `sw.js` `PRECACHE_URLS` (cached via SWR on demand), split `manifest.webmanifest` `"any maskable"` into distinct `"any"` and `"maskable"` entries, standardized `/favicon.svg`, `/apple-touch-icon.png`, and `/manifest.webmanifest` root-relative URLs in `index.html` & `404.html`, added `<meta name="robots" content="noindex" />` and `/en/` link to `404.html`, and added `og:image:alt` to `index.html` & `en/index.html`.
  - **P2 (DevOps & Test Alignment):** Added `command = "npm run build"` to `netlify.toml`, added `pytest.ini` (`testpaths = tests`), exempted clean same-origin `/dist/*.js` script chunks in `e2e_tests/monitors.py`, and updated `tests/test_server.py`, `tests/js/*.test.mjs`, and `e2e_tests/` tests cleanly.
  - **Verification (`b355565aea`):** Deterministic `npm run build` x2, `py_compile`, bare `pytest` (`27 passed`), `npm run test:js` (`86 passed`), `npm run test:ext` (`16 passed`), E2E `--mode self-test` (`252` tests), full Live Static-Only E2E (**`252 passed`** in `683.23s`, `0` failed/skipped), `0` secret leaks, and `PORT_8000_LISTEN_COUNT=0`.
- **UI/UX Live Audit & Polish (`bce283e` / `79b93523d5`):**
  - `404.html`: Switched secondary `/en/` link from `.btn-ghost` to `.btn-secondary` (verified crisp button styling on live `/404.html`).
  - `css/components.css`: Moved `#sw-update-banner` from fixed bottom-left overlay to non-overlapping in-flow banner inside `<main id="main-workbench">` above `.hero-strip` (verified `0` overlap on `"Скрыть данные"`, `#mobile-sticky-cta`, and open modals across `1440×900` and `390×844`).
  - **Verification (`79b93523d5`):** Deterministic `npm run build` x2, `pytest` (`27 passed`), `npm run test:js` (`86 passed`), `npm run test:ext` (`16 passed`), E2E `--mode self-test` (`252` tests), targeted live Static-Only E2E (`5/5` passed: `ACC_04`, `ACC_11`, `ACC_12`, `T4_06`, `T5_32`).
  - **Final Live Production Deploy (`bce283e`):** `https://promptveil.netlify.app` (`deployId: 6b02d335ed70fe705d106966`, `buildId: 6b02d334ed70fe705d106964`, `ready`); verified via `browser` subagent `32bffc72`, GitHub CI (`45014109542`, `45016566078`, `45016724655` = `success`), live Lighthouse (`Desktop 100/100/92/100`, `Mobile 93/100/92/100`), and Gmail delivery (`Sent: ID=1a2030ce9bc9ab27`).

---

## 15. PromptVeil v2.3.0 — Pro Checkout, Owner Console & Seamless MV3 Extension (2026-11-23)
- **R1 — Dedicated Pro Checkout & Activation Pages (`/pro/`, `/en/pro/`):**
  - Added static RU (`app/static/pro/index.html`) and EN (`app/static/en/pro/index.html`) Pro checkout & activation pages with `hreflang` alternates, `app/static/sitemap.xml` entries, Spark Admin light/dark UI (`app/static/js/theme.js` extracted from `modals.js`), `390×844` mobile responsiveness (`>= 44px` tap targets, zero horizontal overflow, zero `100vw`), and strict CSP (`script-src 'self'`, `connect-src 'self'`, zero inline `<script>`/`<style>`/`style=`/`on*`).
  - Implemented `app/static/js/pro-checkout.js` and `app/static/css/pro-checkout.css`: 4 tariff options (`pro-monthly`, `pro-annual`, `pro-lifetime`, `team-pack`), 3 payment methods (`card`, `sbp`, `invoice`, zero raw PAN/CVV fields), buyer form validation (`#checkout-name`, `#checkout-email`, `#checkout-company`, `#checkout-terms`), RAM-only `PV-ORD-...` order receipt with copy/download actions, and an always-visible Ed25519 Activation & Validation Terminal (`#code=PV1...` fragment hydration on `load`/`hashchange`, `.pvkey`/`.txt` upload with `256 KB` pre/post-read guards, claim viewer, `.pvkey` download, and immediate `/downloads/promptveil-pro-extension.zip` unlock).
  - Wired `#pricing-pro-checkout-link` and footer checkout links from `/` & `/en/` plus `.error-pro-link` on `404.html` (preserving `#open-pro-modal-btn`, `#pricing-activate-pro-btn`, `#modal-plan-request`), with 100% RU/EN dictionary & `{placeholder}` parity (`615/615` keys), multi-entry `esbuild` bundling (`scripts/build.mjs`: `app.js` + `pro-checkout.js`, `splitting: true`), and `sw.js` precaching of `/pro/` & `/en/pro/`.
- **R2 — Transparent Owner Pro-Code CLI & Local Loopback Console (`scripts/issue-pro-key.mjs`, `scripts/owner-console.mjs`, `app/static/js/pro-license.js`):**
  - Extended `pro-license.js` with `extractProToken()`, `formatPvKeyFileContent()`, `decodeProTokenPayloadUnsafe()`, `inspectProLicenseToken()`, and fail-closed `nowMs` bounds (`±8.64e15` ms) while preserving `PRO_PUBLIC_KEY_B64U` and `promptveil_pro_license_v1`.
  - Upgraded `scripts/issue-pro-key.mjs` with full payload schema + `exp` + `--now` checks, `PRO_PUBLIC_KEY_B64U` mismatch guard (`--pub` override), `--plan` presets, batch issuance (`--count`, `--prefix`), `--order` references, `.pvkey`/table export, ledger appending, `--inspect-bundle`/`--verify-bundle`/`--redact`, `--json`, and strict `VALUE_FLAGS` validation.
  - Added local loopback `127.0.0.1` Owner Web Console (`scripts/owner-console.mjs`, outside `app/static/` and Git) reading the gitignored offline key bundle for single/batch token issuance, order-to-key fulfillment, `#code=PV1...` link generation, `.pvkey` export, and token validation under strict `OWNER_CONSOLE_CSP` and `Host`/`Origin`/`Referer` CSRF guards; verified via ephemeral runtime `node:crypto` unit tests (`tests/js/issue-pro-key.test.mjs`, `tests/js/pro-checkout.test.mjs`, `tests/js/pro-license.test.mjs`).
- **R3 — MV3 Extension v2.2.0 & Deterministic Build (`extension/`, `scripts/build.mjs`, `app/static/downloads/promptveil-pro-extension.zip`):**
  - Bumped `extension/manifest.json` `"version"` to `"2.2.0"` while keeping minimal `["storage", "activeTab"]` permissions, zero `host_permissions`, zero `background`, exact 6 AI host `matches`, and zero `localStorage`.
  - Upgraded `extension/src/popup.js`, `extension/popup.html`, `extension/popup.css`, `extension/src/i18n-ext.js`, and `extension/src/content.js`: smart `PV1.` extraction, 1-click `#popup-pro-paste-btn` (`navigator.clipboard.readText()`), `.pvkey`/`.txt` file import (`#popup-pro-file-input`, `256 KB` pre/post-read guard, NUL/UTF-8 checks), `#popup-pro-verify-btn` + `#popup-pro-diagnostics`, actionable locked-feature focus hints, async race-sequence guards (`proActionSeq`, `licenseRefreshSeq`, `settingsRefreshSeq`), RU/EN live alert re-translation, `chrome.storage.local` + `onChanged` synchronization, and interactive Shadow DOM `.pv-tier-chip` diagnostics.
- **M4 Phase 1 & Phase 2 Hardening (`e2e_tests/`, `pro-checkout.js`, `pro-license.js`, `owner-console.mjs`, `issue-pro-key.mjs`, `extension/src/popup.js`):**
  - **Phase 1 E2E Alignment:** Added narrow same-origin `/favicon.svg` & `/favicon.ico` exemption in `e2e_tests/monitors.py` (with 4 negative leak checks in `e2e_tests/run_e2e.py`) eliminating Chromium `FaviconHandler` hash-navigation false positives.
  - **Phase 2 Tier 5 Hardening & 53-Test Adversarial Suite (`T5-01..T5-53`):** Added `inspectSeq`/`licenseMutationSeq` race guards, `saveStoredProLicenseToken` quota/storage warning banner, `claims.tier` & `exp` UTC fixes in `pro-checkout.js` / `pro-license.js`; strict loopback `Origin`+`Referer` validation, `//`/`/\` path rejection, `/favicon.ico` `204`, and path-free ledger errors in `owner-console.mjs`; bundle `clientKeys` array/empty-bundle checks and generic `409` ledger errors in `issue-pro-key.mjs`; external `storage.onChanged` inspection/feedback reset in `extension/src/popup.js`; and load/interactive phase isolation fixes in `test_T5_41`, `test_T5_43`, and `test_T5_45`.
- **Final Verification Summary (`2.3.0`, Post-Final-Edit):**
  - **Deterministic `npm run build` (x2):** Identical build hash **`caae73027c`** (`styles.33F4J2G4.css`, `app.2WRYAKBR.js`, `pro-checkout.F3FLKHD7.js`, `chunk-QGSFLC2X.js`, `chunk-WTZKIRLZ.js`, `i18n-en-MGIBIQSQ.js`, `i18n-ru-5KBQW4ZO.js`, `pro-documents-CVYJF6MZ.js`, `sw.js` `CACHE_NAME = "promptveil-build-caae73027c"`), and identical `app/static/downloads/promptveil-pro-extension.zip` SHA-256 **`ACE82CF96E717AA9581D10DCBE4984AD56B60AA48D9EB2A7456DBC8BE6710E66`** (exact 9 entries).
  - **FastAPI / CSP / Static Hygiene (`.\.venv\Scripts\python.exe -m pytest -v`):** **`28 passed`**.
  - **Web JS Unit Tests (`npm run test:js`):** **`110 passed`** across `21` suites.
  - **Extension MV3 Unit Tests (`npm run test:ext`):** **`27 passed`**.
  - **E2E Self-Test (`.\e2e_tests\.venv_e2e\Scripts\python.exe e2e_tests\run_e2e.py --mode self-test`):** **`ALL CHECKS PASSED`** (`221` Tier 1–4 `[103+89+18+11]` + `53` Tier 5 + `18` Acceptance = **`292` unique tests**).
  - **Full Live Static-Only E2E (`--mode live --static-only --tier all`):** **`292 passed, 0 failed, 0 skipped`**.
  - **Full Live FastAPI Start-Server E2E (`--mode live --start-server --tier all`):** **`292 passed, 0 failed, 0 skipped`**.
  - **Release Commit, Netlify Production Deploy & Gmail Report (`2.3.0`):**
    - **Git (`master`):** Release commit `ad4b1f57f767c58d9a67b81b420de814e2e7109d` (`ad4b1f5`, zero `.secrets/` or private/live keys staged).
    - **Netlify Production Deploy (`siteId: 12775486-f2aa-4d79-90c2-a85446c2b7a8`):** `deployId: 6b046f223f001957c8c2ca5c`, `buildId: 6b046f213f001957c8c2ca5a`, state `ready`, live URL `https://promptveil.netlify.app` (`https://6b046f223f001957c8c2ca5c--promptveil.netlify.app`).
    - **Live Production Verification (`https://promptveil.netlify.app`):** Confirmed HTTP `200 OK` and strict `Content-Security-Policy` header across `/`, `/en/`, `/pro/`, `/en/pro/`, and `/downloads/promptveil-pro-extension.zip` (`Content-Type: application/zip`, `79,256` bytes, SHA-256 `ACE82CF96E717AA9581D10DCBE4984AD56B60AA48D9EB2A7456DBC8BE6710E66`).
    - **Completion Email (`kilkauciha@gmail.com`):** Sent via `gmail mutate send` (`Sent: ID=1a2095306951e73c`, `Thread=1a2095306951e73c`).
