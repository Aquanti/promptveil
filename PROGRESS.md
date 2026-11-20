# Project Progress — PromptVeil

**Checkpoint Date:** 2026-11-20T16:27Z (`19:27+03:00`)  
**Session Status:** v2 Audit Remediation — Stage B / Milestone M2 (State, Validation & i18n Parity, Items 6–13) COMPLETE  
**Exact Stop Point:** Stage B / M2 (Items 6–13) implemented, gate-verified (Gate Iteration 1 PASS: Forensic Auditor `CLEAN`, 2/2 Reviewers `APPROVE`, 2/2 Challengers `CONFIRM`), and committed locally (`checkpoint: stage B state validation and i18n parity`). E2E suite in `e2e_tests/` (`172` unique tests) remains aligned in working tree (`self-test` PASS) and Stage A / M1 (`master @ 5636cd9`) is preserved below. Next planned stage: `M3 — Stage C: Mobile UX 390x844`.

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
1. **Next Planned Stage — `M3 — Stage C: Mobile UX 390x844` (Items 14–18):** Compact header (`<= 64px`, `44×44` lock+dot badge, single RU/EN toggle, `"⋯"` overflow menu), shortened Step 2 tab label, `>= 44px` tap targets, collapsible vault + sticky CTA bar, drawer `min(100%, ...)` width fix.
2. **`M4` — Bundling / SW / COOP-CORP / CI (Items 19–27):** `esbuild` CSS/JS bundling, immutable cache headers, lazy i18n & `<template>` modals, SW update banner, COOP/CORP headers, dead code removal, modularization, GitHub Actions CI workflow.
3. **`M5` — Stage E Growth Features:** Safe static client-side growth items (Items 28, 31–34, 36 + out-of-scope roadmap notes).
4. **`M6` — Full Live E2E (`172` tests):** Run `pytest`, `node --test`, `run_e2e.py --mode self-test`, and `run_e2e.py --mode live --base-url http://127.0.0.1:8000 --start-server --tier all` (`172/172` with `0` failures).
5. **`M7` — Production Netlify Deploy & Delivery:** Deploy to production Netlify + confirm via `netlify-open-deployments`, verify live `https://promptveil.netlify.app` in browser, run Desktop & Mobile Lighthouse outside repo, update `PROGRESS.md` + commit, and send completion email to `kilkauciha@gmail.com`.
