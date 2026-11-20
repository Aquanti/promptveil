# Project Progress — PromptVeil

**Checkpoint Date:** 2026-11-20T18:08+03:00  
**Session Status:** Stage 2 (P1 PWA Offline, AI Launchers, P1 Detectors, Dark Theme) Complete — Proceeding to Stage 3 (`app.js` Modularization & Lighthouse >= 95)  
**Exact Stop Point:** Completed and verified all Stage 2 (P1) upgrades: `app/static/sw.js` self-hosted static-only Service Worker + `#proof-offline-card` + `/sw.js` `no-cache` header in `netlify.toml`, `#ai-launchers-bar` 5-LLM launcher strip + clickable `@supv1rus` & `github.com/Aquanti` footer links + allowlisted CSP checks, P1 detectors (`URL_TOKEN`, `RU_AUTO_PLATE`, `RU_FIO` sliding window, `RU_ADDRESS`), Dark Theme (`#theme-toggle-btn`, `promptveil_theme_v1`, `prefers-color-scheme: dark`, `prefers-reduced-motion: reduce`), plus acceptance fixes (`<link rel="canonical">` excluded from external DOM scan, `#modal-terms` registered in `DIALOG_IDS`). Verified `py_compile` (`0` errors), `pytest tests/test_server.py` (`22 passed`), `run_e2e.py --mode self-test` (`150` unique tests), and full live suite `run_e2e.py --mode live --tier all` (`150 passed`, `0 failed`). Next: Stage 3 (`app.js` -> `clipboard.js`, `pricing.js`, `modals.js` + Lighthouse >= 95 + final Netlify production deploy & live HTTPS verification).

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
  - Modular ES6 UI controllers: `js/{i18n,dom,presets,render-workbench,render-drawers,privacy-proof,contacts,app}.js` with full `RU | EN` coverage, Step 1/2 Paste + Copy-and-Go-Step-2 UX, instant `resetSessionToZero()` + `pagehide` scrub, Pricing (`Free`/`Pro`/`Team`, Month/Year −20%) with client-only request modals, and Trust Footer + Privacy Policy modal.
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
- **`e2e_tests/run_e2e.py --mode live --base-url http://127.0.0.1:8000 --start-server --tier all`:** **`150 passed`** (`322.36s`, exit `0`, `0` failed, `0` skipped, `0` console/page/CSP errors).
- **Visual Inspection (`e2e_tests/artifacts/acceptance/*.png`):** Inspected `1440×900` & `390×844` light and dark screenshots (`acc_desktop_dark_1440x900.png`, `acc_mobile_dark_390x844.png`, `acc_desktop_pricing_footer_1440x900.png`) — zero overlaps, zero clipping, zero horizontal overflow, WCAG AA contrast, mobile `.top-rail <= 64px`.

---

## 4. Public Launch & Hosting Record
- **Live Public URL:** `https://promptveil.netlify.app` (renamed from `promtveil` on 2026-11-20)
- **Netlify Project:** `promptveil` (`siteId: 12775486-f2aa-4d79-90c2-a85446c2b7a8`, `teamSlug: kil-ka-uchikha`, `plan: nf_team_dev` / Free)
- **Pending Production Re-deploy:** Deploy updated `app/static/` (Stage 1–3) after Stage 3 completion and verify live HTTPS/offline behavior.
