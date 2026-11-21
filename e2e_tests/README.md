# PromptVeil Opaque-Box E2E Test Suite (`e2e_tests/`)

Standalone Playwright + Pytest end-to-end verification harness for **PromptVeil & PromptVeil Pro (100% Client-Side Zero-Egress Web SaaS, R1–R6)**.

## Architecture & Isolation

- **Isolated Python Environment (`e2e_tests/.venv_e2e/`)**: Uses `playwright>=1.65.0` and `pytest>=9.0.0` without modifying the main project `.venv/` or `requirements.txt`.
- **Zero Browser Download**: Launches system Google Chrome (`channel="chrome"`) with automatic Microsoft Edge (`channel="msedge"`) and Playwright Chromium fallbacks.
- **Contract-First Opaque-Box Locators (`locators.py`)**: `PromptVeilUI` resolves controls by `[data-testid='...']`, ARIA role/name, and bilingual RU/EN labels across Step 1 (`Sanitize`), Step 2 (`Re-Hydrate`), persistent `#ai-launchers-bar`, Pro License modal, Pro Downloads modal, batch queue panel, Rulebook profiles/packs, prompt templates bar, and Audit Receipts, emitting DOM diagnostic snapshots on lookup failures.
- **Zero-Egress & Runtime Monitors (`monitors.py`)**:
  - `NetworkMonitor`: Phase-aware request tracker asserting **0 `http://`, `https://`, `ws://`, `wss://` requests** during interactive workflows (exempting local `blob:` / `data:` downloads) plus raw-secret payload scans.
  - `ConsoleErrorMonitor`: Captures `console.error`, `assert`, uncaught `pageerror`, unexpected dialogs, and CDP `Log.entryAdded` errors (with `allow_expected_csp_errors` and `allow_confirm_accept`).
  - **Header, Launcher & Storage Verifiers**: `verify_health_endpoint`, `verify_csp_and_security_headers` (strict CSP directives + COOP/CORP/nosniff), `verify_ai_launcher_links` (`ALLOWED_AI_LAUNCHER_URLS` covering all 6 AI origins including `ai-launcher-gemini` -> `https://gemini.google.com/app`), `verify_allowed_local_storage_keys` (`ALLOWED_LOCAL_STORAGE_KEYS` covering all 7 keys including `promptveil_pro_license_v1` and `promptveil_profiles_v1`).
  - **Purity & Responsive Verifiers**: `verify_russian_purity` (`<html lang="ru">`, `FORBIDDEN_RU_PHRASES` incl. R2–R5 EN chrome strings, `FORBIDDEN_RU_DEV_CODES`, `skipSelectors` incl. `[data-testid="batch-queue-preview"]`), `verify_responsive_layout`, `verify_no_overlap_or_clipping` (`1440x900`, `1280x800`, `390x844` zero horizontal overflow and `>= 43.5px` mobile tap targets), and `capture_viewport_screenshot`.
- **Ephemeral Node.js Ed25519 Key-Swap Harness (`conftest.py`)**:
  - Zero production private or activation keys in the repository (tests never read `.secrets/pro_keys_bundle.json`).
  - `ephemeral_pro_keys` (session-scoped `node:crypto` Ed25519 keypair + `PV1.*` signer), `pro_license_env`, `pro_browser_context` (`service_workers="block"` + `context.route("**/dist/*.js", ...)` / `**/js/pro-license.js` swapping `PRO_PUBLIC_KEY_B64U` in both raw32 and SPKI DER formats), `pro_raw_session`, and `pro_e2e_session`. `service_workers="block"` prevents Service Worker `CacheStorage` from serving unpatched JS across reloads.
- **Synthetic Document Fixtures (`doc_fixtures.py`)**:
  - Pure-stdlib (`zipfile`, `zlib`, `xml.etree.ElementTree`) generators for `make_synthetic_docx` (paragraphs, tables, headers/footers), `make_synthetic_xlsx` (`sharedStrings.xml` + `sheet1.xml`), `make_synthetic_pdf` (`WinAnsi`/`UTF-16BE` + `Type0`/`Identity-H`/`ToUnicode` CMap + optional `FlateDecode`), `make_scanned_image_pdf`, `make_corrupted_docx`, `make_corrupted_pdf`, and `make_oversized_file` (1 MiB streaming filler for `> 2 MB` Free and `50 MB` / `> 50 MB` Pro boundary checks).

## Test Inventory (245 Cases)

| Module | Tier | Count | Coverage |
|---|---|---|---|
| `test_tier1_features.py` | Tier 1 | 93 | Happy-path across F1–F13 (11 PII/secret categories, Stage A–E, R1 persistent Step 1/2 launchers + Gemini, R2 Ed25519 Pro/Owner license & pricing, R3 `.docx`/`.xlsx`/`.pdf` local batch queue & rehydrate, R4 `/downloads/promptveil-pro-extension.zip` + Pro Downloads modal, R5 profiles/`promptveil_profiles_v1`/Pro packs/templates, R6 Spark Admin themes, CSP, RU purity, zero egress, Privacy Proof) |
| `test_tier2_boundaries.py` | Tier 2 | 81 | Boundary & corner cases across F1–F13 (empty/60KB inputs, Luhn/IBAN/SSN checksums, exclusions, XSS inertness, corrupted `localStorage`, tampered/expired `PV1.*` tokens, pure-JS Ed25519 fallback, Free 2 MB / Pro 50 MB gates, scanned/corrupted/encrypted docs, ZIP traversal 404 & secret-free MV3 manifest, Free profile/pack locks, `QuotaExceededError`, `390x844` mobile tap targets & zero overflow across R1–R5 UI) |
| `test_tier3_combinations.py` | Tier 3 | 14 | Cross-feature pairwise workflows (`T3-01..T3-14`: 9 baseline + 5 R1–R6 combinations: Step 1/2 launchers × Gemini × clipboard flush, Ed25519 tamper/pure-JS fallback × reload × Proof, Free-vs-Pro `.docx`/`.xlsx`/`.pdf`/scanned batch × export × rehydrate, multi-project profiles × Pro packs × templates × Proof isolation, `/downloads/*.zip` × Pro Downloads × SW offline) |
| `test_tier4_scenarios.py` | Tier 4 | 9 | Real-world scenarios (`T4-01..T4-09`: 6 baseline + 3 R1–R6 workflows: Corporate M&A batch `.docx`/`.xlsx`/`.pdf` + custom profile + Gemini, DevSecOps multi-profile `.env`/`.log`/`.pdf` + Step 2 launcher + `EN<->RU`, Mobile `390x844` full Pro workflow & key deactivation downgrade) |
| `test_tier5_adversarial.py` | Tier 5 | 32 | White-box adversarial edge cases (`T5-01..T5-32`: XSS/CSP traps, retranslation, WCAG AA contrast, card suffix & SSN boundaries) |
| `test_acceptance.py` | Acceptance | 16 | Release gates (`ACC-01..ACC-16`: RU purity, `RU \| EN` persistence, full PII cycle, responsive `1440x900` & `390x844` screenshots, FastAPI & `--static-only` Netlify parity, Zero-Retention Proof & reset, Stage E UX, R1–R6 Pro license/batch/extension/profiles/templates gates) |

## Commands

### 1. Recreate Isolated `.venv_e2e` (if needed)
```powershell
& "C:\Program Files\Python314\python.exe" -m venv "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e"
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" -m pip install -r "C:\Users\User\Desktop\коды\AGY\e2e_tests\requirements-e2e.txt"
```

### 2. Self-Test Mode (No `app/` Server Required)
Validates `py_compile`, verifies `pytest --collect-only` collects all 245 unique tests (`197 Tier 1-4 [93+81+14+9] + 32 Tier 5 + 16 Acceptance`), starts an in-process contract smoke server (`e2e_tests/fixtures/smoke_contract.html`), and verifies locators, `BrowserContext` isolation, and negative monitor catches:
```powershell
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" "C:\Users\User\Desktop\коды\AGY\e2e_tests\run_e2e.py" --mode self-test
```

### 3. Live Mode (Against FastAPI or Static-Only Server)
```powershell
# Against an already running FastAPI server at http://127.0.0.1:8000:
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" "C:\Users\User\Desktop\коды\AGY\e2e_tests\run_e2e.py" --mode live --base-url http://127.0.0.1:8000 --tier all

# Auto-start local FastAPI uvicorn from root .venv and generate JSON summary:
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" "C:\Users\User\Desktop\коды\AGY\e2e_tests\run_e2e.py" --mode live --start-server --tier all --report-json "C:\Users\User\Desktop\коды\AGY\e2e_tests\artifacts\live_report.json"

# Netlify-parity static-only mode (serves app/static/ directly without /health):
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" "C:\Users\User\Desktop\коды\AGY\e2e_tests\run_e2e.py" --mode live --static-only --tier all
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" "C:\Users\User\Desktop\коды\AGY\e2e_tests\run_e2e.py" --mode live --static-only --tier acceptance

# Filter a single test ID or tier (or invoke pytest directly):
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" "C:\Users\User\Desktop\коды\AGY\e2e_tests\run_e2e.py" --mode live --tier 4 --filter T4-04
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" -m pytest e2e_tests/test_acceptance.py --static-only -v
```
