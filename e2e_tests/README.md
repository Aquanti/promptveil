# PromptVeil Opaque-Box E2E Test Suite (`e2e_tests/`)

Standalone Playwright + Pytest end-to-end verification harness for **PromptVeil (Option A — Public-Ready 100% Client-Side Web SaaS)**.

## Architecture & Isolation

- **Isolated Python Environment (`e2e_tests/.venv_e2e/`)**: Uses `playwright>=1.65.0` and `pytest>=9.0.0` without modifying the main project `.venv/` or `requirements.txt`.
- **Zero Browser Download**: Launches system Google Chrome (`channel="chrome"`) with automatic Microsoft Edge fallback (`channel="msedge"`).
- **Opaque-Box 3-Tier Semantic Locators (`locators.py`)**: Resolves controls by ARIA role/name, visible labels/placeholders, and structural HTML fallbacks scoped by active mode (`Sanitize` / `Re-Hydrate`) and open drawer (`Rulebook` / `Audit Receipts`). Supports both debounced auto-scan and explicit action buttons, emitting DOM diagnostic snapshots on lookup failures.
- **Zero-Egress & Runtime Monitors (`monitors.py`)**:
  - `NetworkMonitor`: Phase-aware request tracker asserting **0 `http://`, `https://`, `ws://`, `wss://` requests** during interactive workflows (while exempting local `blob:` / `data:` JSON export downloads).
  - `ConsoleErrorMonitor`: Captures `console.error`, `assert`, uncaught `pageerror`, unexpected `alert()` dialogs, and CDP `Log.entryAdded` errors.
  - Header & Layout Verifiers: `GET /health`, strict CSP (`connect-src 'self'`), and `1280x800` / `390x844` zero-horizontal-overflow checks.
- **Per-Test Isolation (`conftest.py`)**: Fresh incognito `BrowserContext` (`localStorage` + vault isolation) and `%TEMP%` `uploads/` + `downloads/` directories per test.

## Test Inventory (109 Cases)

| Module | Tier | Count | Coverage |
|---|---|---|---|
| `test_tier1_features.py` | Tier 1 | 51 | Happy-path across all 11 detection categories, 7 API key vendors, Re-Hydrate, chips, toggles, EN + Cyrillic custom rules, 3 presets, 6 FileReader extensions, SHA-256 audit receipts, `/health`, CSP |
| `test_tier2_boundaries.py` | Tier 2 | 45 | Empty & 55KB inputs, Luhn/IBAN/SSN checksum boundaries, `[EMAIL_1]` vs `[EMAIL_10]`/`[EMAIL_11]`, dates/IPs/versions vs phones/IPv4, URL/UUID/placeholder exclusions, overlap priorities, XSS inertness, malformed JSON/corrupted `localStorage` |
| `test_tier3_combinations.py` | Tier 3 | 8 | Cross-feature pairwise workflows (toggle + Re-Hydrate, Cyrillic rule + bilingual preset + audit, export/clear/import rules, FileReader + chip disable + unresolved tokens, 12-email non-collision) |
| `test_tier4_scenarios.py` | Tier 4 | 5 | Consulting NDA, Prod `.env` + stacktrace, Bilingual RU/CIS HR screening, Zero-HTTP-egress canary audit, Desktop `1280x800` + Mobile `390x844` responsive check |

## Commands

### 1. Recreate Isolated `.venv_e2e` (if needed)
```powershell
& "C:\Program Files\Python314\python.exe" -m venv "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e"
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" -m pip install -r "C:\Users\User\Desktop\коды\AGY\e2e_tests\requirements-e2e.txt"
```

### 2. Self-Test Mode (No `app/` Server Required)
Validates `py_compile`, verifies `pytest --collect-only` collects all 109 unique tests, starts an in-process contract smoke server (`e2e_tests/fixtures/smoke_contract.html`), and verifies locators, `BrowserContext` isolation, and negative monitor catches:
```powershell
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" "C:\Users\User\Desktop\коды\AGY\e2e_tests\run_e2e.py" --mode self-test
```

### 3. Live Mode (Against PromptVeil Server)
```powershell
# Against an already running server at http://127.0.0.1:8000:
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" "C:\Users\User\Desktop\коды\AGY\e2e_tests\run_e2e.py" --mode live --base-url http://127.0.0.1:8000 --tier all

# Or auto-start local FastAPI uvicorn from root .venv and generate JSON summary:
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" "C:\Users\User\Desktop\коды\AGY\e2e_tests\run_e2e.py" --mode live --start-server --tier all --report-json "C:\Users\User\Desktop\коды\AGY\e2e_tests\artifacts\live_report.json"

# Filter a single test ID or tier:
& "C:\Users\User\Desktop\коды\AGY\e2e_tests\.venv_e2e\Scripts\python.exe" "C:\Users\User\Desktop\коды\AGY\e2e_tests\run_e2e.py" --mode live --tier 4 --filter T4-04
```
