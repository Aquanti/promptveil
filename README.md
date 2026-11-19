# PromptVeil — 100% Client-Side AI Prompt PII & Secret Scrubber + Reversible Vault

PromptVeil is a public-ready, multi-tenant-safe Web SaaS that sanitizes sensitive prompts, `.env` configs, logs, and bilingual documents directly inside the user's browser before sending anything to an AI assistant—then deterministically restores the original secrets from the LLM reply via an in-memory reversible vault.

## Security & Zero-Egress Guarantees

- **100% Browser-Local Processing:** All 11 deterministic detectors, overlap resolution, `[CATEGORY_N]` token allocation, single-pass `Re-Hydrate` substitution, and `FileReader` file loading run exclusively in modular ES6 JavaScript inside browser RAM.
- **Zero Server Secret Egress:** There are no `/api/sanitize` or `/api/rehydrate` endpoints. Zero bytes of user prompts, uploaded files, or vault mappings are ever transmitted over HTTP (verifiable in Chrome DevTools Network tab).
- **Per-User Browser Storage:** Custom Rulebook (`promptveil_rules_v1`) and Hash-Only Audit Receipts (`promptveil_audit_v1`) stay strictly in each visitor's own `localStorage`, with JSON Export/Import support.
- **Hash-Only Audit Receipts:** SHA-256 digests are computed client-side via `crypto.subtle.digest("SHA-256", ...)` (with a pure-JS FIPS 180-4 fallback for non-secure contexts). Zero plaintext PII is stored in audit receipts.
- **Strict Content Security Policy (CSP):** Both FastAPI and `netlify.toml` enforce `default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`.

## Detection Categories (Priority Order)

1. `API_KEY` (`[API_KEY_N]`) — AWS, OpenAI, Anthropic, Stripe, GitHub, Slack, Google
2. `JWT` (`[JWT_N]`) — 3-part base64url JWTs
3. `CREDIT_CARD` (`[CARD_N]`) — 13–19 digit cards validated with Luhn checksum
4. `IBAN` (`[IBAN_N]`) — Country length + ISO 7064 mod-97 validation via JS `BigInt`
5. `SSN` (`[SSN_N]`) — US Social Security Numbers
6. `ENV_SECRET` (`[ENV_SECRET_N]`) — RHS secret values only (skips placeholders like `your_key_here`)
7. `CUSTOM` (`[CUSTOM_N]`) — Unicode-boundary (`\p{L}\p{N}_`) rules supporting Cyrillic (`ООО «Вектор»`, `Алексей Смирнов`) & English
8. `EMAIL` (`[EMAIL_N]`) — Email addresses
9. `PHONE` (`[PHONE_N]`) — CIS/RU (`+7`, `8 (...)`) and international phone numbers (10–15 digits, date-guarded)
10. `IPV4` (`[IP_N]`) — Octet-validated IPv4 addresses (version-string guarded)
11. `HIGH_ENTROPY` (`[SECRET_N]`) — Shannon entropy `>= 3.8`, `>= 20` chars, multi-class diversity (excludes URLs, file paths, UUIDs)

## Project Layout

```text
├── .env.example
├── .gitignore
├── netlify.toml
├── requirements.txt
├── README.md
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── schemas.py
│   ├── main.py
│   └── static/
│       ├── favicon.svg
│       ├── index.html
│       ├── styles.css
│       └── js/
│           ├── detector.js
│           ├── vault.js
│           ├── storage.js
│           ├── presets.js
│           └── app.js
└── tests/
    ├── __init__.py
    └── test_server.py
```

## Local Setup & Run

> **Windows Note:** If your workspace path contains non-ASCII characters (such as Cyrillic folders), invoke `.venv\Scripts\python.exe` directly instead of `activate.bat`.

### Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### macOS / Linux

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in your browser.

## Verification Commands

```powershell
.\.venv\Scripts\python.exe -m py_compile app\__init__.py app\config.py app\schemas.py app\main.py tests\__init__.py tests\test_server.py
.\.venv\Scripts\python.exe -m pytest -v tests\test_server.py
```

## Public Static Deployment ($0/mo)

Because `app/static/` is 100% self-contained with relative asset links (`./styles.css`, `./js/app.js`, `./favicon.svg`), you can deploy directly to any static host:

- **Netlify:** Included `netlify.toml` sets `publish = "app/static"` and strict CSP headers out of the box.
- **Cloudflare Pages / GitHub Pages / Vercel Static:** Point the build output / publish directory to `app/static` with no build command required.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `APP_HOST` | `127.0.0.1` | Host interface for local FastAPI static server |
| `APP_PORT` | `8000` | Port for local FastAPI static server (`1–65535`) |
| `LOG_LEVEL` | `info` | Uvicorn log level (`critical`, `error`, `warning`, `info`, `debug`, `trace`) |
| `APP_VERSION` | `1.0.0` | Version reported by `GET /health` |
