# PromptVeil — Клиентская защита данных перед отправкой в ИИ / 100% Client-Side AI Prompt PII & Secret Scrubber

[Русский](#русский) • [English](#english) • [Live App](https://promptveil.netlify.app) • [GitHub](https://github.com/Aquanti/promptveil) • [MIT License](./LICENSE)

---

## Русский

**PromptVeil** — это 100% клиентский веб-инструмент с архитектурой **Zero-Egress** и обратимым словарём замен в оперативной памяти вкладки. Сервис находит персональные данные, реквизиты РФ, финансовые номера, названия организаций и секреты до отправки промпта в нейросеть (ChatGPT, DeepSeek, GigaChat, Алиса / YandexGPT, Claude, Gemini), а затем за один проход возвращает исходные значения в ответ ИИ.

- **Рабочая версия (Production):** https://promptveil.netlify.app
- **Репозиторий:** https://github.com/Aquanti/promptveil
- **Лицензия:** [MIT](./LICENSE) (`Copyright (c) 2026 SupV1rus`)

### Ключевые гарантии приватности

- **100% обработка в браузере:** Все 25 детекторов, разрешение пересечений (AVL-дерево), словарь замен (`SessionVault`), локальный парсер `.docx`/`.pdf`/`.xlsx` и восстановление ответа ИИ выполняются локально в RAM текущей вкладки.
- **0 сетевых утечек текста:** В приложении нет серверных маршрутов `/api/sanitize` или `/api/rehydrate` и нет исходящих `fetch`/`XHR`/`sendBeacon`/`WebSocket` запросов с пользовательским текстом.
- **Строгий CSP:** `default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`.
- **Журнал проверок в RAM по умолчанию:** Записи с SHA-256 отпечатками (без исходного текста) хранятся только в памяти вкладки; сохранение в `localStorage` включается вручную опцией **«Сохранять журнал на этом устройстве»**.
- **Офлайн-режим (PWA):** Service Worker кэширует только статические ресурсы своего origin.

### Удобство работы и прозрачность

- **Постоянная панель «Открыть в ИИ» на шагах 1 и 2 + Gemini:** Панель `#ai-launchers-bar` (`ChatGPT`, `DeepSeek`, `GigaChat`, `Алиса / YandexGPT`, `Claude`, `Gemini`) остаётся видимой и на шаге 1 (очистка), и на шаге 2 (восстановление ответа). Нажатие на любую кнопку синхронно завершает маскировку, копирует безопасный текст в буфер обмена и открывает сервис в новой вкладке.
- **Режим чувствительности («Обычный / Строгий») и подсказки «почему это скрыто»:** Режим «Строгий» дополнительно маскирует `UUID`, организации без кавычек (`ООО Вектор`), более широкий набор пар `Имя + Фамилия` и короткие высокоэнтропийные строки (`>= 16` знаков); каждый элемент в списке «Что скрыто» показывает понятную причину срабатывания.
- **Отраслевые наборы в «Свои слова»:** В выдвижной панели доступны 4 бесплатных набора терминов (`Юриспруденция`, `Кадры и найм`, `Медицина`, `Бухгалтерия`) с добавлением в 1 клик без дублей.
- **Разделы «Как это работает» и «Что мы пока НЕ ловим»:** Визуальная схема трёх шагов и честный список ограничений клиентских правил со ссылкой на добавление своих слов.
- **Оформление, оплата и активация Pro (`/pro/` и `/en/pro/`):** Отдельные страницы оформления Pro с выбором тарифа (`pro-monthly`, `pro-annual`, `pro-lifetime`, `team-pack`), способа оплаты (карта / СБП / счёт без сбора данных карты), генерацией квитанции `PV-ORD-...` только в RAM вкладки, экспортом `.pvkey` и встроенным терминалом офлайн-активации Ed25519 (включая автоподстановку через `#code=PV1...`), а также резервной отправкой заявки на `kilkauciha@gmail.com` и в Telegram (`@supv1rus`).

### PromptVeil Pro (офлайн-активация без сервера)

- **Асимметричная офлайн-проверка ключей (Ed25519) и инструмент владельца:** Токены формата `PV1.<payload>.<sig>` проверяются локально в браузере модулем `app/static/js/pro-license.js` через WebCrypto Ed25519 с pure-JS резервом (RFC 8032 + SHA-512) и сохраняются в `localStorage` (`promptveil_pro_license_v1`). В клиентском коде и репозитории хранится только публичный ключ; выпуск, пакетная генерация и проверка кодов выполняются офлайн через CLI `scripts/issue-pro-key.mjs` и локальную loopback-консоль владельца `scripts/owner-console.mjs` (`127.0.0.1`, вне `app/static/` и Git).
- **Локальная пакетная обработка `.docx`, `.pdf`, `.xlsx` до 50 МБ:** Модуль `app/static/js/pro-documents.js` полностью локально разбирает Офис-документы (ZIP/Deflate через `DecompressionStream` + pure-JS RFC 1951/1950, XML через `DOMParser` + pure-JS резерв) и PDF (`FlateDecode`, `ToUnicode` CMap, защита от zip-бомб и зашифрованных PDF, предупреждение для сканов), поддерживая очередь файлов, экспорт в `.txt`/`.zip` и восстановление батча на шаге 2 (в Free — 1 текстовый файл до 2 МБ).
- **Браузерное расширение Manifest V3 v2.2.0 (`extension/`):** Плавающая Shadow DOM панель с интерактивным индикатором тарифа и popup-контроллер для `chatgpt.com`, `claude.ai`, `gemini.google.com`, `chat.deepseek.com`, `giga.chat` и `alice.yandex.ru` с бесшовной активацией (вставка кода из буфера обмена в 1 клик, импорт `.pvkey`/`.txt`, детальная диагностика и повторная проверка). Настройки, свои слова и ключ Pro хранятся локально в `chrome.storage.local`, а словарь `SessionVault` остаётся только в RAM вкладки. Детерминированный архив собирается в `app/static/downloads/promptveil-pro-extension.zip` и скачивается из `/pro/` или `#modal-pro-downloads`.
- **Профили проектов, Pro-паки и 1-клик шаблоны промптов:** Несколько именованных наборов правил (`promptveil_profiles_v1` в `storage.js`), 4 расширенных пака слов (`Корпоративные сделки (M&A)`, `DevSecOps и код`, `Банки и финтех`, `Трансграничный NDA`) и быстрые обезличенные шаблоны промптов (`#prompt-templates-bar`: аудит договора, проверка NDA, ревью кода и ИБ).

### Архитектурные решения и статус дорожной карты

- **Выполнено в v2.2.0 Pro:** Реализованы локальный парсер `.docx` / `.pdf` / `.xlsx` (ранее `#35`) и браузерное расширение Manifest V3 (ранее `#29`) с полным соблюдением CSP `connect-src 'self'` и Zero-Egress.
- **#30 (Собственный домен):** Вне рамок текущего релиза — используется production-домен `promptveil.netlify.app`.
- **#37 (Аналитика без cookies):** Отклонено — противоречит строгому CSP `connect-src 'self'` и гарантии «0 трекеров и 0 сетевых запросов».

### 25 детекторов (в порядке приоритета)

1. `API_KEY` (100, `[API_KEY_N]`) — ключи AWS, OpenAI, Anthropic, Stripe, GitHub, Slack, Google
2. `URL_TOKEN` (96, `[URL_TOKEN_N]`) — токены/пароли в query/fragment параметрах URL
3. `JWT` (95, `[JWT_N]`) — трёхчастные JWT-токены
4. `IBAN` (92, `[IBAN_N]`) — международные счета (длина страны + ISO 7064 mod-97 через `BigInt`)
5. `RU_ACCOUNT` (91, `[BANK_ACC_N]`) — расчётные/корреспондентские счета РФ (20 цифр, проверка с БИК или по метке)
6. `RU_OMS` (91, `[OMS_N]`) — 16-значные полисы ОМС (метка ОМС + Луна)
7. `CREDIT_CARD` (90, `[CARD_N]`) — банковские карты (13–19 цифр с проверкой по алгоритму Луна)
8. `RU_SNILS` (89, `[SNILS_N]`) — СНИЛС РФ (контрольная сумма ПФР)
9. `RU_INN` (88, `[INN_N]`) — ИНН юрлиц (10 цифр) и физлиц/ИП (12 цифр) с контрольной суммой ФНС
10. `RU_OGRN` (88/91, `[OGRN_N]`) — ОГРН (13 цифр) и ОГРНИП (15 цифр) с проверкой остатка
11. `RU_PASSPORT` (87, `[PASSPORT_N]`) — серия и номер паспорта РФ (с контекстом)
12. `RU_BIK` (86, `[BIK_N]`) — БИК банка РФ (`04...`, с контекстом)
13. `SSN` (85, `[SSN_N]`, secondary) — номера социального страхования США
14. `POSSIBLE_CARD` (84, `[POSSIBLE_CARD_N]`) — номера карт по контексту (`карта`, `карты`, `card`, `№ карты` + 13–19 цифр), даже если контрольная сумма Луна не сходится
15. `ENV_SECRET` (82, `[ENV_SECRET_N]`) — секретные значения в `.env` / конфигах (пропускает заглушки вроде `your_key_here`)
16. `CUSTOM` (80, `[CUSTOM_N]`) — пользовательские слова и фразы с Unicode-границами (RU/EN)
17. `EMAIL` (75, `[EMAIL_N]`) — адреса электронной почты
18. `PHONE` (70, `[PHONE_N]`) — российские (`+7`, `8 (...)`) и международные номера (10–15 цифр, защита от дат)
19. `RU_ORG` (68, `[ORG_N]`) — организации РФ (`ООО`, `ПАО`, `ЗАО`, `ОАО`, `НКО`, `АО`, `ИП` с кавычками и `ИП ФИО` / `ИП Фамилия И.О.`)
20. `RU_AUTO_PLATE` (65, `[PLATE_N]`) — госномера РФ (ГОСТ + коды регионов ГИБДД)
21. `RU_FIO` (64, `[FIO_N]`) — ФИО (3 слова, 2 слова `Имя + Фамилия` / `Фамилия + Имя` в падежах, `Имя + Отчество`, инициалы)
22. `RU_ADDRESS` (63, `[ADDRESS_N]`) — адреса РФ с почтовым индексом и городом (`г. Нижний Новгород`, `Москва, ул. Ленина, д. 5`, `Санкт-Петербург, Невский пр., д. 1`)
23. `IPV4` (60, `[IP_N]`) — IPv4-адреса (защита от версий вроде `v2.4.1.0`)
24. `UUID` (58, `[UUID_N]`, опционально) — стандартные UUID v4/v7 (включается тумблером «Скрывать UUID» или в строгом режиме)
25. `HIGH_ENTROPY` (50, `[SECRET_N]`) — высокоэнтропийные строки (энтропия Шеннона `>= 3.8`, длина `>= 20`)

### Быстрый старт и проверка

```powershell
# 1. Локальный сервер (Windows PowerShell)
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2. Сборка production-бандла и архива расширения (CSS/JS -> app/static/dist/, zip -> app/static/downloads/)
npm ci
npm run build

# 3. Серверные тесты и проверка CSP/гигиены (28 тестов)
.\.venv\Scripts\python.exe -m pytest -v

# 4. Модульные JS-тесты веб-движка (110 тестов) и расширения MV3 (27 тестов)
npm run test:js
npm run test:ext

# 5. E2E-тесты (Playwright, 292 теста)
.\e2e_tests\.venv_e2e\Scripts\python.exe e2e_tests\run_e2e.py --mode live --base-url http://127.0.0.1:8000 --start-server --tier all
```

---

## English

**PromptVeil** is a 100% client-side, zero-egress web workspace that sanitizes sensitive prompts, `.env` configs, logs, and bilingual RU/EN documents directly inside browser RAM before you paste them into AI assistants (ChatGPT, DeepSeek, GigaChat, Alice / YandexGPT, Claude, Gemini)—and deterministically restores the original values from the AI reply in a single pass.

- **Live Production App:** https://promptveil.netlify.app
- **Source Repository:** https://github.com/Aquanti/promptveil
- **License:** [MIT](./LICENSE) (`Copyright (c) 2026 SupV1rus`)

### Security & Zero-Retention Architecture

- **100% Browser-Local Processing:** All 25 deterministic detectors, AVL overlap resolution, `[CATEGORY_N]` token vault (`SessionVault`), local `.docx`/`.pdf`/`.xlsx` parser, single-pass `rehydrate()`, and `FileReader`/`arrayBuffer()` loading execute solely in modular ES6/ES2022 JavaScript inside volatile tab memory.
- **Zero Server Secret Egress:** There are no `/api/sanitize` or `/api/rehydrate` endpoints, and zero `fetch`/`XHR`/`sendBeacon`/`WebSocket` calls for user text.
- **Strict Content Security Policy (CSP):** Enforced identically by both FastAPI (`app/config.py`) and Netlify (`netlify.toml`): `default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`.
- **RAM-Only Audit Journal by Default:** SHA-256 verification receipts (never raw text) stay in volatile tab RAM by default; `localStorage` persistence (`promptveil_audit_v1`) is strictly opt-in via `#audit-persist-toggle`.
- **Offline PWA Support:** Static-only Service Worker (`sw.js`) caches same-origin assets only.

### Workflow Ergonomics & Transparency

- **Persistent Step 1 & Step 2 AI Launcher Bar + Gemini:** `#ai-launchers-bar` (`ChatGPT`, `DeepSeek`, `GigaChat`, `Alice / YandexGPT`, `Claude`, `Gemini`) remains visible across both **Step 1** (Sanitize) and **Step 2** (Restore AI Reply). Clicking any pill flushes live masking synchronously, copies the safe text to clipboard, and opens the assistant in a new tab.
- **Sensitivity Mode (`Normal / Strict`) & Detection Reasons:** `Strict` mode enables `UUID` detection, unquoted Russian legal entities, broader capitalized two-word name pairs, and shorter high-entropy secrets (`>= 16` chars); every entry in *What was hidden* explains why it was masked.
- **Industry Custom Word Packs:** One-click deduplicating packs (`Legal`, `HR & Hiring`, `Medical`, `Accounting`) inside *Custom Words* (`#drawer-rulebook`).
- **How It Works & Honest Limits:** Static HTML+SVG 3-step visual flow and transparent boundaries linking directly to *Custom Words*.
- **Pro Checkout & Offline Key Activation (`/pro/` & `/en/pro/`):** Dedicated bilingual checkout & activation pages featuring tariff (`pro-monthly`, `pro-annual`, `pro-lifetime`, `team-pack`) and payment method (`card`, `sbp`, `invoice`, zero raw card fields) selection, RAM-only `PV-ORD-...` receipt export, `.pvkey` download, and an in-page Ed25519 Activation & Validation Terminal (`#code=PV1...` fragment hydration + `.pvkey`/`.txt` upload), alongside Telegram (`@supv1rus`) / email (`kilkauciha@gmail.com`) fallback inquiry flow.

### PromptVeil Pro Suite (Zero-Server Offline Activation)

- **Ed25519 Offline License Verification & Owner Tooling:** `PV1.<payload>.<sig>` keys are verified locally in `app/static/js/pro-license.js` via WebCrypto Ed25519 with a pure-JS RFC 8032 + SHA-512 fallback and persisted in `localStorage` (`promptveil_pro_license_v1`). Only the public key resides in client source/Git; offline single/batch signing, verification, and order-to-key fulfillment are performed locally via `scripts/issue-pro-key.mjs` and the `127.0.0.1` loopback Owner Console (`scripts/owner-console.mjs`, outside `app/static/`).
- **Local Batch & Office/PDF Scrubber (up to 50 MB / file):** `app/static/js/pro-documents.js` parses `.docx`, `.pdf`, and `.xlsx` files 100% locally (`DecompressionStream` + pure-JS RFC 1951/1950 inflate, XML via `DOMParser` + pure-JS fallback, PDF `FlateDecode` / `ToUnicode` CMap decoding, zip-bomb & encrypted-PDF rejection, and honest scanned-PDF warnings), supporting batch queue masking, `.txt`/`.zip` downloads, and Step 2 batch rehydration (Free remains single text file up to 2 MB).
- **Manifest V3 Browser Extension v2.2.0 (`extension/`):** Interactive Shadow DOM tier pill & popup controller across `chatgpt.com`, `claude.ai`, `gemini.google.com`, `chat.deepseek.com`, `giga.chat`, and `alice.yandex.ru` with seamless activation (1-click clipboard paste-and-activate, `.pvkey`/`.txt` import, detailed claim/expiry diagnostics, and actionable Pro upgrade hints). Preferences, custom rules, and Pro license tokens live in `chrome.storage.local` while `SessionVault` mappings stay strictly in tab RAM. Deterministically packaged by `scripts/build.mjs` into `/downloads/promptveil-pro-extension.zip` for `/pro/` and `#modal-pro-downloads`.
- **Multi-Project Rulebook Profiles, Pro Packs & 1-Click Templates:** Named rulebook workspaces (`promptveil_profiles_v1` in `storage.js`), 4 Pro industry word packs (`Corporate M&A`, `DevSecOps`, `Banking & FinTech`, `Cross-border NDA`), and pre-anonymized 1-click prompt templates (`#prompt-templates-bar`).

### Architecture Decisions & Deferred Scope

- **Shipped in v2.2.0 Pro:** `.docx` / `.pdf` / `.xlsx` local parsing (formerly `#35`) and the Manifest V3 browser extension (formerly `#29`) shipped with strict CSP `connect-src 'self'` and Zero-Egress compliance.
- **#30 (Custom Domain):** Out of scope in the current environment (`promptveil.netlify.app` remains the production host).
- **#37 (Cookie-Free Analytics):** Rejected to preserve strict `connect-src 'self'` CSP and the zero-tracker guarantee.

### All 25 Detectors (Priority Order)

1. `API_KEY` (`100`, `[API_KEY_N]`) — AWS, OpenAI, Anthropic, Stripe, GitHub, Slack, Google keys
2. `URL_TOKEN` (`96`, `[URL_TOKEN_N]`) — Secret query/fragment parameter values inside HTTP(S) URLs
3. `JWT` (`95`, `[JWT_N]`) — 3-part base64url JWTs
4. `IBAN` (`92`, `[IBAN_N]`) — Country length + ISO 7064 mod-97 checksum via `BigInt`
5. `RU_ACCOUNT` (`91`, `[BANK_ACC_N]`) — 20-digit Russian bank settlement/correspondent accounts (BIK or label validated)
6. `RU_OMS` (`91`, `[OMS_N]`) — 16-digit Russian OMS medical insurance policies (label + Luhn)
7. `CREDIT_CARD` (`90`, `[CARD_N]`) — 13–19 digit payment cards validated with Luhn checksum
8. `RU_SNILS` (`89`, `[SNILS_N]`) — Russian SNILS with PFR checksum
9. `RU_INN` (`88`, `[INN_N]`) — 10-digit legal entity and 12-digit individual Russian INN (FNS checksum)
10. `RU_OGRN` (`88/91`, `[OGRN_N]`) — 13-digit OGRN and 15-digit OGRNIP checksum
11. `RU_PASSPORT` (`87`, `[PASSPORT_N]`) — Context-gated Russian internal passport series & number
12. `RU_BIK` (`86`, `[BIK_N]`) — Context-gated Russian bank BIK (`04...`)
13. `SSN` (`85`, `[SSN_N]`, secondary) — US Social Security Numbers
14. `POSSIBLE_CARD` (`84`, `[POSSIBLE_CARD_N]`) — Context-triggered 13–19 digit card spans (`карта`/`card`/`№ карты`) when Luhn fails
15. `ENV_SECRET` (`82`, `[ENV_SECRET_N]`) — `.env` / config RHS secret values (skips placeholders like `your_key_here`)
16. `CUSTOM` (`80`, `[CUSTOM_N]`) — User-defined Unicode-boundary rules (`RU`/`EN`, case-sensitive optional)
17. `EMAIL` (`75`, `[EMAIL_N]`) — Email addresses
18. `PHONE` (`70`, `[PHONE_N]`) — CIS/RU (`+7`, `8 (...)`) and international phone numbers (10–15 digits, date-guarded)
19. `RU_ORG` (`68`, `[ORG_N]`) — Russian legal entities (`ООО`, `ПАО`, `ЗАО`, `ОАО`, `НКО`, `АО`, `ИП` quoted forms and `ИП` FIO/initials)
20. `RU_AUTO_PLATE` (`65`, `[PLATE_N]`) — Russian license plates (GOST letters + GIBDD region codes)
21. `RU_FIO` (`64`, `[FIO_N]`) — Russian full names (3-word, declined 2-word `First+Surname` / `Surname+First`, `Name+Patronymic`, initials)
22. `RU_ADDRESS` (`63`, `[ADDRESS_N]`) — Russian street addresses with postal code and city capture (`Москва, ул. Ленина, д. 5`, `г. Нижний Новгород`, `Санкт-Петербург, Невский пр., д. 1`)
23. `IPV4` (`60`, `[IP_N]`) — Octet-validated IPv4 addresses (semver-guarded)
24. `UUID` (`58`, `[UUID_N]`, opt-in) — Standard UUIDs (enabled via `#detect-uuid-toggle` or strict sensitivity mode)
25. `HIGH_ENTROPY` (`50`, `[SECRET_N]`) — Shannon entropy `>= 3.8`, `>= 20` chars, multi-class diversity (excludes URLs, file paths, UUIDs)

### Project Layout

```text
├── LICENSE                  # MIT License (Copyright (c) 2026 SupV1rus)
├── CHANGELOG.md             # Release history
├── README.md                # Bilingual documentation (RU + EN)
├── netlify.toml             # Static publish config, strict CSP, manifest/zip MIME, cache rules
├── requirements.txt         # FastAPI local preview & pytest dependencies
├── app/
│   ├── __init__.py
│   ├── config.py            # Settings & CSP_POLICY
│   ├── schemas.py           # Typed HealthResponse schema
│   ├── main.py              # Local static host + security headers + /health
│   └── static/
│       ├── index.html
│       ├── en/index.html    # English route (/en/)
│       ├── pro/index.html   # Russian Pro checkout & activation route (/pro/)
│       ├── en/pro/index.html# English Pro checkout & activation route (/en/pro/)
│       ├── 404.html
│       ├── manifest.webmanifest
│       ├── sw.js            # Network-first HTML, cache-first /dist/*, SWR static precache
│       ├── styles.css
│       ├── css/             # tokens.css, layout.css, components.css, drawers.css, modals.css, sections.css, pro-checkout.css
│       ├── js/              # 22 ES modules (detector, vault, storage, pro-license, pro-checkout, pro-documents, theme, ...)
│       ├── dist/            # Content-hashed esbuild CSS & code-split ESM JS bundles
│       └── downloads/       # Deterministic promptveil-pro-extension.zip package
├── extension/
│   ├── manifest.json        # Manifest V3 config (v2.2.0) for 6 supported AI hosts
│   ├── popup.{html,css}     # Extension toolbar UI
│   ├── content.css          # Shadow DOM host positioning
│   ├── src/                 # adapters.js, content.js, popup.js, i18n-ext.js, storage-ext.js
│   ├── dist/                # esbuild IIFE extension bundles
│   └── tests/               # 27 Node.js unit tests (adapters, gating, manifest/CSP)
├── scripts/
│   ├── build.mjs            # esbuild multi-entry web + extension bundler, zip builder, HTML/SW injector
│   ├── issue-pro-key.mjs    # Offline Ed25519 keypair, batch PV1 token & bundle verification CLI
│   └── owner-console.mjs    # Local loopback 127.0.0.1 Owner Pro-Code Web Console (outside app/static/)
├── tests/
│   ├── test_server.py       # 28 FastAPI, CSP/COOP/CORP, zero-egress, zip, and static hygiene tests
│   └── js/
│       └── *.test.mjs       # 110 Node.js unit tests (detectors, vault, licensing, checkout, CLI/console, docs, profiles, i18n)
└── e2e_tests/               # 292 Playwright E2E tests (Tiers 1–5 + Acceptance, FastAPI & Static-Only)
```

### Local Setup & Verification

```bash
# macOS / Linux
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Build production bundles & MV3 extension ZIP
npm ci
npm run build

# Static security, ZIP header & FastAPI tests (28 tests)
.venv/bin/python -m pytest -v

# Node.js unit tests: web engine (110 tests) & extension (27 tests)
npm run test:js
npm run test:ext

# Playwright E2E suite (292 tests)
./e2e_tests/.venv_e2e/bin/python e2e_tests/run_e2e.py --mode live --base-url http://127.0.0.1:8000 --start-server --tier all
```

### Deployment

Static publish directory is `app/static` (`netlify.toml` sets `publish = "app/static"`, CSP/security headers, and `application/manifest+json; charset=utf-8` for `/manifest.webmanifest`). Any static host serving `app/static` works out of the box with zero server-side dependencies.

### License

Released under the [MIT License](./LICENSE).
