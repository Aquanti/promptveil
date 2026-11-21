/**
 * Built-in Realistic Presets (Russian-First HR/CIS, Client Contract, and .env Stacktrace).
 * Preset selection loads sample text without silently overwriting user localStorage rules.
 */

export const PRESETS = Object.freeze([
  {
    id: "bilingual_cis_hr",
    title: "Письмо и реквизиты",
    titleByLang: {
      ru: "Письмо и реквизиты",
      en: "HR & Payout Brief (RU/EN)",
    },
    descriptionByLang: {
      ru: "Письмо о найме с ФИО, названием компании, почтой, телефонами (+7 / 8 / +44), счётом IBAN, банковской картой и датами.",
      en: "Cyrillic name & organization terms, +7 / 8 / +44 phones, email, KZ IBAN, Luhn card, and date negative controls.",
    },
    text: `HR & Contractor Onboarding Brief (Date: 2026-11-19 / 19.11.2026)

Contractor: Алексей Смирнов
Legal Entity: ООО «Вектор»
Work Email: a.smirnov@vektor-group.ru
Mobile (RU): +7 (916) 555-35-35
Office (Moscow): 8 (495) 234-56-78
London Coordinator: +44 20 7946 0958

Payout Details:
- KZ IBAN: KZ86 125K ZT50 0410 0100
- Corporate Card: 4242-4242-4242-4242

Draft a bilingual onboarding checklist for Алексей Смирнов at ООО «Вектор».`,
    suggestedRules: Object.freeze([
      {
        id: "preset_vektor",
        term: "ООО «Вектор»",
        category: "ORG",
        caseSensitive: false,
        enabled: true,
      },
      {
        id: "preset_smirnov",
        term: "Алексей Смирнов",
        category: "PERSON",
        caseSensitive: false,
        enabled: true,
      },
    ]),
  },
  {
    id: "client_contract",
    title: "Договор с клиентом",
    titleByLang: {
      ru: "Договор с клиентом",
      en: "Client NDA & Agreement",
    },
    descriptionByLang: {
      ru: "Деловой договор с почтой, счетами IBAN, картой, телефоном, номером соцстраха и названиями компаний.",
      en: "Legal agreement containing email, IBANs, Luhn card, US phone, SSN, and organization terms.",
    },
    text: `CONFIDENTIAL SERVICES BRIEF — Northstar Ventures LLC
Project Codename: Project Obsidian

Please review the draft MSA before forwarding to outside counsel.
Primary Legal Contact: legal.ops@northstar-ventures.io
US Signatory Phone: +1 (415) 555-0199
Signatory Tax ID (SSN): 123-45-6789

Settlement Accounts:
- EUR Escrow IBAN: DE89 3704 0044 0532 0130 00 USD
- GBP Operating IBAN: GB29 NWBK 6016 1331 9268 19
- Retainer Card on File: 4111-1111-1111-1111

Summarize liability caps and propose redlines for Northstar Ventures LLC under Project Obsidian.`,
    suggestedRules: Object.freeze([
      {
        id: "preset_northstar",
        term: "Northstar Ventures LLC",
        category: "ORG",
        caseSensitive: false,
        enabled: true,
      },
      {
        id: "preset_obsidian",
        term: "Project Obsidian",
        category: "PROJECT",
        caseSensitive: false,
        enabled: true,
      },
    ]),
  },
  {
    id: "prod_env_trace",
    title: "Ключи и настройки (.env)",
    titleByLang: {
      ru: "Ключи и настройки (.env)",
      en: ".env Keys & Stacktrace",
    },
    descriptionByLang: {
      ru: "Ключи API, токены входа, строка подключения к базе данных, IP-адреса и случайные секретные ключи.",
      en: "Cloud API keys, JWT, .env DSN secret, placeholder negative control, IPv4, high-entropy secret, and UUID.",
    },
    text: `# Production Incident Bundle (Service Release v2.4.1.0)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
OPENAI_API_KEY=sk-proj-PromptVeilDemoKey9876543210abcdef
STRIPE_SECRET=sk_test_51N9xDemoPromptVeilKey1234567890
GITHUB_PAT=ghp_ExampleTokenForPromptVeilDemo12345
DATABASE_DSN=postgres://svc_prod:Tr0ub4dor99@10.24.18.42:5432/ledger
DEBUG_TOKEN=your_key_here

Bearer Token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfOTgyMSIsInJvbGUiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Worker Node IP: 192.168.10.250
Correlation UUID: 550e8400-e29b-41d4-a716-446655440000
Session Signing Entropy: K7xM9pQ2vR8nL4wZ6tB1yF5hJ3cN0sD

Diagnose why worker 192.168.10.250 failed auth on release v2.4.1.0.`,
    suggestedRules: Object.freeze([]),
  },
  {
    id: "ru_requisites",
    title: "Договор и реквизиты РФ",
    titleByLang: {
      ru: "Договор и реквизиты РФ",
      en: "Russian Contract & IDs",
    },
    descriptionByLang: {
      ru: "Карточка с ИНН, СНИЛС, паспортом РФ, ОГРН, БИК, счетами, ОМС, ФИО, адресом, госномером авто и токенизированной ссылкой.",
      en: "Synthetic Russian entity brief with INN, SNILS, RF passport, OGRN, BIK, accounts, OMS, full FIO, address, plate, and tokenized URL.",
    },
    text: `РЕКВИЗИТЫ СТОРОНЫ И ДАННЫЕ СОТРУДНИКА (СИНТЕТИЧЕСКИЙ ПРИМЕР)

Организация: АО «ТехноСфера»
ИНН: 7707083893 | ОГРН: 1027700132195
Банк: ПАО «ТестБанк», БИК: 044525225
Расчётный счёт: р/с 40702810938000012345
Корр. счёт: к/с 30101810400000000225
Юр. адрес: 125009, г. Москва, ул. Тверская, д. 12, стр. 1, оф. 45

Ответственный представитель: Соколов Алексей Петрович (Петрова И.С.)
ИНН физлица: 500100732259
СНИЛС: 112-233-445 95
Паспорт РФ: 45 10 № 123456
Полис ОМС: 7746 1234 5678 9019
Пропуск на авто: А123ВС 777
Ссылка на акт сверки: https://portal.techno-test.ru/doc?token=DemoUrlToken998877&lang=ru`,
    suggestedRules: Object.freeze([]),
  },
]);

export function getPresetById(id) {
  return PRESETS.find((preset) => preset.id === id) || null;
}

export function getLocalizedPreset(idOrPreset, lang = "ru") {
  const preset = typeof idOrPreset === "string" ? getPresetById(idOrPreset) : idOrPreset;
  if (!preset) return null;
  const normLang = lang === "en" ? "en" : "ru";
  return {
    id: preset.id,
    title: preset.titleByLang?.[normLang] || preset.title,
    description: preset.descriptionByLang?.[normLang] || "",
    text: preset.text,
    suggestedRules: preset.suggestedRules || [],
  };
}

export const INDUSTRY_WORD_PACKS = Object.freeze([
  {
    id: "legal",
    category: "CUSTOM",
    titleByLang: Object.freeze({
      ru: "Юриспруденция",
      en: "Legal",
    }),
    termsByLang: Object.freeze({
      ru: Object.freeze([
        "коммерческая тайна",
        "конфиденциальная информация",
        "персональные данные",
        "арбитражная оговорка",
        "лицензионное вознаграждение",
        "дополнительное соглашение",
      ]),
      en: Object.freeze([
        "confidential information",
        "trade secret",
        "non-disclosure",
        "arbitration clause",
        "indemnification",
        "liquidated damages",
      ]),
    }),
  },
  {
    id: "hr",
    category: "CUSTOM",
    titleByLang: Object.freeze({
      ru: "Кадры и найм",
      en: "HR & Hiring",
    }),
    termsByLang: Object.freeze({
      ru: Object.freeze([
        "размер оклада",
        "испытательный срок",
        "кадровый резерв",
        "должностной оклад",
        "трудовой договор",
        "премиальная часть",
      ]),
      en: Object.freeze([
        "base salary",
        "performance review",
        "severance package",
        "background check",
        "compensation band",
        "disciplinary action",
      ]),
    }),
  },
  {
    id: "medical",
    category: "CUSTOM",
    titleByLang: Object.freeze({
      ru: "Медицина",
      en: "Medical",
    }),
    termsByLang: Object.freeze({
      ru: Object.freeze([
        "история болезни",
        "амбулаторная карта",
        "клинический диагноз",
        "врачебная тайна",
        "результаты анализов",
        "выписной эпикриз",
      ]),
      en: Object.freeze([
        "medical record",
        "clinical diagnosis",
        "patient history",
        "lab results",
        "discharge summary",
        "prescription dosage",
      ]),
    }),
  },
  {
    id: "accounting",
    category: "CUSTOM",
    titleByLang: Object.freeze({
      ru: "Бухгалтерия",
      en: "Accounting",
    }),
    termsByLang: Object.freeze({
      ru: Object.freeze([
        "налоговая база",
        "бухгалтерский баланс",
        "акт сверки",
        "счёт-фактура",
        "оборотная ведомость",
        "платёжное поручение",
      ]),
      en: Object.freeze([
        "balance sheet",
        "tax liability",
        "payroll register",
        "accounts receivable",
        "general ledger",
        "wire transfer",
      ]),
    }),
  },
]);

export const PRO_INDUSTRY_WORD_PACKS = Object.freeze([
  {
    id: "corporate_ma",
    tier: "pro",
    category: "CUSTOM",
    titleByLang: Object.freeze({
      ru: "Корпоративные сделки (M&A)",
      en: "Corporate M&A",
    }),
    termsByLang: Object.freeze({
      ru: Object.freeze([
        "слияние и поглощение",
        "соглашение о намерениях",
        "оценка стоимости бизнеса",
        "корпоративный договор",
        "акционерное соглашение",
        "раскрытие бенефициаров",
      ]),
      en: Object.freeze([
        "merger agreement",
        "letter of intent",
        "enterprise valuation",
        "shareholder agreement",
        "beneficial owner",
        "earn-out provision",
      ]),
    }),
  },
  {
    id: "devsecops",
    tier: "pro",
    category: "CUSTOM",
    titleByLang: Object.freeze({
      ru: "DevSecOps и код",
      en: "DevSecOps",
    }),
    termsByLang: Object.freeze({
      ru: Object.freeze([
        "приватный ключ",
        "сервисный токен",
        "производственный кластер",
        "переменная окружения",
        "внутренний реестр",
        "учётные данные",
      ]),
      en: Object.freeze([
        "private key",
        "service token",
        "production cluster",
        "environment variable",
        "internal registry",
        "deployment credential",
      ]),
    }),
  },
  {
    id: "banking_fintech",
    tier: "pro",
    category: "CUSTOM",
    titleByLang: Object.freeze({
      ru: "Банки и финтех",
      en: "Banking & FinTech",
    }),
    termsByLang: Object.freeze({
      ru: Object.freeze([
        "платёжный шлюз",
        "корреспондентский счёт",
        "реестр транзакций",
        "банковская тайна",
        "эмитент карты",
        "межбанковский перевод",
      ]),
      en: Object.freeze([
        "payment gateway",
        "correspondent account",
        "settlement ledger",
        "banking secrecy",
        "cardholder data",
        "interbank transfer",
      ]),
    }),
  },
  {
    id: "crossborder_nda",
    tier: "pro",
    category: "CUSTOM",
    titleByLang: Object.freeze({
      ru: "Трансграничный NDA",
      en: "Cross-border NDA",
    }),
    termsByLang: Object.freeze({
      ru: Object.freeze([
        "трансграничная передача",
        "раскрывающая сторона",
        "принимающая сторона",
        "подсудность споров",
        "применимое право",
        "режим конфиденциальности",
      ]),
      en: Object.freeze([
        "cross-border transfer",
        "disclosing party",
        "receiving party",
        "governing law",
        "exclusive jurisdiction",
        "confidentiality obligation",
      ]),
    }),
  },
]);

export function getLocalizedWordPack(packId, lang = "ru") {
  const pack =
    INDUSTRY_WORD_PACKS.find((item) => item.id === packId) ||
    PRO_INDUSTRY_WORD_PACKS.find((item) => item.id === packId);
  if (!pack) return null;
  const normLang = lang === "en" ? "en" : "ru";
  const tier = pack.tier === "pro" ? "pro" : "free";
  return {
    id: pack.id,
    category: pack.category,
    tier,
    isPro: tier === "pro",
    title: pack.titleByLang[normLang] || pack.titleByLang.ru,
    terms: pack.termsByLang[normLang] || pack.termsByLang.ru,
  };
}

export function getIndustryWordPacks(lang = "ru", { includePro = true } = {}) {
  const source = includePro
    ? [...INDUSTRY_WORD_PACKS, ...PRO_INDUSTRY_WORD_PACKS]
    : INDUSTRY_WORD_PACKS;
  return source.map((pack) => getLocalizedWordPack(pack.id, lang));
}

export const PROMPT_TEMPLATES = Object.freeze([
  {
    id: "contract_review",
    tier: "pro",
    titleByLang: Object.freeze({
      ru: "Аудит договора",
      en: "Contract Review",
    }),
    descriptionByLang: Object.freeze({
      ru: "Обезличенный запрос на проверку рисков, неустоек и условий расторжения договора",
      en: "Anonymized contract audit prompt covering liability caps, payment terms, and termination",
    }),
    textByLang: Object.freeze({
      ru: `Проверь проект договора между [ORG_1] и [ORG_2] (контакт [FIO_1], реквизит [RU_INN_1], счёт [RU_ACCOUNT_1]).
1. Выяви односторонние штрафы, скрытые неустойки и условия досрочного расторжения.
2. Проверь лимит ответственности сторон, порядок приёмки и сроки оплаты.
3. Предложи сбалансированные формулировки для защиты интересов заказчика.`,
      en: `Review the draft services agreement between [ORG_1] and [ORG_2] (contact [PERSON_1], account [IBAN_1]).
1. Flag uncapped liability, asymmetric indemnities, and auto-renewal or termination traps.
2. Summarize payment terms, acceptance milestones, and SLA remedies.
3. Propose balanced redlines protecting the buyer.`,
    }),
  },
  {
    id: "nda_redline",
    tier: "pro",
    titleByLang: Object.freeze({
      ru: "Проверка NDA",
      en: "NDA Redline",
    }),
    descriptionByLang: Object.freeze({
      ru: "Обезличенный разбор соглашения о конфиденциальности, исключений и подсудности",
      en: "Anonymized NDA review for mutual obligations, exclusions, survival period, and governing law",
    }),
    textByLang: Object.freeze({
      ru: `Проанализируй соглашение о неразглашении (NDA) между [ORG_1] и [ORG_2] по проекту [PROJECT_1].
1. Оцени симметричность обязательств раскрывающей и принимающей стороны.
2. Проверь срок действия обязательств, перечень исключений и размер штрафов.
3. Подготовь правки по применимому праву, подсудности и возврату материалов.`,
      en: `Audit the mutual NDA between [ORG_1] and [ORG_2] for [PROJECT_1].
1. Check whether confidentiality obligations, exclusions, and residuals clauses are symmetric.
2. Evaluate survival duration, injunctive relief scope, and liquidated damages.
3. Suggest redlines for governing law, cross-border transfers, and record destruction.`,
    }),
  },
  {
    id: "code_security_review",
    tier: "pro",
    titleByLang: Object.freeze({
      ru: "Ревью кода и ИБ",
      en: "Code Security Review",
    }),
    descriptionByLang: Object.freeze({
      ru: "Обезличенный аудит безопасности кода и конфигурации без раскрытия ключей",
      en: "Anonymized DevSecOps audit for auth bypasses, secret handling, and injection vectors",
    }),
    textByLang: Object.freeze({
      ru: `Проведи аудит безопасности кода и конфигурации для узла [IPV4_1] (ключ [API_KEY_1], параметр [ENV_SECRET_1]).
1. Проверь риск обхода авторизации, инъекций и небезопасной обработки входных данных.
2. Оцени изоляцию секретов, принцип минимальных привилегий и заголовки безопасности.
3. Составь приоритизированный список исправлений с кратким обоснованием.`,
      en: `Perform a security code and configuration review for host [IPV4_1] (credential [API_KEY_1], secret [ENV_SECRET_1]).
1. Check for authentication bypasses, injection vectors, SSRF, and unsafe deserialization.
2. Audit secret isolation, least-privilege IAM permissions, and HTTP security headers.
3. Provide prioritized remediation steps with concise rationale.`,
    }),
  },
]);

export function getPromptTemplateById(id) {
  return PROMPT_TEMPLATES.find((tpl) => tpl.id === id) || null;
}

export function getLocalizedPromptTemplate(idOrTpl, lang = "ru") {
  const tpl = typeof idOrTpl === "string" ? getPromptTemplateById(idOrTpl) : idOrTpl;
  if (!tpl) return null;
  const normLang = lang === "en" ? "en" : "ru";
  return {
    id: tpl.id,
    tier: tpl.tier || "pro",
    isPro: (tpl.tier || "pro") === "pro",
    title: tpl.titleByLang?.[normLang] || tpl.titleByLang?.ru || "",
    description: tpl.descriptionByLang?.[normLang] || tpl.descriptionByLang?.ru || "",
    text: tpl.textByLang?.[normLang] || tpl.textByLang?.ru || "",
  };
}

export function getPromptTemplates(lang = "ru") {
  return PROMPT_TEMPLATES.map((tpl) => getLocalizedPromptTemplate(tpl, lang));
}
