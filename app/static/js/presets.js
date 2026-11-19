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
