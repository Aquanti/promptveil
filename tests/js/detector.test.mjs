import test, { afterEach, beforeEach, describe } from "node:test";
import assert from "node:assert/strict";

import { CATEGORIES, CATEGORY_MAP, detectEntities } from "../../app/static/js/detector.js";
import { SessionVault } from "../../app/static/js/vault.js";
import {
  AUDIT_PERSIST_STORAGE_KEY,
  AUDIT_STORAGE_KEY,
  appendAuditReceipt,
  clearAuditLog,
  isAuditPersistenceEnabled,
  loadAuditLog,
  purgeUnoptedAuditStorage,
  setAuditPersistenceEnabled,
} from "../../app/static/js/storage.js";

function createMockLocalStorage() {
  const store = new Map();
  return {
    get length() {
      return store.size;
    },
    key(index) {
      return Array.from(store.keys())[index] ?? null;
    },
    getItem(key) {
      return store.has(key) ? store.get(key) : null;
    },
    setItem(key, value) {
      store.set(String(key), String(value));
    },
    removeItem(key) {
      store.delete(String(key));
    },
    clear() {
      store.clear();
    },
  };
}

describe("PromptVeil M1 Detection Engine (Item 1)", () => {
  test("CATEGORIES registers all 25 detectors with expected priorities", () => {
    assert.equal(CATEGORIES.length, 25);
    assert.equal(CATEGORY_MAP.POSSIBLE_CARD.priority, 84);
    assert.equal(CATEGORY_MAP.POSSIBLE_CARD.tokenPrefix, "POSSIBLE_CARD");
    assert.equal(CATEGORY_MAP.RU_ORG.priority, 68);
    assert.equal(CATEGORY_MAP.RU_ORG.tokenPrefix, "ORG");
    assert.equal(CATEGORY_MAP.UUID.priority, 58);
    assert.equal(CATEGORY_MAP.UUID.tokenPrefix, "UUID");
    assert.equal(CATEGORY_MAP.UUID.secondary, true);
  });

  test("RU_ORG masks quoted forms and IP entities while skipping lowercase/bare prefixes", () => {
    const positives = [
      'ООО «Вектор»',
      'АО «ТехноСфера»',
      'ПАО «ТестБанк»',
      'НКО «Добро»',
      'ОАО «Газ»',
      'ЗАО "Альфа"',
      'НКО „Бета“',
      "ОАО 'Гамма'",
      'ИП «Омега»',
      "ИП Иванов И.И.",
      "ИП Петров Иван Сергеевич",
      "ИП Смирнов Алексей",
    ];

    for (const sample of positives) {
      const spans = detectEntities(sample);
      assert.equal(spans.length, 1, `Expected 1 span for ${sample}`);
      assert.equal(spans[0].category, "RU_ORG", `Expected RU_ORG for ${sample}`);
      assert.equal(spans[0].value, sample);

      const vault = new SessionVault();
      const res = vault.sanitize(sample);
      assert.equal(res.sanitizedText, "[ORG_1]");
      assert.equal(vault.rehydrate(res.sanitizedText).rehydratedText, sample);
    }

    const negatives = "ооо «Вектор», ООО без названия, ооо тест";
    const negSpans = detectEntities(negatives);
    assert.equal(
      negSpans.filter((s) => s.category === "RU_ORG").length,
      0,
      "Lowercase or unquoted bare prefixes must remain unmasked"
    );
  });

  test("RU_FIO detects 2-word names (including declined & hyphenated) and guards prose/streets", () => {
    const positiveCases = [
      "Алексей Смирнов",
      "Иван Петров",
      "Мария Иванова",
      "Смирнов Алексей",
      "Алексея Смирнова",
      "Ивану Петрову",
      "Марии Ивановой",
      "Анна Соколова-Петрова",
      "Пётр Шевченко",
      "Олег Ткачук",
      "Ирина Бойко",
      "Сергей Белых",
      "Дмитрий Белецкий",
    ];

    for (const fullName of positiveCases) {
      const spans = detectEntities(`Сотрудник: ${fullName}.`);
      assert.equal(spans.length, 1, `Expected 1 span for ${fullName}`);
      assert.equal(spans[0].category, "RU_FIO", `Expected RU_FIO for ${fullName}`);
      assert.equal(spans[0].value, fullName);

      const vault = new SessionVault();
      const masked = vault.sanitize(`Сотрудник: ${fullName}.`);
      assert.equal(masked.sanitizedText, "Сотрудник: [FIO_1].");
      assert.equal(vault.rehydrate(masked.sanitizedText).rehydratedText, `Сотрудник: ${fullName}.`);
    }

    const negativeTexts = [
      "Надежда Клиентов",
      "Вера Других",
      "Новый Договор",
      "Иван Город",
      "Главный Директор",
      "Москва Столица",
      "Сергей Работает",
      "Только Несколько",
    ];
    for (const text of negativeTexts) {
      const spans = detectEntities(text);
      assert.equal(
        spans.filter((s) => s.category === "RU_FIO").length,
        0,
        `Did not expect RU_FIO for prose: ${text}`
      );
    }

    const streetText = "ул. Петра Алексеева, д. 5";
    const streetSpans = detectEntities(streetText);
    assert.equal(streetSpans.length, 1);
    assert.equal(streetSpans[0].category, "RU_ADDRESS");
    assert.equal(streetSpans[0].value, streetText);

    const fioAndStreet = "Иван Петров, ул. Ленина, д. 5";
    const bothSpans = detectEntities(fioAndStreet);
    assert.equal(bothSpans.length, 2);
    assert.deepEqual(
      bothSpans.map((s) => [s.category, s.value]),
      [
        ["RU_FIO", "Иван Петров"],
        ["RU_ADDRESS", "ул. Ленина, д. 5"],
      ]
    );
  });

  test("POSSIBLE_CARD masks context-labeled non-Luhn cards while CREDIT_CARD keeps Luhn priority", () => {
    const possibleCases = [
      ["карта 4276 3800 1234 5678", "4276 3800 1234 5678", "карта [POSSIBLE_CARD_1]"],
      ["карты 4276-3800-1234-5678", "4276-3800-1234-5678", "карты [POSSIBLE_CARD_1]"],
      ["card 4276380012345678", "4276380012345678", "card [POSSIBLE_CARD_1]"],
      ["№карты 4276 3800 1234 5678", "4276 3800 1234 5678", "№карты [POSSIBLE_CARD_1]"],
      ["номер карты: 4276 3800 1234 5678", "4276 3800 1234 5678", "номер карты: [POSSIBLE_CARD_1]"],
    ];

    for (const [input, expectedVal, expectedOut] of possibleCases) {
      const spans = detectEntities(input);
      assert.equal(spans.length, 1, `Expected 1 span for ${input}`);
      assert.equal(spans[0].category, "POSSIBLE_CARD");
      assert.equal(spans[0].value, expectedVal);

      const vault = new SessionVault();
      const res = vault.sanitize(input);
      assert.equal(res.sanitizedText, expectedOut);
      assert.equal(vault.rehydrate(res.sanitizedText).rehydratedText, input);
    }

    const validCardCases = [
      ["карта 4111 1111 1111 1111", "4111 1111 1111 1111", "карта [CARD_1]"],
      ["Card 4111111111111111 99", "4111111111111111", "Card [CARD_1] 99"],
      ["Card 4111-1111-1111-1111-123", "4111-1111-1111-1111", "Card [CARD_1]-123"],
    ];
    for (const [input, expectedVal, expectedOut] of validCardCases) {
      const spans = detectEntities(input);
      assert.equal(spans.length, 1);
      assert.equal(spans[0].category, "CREDIT_CARD");
      assert.equal(spans[0].value, expectedVal);
      const vault = new SessionVault();
      assert.equal(vault.sanitize(input).sanitizedText, expectedOut);
    }

    const negativeCards = [
      "4276 3800 1234 5678",
      "Bad1 4111 1111 1111 1112",
      "ИНН 4276 3800 1234 5678",
      "0000 0000 0000 0000",
      "карта 0000 0000 0000 0000",
    ];
    for (const input of negativeCards) {
      const spans = detectEntities(input);
      assert.equal(
        spans.filter((s) => s.category === "CREDIT_CARD" || s.category === "POSSIBLE_CARD").length,
        0,
        `Did not expect card match for ${input}`
      );
    }
  });

  test("UUID is opt-in (off by default, on with detectUuid or sensitivity='strict')", () => {
    const sample = "Correlation UUID: 550e8400-e29b-41d4-a716-446655440000";
    assert.equal(detectEntities(sample).length, 0);
    assert.equal(detectEntities(sample, [], { detectUuid: false }).length, 0);

    const optOnSpans = detectEntities(sample, [], { detectUuid: true });
    assert.equal(optOnSpans.length, 1);
    assert.equal(optOnSpans[0].category, "UUID");
    assert.equal(optOnSpans[0].value, "550e8400-e29b-41d4-a716-446655440000");

    const strictSpans = detectEntities(sample, [], { sensitivity: "strict" });
    assert.equal(strictSpans.length, 1);
    assert.equal(strictSpans[0].category, "UUID");

    const vault = new SessionVault();
    assert.equal(vault.sanitize(sample).sanitizedText, sample);
    const masked = vault.sanitize(sample, [], { detectUuid: true });
    assert.equal(masked.sanitizedText, "Correlation UUID: [UUID_1]");
    assert.equal(vault.rehydrate(masked.sanitizedText).rehydratedText, sample);
  });

  test("RU_ADDRESS captures city prefixes, major cities, and post-street types", () => {
    const cases = [
      ["живу Москва, ул. Ленина, д. 5", "Москва, ул. Ленина, д. 5", "живу [ADDRESS_1]"],
      [
        "125009, г. Москва, ул. Тверская, д. 12, стр. 1, оф. 45",
        "125009, г. Москва, ул. Тверская, д. 12, стр. 1, оф. 45",
        "[ADDRESS_1]",
      ],
      [
        "г. Нижний Новгород, пр. Гагарина, д. 10",
        "г. Нижний Новгород, пр. Гагарина, д. 10",
        "[ADDRESS_1]",
      ],
      [
        "Санкт-Петербург, Невский пр., д. 1",
        "Санкт-Петербург, Невский пр., д. 1",
        "[ADDRESS_1]",
      ],
      ["Таганрог, ул. Чехова, д. 5", "Таганрог, ул. Чехова, д. 5", "[ADDRESS_1]"],
      ["Офис, ул. Ленина, д. 5", "ул. Ленина, д. 5", "Офис, [ADDRESS_1]"],
    ];

    for (const [input, expectedVal, expectedOut] of cases) {
      const spans = detectEntities(input);
      assert.equal(spans.length, 1, `Expected 1 span for ${input}`);
      assert.equal(spans[0].category, "RU_ADDRESS", `Expected RU_ADDRESS for ${input}`);
      assert.equal(spans[0].value, expectedVal);

      const vault = new SessionVault();
      const res = vault.sanitize(input);
      assert.equal(res.sanitizedText, expectedOut);
      assert.equal(vault.rehydrate(res.sanitizedText).rehydratedText, input);
    }
  });

  test("Priority resolution: CUSTOM (80) overrides RU_ORG (68) and RU_FIO (64)", () => {
    const text = "ООО «Вектор» и Алексей Смирнов";
    const rules = [
      { id: "r1", term: "ООО «Вектор»", category: "ORG", enabled: true },
      { id: "r2", term: "Алексей Смирнов", category: "PERSON", enabled: true },
    ];
    const spans = detectEntities(text, rules);
    assert.equal(spans.length, 2);
    assert.equal(spans[0].category, "CUSTOM");
    assert.equal(spans[1].category, "CUSTOM");

    const vault = new SessionVault();
    const res = vault.sanitize(text, rules);
    assert.equal(res.sanitizedText, "[CUSTOM_1] и [CUSTOM_2]");
  });

  test("Iteration 2 regressions: RU_ORG substring/initials/instrumental, multi-word street guard, shifted Luhn, stopwords, Cyrillic street guard", () => {
    // 1. RU_ORG ИП 2-word substring collision & ИП И.И. Иванов & instrumental patronymic
    for (const orgSample of [
      "ИП Иванов Иван",
      "ИП Петров Петр",
      "ИП Романов Роман",
      "ИП И.И. Иванов",
    ]) {
      const spans = detectEntities(orgSample);
      assert.equal(spans.length, 1, `Expected 1 span for ${orgSample}`);
      assert.equal(spans[0].category, "RU_ORG", `Expected RU_ORG for ${orgSample}`);
      assert.equal(spans[0].value, orgSample);

      const vault = new SessionVault();
      const res = vault.sanitize(orgSample);
      assert.equal(res.sanitizedText, "[ORG_1]");
      assert.equal(vault.rehydrate(res.sanitizedText).rehydratedText, orgSample);
    }

    const instrOrg = "Договор с ИП Петровым Иваном Сергеевичем";
    const instrOrgSpans = detectEntities(instrOrg);
    assert.equal(instrOrgSpans.length, 1);
    assert.equal(instrOrgSpans[0].category, "RU_ORG");
    assert.equal(instrOrgSpans[0].value, "ИП Петровым Иваном Сергеевичем");
    {
      const vault = new SessionVault();
      const res = vault.sanitize(instrOrg);
      assert.equal(res.sanitizedText, "Договор с [ORG_1]");
      assert.equal(vault.rehydrate(res.sanitizedText).rehydratedText, instrOrg);
    }

    // 2. RU_FIO instrumental patronymics (masculine -ем & feminine -ой/-ою)
    for (const [text, expectedVal, expectedOut] of [
      ["с Иваном Сергеевичем Петровым", "Иваном Сергеевичем Петровым", "с [FIO_1]"],
      ["с Петровым Иваном Сергеевичем", "Петровым Иваном Сергеевичем", "с [FIO_1]"],
      ["с Анной Сергеевной Смирновой", "Анной Сергеевной Смирновой", "с [FIO_1]"],
      ["с Анной Сергеевною Смирновой", "Анной Сергеевною Смирновой", "с [FIO_1]"],
    ]) {
      const spans = detectEntities(text);
      assert.equal(spans.length, 1, `Expected 1 span for ${text}`);
      assert.equal(spans[0].category, "RU_FIO");
      assert.equal(spans[0].value, expectedVal);
      const vault = new SessionVault();
      const res = vault.sanitize(text);
      assert.equal(res.sanitizedText, expectedOut);
      assert.equal(vault.rehydrate(res.sanitizedText).rehydratedText, text);
    }

    // 3. RU_FIO street-prefix guard on 3-word and titled person streets, while comma splits FIO
    for (const street of [
      "ул. Академика Ивана Павлова, д. 1",
      "ул. Ивана Сергеевича Тургенева, д. 5",
      "ул. Маршала Бориса Шапошникова, д. 3",
      "ул. Генерала Ивана Петрова, д. 5",
    ]) {
      const spans = detectEntities(street);
      assert.equal(spans.length, 1, `Expected 1 span for ${street}`);
      assert.equal(spans[0].category, "RU_ADDRESS", `Expected RU_ADDRESS for ${street}`);
      assert.equal(spans[0].value, street);
    }

    const streetThenFio = "ул. Ленина, Иван Петров";
    const splitSpans = detectEntities(streetThenFio);
    assert.equal(splitSpans.length, 1);
    assert.equal(splitSpans[0].category, "RU_FIO");
    assert.equal(splitSpans[0].value, "Иван Петров");

    // 4. Shifted Luhn sub-span must not hijack POSSIBLE_CARD, and карточкой/карточкою supported
    {
      const shiftedInput = "карта 4276 3800 1234 5678 2";
      const spans = detectEntities(shiftedInput);
      assert.equal(spans.length, 1);
      assert.equal(spans[0].category, "POSSIBLE_CARD");
      assert.equal(spans[0].value, "4276 3800 1234 5678");
      const vault = new SessionVault();
      const res = vault.sanitize(shiftedInput);
      assert.equal(res.sanitizedText, "карта [POSSIBLE_CARD_1] 2");
      assert.equal(vault.rehydrate(res.sanitizedText).rehydratedText, shiftedInput);
    }
    for (const cardKw of ["карточкой 4276 3800 1234 5678", "карточкою 4276 3800 1234 5678"]) {
      const spans = detectEntities(cardKw);
      assert.equal(spans.length, 1, `Expected 1 span for ${cardKw}`);
      assert.equal(spans[0].category, "POSSIBLE_CARD");
      assert.equal(spans[0].value, "4276 3800 1234 5678");
    }

    // 5. Plural genitive prose false positives guarded by RU_FIO_STOPWORDS
    for (const prose of [
      "Надежда Пациентов",
      "Любовь Близких",
      "Вера Молодых",
      "Роман Слов",
    ]) {
      const spans = detectEntities(prose);
      assert.equal(
        spans.filter((s) => s.category === "RU_FIO").length,
        0,
        `Did not expect RU_FIO for prose: ${prose}`
      );
    }

    // 6. STREET_TYPE_WORD_GUARD Cyrillic boundary prevents "г. Улица, " capture
    {
      const streetWordCity = "г. Улица, ул. Ленина, д. 5";
      const spans = detectEntities(streetWordCity);
      assert.equal(spans.length, 1);
      assert.equal(spans[0].category, "RU_ADDRESS");
      assert.equal(spans[0].value, "ул. Ленина, д. 5");
    }
  });
});

describe("PromptVeil M1 Audit Journal RAM-Only Default (Item 5)", () => {
  let prevWindow;
  let mockStorage;

  beforeEach(() => {
    prevWindow = globalThis.window;
    mockStorage = createMockLocalStorage();
    globalThis.window = { localStorage: mockStorage };
    setAuditPersistenceEnabled(false);
    clearAuditLog();
    mockStorage.clear();
  });

  afterEach(() => {
    setAuditPersistenceEnabled(false);
    clearAuditLog();
    globalThis.window = prevWindow;
  });

  test("Default mode keeps audit log in RAM only without writing localStorage", async () => {
    assert.equal(isAuditPersistenceEnabled(), false);

    const res = await appendAuditReceipt({
      action: "SANITIZE",
      inputText: "secret@example.com",
      outputText: "[EMAIL_1]",
      entities: [{ category: "EMAIL", token: "[EMAIL_1]", value: "secret@example.com" }],
      countsByCategory: { EMAIL: 1 },
    });

    assert.equal(res.aborted, false);
    assert.equal(res.storagePersisted, false);
    assert.equal(mockStorage.getItem(AUDIT_STORAGE_KEY), null);
    assert.equal(mockStorage.getItem(AUDIT_PERSIST_STORAGE_KEY), null);
    assert.equal(loadAuditLog().length, 1);
  });

  test("Opting in persists RAM receipts and future receipts; opting out clears localStorage", async () => {
    await appendAuditReceipt({
      action: "SANITIZE",
      inputText: "a@b.ru",
      outputText: "[EMAIL_1]",
      entities: [{ category: "EMAIL", token: "[EMAIL_1]", value: "a@b.ru" }],
      countsByCategory: { EMAIL: 1 },
    });
    assert.equal(mockStorage.getItem(AUDIT_STORAGE_KEY), null);

    const enabled = setAuditPersistenceEnabled(true, loadAuditLog());
    assert.equal(enabled, true);
    assert.equal(isAuditPersistenceEnabled(), true);
    assert.equal(mockStorage.getItem(AUDIT_PERSIST_STORAGE_KEY), "1");
    assert.equal(JSON.parse(mockStorage.getItem(AUDIT_STORAGE_KEY)).length, 1);

    const second = await appendAuditReceipt({
      action: "REHYDRATE",
      inputText: "[EMAIL_1]",
      outputText: "a@b.ru",
      replacedCount: 1,
    });
    assert.equal(second.storagePersisted, true);
    assert.equal(JSON.parse(mockStorage.getItem(AUDIT_STORAGE_KEY)).length, 2);

    const disabled = setAuditPersistenceEnabled(false);
    assert.equal(disabled, false);
    assert.equal(isAuditPersistenceEnabled(), false);
    assert.equal(mockStorage.getItem(AUDIT_PERSIST_STORAGE_KEY), null);
    assert.equal(mockStorage.getItem(AUDIT_STORAGE_KEY), null);
    assert.equal(loadAuditLog().length, 2);
  });

  test("purgeUnoptedAuditStorage removes stale audit storage when opt-in flag is absent", () => {
    mockStorage.setItem(AUDIT_STORAGE_KEY, JSON.stringify([{ action: "SANITIZE" }]));
    purgeUnoptedAuditStorage();
    assert.equal(mockStorage.getItem(AUDIT_STORAGE_KEY), null);
  });
});
