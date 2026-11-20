import test, { afterEach, beforeEach, describe } from "node:test";
import assert from "node:assert/strict";

import {
  TRANSLATIONS,
  applyLanguage,
  pluralizeCount,
  pluralizeEn,
  pluralizeRu,
  setLang,
  t,
} from "../../app/static/js/i18n.js";
import { LANG_STORAGE_KEY, detectPathLanguage, loadLanguage } from "../../app/static/js/storage.js";
import { clearCopyFeedback, showCopyFeedback } from "../../app/static/js/dom.js";
import { isValidContactInput } from "../../app/static/js/pricing.js";
import { renderTelemetryAndActions } from "../../app/static/js/render-workbench.js";

function createMockLocalStorage() {
  const store = new Map();
  return {
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

function createMockEl(initialAttrs = {}) {
  const attrs = new Map(Object.entries(initialAttrs));
  return {
    textContent: "",
    disabled: false,
    placeholder: "",
    setAttribute(name, value) {
      attrs.set(name, String(value));
    },
    getAttribute(name) {
      return attrs.has(name) ? attrs.get(name) : null;
    },
    hasAttribute(name) {
      return attrs.has(name);
    },
    removeAttribute(name) {
      attrs.delete(name);
    },
    classList: {
      toggle() {},
    },
  };
}

describe("PromptVeil M2 Pluralization (Item 12)", () => {
  test("pluralizeRu handles Russian declensions across 0..121 including байт and трекер", () => {
    const byteForms = ["байт", "байта", "байт"];
    assert.equal(pluralizeRu(0, ...byteForms), "байт");
    assert.equal(pluralizeRu(1, ...byteForms), "байт");
    assert.equal(pluralizeRu(2, ...byteForms), "байта");
    assert.equal(pluralizeRu(3, ...byteForms), "байта");
    assert.equal(pluralizeRu(4, ...byteForms), "байта");
    assert.equal(pluralizeRu(5, ...byteForms), "байт");
    assert.equal(pluralizeRu(11, ...byteForms), "байт");
    assert.equal(pluralizeRu(14, ...byteForms), "байт");
    assert.equal(pluralizeRu(21, ...byteForms), "байт");
    assert.equal(pluralizeRu(22, ...byteForms), "байта");
    assert.equal(pluralizeRu(111, ...byteForms), "байт");

    const trackerForms = ["трекер", "трекера", "трекеров"];
    assert.equal(pluralizeRu(0, ...trackerForms), "трекеров");
    assert.equal(pluralizeRu(1, ...trackerForms), "трекер");
    assert.equal(pluralizeRu(2, ...trackerForms), "трекера");
    assert.equal(pluralizeRu(5, ...trackerForms), "трекеров");
    assert.equal(pluralizeRu(11, ...trackerForms), "трекеров");
    assert.equal(pluralizeRu(21, ...trackerForms), "трекер");
    assert.equal(pluralizeRu(22, ...trackerForms), "трекера");

    const prefKeyForms = ["служебный ключ", "служебных ключа", "служебных ключей"];
    assert.equal(pluralizeRu(1, ...prefKeyForms), "служебный ключ");
    assert.equal(pluralizeRu(3, ...prefKeyForms), "служебных ключа");
    assert.equal(pluralizeRu(5, ...prefKeyForms), "служебных ключей");
  });

  test("pluralizeEn and pluralizeCount select correct singular/plural forms", () => {
    assert.equal(pluralizeEn(0, "tracker", "trackers"), "trackers");
    assert.equal(pluralizeEn(1, "tracker", "trackers"), "tracker");
    assert.equal(pluralizeEn(2, "tracker", "trackers"), "trackers");
    assert.equal(pluralizeEn(21, "tracker", "trackers"), "trackers");

    assert.equal(
      pluralizeCount("ru", 2, { one: "запрос", few: "запроса", many: "запросов" }),
      "запроса"
    );
    assert.equal(
      pluralizeCount("en", 1, { one: "request", many: "requests" }),
      "request"
    );
    assert.equal(
      pluralizeCount("en", 0, { one: "byte", many: "bytes" }),
      "bytes"
    );

    assert.equal(t("proof.netMetric", { count: 1, unit: "запрос" }, "ru"), "1 запрос");
    assert.equal(t("proof.storageMetric", { bytes: 2, unit: "байта" }, "ru"), "2 байта");
    assert.equal(
      t("proof.trackersMetricLocal", { trackers: 1, unit: "tracker" }, "en"),
      "1 tracker • Local host"
    );
  });
});

describe("PromptVeil M2 i18n Parity, Meta Sync & Route Detection (Item 13)", () => {
  let prevDocument;
  let prevWindow;

  beforeEach(() => {
    prevDocument = globalThis.document;
    prevWindow = globalThis.window;
  });

  afterEach(() => {
    globalThis.document = prevDocument;
    globalThis.window = prevWindow;
    setLang("ru");
  });

  test("TRANSLATIONS.ru and TRANSLATIONS.en have complete key parity and clean EN free-tier copy", () => {
    const ruKeys = Object.keys(TRANSLATIONS.ru).sort();
    const enKeys = Object.keys(TRANSLATIONS.en).sort();
    assert.deepEqual(enKeys, ruKeys);

    const enFreeFeat = TRANSLATIONS.en["pricing.freeFeat1"];
    const enSubtitle = TRANSLATIONS.en["pricing.subtitle"];
    for (const forbidden of ["INN", "SNILS", "OGRN", "BIK", "OMS", "ИНН", "СНИЛС", "Russian ID"]) {
      assert.equal(enFreeFeat.includes(forbidden), false, `EN freeFeat1 must not contain ${forbidden}`);
      assert.equal(enSubtitle.includes(forbidden), false, `EN pricing.subtitle must not contain ${forbidden}`);
    }
  });

  test("applyLanguage syncs document lang, title, meta/OG/Twitter tags, and theme toggle aria/title", () => {
    const elementsBySelector = new Map([
      ['meta[name="description"]', createMockEl()],
      ['meta[property="og:locale"]', createMockEl()],
      ['meta[property="og:locale:alternate"]', createMockEl()],
      ['meta[property="og:title"]', createMockEl()],
      ['meta[property="og:description"]', createMockEl()],
      ['meta[name="twitter:title"]', createMockEl()],
      ['meta[name="twitter:description"]', createMockEl()],
    ]);
    const themeBtn = createMockEl({
      "data-i18n-aria": "theme.toDark",
      "data-i18n-title": "theme.toDark",
    });

    globalThis.document = {
      documentElement: { lang: "ru" },
      title: "",
      querySelector(selector) {
        return elementsBySelector.get(selector) || null;
      },
      querySelectorAll(selector) {
        if (selector === "[data-i18n-aria]" || selector === "[data-i18n-title]") {
          return [themeBtn];
        }
        return [];
      },
    };

    applyLanguage("en");
    assert.equal(globalThis.document.documentElement.lang, "en");
    assert.equal(globalThis.document.title, TRANSLATIONS.en["meta.title"]);
    assert.equal(
      elementsBySelector.get('meta[name="description"]').getAttribute("content"),
      TRANSLATIONS.en["meta.description"]
    );
    assert.equal(
      elementsBySelector.get('meta[property="og:locale"]').getAttribute("content"),
      "en_US"
    );
    assert.equal(
      elementsBySelector.get('meta[property="og:locale:alternate"]').getAttribute("content"),
      "ru_RU"
    );
    assert.equal(
      elementsBySelector.get('meta[property="og:title"]').getAttribute("content"),
      TRANSLATIONS.en["meta.ogTitle"]
    );
    assert.equal(
      elementsBySelector.get('meta[name="twitter:description"]').getAttribute("content"),
      TRANSLATIONS.en["meta.twitterDescription"]
    );
    assert.equal(themeBtn.getAttribute("aria-label"), TRANSLATIONS.en["theme.toDark"]);
    assert.equal(themeBtn.getAttribute("title"), TRANSLATIONS.en["theme.toDark"]);

    // Dark-mode key survives RU -> EN -> RU switches
    themeBtn.setAttribute("data-i18n-aria", "theme.toLight");
    themeBtn.setAttribute("data-i18n-title", "theme.toLight");
    applyLanguage("ru");
    assert.equal(globalThis.document.documentElement.lang, "ru");
    assert.equal(
      elementsBySelector.get('meta[property="og:locale"]').getAttribute("content"),
      "ru_RU"
    );
    assert.equal(themeBtn.getAttribute("aria-label"), TRANSLATIONS.ru["theme.toLight"]);
    assert.equal(themeBtn.getAttribute("title"), TRANSLATIONS.ru["theme.toLight"]);
  });

  test("loadLanguage prioritizes /en/ route over saved ru localStorage", () => {
    const mockStorage = createMockLocalStorage();
    mockStorage.setItem(LANG_STORAGE_KEY, "ru");
    globalThis.window = {
      localStorage: mockStorage,
      location: { pathname: "/en/" },
    };
    globalThis.document = { documentElement: { lang: "en" } };

    assert.equal(detectPathLanguage(), "en");
    assert.equal(loadLanguage(), "en");

    globalThis.window.location.pathname = "/en";
    assert.equal(loadLanguage(), "en");

    globalThis.window.location.pathname = "/";
    globalThis.document.documentElement.lang = "ru";
    assert.equal(loadLanguage(), "ru");

    mockStorage.setItem(LANG_STORAGE_KEY, "en");
    assert.equal(loadLanguage(), "en");

    mockStorage.removeItem(LANG_STORAGE_KEY);
    assert.equal(loadLanguage(), "ru");
  });
});

describe("PromptVeil M2 Copy Feedback Reset & Contact Validation (Items 7 & 11)", () => {
  let prevWindow;

  beforeEach(() => {
    prevWindow = globalThis.window;
  });

  afterEach(() => {
    globalThis.window = prevWindow;
  });

  test("clearCopyFeedback cancels pending timer, removes data-copied, and restores label; disabled buttons ignore showCopyFeedback", () => {
    let nextTimerId = 10;
    const clearedIds = [];
    const scheduled = [];
    globalThis.window = {
      setTimeout(fn, delay) {
        const id = nextTimerId++;
        scheduled.push({ id, fn, delay });
        return id;
      },
      clearTimeout(id) {
        clearedIds.push(id);
      },
    };

    const btn = createMockEl();
    btn.textContent = "Скопировать для ИИ";

    showCopyFeedback(btn, "Скопировано ✓", () => "Скопировать для ИИ", 2000);
    assert.equal(btn.textContent, "Скопировано ✓");
    assert.equal(btn.getAttribute("data-copied"), "true");
    assert.equal(scheduled.length, 1);

    clearCopyFeedback(btn, () => "Скопировать для ИИ");
    assert.deepEqual(clearedIds, [10]);
    assert.equal(btn.hasAttribute("data-copied"), false);
    assert.equal(btn.textContent, "Скопировать для ИИ");

    // Disabled button guard in showCopyFeedback
    const disabledBtn = createMockEl();
    disabledBtn.disabled = true;
    disabledBtn.textContent = "Скопировать для ИИ";
    showCopyFeedback(disabledBtn, "Скопировано ✓", () => "Скопировать для ИИ");
    assert.equal(disabledBtn.hasAttribute("data-copied"), false);
    assert.equal(disabledBtn.textContent, "Скопировать для ИИ");
    assert.equal(scheduled.length, 1);

    // Safe no-ops
    assert.doesNotThrow(() => clearCopyFeedback(null));
    assert.doesNotThrow(() => clearCopyFeedback(createMockEl()));
  });

  test("isValidContactInput validates email and @telegram handles", () => {
    assert.equal(isValidContactInput("user@example.com"), true);
    assert.equal(isValidContactInput("@supv1rus"), true);
    assert.equal(isValidContactInput(""), false);
    assert.equal(isValidContactInput("not-a-contact"), false);
    assert.equal(isValidContactInput("@ab"), false);
  });
});

describe("PromptVeil M3 Mobile UX Helpers (Items 14, 15, 17)", () => {
  let prevDocument;
  let prevWindow;

  beforeEach(() => {
    prevDocument = globalThis.document;
    prevWindow = globalThis.window;
  });

  afterEach(() => {
    globalThis.document = prevDocument;
    globalThis.window = prevWindow;
    setLang("ru");
  });

  test("applyLanguage syncs mobile language toggle and Step 2 dual-span label with fallback", () => {
    const mobileLangBtn = createMockEl({ "data-lang": "ru" });
    const shortSpan = createMockEl();
    const tailSpan = createMockEl();
    const step2DualEl = createMockEl({ "data-i18n": "nav.step2" });
    step2DualEl.querySelector = (sel) => {
      if (sel === ".tab-label-short") return shortSpan;
      if (sel === ".tab-label-tail") return tailSpan;
      return null;
    };
    const step2FallbackEl = createMockEl({ "data-i18n": "nav.step2" });

    globalThis.document = {
      documentElement: { lang: "ru" },
      title: "",
      querySelector(selector) {
        if (selector === '[data-testid="lang-mobile-toggle"]') return mobileLangBtn;
        return null;
      },
      querySelectorAll(selector) {
        if (selector === "[data-i18n]") return [step2DualEl, step2FallbackEl];
        return [];
      },
    };

    applyLanguage("en");
    assert.equal(mobileLangBtn.textContent, "EN");
    assert.equal(mobileLangBtn.getAttribute("data-lang"), "en");
    assert.equal(mobileLangBtn.getAttribute("aria-label"), TRANSLATIONS.en["lang.mobileToggleToRu"]);
    assert.equal(mobileLangBtn.getAttribute("title"), TRANSLATIONS.en["lang.mobileToggleToRu"]);
    assert.equal(shortSpan.textContent, "2. Restore");
    assert.equal(tailSpan.textContent, " in AI Reply");
    assert.equal(step2FallbackEl.textContent, "2. Restore in AI Reply");

    applyLanguage("ru");
    assert.equal(mobileLangBtn.textContent, "RU");
    assert.equal(mobileLangBtn.getAttribute("data-lang"), "ru");
    assert.equal(mobileLangBtn.getAttribute("aria-label"), TRANSLATIONS.ru["lang.mobileToggleToEn"]);
    assert.equal(shortSpan.textContent, "2. Вернуть");
    assert.equal(tailSpan.textContent, " в ответ ИИ");
    assert.equal(step2FallbackEl.textContent, "2. Вернуть в ответ ИИ");
  });

  test("renderTelemetryAndActions toggles and resets mobileStickyCopyBtn state", () => {
    let nextTimerId = 1;
    globalThis.window = {
      setTimeout() {
        return nextTimerId++;
      },
      clearTimeout() {},
    };

    const copyBtn = createMockEl();
    const stickyBtn = createMockEl();

    renderTelemetryAndActions(
      { copySanitizedBtn: copyBtn, mobileStickyCopyBtn: stickyBtn },
      { rawText: "hello", result: { sanitizedText: "hello" }, maskedCount: 1, revealValues: true, lang: "ru" }
    );
    assert.equal(stickyBtn.disabled, false);
    assert.equal(stickyBtn.textContent, TRANSLATIONS.ru["step1.mobileStickyCta"]);

    showCopyFeedback(stickyBtn, TRANSLATIONS.ru["action.copiedFeedback"], () => TRANSLATIONS.ru["step1.mobileStickyCta"]);
    assert.equal(stickyBtn.getAttribute("data-copied"), "true");

    renderTelemetryAndActions(
      { copySanitizedBtn: copyBtn, mobileStickyCopyBtn: stickyBtn },
      { rawText: "", result: null, maskedCount: 0, revealValues: true, lang: "en" }
    );
    assert.equal(stickyBtn.disabled, true);
    assert.equal(stickyBtn.hasAttribute("data-copied"), false);
    assert.equal(stickyBtn.textContent, TRANSLATIONS.en["step1.mobileStickyCta"]);
  });
});
