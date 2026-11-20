/**
 * Lightweight bilingual RU (default) / EN lazy dictionary loader and live DOM translator.
 * Uses dynamic ES import() with zero network requests.
 */

export const SUPPORTED_LANGS = Object.freeze(["ru", "en"]);
export const DEFAULT_LANG = "ru";

const loadedDicts = Object.create(null);
const pendingLoads = new Map();
let currentLang = DEFAULT_LANG;
let applySeq = 0;

export function normalizeLang(lang) {
  return lang === "en" ? "en" : "ru";
}

export function getLang() {
  return currentLang;
}

export function setLang(lang) {
  currentLang = normalizeLang(lang);
  return currentLang;
}

export function isLangLoaded(lang) {
  return Boolean(loadedDicts[normalizeLang(lang)]);
}

export async function ensureDictionary(lang) {
  const norm = normalizeLang(lang);
  if (loadedDicts[norm]) {
    return loadedDicts[norm];
  }
  if (pendingLoads.has(norm)) {
    return pendingLoads.get(norm);
  }
  const loaderPromise = (
    norm === "en"
      ? import("./i18n-en.js").then((mod) => mod.EN)
      : import("./i18n-ru.js").then((mod) => mod.RU)
  )
    .then((dict) => {
      loadedDicts[norm] = dict;
      return dict;
    })
    .finally(() => {
      pendingLoads.delete(norm);
    });
  pendingLoads.set(norm, loaderPromise);
  return loaderPromise;
}

export function t(key, vars = {}, lang = currentLang) {
  const norm = normalizeLang(lang);
  const dict = loadedDicts[norm] || loadedDicts[currentLang] || loadedDicts.ru || {};
  const fallback = loadedDicts.ru?.[key] ?? key;
  const template = dict[key] ?? fallback;
  return String(template).replace(/\{([a-zA-Z0-9_]+)\}/g, (match, name) => {
    if (Object.prototype.hasOwnProperty.call(vars, name)) {
      return String(vars[name]);
    }
    return match;
  });
}

export function pluralizeRu(n, one, few, many) {
  const intVal = Math.floor(Math.abs(Number(n) || 0));
  const abs = intVal % 100;
  const mod10 = abs % 10;
  if (abs >= 11 && abs <= 19) return many;
  if (mod10 === 1) return one;
  if (mod10 >= 2 && mod10 <= 4) return few;
  return many;
}

export function pluralizeEn(n, one, many) {
  return Math.abs(Number(n) || 0) === 1 ? one : many;
}

export function pluralizeCount(lang, n, forms) {
  if (normalizeLang(lang) === "en") {
    return pluralizeEn(n, forms.one, forms.many);
  }
  return pluralizeRu(n, forms.one, forms.few, forms.many);
}

export function getCategoryLabel(category, lang = currentLang) {
  const norm = String(category || "").trim().toUpperCase();
  const key = `cat.${norm}`;
  const dict = loadedDicts[normalizeLang(lang)] || loadedDicts[currentLang] || loadedDicts.ru || {};
  return dict[key] || loadedDicts.ru?.[key] || norm || "";
}

export function getCustomRuleTagLabel(ruleCategory, lang = currentLang) {
  const norm = String(ruleCategory || "CUSTOM").trim().toUpperCase();
  const key = `rulebook.tag.${norm}`;
  const dict = loadedDicts[normalizeLang(lang)] || loadedDicts[currentLang] || loadedDicts.ru || {};
  return dict[key] || dict["rulebook.tag.CUSTOM"] || loadedDicts.ru?.[key] || "CUSTOM";
}

export function getDetectionReasonLabel(entry, lang = currentLang) {
  const reasonKey = typeof entry?.reasonKey === "string" ? entry.reasonKey : "";
  if (reasonKey) {
    const resolved = t(reasonKey, {}, lang);
    if (resolved !== reasonKey) {
      return resolved;
    }
  }
  const catLabel = getCategoryLabel(entry?.category, lang);
  const fallback = t("reason.fallback", { label: catLabel }, lang);
  return fallback === "reason.fallback" ? catLabel : fallback;
}

export function applyTranslationsToRoot(root, lang = currentLang) {
  if (!root || typeof root.querySelectorAll !== "function") {
    return;
  }
  const next = normalizeLang(lang);

  for (const el of root.querySelectorAll("[data-i18n]")) {
    if (el.hasAttribute("data-copied")) {
      el.textContent = t("action.copiedFeedback", {}, next);
      continue;
    }
    const key = el.getAttribute("data-i18n");
    if (key === "nav.step2" && typeof el.querySelector === "function") {
      const shortEl = el.querySelector(".tab-label-short");
      const tailEl = el.querySelector(".tab-label-tail");
      if (shortEl && tailEl) {
        shortEl.textContent = t("nav.step2Short", {}, next);
        tailEl.textContent = t("nav.step2Tail", {}, next);
        continue;
      }
    }
    if (key) el.textContent = t(key, {}, next);
  }

  for (const el of root.querySelectorAll("[data-i18n-placeholder]")) {
    const key = el.getAttribute("data-i18n-placeholder");
    if (key) {
      const val = t(key, {}, next);
      if ("placeholder" in el) {
        el.placeholder = val;
      }
      el.setAttribute("data-placeholder", val);
    }
  }

  for (const el of root.querySelectorAll("[data-i18n-aria]")) {
    const key = el.getAttribute("data-i18n-aria");
    if (key) el.setAttribute("aria-label", t(key, {}, next));
  }

  for (const el of root.querySelectorAll("[data-i18n-title]")) {
    const key = el.getAttribute("data-i18n-title");
    if (key) el.setAttribute("title", t(key, {}, next));
  }
}

export async function applyLanguage(lang, hooks = {}) {
  const seq = ++applySeq;
  const targetLang = normalizeLang(lang);
  await ensureDictionary(targetLang);
  if (seq !== applySeq) {
    return getLang();
  }

  const next = setLang(targetLang);
  if (typeof document !== "undefined") {
    if (document.documentElement) {
      document.documentElement.lang = next;
    }
    document.title = t("meta.title", {}, next);

    const metaBindings = [
      ['meta[name="description"]', "content", "meta.description"],
      ['meta[property="og:locale"]', "content", "meta.ogLocale"],
      ['meta[property="og:locale:alternate"]', "content", "meta.ogLocaleAlternate"],
      ['meta[property="og:title"]', "content", "meta.ogTitle"],
      ['meta[property="og:description"]', "content", "meta.ogDescription"],
      ['meta[name="twitter:title"]', "content", "meta.twitterTitle"],
      ['meta[name="twitter:description"]', "content", "meta.twitterDescription"],
    ];
    for (const [selector, attr, key] of metaBindings) {
      const metaEl = document.querySelector(selector);
      if (metaEl) {
        metaEl.setAttribute(attr, t(key, {}, next));
      }
    }

    const ruBtn = document.querySelector('[data-testid="lang-ru"]');
    const enBtn = document.querySelector('[data-testid="lang-en"]');
    if (ruBtn) {
      ruBtn.classList.toggle("is-active", next === "ru");
      ruBtn.setAttribute("aria-pressed", next === "ru" ? "true" : "false");
    }
    if (enBtn) {
      enBtn.classList.toggle("is-active", next === "en");
      enBtn.setAttribute("aria-pressed", next === "en" ? "true" : "false");
    }
    const mobileLangBtn = document.querySelector('[data-testid="lang-mobile-toggle"]');
    if (mobileLangBtn) {
      const mobileAria = t(
        next === "ru" ? "lang.mobileToggleToEn" : "lang.mobileToggleToRu",
        {},
        next
      );
      mobileLangBtn.textContent = next.toUpperCase();
      mobileLangBtn.setAttribute("data-lang", next);
      mobileLangBtn.setAttribute("aria-label", mobileAria);
      mobileLangBtn.setAttribute("title", mobileAria);
    }

    applyTranslationsToRoot(document, next);
  }

  if (typeof hooks.onAfterApply === "function") {
    hooks.onAfterApply(next);
  }
  return next;
}
