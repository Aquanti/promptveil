/**
 * Bilingual RU (default) / EN dictionary and live DOM translation helper.
 * Zero English developer jargon in RU mode.
 */

export const SUPPORTED_LANGS = Object.freeze(["ru", "en"]);
export const DEFAULT_LANG = "ru";

export const TRANSLATIONS = Object.freeze({
  ru: {
    "meta.title": "PromptVeil — скрытие личных данных перед отправкой в ИИ",
    "a11y.skipLink": "Перейти к работе с текстом",
    "brand.name": "PromptVeil",
    "brand.badge": "Только в браузере",
    "brand.badgeTitle": "Все проверки и замены выполняются только в вашем браузере",
    "lang.switchAria": "Переключение языка",
    "hero.title": "Защитите личные данные перед отправкой текста в ИИ",
    "hero.subtitle":
      "Вставьте письмо, договор или код — сервис заменит контакты, карты и пароли на безопасные метки прямо в браузере, а затем вернёт исходные данные в ответ нейросети.",
    "hero.stepsAria": "Порядок работы",
    "hero.step1": "Вставьте текст и скройте данные",
    "hero.step2": "Скопируйте безопасный текст в ИИ",
    "hero.step3": "Вставьте ответ ИИ и верните исходники",
    "nav.stepsAria": "Этапы работы",
    "nav.tablistAria": "Режим работы",
    "nav.step1": "1. Скрыть данные",
    "nav.step2": "2. Вернуть в ответ ИИ",
    "nav.rulebook": "Свои слова",
    "nav.audit": "Журнал",
    "presets.heading": "Попробуйте на готовом примере:",
    "presets.groupAria": "Примеры текста",
    "presets.applyRulesBtn": "Скрыть имена и названия (+{count})",
    "presets.applyRulesHint":
      "Контакты и карты скрываются сами. Нажмите, чтобы также скрыть названия и имена из примера ({terms}).",
    "step1.inputHeading": "Исходный текст",
    "step1.inputPlaceholder":
      "Вставьте письмо, договор, резюме или фрагмент кода — ничего не отправляется на сервер...",
    "step1.uploadBtn": "Загрузить файл",
    "step1.fileLoading": "Читаем файл в браузере...",
    "step1.clearBtn": "Очистить",
    "step1.autoToggle": "Скрывать автоматически",
    "step1.sanitizeNowBtn": "Скрыть данные",
    "step1.outputHeading": "Безопасный текст для ИИ",
    "step1.outputEmpty":
      "Здесь появится безопасная версия текста с метками вместо личных данных.",
    "step1.outputHint": "Замены запоминаются только в текущей вкладке.",
    "step1.copyBtn": "Скопировать для ИИ",
    "step1.downloadBtn": "Скачать .txt",
    "step1.goStep2Btn": "Перейти к шагу 2: вернуть данные →",
    "step1.maskedCount": "Скрыто: {count}",
    "step1.filtersHeading": "Типы данных",
    "step1.filtersAria": "Типы найденных данных",
    "step1.allCategories": "Все",
    "step1.showAllCategories": "Показать все ({count})",
    "step1.hideEmptyCategories": "Скрыть пустые",
    "step1.vaultHeading": "Что скрыто",
    "step1.vaultSubheading":
      "Нажмите на метку в тексте или переключатель ниже, чтобы управлять скрытием",
    "step1.vaultEmpty":
      "Пока пусто: вставьте текст или выберите пример выше, чтобы сервис нашёл личные данные.",
    "step1.hideValues": "Скрыть значения",
    "step1.showValues": "Показать значения",
    "step1.itemOn": "Скрыто",
    "step1.itemOff": "Открыто",
    "step1.tokenTooltip": "{label}: нажмите, чтобы найти в списке",
    "step1.hits": "×{count}",
    "step2.inputHeading": "Ответ нейросети",
    "step2.inputPlaceholder":
      "Вставьте сюда ответ ИИ, в котором остались подставленные метки...",
    "step2.inputHint": "Метки подставляются за один проход в памяти браузера.",
    "step2.restoreBtn": "Вернуть исходные данные",
    "step2.clearBtn": "Очистить",
    "step2.vaultReady": "Замен в сессии: {count}",
    "step2.outputHeading": "Готовый текст с вашими данными",
    "step2.outputEmpty":
      "Здесь появится ответ ИИ с подставленными обратно именами, контактами и номерами.",
    "step2.outputHint": "Восстановление происходит полностью в памяти браузера.",
    "step2.copyBtn": "Скопировать итог",
    "step2.downloadBtn": "Скачать .txt",
    "step2.backBtn": "← Вернуться к шагу 1",
    "step2.restoredCount": "Восстановлено: {count}",
    "step2.restoredTooltip": "Восстановлено из {token}",
    "step2.emptySessionNotice":
      "В этой вкладке ещё нет скрытых данных. Сначала выполните шаг 1 (после обновления страницы словарь замен очищается ради приватности).",
    "step2.unresolvedWarning":
      "Не найдены исходники для меток (возможно, страница была обновлена): ",
    "step2.emptyInputError": "Сначала вставьте ответ нейросети в поле слева.",
    "action.copiedFeedback": "Скопировано ✓",
    "rulebook.title": "Свои слова и фразы",
    "rulebook.subtitle":
      "Добавьте имена, названия компаний или кодовые слова, которые нужно скрывать всегда.",
    "rulebook.termLabel": "Слово или фраза",
    "rulebook.termPlaceholder": "Например: Алексей Смирнов или ООО «Вектор»",
    "rulebook.categoryLabel": "Тип метки",
    "rulebook.caseLabel": "Учитывать регистр",
    "rulebook.addBtn": "Добавить",
    "rulebook.exportBtn": "Сохранить список (.json)",
    "rulebook.importBtn": "Загрузить список (.json)",
    "rulebook.empty": "Своих слов пока нет. Добавьте имя или компанию выше.",
    "rulebook.caseSensitive": "С учётом регистра",
    "rulebook.caseInsensitive": "Без учёта регистра",
    "rulebook.tag.PERSON": "Имя / ФИО",
    "rulebook.tag.ORG": "Компания",
    "rulebook.tag.PROJECT": "Проект",
    "rulebook.tag.SECRET": "Секрет",
    "rulebook.tag.CUSTOM": "Своё слово",
    "rulebook.errorEmpty": "Введите слово или фразу.",
    "rulebook.errorDuplicate": "Такое слово уже есть в вашем списке.",
    "rulebook.added": "Добавлено правило «{term}».",
    "rulebook.exported": "Список своих слов сохранён на компьютер.",
    "rulebook.imported": "Загружено слов: {added} (пропущено дублей: {skipped}).",
    "rulebook.importInvalidExt":
      "Неподдерживаемый формат «{ext}». Нужен файл .json.",
    "rulebook.importTooLarge": "Файл «{name}» больше 2 МБ.",
    "rulebook.importBadJson":
      "Не удалось прочитать список слов: проверьте формат JSON.",
    "rulebook.importReadError": "Ошибка чтения файла в браузере.",
    "audit.title": "Журнал проверок",
    "audit.subtitle":
      "Хранятся только цифровые отпечатки (SHA-256) и счётчики — исходные тексты и пароли не записываются.",
    "audit.notice":
      "Контрольные отпечатки вычисляются прямо в браузере (SHA-256). Исходные тексты, секреты и таблица замен не сохраняются и никуда не отправляются.",
    "audit.exportBtn": "Скачать отчёт (.json)",
    "audit.clearBtn": "Очистить журнал",
    "audit.empty": "Журнал пуст. Записи появятся после первой проверки текста.",
    "audit.confirmClear": "Очистить весь журнал проверок в этом браузере?",
    "audit.cleared": "Журнал проверок очищен.",
    "audit.exported": "Отчёт журнала (только хеши SHA-256) скачан.",
    "audit.action.SANITIZE": "Скрытие данных",
    "audit.action.REHYDRATE": "Восстановление",
    "audit.hashLine": "вход: {inHash} | выход: {outHash}",
    "audit.detailSanitize": "Найдено фрагментов: {count}",
    "audit.detailRehydrate": "Восстановлено меток: {count}",
    "common.close": "Закрыть",
    "common.delete": "Удалить",
    "banner.copied": "Текст скопирован в буфер обмена.",
    "banner.copyFailed": "Браузер запретил доступ к буферу обмена.",
    "banner.downloaded": "Файл сохранён на ваше устройство.",
    "banner.presetLoaded": "Загружен пример «{title}».",
    "banner.presetRulesAdded":
      "Добавлено правил: {count} — теперь имена и названия тоже скрыты.",
    "banner.fileLoaded": "Файл «{name}» открыт локально в браузере.",
    "banner.fileUnsupported":
      "Формат «{ext}» не поддерживается. Выберите .txt, .md, .csv, .json, .log или .env.",
    "banner.fileTooLarge":
      "Файл «{name}» превышает ограничение 2 МБ для безопасной обработки в браузере.",
    "banner.fileReadError": "Не удалось прочитать файл «{name}».",
    "banner.storageWarning":
      "Хранилище браузера заполнено или заблокировано — изменения сохраняются только в памяти вкладки.",
    "banner.auditWriteError":
      "Не удалось записать событие в локальный журнал.",
    "cat.API_KEY": "Ключи API",
    "cat.JWT": "Токены входа",
    "cat.CREDIT_CARD": "Банк. карты",
    "cat.IBAN": "Счета (IBAN)",
    "cat.SSN": "Номера соцстраха",
    "cat.ENV_SECRET": "Пароли настроек",
    "cat.CUSTOM": "Свои слова",
    "cat.EMAIL": "Почта",
    "cat.PHONE": "Телефоны",
    "cat.IPV4": "IP-адреса",
    "cat.HIGH_ENTROPY": "Секретные строки",
    "footer.localNote": "Все проверки выполняются локально в вашем браузере",
  },
  en: {
    "meta.title": "PromptVeil — Hide Sensitive Data Before AI",
    "a11y.skipLink": "Skip to workbench",
    "brand.name": "PromptVeil",
    "brand.badge": "Browser-local only",
    "brand.badgeTitle": "All detection and restoration runs strictly inside your browser",
    "lang.switchAria": "Language switcher",
    "hero.title": "Protect private details before sending text to AI",
    "hero.subtitle":
      "Paste a message, contract, or code snippet — contacts, cards, and secrets are masked locally in your browser and restored in the AI reply.",
    "hero.stepsAria": "Workflow steps",
    "hero.step1": "Paste text & hide data",
    "hero.step2": "Copy safe text to AI",
    "hero.step3": "Paste AI reply & restore",
    "nav.stepsAria": "Workflow stages",
    "nav.tablistAria": "Workbench mode",
    "nav.step1": "1. Hide Data",
    "nav.step2": "2. Restore in AI Reply",
    "nav.rulebook": "Custom Words",
    "nav.audit": "History",
    "presets.heading": "Try a ready example:",
    "presets.groupAria": "Sample presets",
    "presets.applyRulesBtn": "Hide names & companies (+{count})",
    "presets.applyRulesHint":
      "Contacts and cards are hidden automatically. Click to also hide names and companies from this example ({terms}).",
    "step1.inputHeading": "Original text",
    "step1.inputPlaceholder":
      "Paste an email, contract, resume, or code snippet — nothing leaves your browser...",
    "step1.uploadBtn": "Load file",
    "step1.fileLoading": "Reading file locally...",
    "step1.clearBtn": "Clear",
    "step1.autoToggle": "Hide automatically",
    "step1.sanitizeNowBtn": "Hide data",
    "step1.outputHeading": "Safe text for AI",
    "step1.outputEmpty":
      "Your safe version with placeholder tags will appear here.",
    "step1.outputHint": "Mappings stay strictly in this browser tab.",
    "step1.copyBtn": "Copy for AI",
    "step1.downloadBtn": "Download .txt",
    "step1.goStep2Btn": "Go to Step 2: restore reply →",
    "step1.maskedCount": "Masked: {count}",
    "step1.filtersHeading": "Data types",
    "step1.filtersAria": "Detected data categories",
    "step1.allCategories": "All",
    "step1.showAllCategories": "Show all ({count})",
    "step1.hideEmptyCategories": "Hide unused",
    "step1.vaultHeading": "What was hidden",
    "step1.vaultSubheading":
      "Click a tag in the text or use a switch below to manage masking",
    "step1.vaultEmpty":
      "Nothing hidden yet: paste text or pick an example above to detect private data.",
    "step1.hideValues": "Hide values",
    "step1.showValues": "Show values",
    "step1.itemOn": "Hidden",
    "step1.itemOff": "Visible",
    "step1.tokenTooltip": "{label}: click to locate in list",
    "step1.hits": "×{count}",
    "step2.inputHeading": "AI reply",
    "step2.inputPlaceholder":
      "Paste the AI reply containing placeholder tags here...",
    "step2.inputHint": "Single-pass substitution prevents token collisions.",
    "step2.restoreBtn": "Restore original data",
    "step2.clearBtn": "Clear",
    "step2.vaultReady": "Session mappings: {count}",
    "step2.outputHeading": "Final text with your data",
    "step2.outputEmpty":
      "The AI reply with your original names, contacts, and numbers restored will appear here.",
    "step2.outputHint": "All restoration runs locally in browser RAM.",
    "step2.copyBtn": "Copy result",
    "step2.downloadBtn": "Download .txt",
    "step2.backBtn": "← Back to Step 1",
    "step2.restoredCount": "Restored: {count}",
    "step2.restoredTooltip": "Restored from {token}",
    "step2.emptySessionNotice":
      "No active session mappings yet. Run Step 1 first (mappings are cleared on page reload for privacy).",
    "step2.unresolvedWarning":
      "Original values not found in current session for: ",
    "step2.emptyInputError": "Paste an AI reply first.",
    "action.copiedFeedback": "Copied ✓",
    "rulebook.title": "Custom words & phrases",
    "rulebook.subtitle":
      "Add names, company titles, or project words to always hide.",
    "rulebook.termLabel": "Word or phrase",
    "rulebook.termPlaceholder": "e.g. Acme Corp or Project Orion",
    "rulebook.categoryLabel": "Tag type",
    "rulebook.caseLabel": "Match exact letter case",
    "rulebook.addBtn": "Add",
    "rulebook.exportBtn": "Export (.json)",
    "rulebook.importBtn": "Import (.json)",
    "rulebook.empty": "No custom words yet. Add a name or company above.",
    "rulebook.caseSensitive": "Case-sensitive",
    "rulebook.caseInsensitive": "Case-insensitive",
    "rulebook.tag.PERSON": "Person",
    "rulebook.tag.ORG": "Organization",
    "rulebook.tag.PROJECT": "Project",
    "rulebook.tag.SECRET": "Secret",
    "rulebook.tag.CUSTOM": "Custom",
    "rulebook.errorEmpty": "Enter a non-empty word or phrase.",
    "rulebook.errorDuplicate": "This phrase already exists in your list.",
    "rulebook.added": 'Added rule "{term}".',
    "rulebook.exported": "Custom words exported locally.",
    "rulebook.imported": "Imported {added} rule(s) ({skipped} skipped).",
    "rulebook.importInvalidExt":
      'Unsupported extension "{ext}". Only .json files are allowed.',
    "rulebook.importTooLarge": 'File "{name}" exceeds the 2 MB limit.',
    "rulebook.importBadJson":
      "Could not import rules: invalid JSON format.",
    "rulebook.importReadError": "Unable to read the selected file.",
    "audit.title": "Verification History",
    "audit.subtitle":
      "Stores only cryptographic SHA-256 digests and counts — zero raw text or secrets.",
    "audit.notice":
      "SHA-256 digests are computed strictly in your browser. Raw text, secrets, and mappings are never stored or transmitted.",
    "audit.exportBtn": "Export (.json)",
    "audit.clearBtn": "Clear history",
    "audit.empty": "No history entries yet.",
    "audit.confirmClear":
      "Clear all verification history from this browser?",
    "audit.cleared": "History cleared.",
    "audit.exported": "SHA-256 history report downloaded.",
    "audit.action.SANITIZE": "Masked",
    "audit.action.REHYDRATE": "Restored",
    "audit.hashLine": "in: {inHash} | out: {outHash}",
    "audit.detailSanitize": "Detected items: {count}",
    "audit.detailRehydrate": "Restored tags: {count}",
    "common.close": "Close",
    "common.delete": "Delete",
    "banner.copied": "Copied to clipboard.",
    "banner.copyFailed": "Clipboard copy blocked by browser.",
    "banner.downloaded": "File saved locally.",
    "banner.presetLoaded": 'Loaded example "{title}".',
    "banner.presetRulesAdded":
      "Added {count} word rule(s) — names and companies are now masked too.",
    "banner.fileLoaded": 'Opened "{name}" locally in browser memory.',
    "banner.fileUnsupported":
      'Unsupported format "{ext}". Allowed: .txt, .md, .csv, .json, .log, .env.',
    "banner.fileTooLarge":
      'File "{name}" exceeds the 2 MB browser safety limit.',
    "banner.fileReadError": 'Failed to read "{name}".',
    "banner.storageWarning":
      "Browser storage is full or blocked; keeping changes in tab memory only.",
    "banner.auditWriteError":
      "Unable to store history entry in browser storage.",
    "cat.API_KEY": "API Keys",
    "cat.JWT": "JWT Tokens",
    "cat.CREDIT_CARD": "Cards",
    "cat.IBAN": "Bank Accounts",
    "cat.SSN": "US SSN",
    "cat.ENV_SECRET": ".env Secrets",
    "cat.CUSTOM": "Custom Words",
    "cat.EMAIL": "Email",
    "cat.PHONE": "Phones",
    "cat.IPV4": "IP Addresses",
    "cat.HIGH_ENTROPY": "Secret Strings",
    "footer.localNote": "All checks run locally in your browser",
  },
});

let currentLang = DEFAULT_LANG;

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

export function t(key, vars = {}, lang = currentLang) {
  const dict = TRANSLATIONS[normalizeLang(lang)] || TRANSLATIONS.ru;
  const fallback = TRANSLATIONS.ru[key] ?? key;
  const template = dict[key] ?? fallback;
  return String(template).replace(/\{([a-zA-Z0-9_]+)\}/g, (match, name) => {
    if (Object.prototype.hasOwnProperty.call(vars, name)) {
      return String(vars[name]);
    }
    return match;
  });
}

export function pluralizeRu(n, one, few, many) {
  const abs = Math.abs(Number(n) || 0) % 100;
  const mod10 = abs % 10;
  if (abs >= 11 && abs <= 19) return many;
  if (mod10 === 1) return one;
  if (mod10 >= 2 && mod10 <= 4) return few;
  return many;
}

export function getCategoryLabel(category, lang = currentLang) {
  const norm = String(category || "").trim().toUpperCase();
  const key = `cat.${norm}`;
  const dict = TRANSLATIONS[normalizeLang(lang)] || TRANSLATIONS.ru;
  return dict[key] || TRANSLATIONS.ru[key] || norm || "";
}

export function getCustomRuleTagLabel(ruleCategory, lang = currentLang) {
  const norm = String(ruleCategory || "CUSTOM").trim().toUpperCase();
  const key = `rulebook.tag.${norm}`;
  const dict = TRANSLATIONS[normalizeLang(lang)] || TRANSLATIONS.ru;
  return dict[key] || dict["rulebook.tag.CUSTOM"] || "CUSTOM";
}

export function applyLanguage(lang, hooks = {}) {
  const next = setLang(lang);
  document.documentElement.lang = next;
  document.title = t("meta.title", {}, next);

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

  for (const el of document.querySelectorAll("[data-i18n]")) {
    if (el.hasAttribute("data-copied")) {
      el.textContent = t("action.copiedFeedback", {}, next);
      continue;
    }
    const key = el.getAttribute("data-i18n");
    if (key) el.textContent = t(key, {}, next);
  }
  for (const el of document.querySelectorAll("[data-i18n-placeholder]")) {
    const key = el.getAttribute("data-i18n-placeholder");
    if (key) {
      const val = t(key, {}, next);
      if ("placeholder" in el) {
        el.placeholder = val;
      }
      el.setAttribute("data-placeholder", val);
    }
  }
  for (const el of document.querySelectorAll("[data-i18n-aria]")) {
    const key = el.getAttribute("data-i18n-aria");
    if (key) el.setAttribute("aria-label", t(key, {}, next));
  }
  for (const el of document.querySelectorAll("[data-i18n-title]")) {
    const key = el.getAttribute("data-i18n-title");
    if (key) el.setAttribute("title", t(key, {}, next));
  }

  if (typeof hooks.onAfterApply === "function") {
    hooks.onAfterApply(next);
  }
  return next;
}
