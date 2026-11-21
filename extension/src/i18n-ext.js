/**
 * PromptVeil Extension Bilingual Localization (RU / EN).
 * Full parity across all keys; zero English jargon in Russian UI copy.
 */

export const EXTENSION_STRINGS = Object.freeze({
  ru: Object.freeze({
    "ext.name": "PromptVeil",
    "ext.tagline": "Локальная защита промптов",
    "ext.langRu": "RU",
    "ext.langEn": "EN",
    "ext.themeToDark": "Включить тёмную тему",
    "ext.themeToLight": "Включить светлую тему",

    "site.active": "Активно на {host}",
    "site.unsupported": "Откройте один из 6 поддерживаемых ИИ-чатов",
    "site.unknownTab": "Откройте ChatGPT, Claude, Gemini, DeepSeek, GigaChat или Алису",
    "site.hostsList": "ChatGPT • Claude • Gemini • DeepSeek • GigaChat • Алиса",

    "controls.title": "Защита в ИИ-чате",
    "controls.overlayLabel": "Плавающая панель поверх ИИ-чата",
    "controls.sensitivityLabel": "Режим проверки",
    "controls.sensitivityNormal": "Обычный",
    "controls.sensitivityStrict": "Строгий",
    "controls.uuidLabel": "Скрывать UUID",
    "controls.uuidStrictHint": "В строгом режиме UUID скрываются всегда",

    "categories.title": "Категории детектора",
    "categories.reset": "Включить все",
    "categories.proLockBadge": "Pro",
    "categories.proHint":
      "Выборочное отключение категорий доступно в Pro. В режиме Free работают все категории.",
    "categories.activeSummary": "Включено: {enabled} из {total}",

    "rules.title": "Свои слова",
    "rules.counterFree": "{count} / {limit} (Free)",
    "rules.counterPro": "{count} (безлимит Pro)",
    "rules.placeholder": "Имя, проект или компания...",
    "rules.addBtn": "Добавить",
    "rules.empty": "Список пуст. Добавьте имена, проекты или термины, которые нужно скрывать.",
    "rules.limitReached":
      "В тарифе Free действует лимит {limit} своих слов. Активируйте ключ Pro для снятия ограничения.",
    "rules.duplicate": "Такое слово уже есть в списке.",
    "rules.toggleAria": "Включить или отключить правило",
    "rules.removeAria": "Удалить правило",
    "rules.cat.CUSTOM": "Своё слово",
    "rules.cat.PERSON": "ФИО / Имя",
    "rules.cat.ORG": "Компания",
    "rules.cat.PROJECT": "Проект",
    "rules.cat.SECRET": "Секрет",

    "packs.title": "Отраслевые наборы слов",
    "packs.proBadge": "Только Pro",
    "packs.lockedNotice":
      "Отраслевые наборы доступны после активации ключа Pro ниже.",
    "packs.imported": "Набор «{title}»: добавлено правил {added}.",
    "packs.alreadyAdded": "Все слова из набора «{title}» уже добавлены.",

    "pro.badgeFree": "Free",
    "pro.badgePro": "Pro Активен",
    "pro.badgeOwner": "Owner Pro",
    "pro.sectionTitle": "Лицензия Pro (Ed25519)",
    "pro.statusTitleFree": "Тариф: Старт (Free)",
    "pro.statusDescFree":
      "Базовая защита, строгий режим и до 5 своих слов. Вставьте ключ PV1..., чтобы открыть безлимит, категории и наборы слов.",
    "pro.statusTitlePro": "Статус: Pro Активен",
    "pro.statusTitleOwner": "Статус: Owner Pro",
    "pro.metaTier": "Уровень: {tier}",
    "pro.metaKeyId": "ID ключа: {keyId}",
    "pro.metaLabel": "Метка: {label}",
    "pro.metaIssuedAt": "Выдан: {date}",
    "pro.metaExp": "Действует до: {date}",
    "pro.metaExpNever": "Срок: бессрочный офлайн-ключ",
    "pro.inputPlaceholder": "Вставьте ключ вида PV1....",
    "pro.activateBtn": "Активировать",
    "pro.removeBtn": "Удалить ключ",
    "pro.errorEmpty": "Вставьте ключ активации перед проверкой.",
    "pro.errorExpired": "Срок действия этого ключа истёк.",
    "pro.errorInvalid": "Ключ не прошёл проверку подписи Ed25519 или повреждён.",
    "pro.activatedSuccess": "Лицензия активирована ({tier}: {keyId}).",
    "pro.removedSuccess": "Ключ удалён — включён режим Free.",

    "footer.zeroRetention": "0 хранения текстов • Метки только в RAM вкладки",

    "pill.title": "PromptVeil",
    "pill.sanitizeBtn": "Скрыть перед отправкой",
    "pill.rehydrateBtn": "Вернуть ответ",
    "pill.vaultCount": "Замен в RAM: {count}",
    "pill.resetTitle": "Очистить словарь вкладки",
    "pill.collapseTitle": "Свернуть или развернуть панель",
    "pill.noInput": "Не найдено поле ввода промпта на странице.",
    "pill.emptyInput": "Введите текст промпта перед скрытием.",
    "pill.noMatches": "Конфиденциальные данные не обнаружены.",
    "pill.maskedSuccess": "Скрыто значений: {count} (только в RAM вкладки).",
    "pill.emptyVault":
      "В этой вкладке ещё нет замен. Сначала нажмите «Скрыть перед отправкой».",
    "pill.noReplySource":
      "Выделите ответ ИИ на странице или скопируйте его в буфер обмена.",
    "pill.noTokensInReply": "В ответе не найдено меток вида [TAG_1] из текущей сессии.",
    "pill.restoredAndCopied": "Восстановлено значений: {count}. Текст скопирован в буфер.",
    "pill.restoredOnly": "Восстановлено значений: {count}. Нажмите «Копировать».",
    "pill.popoverTitle": "Восстановленный ответ ({count})",
    "pill.unresolvedWarning": "Неизвестные метки: {tokens}",
    "pill.copyBtn": "Копировать",
    "pill.copiedBtn": "Скопировано",
    "pill.closeBtn": "Закрыть",
    "pill.vaultCleared": "Словарь замен этой вкладки очищен.",

    "cat.API_KEY": "Ключи API",
    "cat.URL_TOKEN": "Токены в URL",
    "cat.JWT": "Токены входа",
    "cat.CREDIT_CARD": "Банк. карты",
    "cat.POSSIBLE_CARD": "Возможная карта",
    "cat.IBAN": "Счета (IBAN)",
    "cat.RU_INN": "ИНН",
    "cat.RU_SNILS": "СНИЛС",
    "cat.RU_PASSPORT": "Паспорт РФ",
    "cat.RU_OGRN": "ОГРН / ОГРНИП",
    "cat.RU_BIK": "БИК",
    "cat.RU_ACCOUNT": "Счёт РФ",
    "cat.RU_OMS": "Полис ОМС",
    "cat.SSN": "SSN (США)",
    "cat.ENV_SECRET": "Пароли настроек",
    "cat.CUSTOM": "Свои слова",
    "cat.EMAIL": "Почта",
    "cat.PHONE": "Телефоны",
    "cat.RU_ORG": "Организации",
    "cat.RU_AUTO_PLATE": "Госномера авто",
    "cat.RU_FIO": "ФИО",
    "cat.RU_ADDRESS": "Адреса РФ",
    "cat.IPV4": "IP-адреса",
    "cat.UUID": "UUID",
    "cat.HIGH_ENTROPY": "Секретные строки",
  }),
  en: Object.freeze({
    "ext.name": "PromptVeil",
    "ext.tagline": "Local prompt privacy",
    "ext.langRu": "RU",
    "ext.langEn": "EN",
    "ext.themeToDark": "Switch to dark theme",
    "ext.themeToLight": "Switch to light theme",

    "site.active": "Active on {host}",
    "site.unsupported": "Open one of the 6 supported AI chats",
    "site.unknownTab": "Open ChatGPT, Claude, Gemini, DeepSeek, GigaChat, or Alice",
    "site.hostsList": "ChatGPT • Claude • Gemini • DeepSeek • GigaChat • Alice",

    "controls.title": "AI Chat Protection",
    "controls.overlayLabel": "Floating panel in AI chat",
    "controls.sensitivityLabel": "Detection mode",
    "controls.sensitivityNormal": "Normal",
    "controls.sensitivityStrict": "Strict",
    "controls.uuidLabel": "Hide UUIDs",
    "controls.uuidStrictHint": "UUIDs are always masked in Strict mode",

    "categories.title": "Detector Categories",
    "categories.reset": "Enable all",
    "categories.proLockBadge": "Pro",
    "categories.proHint":
      "Per-category toggles require Pro. In Free mode, all categories stay active.",
    "categories.activeSummary": "Active: {enabled} of {total}",

    "rules.title": "Custom Words",
    "rules.counterFree": "{count} / {limit} (Free)",
    "rules.counterPro": "{count} (Pro unlimited)",
    "rules.placeholder": "Name, project, or company...",
    "rules.addBtn": "Add",
    "rules.empty": "No custom words yet. Add names, projects, or terms to mask.",
    "rules.limitReached":
      "Free tier allows up to {limit} custom words. Activate a Pro key for unlimited rules.",
    "rules.duplicate": "This word is already in the list.",
    "rules.toggleAria": "Enable or disable rule",
    "rules.removeAria": "Remove rule",
    "rules.cat.CUSTOM": "Custom",
    "rules.cat.PERSON": "Person",
    "rules.cat.ORG": "Organization",
    "rules.cat.PROJECT": "Project",
    "rules.cat.SECRET": "Secret",

    "packs.title": "Industry Word Packs",
    "packs.proBadge": "Pro only",
    "packs.lockedNotice":
      "Industry word packs unlock once you activate a Pro key below.",
    "packs.imported": "Pack “{title}”: added {added} rules.",
    "packs.alreadyAdded": "All terms from “{title}” are already active.",

    "pro.badgeFree": "Free",
    "pro.badgePro": "Pro Active",
    "pro.badgeOwner": "Owner Pro",
    "pro.sectionTitle": "Pro License (Ed25519)",
    "pro.statusTitleFree": "Plan: Start (Free)",
    "pro.statusDescFree":
      "Core masking, strict mode, and up to 5 custom words are active. Paste a PV1... key to unlock unlimited rules, category toggles, and word packs.",
    "pro.statusTitlePro": "Status: Pro Active",
    "pro.statusTitleOwner": "Status: Owner Pro",
    "pro.metaTier": "Tier: {tier}",
    "pro.metaKeyId": "Key ID: {keyId}",
    "pro.metaLabel": "Label: {label}",
    "pro.metaIssuedAt": "Issued: {date}",
    "pro.metaExp": "Expires: {date}",
    "pro.metaExpNever": "Term: lifetime offline key",
    "pro.inputPlaceholder": "Paste a PV1.... license key",
    "pro.activateBtn": "Activate",
    "pro.removeBtn": "Remove key",
    "pro.errorEmpty": "Paste an activation key before verifying.",
    "pro.errorExpired": "This license key has expired.",
    "pro.errorInvalid": "Key failed Ed25519 signature verification or is malformed.",
    "pro.activatedSuccess": "License activated ({tier}: {keyId}).",
    "pro.removedSuccess": "License key removed — switched back to Free.",

    "footer.zeroRetention": "0 text retention • Mappings stay in tab RAM",

    "pill.title": "PromptVeil",
    "pill.sanitizeBtn": "Sanitize before send",
    "pill.rehydrateBtn": "Rehydrate reply",
    "pill.vaultCount": "RAM tokens: {count}",
    "pill.resetTitle": "Clear tab session vault",
    "pill.collapseTitle": "Collapse or expand panel",
    "pill.noInput": "No active AI prompt box found on this page.",
    "pill.emptyInput": "Enter prompt text before sanitizing.",
    "pill.noMatches": "No sensitive data detected.",
    "pill.maskedSuccess": "Masked {count} item(s) in tab RAM.",
    "pill.emptyVault":
      "No active mappings in this tab yet. Click “Sanitize before send” first.",
    "pill.noReplySource":
      "Select an AI reply on the page or copy it to your clipboard.",
    "pill.noTokensInReply": "No [TAG_1] tokens from this session found in the reply.",
    "pill.restoredAndCopied": "Restored {count} item(s) and copied to clipboard.",
    "pill.restoredOnly": "Restored {count} item(s). Click Copy to copy the text.",
    "pill.popoverTitle": "Rehydrated reply ({count})",
    "pill.unresolvedWarning": "Unresolved tags: {tokens}",
    "pill.copyBtn": "Copy",
    "pill.copiedBtn": "Copied",
    "pill.closeBtn": "Close",
    "pill.vaultCleared": "Tab session mappings cleared.",

    "cat.API_KEY": "API Keys",
    "cat.URL_TOKEN": "URL Tokens",
    "cat.JWT": "JWT Tokens",
    "cat.CREDIT_CARD": "Cards",
    "cat.POSSIBLE_CARD": "Possible card",
    "cat.IBAN": "Bank Accounts (IBAN)",
    "cat.RU_INN": "RU INN",
    "cat.RU_SNILS": "RU SNILS",
    "cat.RU_PASSPORT": "RU Passport",
    "cat.RU_OGRN": "RU OGRN",
    "cat.RU_BIK": "RU BIK",
    "cat.RU_ACCOUNT": "RU Bank Account",
    "cat.RU_OMS": "RU OMS Policy",
    "cat.SSN": "US SSN",
    "cat.ENV_SECRET": ".env Secrets",
    "cat.CUSTOM": "Custom Words",
    "cat.EMAIL": "Email",
    "cat.PHONE": "Phones",
    "cat.RU_ORG": "RU Organizations",
    "cat.RU_AUTO_PLATE": "RU Auto Plates",
    "cat.RU_FIO": "RU Full Names",
    "cat.RU_ADDRESS": "RU Addresses",
    "cat.IPV4": "IP Addresses",
    "cat.UUID": "UUID",
    "cat.HIGH_ENTROPY": "Secret Strings",
  }),
});

export function t(lang, key, vars = null) {
  const normLang = lang === "en" ? "en" : "ru";
  const dict = EXTENSION_STRINGS[normLang] || EXTENSION_STRINGS.ru;
  const raw = dict[key] ?? EXTENSION_STRINGS.ru[key] ?? key;
  if (!vars || typeof vars !== "object") {
    return raw;
  }
  return String(raw).replace(/\{([a-zA-Z0-9_]+)\}/g, (_, token) =>
    Object.prototype.hasOwnProperty.call(vars, token) ? String(vars[token]) : `{${token}}`
  );
}

export function getCategoryLabel(lang, category) {
  return t(lang, `cat.${category}`);
}
