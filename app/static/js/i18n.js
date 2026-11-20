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
    "proof.triggerLabel": "Гарантия 0 хранения • Проверить",
    "proof.triggerTitle": "Открыть клиентскую проверку конфиденциальности (0 хранения)",
    "lang.switchAria": "Переключение языка",
    "nav.pricing": "Тарифы",
    "nav.resetSession": "Сбросить сессию в 0",
    "hero.title": "Защитите личные данные перед отправкой текста в ИИ",
    "hero.subtitle":
      "Вставьте письмо, договор или код — сервис заменит контакты, карты и пароли на безопасные метки в памяти вкладки, а затем вернёт исходные данные в ответ нейросети.",
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
    "action.paste": "Вставить",
    "action.copy": "Скопировать",
    "step1.inputHeading": "Исходный текст",
    "step1.inputPlaceholder":
      "Вставьте письмо, договор, резюме или фрагмент кода...",
    "step1.uploadBtn": "Загрузить файл",
    "step1.fileLoading": "Читаем файл...",
    "step1.clearBtn": "Очистить",
    "step1.autoToggle": "Скрывать автоматически",
    "step1.sanitizeNowBtn": "Скрыть данные",
    "step1.outputHeading": "Безопасный текст для ИИ",
    "step1.outputEmpty":
      "Здесь появится безопасная версия текста с метками вместо личных данных.",
    "step1.outputHint": "Замены хранятся только в оперативной памяти текущей вкладки.",
    "step1.copyBtn": "Скопировать для ИИ",
    "step1.downloadBtn": "Скачать .txt",
    "step1.copyGoStep2Btn": "Скопировать и перейти к шагу 2 →",
    "step1.goStep2Btn": "Перейти к шагу 2 →",
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
    "step2.inputHint": "Метки подставляются за один проход в оперативной памяти.",
    "step2.restoreBtn": "Вернуть исходные данные",
    "step2.clearBtn": "Очистить",
    "step2.vaultReady": "Замен в сессии: {count}",
    "step2.outputHeading": "Готовый текст с вашими данными",
    "step2.outputEmpty":
      "Здесь появится ответ ИИ с подставленными обратно именами, контактами и номерами.",
    "step2.outputHint": "Восстановление происходит в оперативной памяти вкладки.",
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
    "rulebook.importReadError": "Не удалось прочитать выбранный файл.",
    "audit.title": "Журнал проверок",
    "audit.subtitle":
      "Хранятся только цифровые отпечатки (SHA-256) и счётчики — исходные тексты и пароли не записываются.",
    "audit.notice":
      "Контрольные отпечатки (SHA-256) вычисляются на вашем устройстве. Исходные тексты, секреты и таблица замен не сохраняются.",
    "audit.exportBtn": "Скачать отчёт (.json)",
    "audit.clearBtn": "Очистить журнал",
    "audit.empty": "Журнал пуст. Записи появятся после первой проверки текста.",
    "audit.confirmClear": "Очистить весь журнал проверок?",
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
    "banner.copyFailed": "Доступ к буферу обмена ограничен — используйте Ctrl+C / Cmd+C.",
    "banner.pasted": "Текст вставлен из буфера обмена.",
    "banner.clipboardEmpty": "Буфер обмена пуст.",
    "banner.pasteFallback":
      "Нажмите Ctrl+V (Cmd+V) в поле ввода — браузер ограничил прямое чтение буфера.",
    "banner.sessionReset": "Сессия очищена в 0: тексты и словарь замен удалены из памяти.",
    "banner.downloaded": "Файл сохранён на ваше устройство.",
    "banner.presetLoaded": "Загружен пример «{title}».",
    "banner.presetRulesAdded":
      "Добавлено правил: {count} — теперь имена и названия тоже скрыты.",
    "banner.fileLoaded": "Файл «{name}» открыт в памяти вкладки.",
    "banner.fileUnsupported":
      "Формат «{ext}» не поддерживается. Выберите .txt, .md, .csv, .json, .log или .env.",
    "banner.fileTooLarge": "Файл «{name}» превышает ограничение 2 МБ.",
    "banner.fileReadError": "Не удалось прочитать файл «{name}».",
    "banner.storageWarning":
      "Хранилище устройства заполнено или заблокировано — изменения сохраняются только в памяти вкладки.",
    "banner.auditWriteError": "Не удалось записать событие в журнал.",
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
    "proof.title": "Клиентская проверка конфиденциальности (Zero-Retention Proof)",
    "proof.subtitle":
      "Живая проверка изоляции страницы в реальном времени без единого сетевого запроса.",
    "proof.runBtn": "Запустить самопроверку",
    "proof.resetBtn": "Сбросить сессию в 0",
    "proof.statusPass": "Подтверждено: 0 хранения и 0 утечек текста",
    "proof.statusWarn": "Обнаружено отклонение — проверьте детали ниже",
    "proof.checkedAt": "Проверено: {time}",
    "proof.netTitle": "Передача текста на сервер и политика CSP",
    "proof.netMetric": "{count} запросов",
    "proof.netDetail":
      "Внешних сетевых запросов: {ext}, запросов текста к серверу: {count}, нарушений CSP: {cspViolations}. Активна политика {policy}.",
    "proof.storageTitle": "Сохранённые тексты и реквизиты на сайте",
    "proof.storageMetric": "{bytes} байт",
    "proof.storageDetail":
      "sessionStorage: {sessionKeys} ключей, cookies: {cookies}, неизвестные ключи: {unknownKeys}. В хранилище настроек хранятся только ваши правила/язык/SHA-256 ({prefKeys} служебных ключа без исходных текстов).",
    "proof.trackersTitle": "Рекламные трекеры, аналитика и транспорт",
    "proof.trackersMetricHttps": "{trackers} трекеров • HTTPS / TLS",
    "proof.trackersMetricLocal": "{trackers} трекеров • Локальный стенд",
    "proof.trackersMetricHttp": "{trackers} трекеров • Проверить TLS",
    "proof.trackersDetail":
      "Сторонних скриптов и счётчиков аналитики: {trackers}. Режим соединения: {transport}.",
    "proof.transportHttps": "защищённый канал HTTPS / TLS",
    "proof.transportLocal": "локальный тестовый стенд (127.0.0.1 / localhost)",
    "proof.transportHttp": "незащищённый HTTP (для публичного запуска включите HTTPS)",
    "proof.ramNote":
      "Оперативная память текущей вкладки (очищается при закрытии/перезагрузке или кнопкой «Сбросить сессию в 0»): символов текста — {chars}, активных замен — {entities}.",
    "pricing.title": "Тарифы",
    "pricing.subtitle":
      "Весь базовый функционал сервиса полностью бесплатен и открыт для старта.",
    "pricing.toggleAria": "Период оплаты",
    "pricing.toggleMonth": "Месяц",
    "pricing.toggleYear": "Год −20%",
    "pricing.periodMonth": "/ мес",
    "pricing.noteFree": "Открыт без регистрации и карты",
    "pricing.noteYearDiscount": "При оплате за год (−20%)",
    "pricing.noteMonthly": "Помесячная оплата",
    "pricing.noteTeamSeats": "до 10 человек",
    "pricing.noteTeamYear": "до 10 человек • при оплате за год (−20%)",
    "pricing.freeName": "Старт (Free)",
    "pricing.freeBadge": "Активен сейчас",
    "pricing.freePrice": "0 ₽",
    "pricing.freeFeat1": "Полная защита текстов и файлов до 2 МБ (11 категорий)",
    "pricing.freeFeat2": "Возврат данных в ответ ИИ в 1 клик",
    "pricing.freeFeat3": "Свои слова-исключения и экспорт правил",
    "pricing.freeFeat4": "Живая проверка «0 хранения» и сброс сессии в 0",
    "pricing.freeCta": "Пользоваться бесплатно",
    "pricing.proName": "Pro",
    "pricing.proBadge": "Ранний доступ",
    "pricing.proPriceMonth": "490 ₽",
    "pricing.proPriceYear": "390 ₽",
    "pricing.proFeat1": "Пакетная обработка .docx, .pdf, .xlsx до 50 МБ",
    "pricing.proFeat2": "Расширение для браузера поверх ChatGPT / Claude / DeepSeek",
    "pricing.proFeat3": "Отдельные профили правил под рабочие проекты",
    "pricing.proFeat4": "Авто-распознавание реквизитов РФ/СНГ (ИНН, СНИЛС, паспорт)",
    "pricing.proCta": "Ранний доступ • 30 дней бесплатно",
    "pricing.teamName": "Бизнес / Команда",
    "pricing.teamBadge": "Для команд",
    "pricing.teamPriceMonth": "1 990 ₽",
    "pricing.teamPriceYear": "1 590 ₽",
    "pricing.teamFeat1": "Общий корпоративный словарь NDA-терминов",
    "pricing.teamFeat2": "Брендированные сертификаты проверки для ИБ (152-ФЗ / GDPR)",
    "pricing.teamFeat3": "Единый вход (SSO) и управление ролями",
    "pricing.teamFeat4": "Приоритетная поддержка и помощь с внедрением",
    "pricing.teamCta": "Оставить корпоративную заявку",
    "request.proTitle": "Ранний доступ к PromptVeil Pro",
    "request.proSubtitle": "Предзаказ: 30 дней бесплатно после запуска без сбора текстов промптов.",
    "request.teamTitle": "Корпоративная заявка — Бизнес / Команда",
    "request.teamSubtitle": "Подключение команды, единый словарь терминов и отчётность для ИБ.",
    "request.privacyNote":
      "Полностью клиентская форма: никаких сетевых запросов и сбора ваших промптов. Готовый текст заявки формируется на вашем устройстве.",
    "request.nameLabel": "Имя или компания",
    "request.namePlaceholder": "Например: Алексей или ООО «Вектор»",
    "request.contactLabel": "Эл. почта или Telegram для связи",
    "request.contactPlaceholder": "name@company.ru или @username",
    "request.seatsLabel": "Размер команды (чел.)",
    "request.noteLabel": "Комментарий (необязательно)",
    "request.notePlaceholder": "Какие форматы файлов или требования ИБ актуальны?",
    "request.submitBtn": "Сформировать заявку",
    "request.errorName": "Укажите имя или название компании.",
    "request.errorContact": "Укажите корректную эл. почту или @ник в Telegram.",
    "request.errorSeats": "Укажите количество участников от 1 до 5000.",
    "request.resultTitle": "Готовая заявка (без отправки с сайта):",
    "request.copyBtn": "Скопировать заявку",
    "request.mailtoBtn": "Открыть в почтовом клиенте",
    "request.summaryPlan": "Тариф",
    "request.summaryBilling": "Оплата",
    "request.summaryName": "Имя / компания",
    "request.summaryContact": "Контакт",
    "request.summarySeats": "Команда",
    "request.summaryNote": "Комментарий",
    "request.mailSubjectPro": "Заявка на ранний доступ PromptVeil Pro",
    "request.mailSubjectTeam": "Корпоративная заявка PromptVeil Team",
    "footer.brandDesc":
      "Инструмент защиты персональных и корпоративных данных перед работой с нейросетями.",
    "footer.navWorkbench": "Рабочая область",
    "footer.navPricing": "Тарифы",
    "footer.privacyPolicyBtn": "Политика конфиденциальности",
    "footer.trustHeading": "Архитектура доверия",
    "footer.badgeTls": "HTTPS / TLS",
    "footer.badgeZero": "Zero-Retention (0 логов)",
    "footer.badgeCsp": "Strict CSP",
    "footer.badgeNoTrack": "Без cookies и трекеров",
    "footer.contactsHeading": "Контакты и связь",
    "footer.telegramLabel": "Telegram",
    "footer.emailLabel": "Эл. почта / Поддержка",
    "footer.githubLabel": "GitHub",
    "footer.copyright": "© 2026 PromptVeil • Автор проекта: {author}",
    "footer.zeroNote": "Никаких cookies, рекламных трекеров и серверных логов промптов.",
    "policy.title": "Краткая политика конфиденциальности",
    "policy.subtitle": "Прозрачные принципы работы с текстом и настройками.",
    "policy.item1Title": "1. Нулевое хранение текстов и секретов",
    "policy.item1Body":
      "Исходный текст, ответ ИИ и таблица временных замен существуют только в оперативной памяти текущей вкладки и очищаются при сбросе или закрытии страницы.",
    "policy.item2Title": "2. Нулевая сетевая передача",
    "policy.item2Body":
      "Политика безопасности CSP (connect-src 'self') технически блокирует любые сторонние запросы. Тексты не передаются на сервер или в аналитику.",
    "policy.item3Title": "3. Что хранится локально по желанию",
    "policy.item3Body":
      "В настройках устройства могут сохраняться выбранный язык, список ваших слов-исключений и журнал цифровых отпечатков (SHA-256 без исходного текста), которые можно удалить в любой момент.",
    "policy.item4Title": "4. Контакты владельца проекта",
    "policy.item4Body":
      "По вопросам безопасности, поддержки и сотрудничества: {email} или Telegram {telegram}.",
  },
  en: {
    "meta.title": "PromptVeil — Hide Sensitive Data Before AI",
    "a11y.skipLink": "Skip to workbench",
    "brand.name": "PromptVeil",
    "proof.triggerLabel": "Zero-Retention • Verify",
    "proof.triggerTitle": "Open live client-side Zero-Retention Proof",
    "lang.switchAria": "Language switcher",
    "nav.pricing": "Pricing",
    "nav.resetSession": "Reset session to 0",
    "hero.title": "Protect private details before sending text to AI",
    "hero.subtitle":
      "Paste a message, contract, or code snippet — contacts, cards, and secrets are masked in tab RAM and restored cleanly in the AI reply.",
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
    "action.paste": "Paste",
    "action.copy": "Copy",
    "step1.inputHeading": "Original text",
    "step1.inputPlaceholder":
      "Paste a message, contract, resume, or code snippet...",
    "step1.uploadBtn": "Load file",
    "step1.fileLoading": "Reading file...",
    "step1.clearBtn": "Clear",
    "step1.autoToggle": "Hide automatically",
    "step1.sanitizeNowBtn": "Hide data",
    "step1.outputHeading": "Safe text for AI",
    "step1.outputEmpty":
      "Your safe version with placeholder tags will appear here.",
    "step1.outputHint": "Mappings stay only in volatile tab RAM.",
    "step1.copyBtn": "Copy for AI",
    "step1.downloadBtn": "Download .txt",
    "step1.copyGoStep2Btn": "Copy & Go to Step 2 →",
    "step1.goStep2Btn": "Go to Step 2 →",
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
    "step2.inputHint": "Single-pass substitution runs in tab RAM.",
    "step2.restoreBtn": "Restore original data",
    "step2.clearBtn": "Clear",
    "step2.vaultReady": "Session mappings: {count}",
    "step2.outputHeading": "Final text with your data",
    "step2.outputEmpty":
      "The AI reply with your original names, contacts, and numbers restored will appear here.",
    "step2.outputHint": "Restoration runs in volatile tab RAM.",
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
      "SHA-256 digests are computed on your device. Raw text, secrets, and mappings are never stored.",
    "audit.exportBtn": "Export (.json)",
    "audit.clearBtn": "Clear history",
    "audit.empty": "No history entries yet.",
    "audit.confirmClear": "Clear all verification history?",
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
    "banner.copyFailed": "Clipboard access restricted — use Ctrl+C / Cmd+C.",
    "banner.pasted": "Pasted from clipboard.",
    "banner.clipboardEmpty": "Clipboard is empty.",
    "banner.pasteFallback":
      "Press Ctrl+V (Cmd+V) in the input field — browser restricted direct clipboard read.",
    "banner.sessionReset": "Session reset to 0: text and replacement vault scrubbed from RAM.",
    "banner.downloaded": "File saved locally.",
    "banner.presetLoaded": 'Loaded example "{title}".',
    "banner.presetRulesAdded":
      "Added {count} word rule(s) — names and companies are now masked too.",
    "banner.fileLoaded": 'Opened "{name}" in tab RAM.',
    "banner.fileUnsupported":
      'Unsupported format "{ext}". Allowed: .txt, .md, .csv, .json, .log, .env.',
    "banner.fileTooLarge": 'File "{name}" exceeds the 2 MB limit.',
    "banner.fileReadError": 'Failed to read "{name}".',
    "banner.storageWarning":
      "Device storage is full or blocked; keeping changes in tab RAM only.",
    "banner.auditWriteError": "Unable to store history entry.",
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
    "proof.title": "Client-Side Privacy Check (Zero-Retention Proof)",
    "proof.subtitle":
      "Live real-time isolation audit with zero outbound network requests.",
    "proof.runBtn": "Run live self-test",
    "proof.resetBtn": "Reset session to 0",
    "proof.statusPass": "Verified: 0 retention and 0 text egress",
    "proof.statusWarn": "Attention needed — inspect details below",
    "proof.checkedAt": "Verified: {time}",
    "proof.netTitle": "Server text transmission & CSP policy",
    "proof.netMetric": "{count} requests",
    "proof.netDetail":
      "External requests: {ext}, server text calls: {count}, CSP violations: {cspViolations}. Active policy: {policy}.",
    "proof.storageTitle": "Stored text & secrets on site",
    "proof.storageMetric": "{bytes} bytes",
    "proof.storageDetail":
      "sessionStorage: {sessionKeys} keys, cookies: {cookies}, unknown keys: {unknownKeys}. Preference storage holds only your rules/language/SHA-256 digests ({prefKeys} non-PII keys).",
    "proof.trackersTitle": "Ad trackers, analytics & transport",
    "proof.trackersMetricHttps": "{trackers} trackers • HTTPS / TLS",
    "proof.trackersMetricLocal": "{trackers} trackers • Local host",
    "proof.trackersMetricHttp": "{trackers} trackers • Check TLS",
    "proof.trackersDetail":
      "Third-party scripts and analytics counters: {trackers}. Transport: {transport}.",
    "proof.transportHttps": "encrypted HTTPS / TLS",
    "proof.transportLocal": "local verification host (127.0.0.1 / localhost)",
    "proof.transportHttp": "unencrypted HTTP (enable HTTPS for public launch)",
    "proof.ramNote":
      "Volatile tab RAM (cleared on reload/close or via Reset to 0): text chars — {chars}, active mappings — {entities}.",
    "pricing.title": "Pricing",
    "pricing.subtitle":
      "All core data masking and restoration tools are 100% free and open.",
    "pricing.toggleAria": "Billing cycle",
    "pricing.toggleMonth": "Month",
    "pricing.toggleYear": "Year −20%",
    "pricing.periodMonth": "/ mo",
    "pricing.noteFree": "Open immediately with no account",
    "pricing.noteYearDiscount": "Billed annually (−20%)",
    "pricing.noteMonthly": "Monthly billing",
    "pricing.noteTeamSeats": "up to 10 seats",
    "pricing.noteTeamYear": "up to 10 seats • billed annually (−20%)",
    "pricing.freeName": "Start (Free)",
    "pricing.freeBadge": "Active now",
    "pricing.freePrice": "$0",
    "pricing.freeFeat1": "Full text & file masking up to 2 MB (11 categories)",
    "pricing.freeFeat2": "1-click AI reply restoration",
    "pricing.freeFeat3": "Custom exclusion rules & JSON export",
    "pricing.freeFeat4": "Live Zero-Retention Proof & instant reset to 0",
    "pricing.freeCta": "Use for free",
    "pricing.proName": "Pro",
    "pricing.proBadge": "Early Access",
    "pricing.proPriceMonth": "$6",
    "pricing.proPriceYear": "$5",
    "pricing.proFeat1": "Batch .docx, .pdf, .xlsx processing up to 50 MB",
    "pricing.proFeat2": "Browser extension overlay for ChatGPT / Claude / DeepSeek",
    "pricing.proFeat3": "Dedicated rule profiles per client project",
    "pricing.proFeat4": "Extended regional ID patterns & smart presets",
    "pricing.proCta": "Early Access • 30 days free",
    "pricing.teamName": "Business / Team",
    "pricing.teamBadge": "For Teams",
    "pricing.teamPriceMonth": "$24",
    "pricing.teamPriceYear": "$19",
    "pricing.teamFeat1": "Shared corporate NDA term dictionary",
    "pricing.teamFeat2": "Branded security audit certificates (152-FZ / GDPR)",
    "pricing.teamFeat3": "Single Sign-On (SSO) & role management",
    "pricing.teamFeat4": "Priority onboarding & security support",
    "pricing.teamCta": "Submit Team Request",
    "request.proTitle": "Early Access to PromptVeil Pro",
    "request.proSubtitle": "30-day free pre-order trial with zero prompt collection.",
    "request.teamTitle": "Team Request — Business / Team",
    "request.teamSubtitle": "Team onboarding, shared dictionary, and compliance certificates.",
    "request.privacyNote":
      "100% client-side form: zero network requests and zero prompt collection. Your request summary is generated on your device.",
    "request.nameLabel": "Name or company",
    "request.namePlaceholder": "e.g. Alex or Acme Corp",
    "request.contactLabel": "Email or Telegram handle",
    "request.contactPlaceholder": "name@company.com or @username",
    "request.seatsLabel": "Team size (seats)",
    "request.noteLabel": "Note (optional)",
    "request.notePlaceholder": "Which file formats or compliance workflows do you need?",
    "request.submitBtn": "Generate request",
    "request.errorName": "Enter your name or company.",
    "request.errorContact": "Enter a valid email or @Telegram handle.",
    "request.errorSeats": "Enter a team size between 1 and 5000.",
    "request.resultTitle": "Ready-to-send request (0 bytes transmitted):",
    "request.copyBtn": "Copy request",
    "request.mailtoBtn": "Open in mail client",
    "request.summaryPlan": "Plan",
    "request.summaryBilling": "Billing",
    "request.summaryName": "Name / Company",
    "request.summaryContact": "Contact",
    "request.summarySeats": "Seats",
    "request.summaryNote": "Note",
    "request.mailSubjectPro": "PromptVeil Pro Early Access Request",
    "request.mailSubjectTeam": "PromptVeil Business / Team Request",
    "footer.brandDesc":
      "Privacy-first masking and restoration workspace for everyday AI workflows.",
    "footer.navWorkbench": "Workbench",
    "footer.navPricing": "Pricing",
    "footer.privacyPolicyBtn": "Privacy Policy",
    "footer.trustHeading": "Trust Architecture",
    "footer.badgeTls": "HTTPS / TLS",
    "footer.badgeZero": "Zero-Retention (0 logs)",
    "footer.badgeCsp": "Strict CSP",
    "footer.badgeNoTrack": "Zero cookies & trackers",
    "footer.contactsHeading": "Contacts & Support",
    "footer.telegramLabel": "Telegram",
    "footer.emailLabel": "Email / Support",
    "footer.githubLabel": "GitHub",
    "footer.copyright": "© 2026 PromptVeil • Created by {author}",
    "footer.zeroNote": "Zero cookies, zero ad trackers, and zero server prompt logs.",
    "policy.title": "Privacy Policy Summary",
    "policy.subtitle": "Clear rules on how your text and preferences are handled.",
    "policy.item1Title": "1. Zero retention of text & secrets",
    "policy.item1Body":
      "Original text, AI replies, and active replacement mappings live exclusively in volatile tab RAM and are cleared on reset or page close.",
    "policy.item2Title": "2. Zero network transmission",
    "policy.item2Body":
      "Strict CSP (connect-src 'self') technically prevents third-party requests. Text is never uploaded or sent to analytics.",
    "policy.item3Title": "3. Optional device preferences",
    "policy.item3Body":
      "Language choice, custom exclusion rules, and SHA-256 hash-only verification receipts may be stored on your device and cleared anytime.",
    "policy.item4Title": "4. Project owner contacts",
    "policy.item4Body":
      "For security, support, or partnerships: {email} or Telegram {telegram}.",
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
