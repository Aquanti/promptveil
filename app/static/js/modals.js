/**
 * PromptVeil Modals, Zero-Retention Proof Renderer, Theme Switcher, Contacts & SW Registration.
 */

import { copyWithFeedback } from "./clipboard.js";
import { SITE_CONTACTS, buildMailtoHref } from "./contacts.js";
import { clearEl, createEl, getEl, handleDrawerKeydown } from "./dom.js";
import { getLang, normalizeLang, pluralizeCount, t } from "./i18n.js";
import { runZeroRetentionSelfTest } from "./privacy-proof.js";
import { closeDrawers, getOpenDialogEl, openDrawer } from "./render-drawers.js";
import { loadThemePreference, saveThemePreference } from "./storage.js";

export const THEME_MOON_PATH = "M16.2 12.6A6.8 6.8 0 0 1 7.4 3.8a7 7 0 1 0 8.8 8.8Z";
export const THEME_SUN_PATH =
  "M10 2.5v2M10 15.5v2M2.5 10h2M15.5 10h2M4.7 4.7l1.4 1.4M13.9 13.9l1.4 1.4M15.3 4.7l-1.4 1.4M6.1 13.9l-1.4 1.4M13 10a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z";

export function resolveInitialTheme() {
  const saved = loadThemePreference();
  if (saved) return saved;
  try {
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      return "dark";
    }
  } catch {
    // Ignore matchMedia unavailability.
  }
  return "light";
}

export function updateThemeToggleButton(theme, lang = getLang()) {
  const btn = getEl("theme-toggle-btn");
  if (!btn) return;
  const isDark = theme === "dark";
  const key = isDark ? "theme.toLight" : "theme.toDark";
  const label = t(key, {}, lang);
  btn.setAttribute("aria-pressed", isDark ? "true" : "false");
  btn.setAttribute("data-i18n-aria", key);
  btn.setAttribute("data-i18n-title", key);
  btn.setAttribute("aria-label", label);
  btn.setAttribute("title", label);
  const pathEl = btn.querySelector("path");
  if (pathEl) {
    pathEl.setAttribute("d", isDark ? THEME_SUN_PATH : THEME_MOON_PATH);
  }
}

export function applyTheme(nextTheme, state, { persist = false } = {}) {
  const normalized = nextTheme === "dark" ? "dark" : "light";
  state.theme = persist ? saveThemePreference(normalized) : normalized;
  if (typeof document !== "undefined") {
    document.documentElement.dataset.theme = state.theme;
  }
  updateThemeToggleButton(state.theme, state.lang || getLang());
  return state.theme;
}

export function formatProofTime(isoString, lang) {
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return isoString;
  const locale = lang === "en" ? "en-US" : "ru-RU";
  try {
    return new Intl.DateTimeFormat(locale, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(date);
  } catch {
    return date.toLocaleTimeString(locale);
  }
}

export function renderPrivacyProofModal(state, lang = getLang()) {
  const report = runZeroRetentionSelfTest({
    rawText: state.rawText,
    llmReply: state.llmReply,
    vault: state.vault,
  });

  const summaryCard = getEl("proof-summary-card");
  const summaryStatus = getEl("proof-summary-status");
  const checkedAtEl = getEl("proof-checked-at");
  const listEl = getEl("proof-checks-list");
  const ramNoteEl = getEl("proof-ram-note");

  if (summaryCard) {
    summaryCard.classList.toggle("proof-summary-card--warn", !report.allPassed);
  }
  if (summaryStatus) {
    summaryStatus.textContent = t(
      report.allPassed ? "proof.statusPass" : "proof.statusWarn",
      {},
      lang
    );
  }
  if (checkedAtEl) {
    checkedAtEl.textContent = t(
      "proof.checkedAt",
      { time: formatProofTime(report.checkedAt, lang) },
      lang
    );
  }

  if (listEl) {
    clearEl(listEl);

    const isEn = normalizeLang(lang) === "en";
    const trackerUnit = pluralizeCount(
      lang,
      report.trackers.trackerCount,
      isEn
        ? { one: "tracker", many: "trackers" }
        : { one: "трекер", few: "трекера", many: "трекеров" }
    );
    const netUnit = pluralizeCount(
      lang,
      report.network.textRequests,
      isEn
        ? { one: "request", many: "requests" }
        : { one: "запрос", few: "запроса", many: "запросов" }
    );
    const bytesUnit = pluralizeCount(
      lang,
      report.storage.storedTextBytes,
      isEn
        ? { one: "byte", many: "bytes" }
        : { one: "байт", few: "байта", many: "байт" }
    );
    const sessionUnit = pluralizeCount(
      lang,
      report.storage.sessionStorageKeys,
      isEn
        ? { one: "key", many: "keys" }
        : { one: "ключ", few: "ключа", many: "ключей" }
    );
    const prefUnit = pluralizeCount(
      lang,
      report.storage.allowedPrefKeysPresent,
      isEn
        ? { one: "non-PII key", many: "non-PII keys" }
        : { one: "служебный ключ", few: "служебных ключа", many: "служебных ключей" }
    );

    const transportText = report.trackers.isHttps
      ? t("proof.transportHttps", {}, lang)
      : report.trackers.isLocalStand
        ? t("proof.transportLocal", {}, lang)
        : t("proof.transportHttp", {}, lang);
    const trackersBadge = report.trackers.isHttps
      ? t("proof.trackersMetricHttps", { trackers: report.trackers.trackerCount, unit: trackerUnit }, lang)
      : report.trackers.isLocalStand
        ? t("proof.trackersMetricLocal", { trackers: report.trackers.trackerCount, unit: trackerUnit }, lang)
        : t("proof.trackersMetricHttp", { trackers: report.trackers.trackerCount, unit: trackerUnit }, lang);

    const rows = [
      {
        ok: report.network.ok,
        title: t("proof.netTitle", {}, lang),
        metric: t("proof.netMetric", { count: report.network.textRequests, unit: netUnit }, lang),
        detail: t(
          "proof.netDetail",
          {
            ext: report.network.externalResourceCount,
            count: report.network.textRequests,
            cspViolations: report.network.cspViolationCount,
            policy: report.network.cspPolicy,
          },
          lang
        ),
      },
      {
        ok: report.storage.ok,
        title: t("proof.storageTitle", {}, lang),
        metric: t("proof.storageMetric", { bytes: report.storage.storedTextBytes, unit: bytesUnit }, lang),
        detail: t(
          "proof.storageDetail",
          {
            sessionKeys: report.storage.sessionStorageKeys,
            sessionUnit,
            cookies: report.storage.cookieCount,
            unknownKeys: report.storage.unknownStorageKeys,
            prefKeys: report.storage.allowedPrefKeysPresent,
            prefUnit,
          },
          lang
        ),
      },
      {
        ok: report.trackers.ok,
        title: t("proof.trackersTitle", {}, lang),
        metric: trackersBadge,
        detail: t(
          "proof.trackersDetail",
          {
            trackers: report.trackers.trackerCount,
            transport: transportText,
          },
          lang
        ),
      },
    ];

    for (const row of rows) {
      const li = createEl("li", "proof-check-row");
      const top = createEl("div", "proof-check-top");
      top.appendChild(createEl("span", "proof-check-label", row.title));
      top.appendChild(
        createEl(
          "span",
          row.ok
            ? "proof-check-metric tabular-nums"
            : "proof-check-metric proof-check-metric--warn tabular-nums",
          row.metric
        )
      );
      li.appendChild(top);
      li.appendChild(createEl("p", "proof-check-detail", row.detail));
      listEl.appendChild(li);
    }
  }

  if (ramNoteEl) {
    ramNoteEl.textContent = t(
      "proof.ramNote",
      {
        chars: report.ram.ramChars,
        entities: report.ram.ramEntities,
      },
      lang
    );
  }

  const offlineMetricEl = getEl("proof-offline-metric");
  if (offlineMetricEl) {
    const sw = typeof navigator !== "undefined" ? navigator.serviceWorker : null;
    if (!sw) {
      offlineMetricEl.textContent = t("proof.offlineMetricUnsupported", {}, lang);
    } else {
      const hasCtrl = Boolean(sw.controller);
      offlineMetricEl.textContent = t(
        hasCtrl ? "proof.offlineMetricReady" : "proof.offlineMetricPending",
        {},
        lang
      );
      if (typeof sw.getRegistration === "function") {
        sw.getRegistration()
          .then((reg) => {
            const active = Boolean(sw.controller || reg?.active);
            const activeLang = getLang();
            offlineMetricEl.textContent = t(
              active ? "proof.offlineMetricReady" : "proof.offlineMetricPending",
              {},
              activeLang
            );
          })
          .catch(() => {});
      }
    }
  }
}

export function renderContactsAndPolicy(lang = getLang()) {
  const tgEl = getEl("contact-telegram-text");
  const emailLinkEl = getEl("contact-email-link");
  const githubEl = getEl("contact-github-text");
  const copyrightEl = getEl("footer-copyright");
  const policyOwnerEl = getEl("policy-owner-contact-body");
  const termsOwnerEl = getEl("terms-owner-contact-body");

  if (tgEl) tgEl.textContent = SITE_CONTACTS.telegramHandle;
  if (emailLinkEl) {
    emailLinkEl.textContent = SITE_CONTACTS.email;
    emailLinkEl.setAttribute("href", buildMailtoHref(SITE_CONTACTS.email));
  }
  if (githubEl) githubEl.textContent = SITE_CONTACTS.githubDisplay;
  if (copyrightEl) {
    copyrightEl.textContent = t(
      "footer.copyright",
      { author: SITE_CONTACTS.authorSignature },
      lang
    );
  }
  if (policyOwnerEl) {
    policyOwnerEl.textContent = t(
      "policy.item5Body",
      {
        email: SITE_CONTACTS.email,
        telegram: SITE_CONTACTS.telegramHandle,
      },
      lang
    );
  }
  if (termsOwnerEl) {
    termsOwnerEl.textContent = t(
      "terms.item4Body",
      {
        author: SITE_CONTACTS.authorSignature,
        email: SITE_CONTACTS.email,
        telegram: SITE_CONTACTS.telegramHandle,
      },
      lang
    );
  }
}

export function registerOfflineServiceWorker() {
  if (typeof navigator !== "undefined" && "serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }
}

export function bindModalAndThemeEvents({
  state,
  hideInlineAlert,
  showStatusBanner,
  onResetSession,
}) {
  getEl("theme-toggle-btn")?.addEventListener("click", () => {
    applyTheme(state.theme === "dark" ? "light" : "dark", state, { persist: true });
  });

  getEl("open-rulebook-btn")?.addEventListener("click", (event) => {
    hideInlineAlert("rulebook-alert");
    openDrawer("drawer-rulebook", event.currentTarget, state);
  });
  getEl("open-audit-btn")?.addEventListener("click", (event) => {
    openDrawer("drawer-audit", event.currentTarget, state);
  });

  const handleOpenProofModal = (event) => {
    renderPrivacyProofModal(state, getLang());
    openDrawer("modal-privacy-proof", event.currentTarget, state);
  };
  getEl("open-proof-btn")?.addEventListener("click", handleOpenProofModal);
  getEl("footer-open-proof-btn")?.addEventListener("click", handleOpenProofModal);
  getEl("run-proof-check-btn")?.addEventListener("click", () => {
    renderPrivacyProofModal(state, getLang());
  });
  getEl("reset-session-btn")?.addEventListener("click", onResetSession);

  getEl("open-privacy-policy-btn")?.addEventListener("click", (event) => {
    renderContactsAndPolicy(getLang());
    openDrawer("modal-privacy-policy", event.currentTarget, state);
  });
  getEl("open-terms-btn")?.addEventListener("click", (event) => {
    renderContactsAndPolicy(getLang());
    openDrawer("modal-terms", event.currentTarget, state);
  });

  const closeIds = [
    "close-rulebook-btn",
    "close-audit-btn",
    "close-proof-btn",
    "close-proof-footer-btn",
    "close-plan-modal-btn",
    "close-policy-modal-btn",
    "close-policy-footer-btn",
    "close-terms-modal-btn",
    "close-terms-footer-btn",
    "drawer-backdrop",
  ];
  for (const id of closeIds) {
    getEl(id)?.addEventListener("click", () => {
      hideInlineAlert("rulebook-alert");
      closeDrawers(true, state);
    });
  }

  const contactCopyTargets = [
    ["copy-contact-telegram-btn", SITE_CONTACTS.telegramHandle],
    ["copy-contact-email-btn", SITE_CONTACTS.email],
    ["copy-contact-github-btn", SITE_CONTACTS.githubDisplay],
  ];
  for (const [btnId, value] of contactCopyTargets) {
    getEl(btnId)?.addEventListener("click", async () => {
      await copyWithFeedback({
        text: value,
        buttonEl: getEl(btnId),
        resetLabelGetter: () => t("action.copy"),
        showStatusBanner,
      });
    });
  }

  document.addEventListener("keydown", (event) => {
    const openDialogEl = getOpenDialogEl();
    handleDrawerKeydown(event, openDialogEl, () => {
      hideInlineAlert("rulebook-alert");
      closeDrawers(true, state);
    });
  });
}
