/**
 * PromptVeil Modals, Lazy <template> Hydration, Zero-Retention Proof Renderer, Theme Switcher, Contacts & SW Registration.
 */

import { copyWithFeedback } from "./clipboard.js";
import { SITE_CONTACTS, buildMailtoHref } from "./contacts.js";
import { clearEl, createEl, getEl, handleDrawerKeydown } from "./dom.js";
import { applyTranslationsToRoot, getLang, normalizeLang, pluralizeCount, t } from "./i18n.js";
import { runZeroRetentionSelfTest } from "./privacy-proof.js";
import {
  activateProLicense,
  createFreeLicenseState,
  deactivateProLicense,
} from "./pro-license.js";
import { closeDrawers, getOpenDialogEl, openDrawer } from "./render-drawers.js";
import { loadThemePreference, saveThemePreference } from "./storage.js";

export const THEME_MOON_PATH = "M16.2 12.6A6.8 6.8 0 0 1 7.4 3.8a7 7 0 1 0 8.8 8.8Z";
export const THEME_SUN_PATH =
  "M10 2.5v2M10 15.5v2M2.5 10h2M15.5 10h2M4.7 4.7l1.4 1.4M13.9 13.9l1.4 1.4M15.3 4.7l-1.4 1.4M6.1 13.9l-1.4 1.4M13 10a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z";

const modalHydrators = new Map();

export function registerModalHydrator(modalId, bindFn) {
  modalHydrators.set(modalId, bindFn);
}

export function ensureModalMounted(modalId) {
  if (typeof document === "undefined") {
    return null;
  }
  let modalEl = getEl(modalId);
  if (!modalEl) {
    const tpl = getEl(`tpl-${modalId}`);
    if (!tpl || !("content" in tpl) || !document.body) {
      return null;
    }
    const fragment = document.importNode(tpl.content, true);
    document.body.appendChild(fragment);
    modalEl = getEl(modalId);
  }
  if (modalEl) {
    applyTranslationsToRoot(modalEl, getLang());
    if (modalEl.dataset?.boundModal !== "1") {
      if (modalEl.dataset) {
        modalEl.dataset.boundModal = "1";
      }
      modalHydrators.get(modalId)?.(modalEl);
    }
  }
  return modalEl;
}

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
  const planEmailDirectEl = getEl("plan-req-email-direct");
  const planTgHandleEl = getEl("plan-req-tg-handle");
  const copyrightEl = getEl("footer-copyright");
  const policyOwnerEl = getEl("policy-owner-contact-body");
  const termsOwnerEl = getEl("terms-owner-contact-body");

  if (tgEl) tgEl.textContent = SITE_CONTACTS.telegramHandle;
  if (emailLinkEl) {
    emailLinkEl.textContent = SITE_CONTACTS.email;
    emailLinkEl.setAttribute("href", buildMailtoHref(SITE_CONTACTS.email));
  }
  if (githubEl) githubEl.textContent = SITE_CONTACTS.githubDisplay;
  if (planEmailDirectEl) {
    planEmailDirectEl.textContent = SITE_CONTACTS.email;
    planEmailDirectEl.setAttribute("href", buildMailtoHref(SITE_CONTACTS.email));
  }
  if (planTgHandleEl) planTgHandleEl.textContent = SITE_CONTACTS.telegramHandle;
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
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) {
    return;
  }

  let waitingWorker = null;
  let registrationRef = null;
  let swUpdateRequested = false;
  let reloading = false;

  const showSwUpdateBanner = (worker) => {
    if (worker) {
      waitingWorker = worker;
    }
    const banner = getEl("sw-update-banner");
    if (!banner) return;
    applyTranslationsToRoot(banner, getLang());
    const updateBtn = getEl("sw-update-btn");
    if (updateBtn) {
      updateBtn.disabled = false;
    }
    banner.hidden = false;
  };

  const updateBtn = getEl("sw-update-btn");
  if (updateBtn && updateBtn.dataset.boundSw !== "1") {
    updateBtn.dataset.boundSw = "1";
    updateBtn.addEventListener("click", () => {
      swUpdateRequested = true;
      updateBtn.disabled = true;
      const targetWorker = waitingWorker || registrationRef?.waiting;
      if (targetWorker && targetWorker.state !== "redundant") {
        targetWorker.postMessage({ type: "SKIP_WAITING" });
      } else {
        window.location.reload();
      }
    });
  }

  const dismissBtn = getEl("sw-update-dismiss-btn");
  if (dismissBtn && dismissBtn.dataset.boundSw !== "1") {
    dismissBtn.dataset.boundSw = "1";
    dismissBtn.addEventListener("click", () => {
      const banner = getEl("sw-update-banner");
      if (banner) {
        banner.hidden = true;
      }
    });
  }

  if (typeof navigator.serviceWorker.addEventListener === "function") {
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      if (swUpdateRequested && !reloading) {
        reloading = true;
        window.location.reload();
      }
    });
  }

  navigator.serviceWorker
    .register("/sw.js")
    .then((reg) => {
      registrationRef = reg;
      if (reg.waiting && (navigator.serviceWorker.controller || reg.active)) {
        showSwUpdateBanner(reg.waiting);
      }
      reg.addEventListener("updatefound", () => {
        const installing = reg.installing;
        if (!installing) return;
        installing.addEventListener("statechange", () => {
          if (
            installing.state === "installed" &&
            (navigator.serviceWorker.controller || reg.active)
          ) {
            showSwUpdateBanner(installing);
          }
        });
      });
    })
    .catch(() => {});
}

export function formatLicenseDate(isoString, lang) {
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return String(isoString || "");
  const locale = normalizeLang(lang) === "en" ? "en-US" : "ru-RU";
  try {
    return new Intl.DateTimeFormat(locale, {
      year: "numeric",
      month: "short",
      day: "numeric",
    }).format(date);
  } catch {
    return date.toISOString().slice(0, 10);
  }
}

export function renderProLicenseStatusCard(licenseState, lang = getLang()) {
  const card = getEl("pro-license-status-card");
  if (!card) return;
  clearEl(card);

  const lic = licenseState || createFreeLicenseState("none");
  const isPro = Boolean(lic.isPro);
  const isOwner = Boolean(lic.isOwner);
  card.classList.toggle("is-active", isPro);
  card.classList.toggle("is-owner", isOwner);

  const titleKey = isOwner
    ? "pro.statusTitleOwner"
    : isPro
      ? "pro.statusTitlePro"
      : "pro.statusTitleFree";
  card.appendChild(createEl("div", "pro-license-status-title", t(titleKey, {}, lang)));

  if (!isPro) {
    card.appendChild(createEl("p", "pro-license-status-desc", t("pro.statusDescFree", {}, lang)));
    return;
  }

  const metaList = createEl("ul", "pro-license-meta-list");
  const tierName = isOwner ? "Owner Pro" : "Pro";
  const expText = lic.exp
    ? t("pro.metaExp", { date: formatLicenseDate(lic.exp, lang) }, lang)
    : t("pro.metaExpNever", {}, lang);
  const rows = [
    t("pro.metaTier", { tier: tierName }, lang),
    t("pro.metaKeyId", { keyId: lic.keyId }, lang),
    t("pro.metaLabel", { label: lic.label }, lang),
    t("pro.metaIssuedAt", { date: formatLicenseDate(lic.issuedAt, lang) }, lang),
    expText,
  ];
  for (const rowText of rows) {
    metaList.appendChild(createEl("li", "pro-license-meta-item", rowText));
  }
  card.appendChild(metaList);
}

export function syncProUiState(state, lang = getLang()) {
  const lic = state?.proLicense || createFreeLicenseState("none");
  const isPro = Boolean(lic.isPro);
  const isOwner = Boolean(lic.isOwner);
  const proStateAttr = isOwner ? "owner" : isPro ? "pro" : "free";

  const headerBtn = getEl("open-pro-license-btn");
  if (headerBtn) {
    headerBtn.dataset.proState = proStateAttr;
    headerBtn.classList.toggle("is-pro", isPro && !isOwner);
    headerBtn.classList.toggle("is-owner", isOwner);
    headerBtn.textContent = t(
      isOwner ? "pro.badgeOwner" : isPro ? "pro.badgePro" : "pro.badgeFree",
      {},
      lang
    );
    headerBtn.setAttribute("aria-label", t("pro.badgeAria", {}, lang));
  }

  const proCard = document.querySelector('[data-testid="pricing-card-pro"]');
  if (proCard) {
    proCard.classList.toggle("pricing-card--pro-unlocked", isPro);
  }
  const proBadge = getEl("pricing-pro-badge");
  if (proBadge) {
    proBadge.textContent = t(
      isOwner ? "pricing.proBadgeOwner" : isPro ? "pricing.proBadgeActive" : "pricing.proBadge",
      {},
      lang
    );
  }
  const proValue = getEl("price-pro-value");
  if (proValue) {
    proValue.textContent = t(
      isPro ? "pricing.proActiveTitle" : "pricing.proWaitlistTitle",
      {},
      lang
    );
  }
  const proNote = getEl("price-pro-note");
  if (proNote) {
    proNote.textContent = isPro
      ? t("pricing.proActiveNote", { keyId: lic.keyId }, lang)
      : t("pricing.proWaitlistNote", {}, lang);
  }
  const unlockedNote = getEl("pricing-pro-unlocked-note");
  if (unlockedNote) {
    unlockedNote.hidden = !isPro;
    unlockedNote.textContent = isPro ? `${lic.label} • ${lic.keyId}` : "";
  }
  const activateCardBtn = getEl("pricing-activate-pro-btn");
  if (activateCardBtn) {
    activateCardBtn.textContent = t(
      isPro ? "pricing.proManageCta" : "pricing.proActivateCta",
      {},
      lang
    );
  }

  renderProLicenseStatusCard(lic, lang);
  const removeBtn = getEl("pro-license-remove-btn");
  if (removeBtn) {
    removeBtn.disabled = !isPro;
  }

  const openDownloadsBtn = getEl("open-pro-downloads-btn");
  if (openDownloadsBtn) {
    openDownloadsBtn.hidden = !isPro;
    if (!isPro) {
      openDownloadsBtn.setAttribute("aria-expanded", "false");
    }
  }
  const licenseDownloadsBtn = getEl("pro-license-downloads-btn");
  if (licenseDownloadsBtn) {
    licenseDownloadsBtn.hidden = !isPro;
  }
  if (!isPro) {
    const downloadsModal = getEl("modal-pro-downloads");
    if (downloadsModal && !downloadsModal.hidden) {
      downloadsModal.hidden = true;
      closeDrawers(false, state);
    }
  }
}

export function openProLicenseModal(triggerEl, state, hideInlineAlert) {
  const downloadsModal = getEl("modal-pro-downloads");
  if (downloadsModal && !downloadsModal.hidden) {
    downloadsModal.hidden = true;
  }
  getEl("open-pro-downloads-btn")?.setAttribute("aria-expanded", "false");
  ensureModalMounted("modal-pro-license");
  hideInlineAlert?.("pro-license-alert");
  syncProUiState(state, getLang());
  openDrawer("modal-pro-license", triggerEl, state);
  getEl("open-pro-license-btn")?.setAttribute("aria-expanded", "true");
}

export function openProDownloadsModal(triggerEl, state) {
  if (!state?.proLicense?.isPro) {
    return null;
  }
  const proModal = getEl("modal-pro-license");
  if (proModal && !proModal.hidden) {
    proModal.hidden = true;
  }
  getEl("open-pro-license-btn")?.setAttribute("aria-expanded", "false");
  const modalEl = ensureModalMounted("modal-pro-downloads");
  openDrawer("modal-pro-downloads", triggerEl, state);
  getEl("open-pro-downloads-btn")?.setAttribute("aria-expanded", "true");
  return modalEl;
}

export function bindModalAndThemeEvents({
  state,
  showInlineAlert,
  hideInlineAlert,
  showStatusBanner,
  onResetSession,
}) {
  const closeActiveDialog = () => {
    hideInlineAlert("rulebook-alert");
    hideInlineAlert?.("pro-license-alert");
    const proModal = getEl("modal-pro-license");
    if (proModal && !proModal.hidden) {
      proModal.hidden = true;
    }
    const downloadsModal = getEl("modal-pro-downloads");
    if (downloadsModal && !downloadsModal.hidden) {
      downloadsModal.hidden = true;
    }
    getEl("open-pro-license-btn")?.setAttribute("aria-expanded", "false");
    getEl("open-pro-downloads-btn")?.setAttribute("aria-expanded", "false");
    closeDrawers(true, state);
  };

  registerModalHydrator("modal-privacy-proof", () => {
    getEl("run-proof-check-btn")?.addEventListener("click", () => {
      renderPrivacyProofModal(state, getLang());
    });
    getEl("reset-session-btn")?.addEventListener("click", onResetSession);
    getEl("close-proof-btn")?.addEventListener("click", closeActiveDialog);
    getEl("close-proof-footer-btn")?.addEventListener("click", closeActiveDialog);
  });

  registerModalHydrator("modal-privacy-policy", () => {
    getEl("close-policy-modal-btn")?.addEventListener("click", closeActiveDialog);
    getEl("close-policy-footer-btn")?.addEventListener("click", closeActiveDialog);
  });

  registerModalHydrator("modal-terms", () => {
    getEl("close-terms-modal-btn")?.addEventListener("click", closeActiveDialog);
    getEl("close-terms-footer-btn")?.addEventListener("click", closeActiveDialog);
  });

  registerModalHydrator("modal-pro-license", () => {
    getEl("close-pro-license-btn")?.addEventListener("click", closeActiveDialog);
    getEl("close-pro-license-footer-btn")?.addEventListener("click", closeActiveDialog);
    getEl("pro-license-downloads-btn")?.addEventListener("click", () => {
      openProDownloadsModal(getEl("open-pro-downloads-btn") || getEl("open-pro-license-btn"), state);
    });
    getEl("pro-license-get-key-btn")?.addEventListener("click", () => {
      const proModal = getEl("modal-pro-license");
      if (proModal) proModal.hidden = true;
      getEl("open-pro-license-btn")?.setAttribute("aria-expanded", "false");
      hideInlineAlert?.("pro-license-alert");
      getEl("open-pro-modal-btn")?.click();
    });
    getEl("pro-license-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      hideInlineAlert?.("pro-license-alert");
      const keyInput = getEl("pro-license-key-input");
      const rawKey = (keyInput?.value || "").trim();
      if (!rawKey) {
        showInlineAlert?.("pro-license-alert", "pro.errorEmpty");
        keyInput?.focus();
        return;
      }
      const result = await activateProLicense(rawKey);
      if (!result.valid) {
        const errKey = result.reason === "expired" ? "pro.errorExpired" : "pro.errorInvalid";
        showInlineAlert?.("pro-license-alert", errKey);
        keyInput?.focus();
        return;
      }
      state.proLicense = result;
      if (keyInput) keyInput.value = "";
      syncProUiState(state, getLang());
      showStatusBanner("pro.activatedSuccess", {
        tier: result.isOwner ? "Owner Pro" : "Pro",
        keyId: result.keyId,
      });
    });
    getEl("pro-license-remove-btn")?.addEventListener("click", () => {
      state.proLicense = deactivateProLicense();
      hideInlineAlert?.("pro-license-alert");
      syncProUiState(state, getLang());
      showStatusBanner("pro.removedSuccess");
    });
  });

  registerModalHydrator("modal-pro-downloads", () => {
    getEl("close-pro-downloads-btn")?.addEventListener("click", closeActiveDialog);
    getEl("close-pro-downloads-footer-btn")?.addEventListener("click", closeActiveDialog);
  });

  getEl("open-pro-license-btn")?.addEventListener("click", (event) => {
    openProLicenseModal(event.currentTarget, state, hideInlineAlert);
  });

  getEl("open-pro-downloads-btn")?.addEventListener("click", (event) => {
    openProDownloadsModal(event.currentTarget, state);
  });

  getEl("theme-toggle-btn")?.addEventListener("click", () => {
    applyTheme(state.theme === "dark" ? "light" : "dark", state, { persist: true });
  });

  getEl("open-rulebook-btn")?.addEventListener("click", (event) => {
    hideInlineAlert("rulebook-alert");
    openDrawer("drawer-rulebook", event.currentTarget, state);
  });
  getEl("limits-open-rulebook-btn")?.addEventListener("click", (event) => {
    hideInlineAlert("rulebook-alert");
    openDrawer("drawer-rulebook", event.currentTarget, state);
  });
  getEl("open-audit-btn")?.addEventListener("click", (event) => {
    openDrawer("drawer-audit", event.currentTarget, state);
  });

  const handleOpenProofModal = (event) => {
    ensureModalMounted("modal-privacy-proof");
    renderPrivacyProofModal(state, getLang());
    openDrawer("modal-privacy-proof", event.currentTarget, state);
  };
  getEl("open-proof-btn")?.addEventListener("click", handleOpenProofModal);
  getEl("footer-open-proof-btn")?.addEventListener("click", handleOpenProofModal);

  getEl("open-privacy-policy-btn")?.addEventListener("click", (event) => {
    ensureModalMounted("modal-privacy-policy");
    renderContactsAndPolicy(getLang());
    openDrawer("modal-privacy-policy", event.currentTarget, state);
  });
  getEl("open-terms-btn")?.addEventListener("click", (event) => {
    ensureModalMounted("modal-terms");
    renderContactsAndPolicy(getLang());
    openDrawer("modal-terms", event.currentTarget, state);
  });

  for (const id of ["close-rulebook-btn", "close-audit-btn", "drawer-backdrop"]) {
    getEl(id)?.addEventListener("click", closeActiveDialog);
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
    const proModal = getEl("modal-pro-license");
    const downloadsModal = getEl("modal-pro-downloads");
    const openDialogEl =
      proModal && !proModal.hidden
        ? proModal
        : downloadsModal && !downloadsModal.hidden
          ? downloadsModal
          : getOpenDialogEl();
    handleDrawerKeydown(event, openDialogEl, closeActiveDialog);
  });

  const setMobileMoreOpen = (open, { restoreFocus = false } = {}) => {
    const btn = getEl("mobile-more-btn");
    const menu = getEl("mobile-more-menu");
    if (!btn || !menu) return;
    menu.hidden = !open;
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    if (!open && restoreFocus) {
      btn.focus();
    }
  };

  getEl("mobile-more-btn")?.addEventListener("click", () => {
    const menu = getEl("mobile-more-menu");
    if (!menu) return;
    setMobileMoreOpen(menu.hidden);
  });
  getEl("mobile-open-rulebook-btn")?.addEventListener("click", () => {
    setMobileMoreOpen(false);
    hideInlineAlert("rulebook-alert");
    openDrawer("drawer-rulebook", getEl("mobile-more-btn"), state);
  });
  getEl("mobile-open-audit-btn")?.addEventListener("click", () => {
    setMobileMoreOpen(false);
    openDrawer("drawer-audit", getEl("mobile-more-btn"), state);
  });
  getEl("mobile-pricing-btn")?.addEventListener("click", () => {
    setMobileMoreOpen(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const menu = getEl("mobile-more-menu");
    if (menu && !menu.hidden && !getOpenDialogEl()) {
      event.preventDefault();
      setMobileMoreOpen(false, { restoreFocus: true });
    }
  });
  document.addEventListener("click", (event) => {
    const menu = getEl("mobile-more-menu");
    if (!menu || menu.hidden) return;
    if (
      event.target instanceof Element &&
      event.target.closest("#mobile-more-btn, #mobile-more-menu")
    ) {
      return;
    }
    setMobileMoreOpen(false);
  });
  if (typeof window.matchMedia === "function") {
    const mobileMediaQuery = window.matchMedia("(max-width: 639px)");
    const handleMobileMediaChange = (event) => {
      if (!event.matches) {
        setMobileMoreOpen(false);
      }
    };
    if (typeof mobileMediaQuery.addEventListener === "function") {
      mobileMediaQuery.addEventListener("change", handleMobileMediaChange);
    } else if (typeof mobileMediaQuery.addListener === "function") {
      mobileMediaQuery.addListener(handleMobileMediaChange);
    }
  }
}
