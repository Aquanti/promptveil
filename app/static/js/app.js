/**
 * PromptVeil Thin UI Coordinator.
 * Strict browser-local processing, zero external network requests, zero unsafe HTML sinks.
 */

import { SessionVault } from "./vault.js";
import { SITE_CONTACTS, buildMailtoHref } from "./contacts.js";
import { attachCspViolationTracker, runZeroRetentionSelfTest } from "./privacy-proof.js";
import {
  createRuleId,
  makeRuleDedupKey,
  loadRules,
  saveRules,
  exportRulesJson,
  importRulesJson,
  loadAuditLog,
  appendAuditReceipt,
  exportAuditJson,
  clearAuditLog,
  loadLanguage,
  saveLanguage,
  onStorageWarning,
} from "./storage.js";
import { PRESETS, getLocalizedPreset, getPresetById } from "./presets.js";
import {
  applyLanguage,
  getLang,
  t,
} from "./i18n.js";
import {
  clearEl,
  copyTextToClipboard,
  createEl,
  downloadTextFile,
  getEl,
  handleDrawerKeydown,
  readTextFromClipboard,
  showCopyFeedback,
} from "./dom.js";
import {
  renderCategoryChips,
  renderPresetRuleSuggestion,
  renderPresetsBar,
  renderRawMetrics,
  renderRehydrateView,
  renderSanitizedOutput,
  renderTelemetryAndActions,
  renderVaultList,
} from "./render-workbench.js";
import {
  closeDrawers,
  getOpenDialogEl,
  openDrawer,
  renderAuditList,
  renderRulebookList,
} from "./render-drawers.js";

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set([".txt", ".md", ".csv", ".json", ".log", ".env"]);

const state = {
  lang: "ru",
  mode: "sanitize",
  rawText: "",
  llmReply: "",
  activePresetId: "",
  lastSanitizeResult: null,
  lastSanitizedInput: "",
  lastRehydrateResult: null,
  revealVaultValues: true,
  showAllCategories: false,
  highlightedToken: "",
  pinnedToken: "",
  rules: [],
  auditLog: [],
  vault: new SessionVault(),
  lastFocusedTrigger: null,
  billingCycle: "month",
  activeRequestPlan: "pro",
  lastRequestSummary: "",
};

let liveAuditTimer = null;
let liveSanitizeTimer = null;
let statusBannerTimer = null;
let activeFileReadId = 0;
let activeStatusBanner = null;
const activeInlineAlerts = new Map();

function cancelPendingLiveAudit() {
  if (liveAuditTimer !== null) {
    window.clearTimeout(liveAuditTimer);
    liveAuditTimer = null;
  }
}

function cancelPendingLiveSanitize() {
  if (liveSanitizeTimer !== null) {
    window.clearTimeout(liveSanitizeTimer);
    liveSanitizeTimer = null;
  }
}

function cancelPendingFileRead() {
  activeFileReadId += 1;
  const loading = getEl("file-loading-indicator");
  if (loading) loading.hidden = true;
}

function resolveAlertVars(varsOrFn, lang) {
  if (typeof varsOrFn === "function") {
    return varsOrFn(lang) || {};
  }
  return varsOrFn || {};
}

function renderActiveStatusBanner(lang = getLang()) {
  const banner = getEl("global-status-banner");
  if (!banner) return;
  if (!activeStatusBanner) {
    banner.hidden = true;
    return;
  }
  const message = t(
    activeStatusBanner.key,
    resolveAlertVars(activeStatusBanner.varsOrFn, lang),
    lang
  );
  banner.replaceChildren(createEl("span", "status-banner-text", message));
  banner.classList.toggle("status-banner--error", Boolean(activeStatusBanner.isError));
  banner.setAttribute("role", activeStatusBanner.isError ? "alert" : "status");
  banner.hidden = false;
}

function showStatusBanner(key, varsOrFn = {}, isError = false) {
  activeStatusBanner = { key, varsOrFn, isError: Boolean(isError) };
  renderActiveStatusBanner(getLang());
  window.clearTimeout(statusBannerTimer);
  statusBannerTimer = window.setTimeout(() => {
    activeStatusBanner = null;
    const banner = getEl("global-status-banner");
    if (banner) banner.hidden = true;
  }, 4500);
}

function renderInlineAlert(elementId, lang = getLang()) {
  const el = getEl(elementId);
  if (!el) return;
  const spec = activeInlineAlerts.get(elementId);
  if (!spec) {
    el.textContent = "";
    el.hidden = true;
    return;
  }
  el.textContent = t(spec.key, resolveAlertVars(spec.varsOrFn, lang), lang);
  el.className = `inline-alert inline-alert--${spec.variant}`;
  el.setAttribute("role", spec.variant === "error" ? "alert" : "status");
  el.hidden = false;
}

function showInlineAlert(elementId, key, varsOrFn = {}, variant = "error") {
  activeInlineAlerts.set(elementId, { key, varsOrFn, variant });
  renderInlineAlert(elementId, getLang());
}

function hideInlineAlert(elementId) {
  activeInlineAlerts.delete(elementId);
  const el = getEl(elementId);
  if (!el) return;
  el.textContent = "";
  el.hidden = true;
}

function refreshBannersAndAlerts(lang = getLang()) {
  if (activeStatusBanner) {
    renderActiveStatusBanner(lang);
  }
  for (const elementId of activeInlineAlerts.keys()) {
    renderInlineAlert(elementId, lang);
  }
}

function getUnappliedPresetRules(preset) {
  if (!preset || !Array.isArray(preset.suggestedRules) || preset.suggestedRules.length === 0) {
    return [];
  }
  const existingKeys = new Set(state.rules.map(makeRuleDedupKey));
  return preset.suggestedRules.filter((rule) => !existingKeys.has(makeRuleDedupKey(rule)));
}

function setTokenHighlight(token, active) {
  if (!active && token && state.highlightedToken && state.highlightedToken !== token) {
    return;
  }
  state.highlightedToken = active ? token : "";
  const marks = document.querySelectorAll("#sanitized-output mark[data-token]");
  for (const mark of marks) {
    mark.classList.toggle("is-highlighted", Boolean(active && mark.dataset.token === token));
  }
  const items = document.querySelectorAll('#entity-vault-list [data-testid="vault-item"]');
  for (const item of items) {
    item.classList.toggle("is-highlighted", Boolean(active && item.dataset.token === token));
  }
}

function handleTokenHover(token, active) {
  if (active) {
    if (state.pinnedToken && state.pinnedToken !== token) {
      state.pinnedToken = "";
    }
    setTokenHighlight(token, true);
    return;
  }
  if (state.pinnedToken && state.pinnedToken === token) {
    return;
  }
  setTokenHighlight(token, false);
}

function handleVaultItemBlur(token) {
  if (state.pinnedToken === token) {
    state.pinnedToken = "";
    setTokenHighlight(token, false);
  }
}

function scrollToVaultItem(token) {
  const items = document.querySelectorAll('#entity-vault-list [data-testid="vault-item"]');
  const prefersReducedMotion =
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  for (const item of items) {
    if (item.dataset.token === token) {
      state.pinnedToken = token;
      setTokenHighlight(token, true);
      item.scrollIntoView({
        behavior: prefersReducedMotion ? "auto" : "smooth",
        block: "nearest",
      });
      item.focus({ preventScroll: true });
      break;
    }
  }
}

function refreshPresetsUi() {
  const lang = getLang();
  renderPresetsBar(
    getEl("preset-bar"),
    PRESETS,
    state.activePresetId,
    lang,
    loadPresetById
  );
  const preset = getPresetById(state.activePresetId);
  renderPresetRuleSuggestion(
    getEl("apply-preset-rules-btn"),
    getEl("preset-rule-hint"),
    getUnappliedPresetRules(preset),
    lang
  );
}

function refreshWorkbenchUi() {
  const lang = getLang();
  const result = state.lastSanitizeResult;
  const vaultSize = state.vault.tokenToEntry.size;

  renderRawMetrics(getEl("raw-metrics"), state.rawText, lang);
  renderSanitizedOutput(getEl("sanitized-output"), state.rawText, result, lang, {
    highlightedToken: state.highlightedToken,
    onTokenHover: handleTokenHover,
    onTokenClick: scrollToVaultItem,
  });
  renderCategoryChips(
    getEl("category-chips"),
    result,
    state.vault,
    state.showAllCategories,
    lang,
    {
      onToggleCategory: (category) => {
        state.pinnedToken = "";
        state.highlightedToken = "";
        state.vault.toggleCategory(category);
        runSanitizePipeline(false);
      },
      onResetCategories: () => {
        state.pinnedToken = "";
        state.highlightedToken = "";
        state.vault.disabledCategories.clear();
        runSanitizePipeline(false);
      },
      onToggleShowAll: () => {
        state.showAllCategories = !state.showAllCategories;
        refreshWorkbenchUi();
      },
    }
  );
  renderVaultList(getEl("entity-vault-list"), result, {
    revealValues: state.revealVaultValues,
    highlightedToken: state.highlightedToken,
    lang,
    onToggleEntity: (entry) => {
      state.pinnedToken = "";
      state.highlightedToken = "";
      state.vault.toggleValue(entry.category, entry.value, !entry.enabled);
      runSanitizePipeline(false);
    },
    onSelectToken: scrollToVaultItem,
    onTokenHover: handleTokenHover,
    onVaultItemBlur: handleVaultItemBlur,
  });
  renderTelemetryAndActions(
    {
      sanitizedMetricsEl: getEl("sanitized-metrics"),
      rehydrateBadgeEl: getEl("rehydrate-ready-badge"),
      vaultReadyMetaEl: getEl("vault-ready-meta"),
      copySanitizedBtn: getEl("copy-sanitized-btn"),
      downloadSanitizedBtn: getEl("download-sanitized-btn"),
      copyGoStep2Btn: getEl("copy-goto-step2-btn"),
      toggleRevealBtn: getEl("toggle-reveal-btn"),
    },
    {
      rawText: state.rawText,
      result,
      vaultSize,
      revealValues: state.revealVaultValues,
      lang,
    }
  );
  renderRehydrateView(
    {
      outputEl: getEl("restored-output"),
      warningEl: getEl("unresolved-tokens-banner"),
      metricsEl: getEl("rehydrate-metrics"),
      sessionNoticeEl: getEl("rehydrate-empty-session-notice"),
      copyBtn: getEl("copy-restored-btn"),
      downloadBtn: getEl("download-restored-btn"),
    },
    {
      llmReply: state.llmReply,
      result: state.lastRehydrateResult,
      vaultSize,
      lang,
    }
  );
  refreshPresetsUi();
}

function refreshDrawersUi() {
  const lang = getLang();
  renderRulebookList(
    {
      listEl: getEl("rulebook-list"),
      emptyEl: getEl("rulebook-empty"),
      countBadgeEl: getEl("rulebook-count"),
    },
    state.rules,
    lang,
    {
      onToggleRule: (ruleId) => {
        state.rules = saveRules(
          state.rules.map((r) =>
            r.id === ruleId ? { ...r, enabled: r.enabled === false } : r
          )
        );
        refreshDrawersUi();
        runSanitizePipeline(false);
      },
      onDeleteRule: (ruleId) => {
        state.rules = saveRules(state.rules.filter((r) => r.id !== ruleId));
        refreshDrawersUi();
        runSanitizePipeline(false);
      },
    }
  );
  renderAuditList(
    {
      listEl: getEl("audit-list"),
      emptyEl: getEl("audit-empty"),
      countBadgeEl: getEl("audit-count"),
      clearBtnEl: getEl("clear-audit-btn"),
      exportBtnEl: getEl("export-audit-btn"),
    },
    state.auditLog,
    lang
  );
}

function formatProofTime(isoString, lang) {
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

function renderPrivacyProofModal(lang = getLang()) {
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

    const transportText = report.trackers.isHttps
      ? t("proof.transportHttps", {}, lang)
      : report.trackers.isLocalStand
        ? t("proof.transportLocal", {}, lang)
        : t("proof.transportHttp", {}, lang);
    const trackersBadge = report.trackers.isHttps
      ? t("proof.trackersMetricHttps", { trackers: report.trackers.trackerCount }, lang)
      : report.trackers.isLocalStand
        ? t("proof.trackersMetricLocal", { trackers: report.trackers.trackerCount }, lang)
        : t("proof.trackersMetricHttp", { trackers: report.trackers.trackerCount }, lang);

    const rows = [
      {
        ok: report.network.ok,
        title: t("proof.netTitle", {}, lang),
        metric: t("proof.netMetric", { count: report.network.textRequests }, lang),
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
        metric: t("proof.storageMetric", { bytes: report.storage.storedTextBytes }, lang),
        detail: t(
          "proof.storageDetail",
          {
            sessionKeys: report.storage.sessionStorageKeys,
            cookies: report.storage.cookieCount,
            unknownKeys: report.storage.unknownStorageKeys,
            prefKeys: report.storage.allowedPrefKeysPresent,
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
          row.ok ? "proof-check-metric tabular-nums" : "proof-check-metric proof-check-metric--warn tabular-nums",
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
}

function getPlanPricing(plan, cycle, lang) {
  const isYear = cycle === "year";
  if (plan === "team") {
    return {
      planName: t("pricing.teamName", {}, lang),
      price: t(isYear ? "pricing.teamPriceYear" : "pricing.teamPriceMonth", {}, lang),
      period: t("pricing.periodMonth", {}, lang),
    };
  }
  return {
    planName: t("pricing.proName", {}, lang),
    price: t(isYear ? "pricing.proPriceYear" : "pricing.proPriceMonth", {}, lang),
    period: t("pricing.periodMonth", {}, lang),
  };
}

function renderPricingSection(lang = getLang()) {
  const isYear = state.billingCycle === "year";
  const monthBtn = getEl("billing-month-btn");
  const yearBtn = getEl("billing-year-btn");
  if (monthBtn) {
    monthBtn.classList.toggle("is-active", !isYear);
    monthBtn.setAttribute("aria-pressed", !isYear ? "true" : "false");
  }
  if (yearBtn) {
    yearBtn.classList.toggle("is-active", isYear);
    yearBtn.setAttribute("aria-pressed", isYear ? "true" : "false");
  }

  const proPriceEl = getEl("price-pro-value");
  const proNoteEl = getEl("price-pro-note");
  const teamPriceEl = getEl("price-team-value");
  const teamNoteEl = getEl("price-team-note");

  if (proPriceEl) {
    proPriceEl.textContent = t(isYear ? "pricing.proPriceYear" : "pricing.proPriceMonth", {}, lang);
  }
  if (proNoteEl) {
    proNoteEl.textContent = t(isYear ? "pricing.noteYearDiscount" : "pricing.noteMonthly", {}, lang);
  }
  if (teamPriceEl) {
    teamPriceEl.textContent = t(isYear ? "pricing.teamPriceYear" : "pricing.teamPriceMonth", {}, lang);
  }
  if (teamNoteEl) {
    teamNoteEl.textContent = t(isYear ? "pricing.noteTeamYear" : "pricing.noteTeamSeats", {}, lang);
  }
}

function renderContactsAndPolicy(lang = getLang()) {
  const tgEl = getEl("contact-telegram-text");
  const emailLinkEl = getEl("contact-email-link");
  const githubEl = getEl("contact-github-text");
  const copyrightEl = getEl("footer-copyright");
  const policyOwnerEl = getEl("policy-owner-contact-body");

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
      "policy.item4Body",
      {
        email: SITE_CONTACTS.email,
        telegram: SITE_CONTACTS.telegramHandle,
      },
      lang
    );
  }
}

function syncPlanRequestModalMeta(lang = getLang()) {
  const isTeam = state.activeRequestPlan === "team";
  const titleEl = getEl("plan-modal-title");
  const subtitleEl = getEl("plan-modal-subtitle");
  const summaryPillEl = getEl("plan-summary-pill");
  const seatsFieldEl = getEl("plan-req-seats-field");

  if (titleEl) {
    titleEl.textContent = t(isTeam ? "request.teamTitle" : "request.proTitle", {}, lang);
  }
  if (subtitleEl) {
    subtitleEl.textContent = t(isTeam ? "request.teamSubtitle" : "request.proSubtitle", {}, lang);
  }
  if (seatsFieldEl) {
    seatsFieldEl.hidden = !isTeam;
  }
  if (summaryPillEl) {
    const info = getPlanPricing(state.activeRequestPlan, state.billingCycle, lang);
    const cycleLabel = t(
      state.billingCycle === "year" ? "pricing.toggleYear" : "pricing.toggleMonth",
      {},
      lang
    );
    summaryPillEl.textContent = `${info.planName} • ${info.price} ${info.period} (${cycleLabel})`;
  }
}

function openPlanRequestModal(plan, triggerEl) {
  state.activeRequestPlan = plan === "team" ? "team" : "pro";
  state.lastRequestSummary = "";
  hideInlineAlert("plan-request-alert");
  const resultBox = getEl("plan-request-result");
  const previewEl = getEl("plan-request-preview");
  if (resultBox) resultBox.hidden = true;
  if (previewEl) previewEl.textContent = "";
  syncPlanRequestModalMeta(getLang());
  openDrawer("modal-plan-request", triggerEl, state);
}

function isValidContactInput(val) {
  const trimmed = String(val || "").trim();
  if (!trimmed) return false;
  const emailLike = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]{2,}$/;
  const telegramLike = /^@[A-Za-z0-9_]{3,64}$/;
  return emailLike.test(trimmed) || telegramLike.test(trimmed);
}

function resetSessionToZero({ silent = false, wipeDomOnly = false } = {}) {
  cancelPendingFileRead();
  cancelPendingLiveSanitize();
  cancelPendingLiveAudit();
  hideInlineAlert("input-error-banner");
  hideInlineAlert("rehydrate-error-banner");

  state.rawText = "";
  state.llmReply = "";
  state.activePresetId = "";
  state.lastSanitizeResult = null;
  state.lastSanitizedInput = "";
  state.lastRehydrateResult = null;
  state.showAllCategories = false;
  state.highlightedToken = "";
  state.pinnedToken = "";
  state.vault.reset();

  const rawInput = getEl("raw-prompt-input");
  const llmInput = getEl("llm-reply-input");
  const fileInput = getEl("file-upload-input");
  if (rawInput) rawInput.value = "";
  if (llmInput) llmInput.value = "";
  if (fileInput) fileInput.value = "";

  if (wipeDomOnly) {
    refreshWorkbenchUi();
    return;
  }

  runSanitizePipeline(false);
  const proofModal = getEl("modal-privacy-proof");
  if (proofModal && !proofModal.hidden) {
    renderPrivacyProofModal(getLang());
  }
  if (!silent) {
    showStatusBanner("banner.sessionReset");
  }
}

function rerenderAll() {
  const lang = getLang();
  refreshWorkbenchUi();
  refreshDrawersUi();
  refreshBannersAndAlerts(lang);
  renderPricingSection(lang);
  renderContactsAndPolicy(lang);
  syncPlanRequestModalMeta(lang);
  const proofModal = getEl("modal-privacy-proof");
  if (proofModal && !proofModal.hidden) {
    renderPrivacyProofModal(lang);
  }
}

async function recordAuditEntry(
  action,
  inputText,
  outputText,
  entities,
  replacedCount,
  countsByCategory
) {
  try {
    const res = await appendAuditReceipt({
      action,
      inputText,
      outputText,
      entities,
      replacedCount,
      countsByCategory,
    });
    if (res?.aborted) {
      return;
    }
    state.auditLog = res.auditLog;
    refreshDrawersUi();
  } catch {
    showStatusBanner("banner.auditWriteError", {}, true);
  }
}

function runSanitizePipeline(recordAudit = false, { evolveTransient = false } = {}) {
  const result = state.vault.sanitize(state.rawText, state.rules, { evolveTransient });
  state.lastSanitizeResult = result;
  state.lastSanitizedInput = state.rawText;
  refreshWorkbenchUi();

  if (recordAudit && state.rawText.trim().length > 0) {
    cancelPendingLiveAudit();
    recordAuditEntry(
      "SANITIZE",
      state.rawText,
      result.sanitizedText,
      result.entities,
      0,
      result.countsByCategory
    );
  }
  return result;
}

function ensureFreshSanitizedOutput() {
  const rawInput = getEl("raw-prompt-input");
  if (rawInput && rawInput.value !== state.rawText) {
    state.rawText = rawInput.value;
  }
  const hadPendingLive = liveSanitizeTimer !== null;
  const needsSync =
    hadPendingLive ||
    state.rawText !== state.lastSanitizedInput ||
    !state.lastSanitizeResult;
  if (needsSync) {
    cancelPendingLiveSanitize();
    cancelPendingLiveAudit();
    runSanitizePipeline(state.rawText.trim().length > 0, {
      evolveTransient: hadPendingLive,
    });
  }
  return state.lastSanitizeResult?.sanitizedText || "";
}

function switchMode(nextMode) {
  state.mode = nextMode === "rehydrate" ? "rehydrate" : "sanitize";
  const isSanitize = state.mode === "sanitize";

  const btnSanitize = getEl("mode-btn-sanitize");
  const btnRehydrate = getEl("mode-btn-rehydrate");
  const panelSanitize = getEl("panel-sanitize");
  const panelRehydrate = getEl("panel-rehydrate");

  if (btnSanitize) {
    btnSanitize.classList.toggle("is-active", isSanitize);
    btnSanitize.setAttribute("aria-selected", isSanitize ? "true" : "false");
  }
  if (btnRehydrate) {
    btnRehydrate.classList.toggle("is-active", !isSanitize);
    btnRehydrate.setAttribute("aria-selected", !isSanitize ? "true" : "false");
  }
  if (panelSanitize) panelSanitize.hidden = !isSanitize;
  if (panelRehydrate) panelRehydrate.hidden = isSanitize;
  refreshWorkbenchUi();
}

function loadPresetById(presetId) {
  const preset = getLocalizedPreset(presetId, getLang());
  if (!preset) return;
  cancelPendingFileRead();
  cancelPendingLiveSanitize();
  cancelPendingLiveAudit();
  hideInlineAlert("input-error-banner");
  state.vault.reset();
  state.showAllCategories = false;
  state.highlightedToken = "";
  state.pinnedToken = "";
  state.activePresetId = preset.id;
  state.rawText = preset.text;
  const rawInput = getEl("raw-prompt-input");
  if (rawInput) rawInput.value = preset.text;
  runSanitizePipeline(true);
  showStatusBanner("banner.presetLoaded", (lang) => ({
    title: getLocalizedPreset(preset.id, lang)?.title || preset.title,
  }));
}

function handleLocalFile(file) {
  hideInlineAlert("input-error-banner");
  if (!file) return;

  const lowerName = file.name.toLowerCase();
  const dotIdx = lowerName.lastIndexOf(".");
  const ext = dotIdx >= 0 ? lowerName.slice(dotIdx) : "";
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    showInlineAlert("input-error-banner", "banner.fileUnsupported", {
      ext: ext || "—",
    });
    return;
  }

  if (file.size > MAX_FILE_BYTES) {
    showInlineAlert("input-error-banner", "banner.fileTooLarge", { name: file.name });
    return;
  }

  cancelPendingLiveSanitize();
  cancelPendingLiveAudit();
  const readId = ++activeFileReadId;
  const loading = getEl("file-loading-indicator");
  if (loading) loading.hidden = false;

  const reader = new FileReader();
  reader.onload = () => {
    if (readId !== activeFileReadId) return;
    if (loading) loading.hidden = true;
    state.vault.reset();
    state.activePresetId = "";
    state.showAllCategories = false;
    state.highlightedToken = "";
    state.pinnedToken = "";
    state.rawText = String(reader.result || "");
    const rawInput = getEl("raw-prompt-input");
    if (rawInput) rawInput.value = state.rawText;
    runSanitizePipeline(true);
    showStatusBanner("banner.fileLoaded", { name: file.name });
  };
  reader.onerror = () => {
    if (readId !== activeFileReadId) return;
    if (loading) loading.hidden = true;
    showInlineAlert("input-error-banner", "banner.fileReadError", { name: file.name });
  };
  reader.readAsText(file, "UTF-8");
}

function translateImportError() {
  return "rulebook.importBadJson";
}

function bindEvents() {
  // Language switcher (live without reload)
  getEl("lang-ru-btn")?.addEventListener("click", () => {
    state.lang = saveLanguage("ru");
    applyLanguage(state.lang, { onAfterApply: rerenderAll });
  });
  getEl("lang-en-btn")?.addEventListener("click", () => {
    state.lang = saveLanguage("en");
    applyLanguage(state.lang, { onAfterApply: rerenderAll });
  });

  // Mode tabs & arrow navigation
  getEl("mode-btn-sanitize")?.addEventListener("click", () => switchMode("sanitize"));
  getEl("mode-btn-rehydrate")?.addEventListener("click", () => switchMode("rehydrate"));
  document.querySelector(".mode-switch")?.addEventListener("keydown", (event) => {
    if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
      event.preventDefault();
      const next = state.mode === "sanitize" ? "rehydrate" : "sanitize";
      switchMode(next);
      getEl(next === "rehydrate" ? "mode-btn-rehydrate" : "mode-btn-sanitize")?.focus();
    }
  });
  getEl("goto-rehydrate-btn")?.addEventListener("click", () => switchMode("rehydrate"));
  getEl("copy-goto-step2-btn")?.addEventListener("click", async () => {
    const text = ensureFreshSanitizedOutput();
    if (!text) return;
    const ok = await copyTextToClipboard(text);
    showStatusBanner(ok ? "banner.copied" : "banner.copyFailed", {}, !ok);
    switchMode("rehydrate");
    getEl("llm-reply-input")?.focus();
  });
  getEl("back-to-sanitize-btn")?.addEventListener("click", () => switchMode("sanitize"));
  getEl("quick-reset-session-btn")?.addEventListener("click", () => resetSessionToZero());

  // Apply suggested custom words from active preset
  getEl("apply-preset-rules-btn")?.addEventListener("click", () => {
    const preset = getPresetById(state.activePresetId);
    const unapplied = getUnappliedPresetRules(preset);
    if (unapplied.length === 0) return;

    const toAdd = unapplied.map((r) => ({
      id: createRuleId(),
      term: r.term,
      category: r.category || "CUSTOM",
      caseSensitive: Boolean(r.caseSensitive),
      enabled: true,
    }));
    state.rules = saveRules([...state.rules, ...toAdd]);
    refreshDrawersUi();
    runSanitizePipeline(false);
    showStatusBanner("banner.presetRulesAdded", { count: toAdd.length });
  });

  // Step 1 input & auto-sanitize
  const liveToggle = getEl("live-sanitize-toggle");
  liveToggle?.addEventListener("change", () => {
    if (!liveToggle.checked) {
      cancelPendingLiveSanitize();
      cancelPendingLiveAudit();
    }
  });

  const rawInput = getEl("raw-prompt-input");
  rawInput?.addEventListener("input", () => {
    cancelPendingFileRead();
    hideInlineAlert("input-error-banner");
    state.rawText = rawInput.value;
    renderRawMetrics(getEl("raw-metrics"), state.rawText, getLang());

    if (state.rawText.trim().length === 0) {
      cancelPendingLiveSanitize();
      cancelPendingLiveAudit();
      state.activePresetId = "";
      state.showAllCategories = false;
      state.highlightedToken = "";
      state.pinnedToken = "";
      runSanitizePipeline(false);
      return;
    }

    if (state.activePresetId) {
      const activePreset = getPresetById(state.activePresetId);
      if (!activePreset || state.rawText !== activePreset.text) {
        state.activePresetId = "";
        refreshPresetsUi();
      }
    }

    if (liveToggle && liveToggle.checked) {
      cancelPendingLiveSanitize();
      cancelPendingLiveAudit();
      const snapshotText = state.rawText;
      liveSanitizeTimer = window.setTimeout(() => {
        liveSanitizeTimer = null;
        if (state.rawText === snapshotText && liveToggle.checked) {
          runSanitizePipeline(false, { evolveTransient: true });
        }
      }, 140);
      liveAuditTimer = window.setTimeout(() => {
        liveAuditTimer = null;
        if (
          liveToggle.checked &&
          state.rawText === snapshotText &&
          state.rawText.trim().length > 0 &&
          state.lastSanitizeResult
        ) {
          recordAuditEntry(
            "SANITIZE",
            snapshotText,
            state.lastSanitizeResult.sanitizedText,
            state.lastSanitizeResult.entities,
            0,
            state.lastSanitizeResult.countsByCategory
          );
        }
      }, 320);
    }
  });

  getEl("sanitize-now-btn")?.addEventListener("click", () => {
    cancelPendingLiveSanitize();
    cancelPendingLiveAudit();
    hideInlineAlert("input-error-banner");
    if (rawInput) state.rawText = rawInput.value;
    runSanitizePipeline(true);
  });

  getEl("clear-raw-btn")?.addEventListener("click", () => {
    cancelPendingFileRead();
    cancelPendingLiveSanitize();
    cancelPendingLiveAudit();
    hideInlineAlert("input-error-banner");
    state.rawText = "";
    state.activePresetId = "";
    state.showAllCategories = false;
    state.highlightedToken = "";
    state.pinnedToken = "";
    state.vault.reset();
    if (rawInput) rawInput.value = "";
    runSanitizePipeline(false);
  });

  getEl("paste-raw-btn")?.addEventListener("click", async () => {
    const res = await readTextFromClipboard();
    if (!res.ok) {
      rawInput?.focus();
      showStatusBanner("banner.pasteFallback", {}, true);
      return;
    }
    if (!res.text.trim()) {
      rawInput?.focus();
      showStatusBanner("banner.clipboardEmpty");
      return;
    }
    cancelPendingFileRead();
    cancelPendingLiveSanitize();
    cancelPendingLiveAudit();
    hideInlineAlert("input-error-banner");
    state.vault.reset();
    state.activePresetId = "";
    state.showAllCategories = false;
    state.highlightedToken = "";
    state.pinnedToken = "";
    state.rawText = res.text;
    if (rawInput) rawInput.value = res.text;
    runSanitizePipeline(true);
    showStatusBanner("banner.pasted");
  });

  // File upload & drag-drop
  const fileInput = getEl("file-upload-input");
  getEl("upload-file-btn")?.addEventListener("click", () => fileInput?.click());
  fileInput?.addEventListener("change", (event) => {
    const file = event.target.files?.[0];
    if (file) handleLocalFile(file);
    event.target.value = "";
  });

  const dropzone = getEl("input-dropzone");
  dropzone?.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropzone.classList.add("is-dragover");
  });
  dropzone?.addEventListener("dragleave", () => {
    dropzone.classList.remove("is-dragover");
  });
  dropzone?.addEventListener("drop", (event) => {
    event.preventDefault();
    dropzone.classList.remove("is-dragover");
    const file = event.dataTransfer?.files?.[0];
    if (file) handleLocalFile(file);
  });

  getEl("toggle-reveal-btn")?.addEventListener("click", () => {
    state.revealVaultValues = !state.revealVaultValues;
    refreshWorkbenchUi();
  });

  getEl("copy-sanitized-btn")?.addEventListener("click", async () => {
    const text = ensureFreshSanitizedOutput();
    if (!text) return;
    const ok = await copyTextToClipboard(text);
    if (ok) {
      showCopyFeedback(
        getEl("copy-sanitized-btn"),
        t("action.copiedFeedback"),
        () => t("step1.copyBtn")
      );
    }
    showStatusBanner(ok ? "banner.copied" : "banner.copyFailed", {}, !ok);
  });

  getEl("download-sanitized-btn")?.addEventListener("click", () => {
    const text = ensureFreshSanitizedOutput();
    if (!text) return;
    downloadTextFile("promptveil-sanitized.txt", text);
    showStatusBanner("banner.downloaded");
  });

  // Step 2: Restore in AI Reply
  const llmInput = getEl("llm-reply-input");
  llmInput?.addEventListener("input", () => {
    hideInlineAlert("rehydrate-error-banner");
    state.llmReply = llmInput.value;
    if (!state.llmReply.trim()) {
      state.lastRehydrateResult = null;
      refreshWorkbenchUi();
    }
  });

  getEl("rehydrate-btn")?.addEventListener("click", () => {
    const reply = llmInput?.value || "";
    if (!reply.trim()) {
      state.llmReply = "";
      state.lastRehydrateResult = null;
      refreshWorkbenchUi();
      showInlineAlert("rehydrate-error-banner", "step2.emptyInputError");
      return;
    }
    hideInlineAlert("rehydrate-error-banner");
    state.llmReply = reply;
    const res = state.vault.rehydrate(reply);
    state.lastRehydrateResult = res;
    refreshWorkbenchUi();
    recordAuditEntry("REHYDRATE", reply, res.rehydratedText, [], res.replacedCount, {});
  });

  getEl("clear-rehydrate-btn")?.addEventListener("click", () => {
    hideInlineAlert("rehydrate-error-banner");
    if (llmInput) llmInput.value = "";
    state.llmReply = "";
    state.lastRehydrateResult = null;
    refreshWorkbenchUi();
  });

  getEl("paste-rehydrate-btn")?.addEventListener("click", async () => {
    const res = await readTextFromClipboard();
    if (!res.ok) {
      llmInput?.focus();
      showStatusBanner("banner.pasteFallback", {}, true);
      return;
    }
    if (!res.text.trim()) {
      llmInput?.focus();
      showStatusBanner("banner.clipboardEmpty");
      return;
    }
    hideInlineAlert("rehydrate-error-banner");
    state.llmReply = res.text;
    state.lastRehydrateResult = null;
    if (llmInput) llmInput.value = res.text;
    refreshWorkbenchUi();
    llmInput?.focus();
    showStatusBanner("banner.pasted");
  });

  getEl("copy-restored-btn")?.addEventListener("click", async () => {
    const text = state.lastRehydrateResult?.rehydratedText || "";
    const ok = await copyTextToClipboard(text);
    if (ok) {
      showCopyFeedback(
        getEl("copy-restored-btn"),
        t("action.copiedFeedback"),
        () => t("step2.copyBtn")
      );
    }
    showStatusBanner(ok ? "banner.copied" : "banner.copyFailed", {}, !ok);
  });

  getEl("download-restored-btn")?.addEventListener("click", () => {
    const text = state.lastRehydrateResult?.rehydratedText || "";
    if (!text) return;
    downloadTextFile("promptveil-restored.txt", text);
    showStatusBanner("banner.downloaded");
  });

  // Drawers & Modals
  getEl("open-rulebook-btn")?.addEventListener("click", (event) => {
    hideInlineAlert("rulebook-alert");
    openDrawer("drawer-rulebook", event.currentTarget, state);
  });
  getEl("open-audit-btn")?.addEventListener("click", (event) => {
    openDrawer("drawer-audit", event.currentTarget, state);
  });
  const handleOpenProofModal = (event) => {
    renderPrivacyProofModal(getLang());
    openDrawer("modal-privacy-proof", event.currentTarget, state);
  };
  getEl("open-proof-btn")?.addEventListener("click", handleOpenProofModal);
  getEl("footer-open-proof-btn")?.addEventListener("click", handleOpenProofModal);
  getEl("run-proof-check-btn")?.addEventListener("click", () => {
    renderPrivacyProofModal(getLang());
  });
  getEl("reset-session-btn")?.addEventListener("click", () => {
    resetSessionToZero();
  });
  getEl("open-privacy-policy-btn")?.addEventListener("click", (event) => {
    renderContactsAndPolicy(getLang());
    openDrawer("modal-privacy-policy", event.currentTarget, state);
  });
  getEl("close-rulebook-btn")?.addEventListener("click", () => closeDrawers(true, state));
  getEl("close-audit-btn")?.addEventListener("click", () => closeDrawers(true, state));
  getEl("close-proof-btn")?.addEventListener("click", () => closeDrawers(true, state));
  getEl("close-proof-footer-btn")?.addEventListener("click", () => closeDrawers(true, state));
  getEl("close-plan-modal-btn")?.addEventListener("click", () => closeDrawers(true, state));
  getEl("close-policy-modal-btn")?.addEventListener("click", () => closeDrawers(true, state));
  getEl("close-policy-footer-btn")?.addEventListener("click", () => closeDrawers(true, state));
  getEl("drawer-backdrop")?.addEventListener("click", () => closeDrawers(true, state));

  // Pricing & Client-Only Request Modals
  getEl("billing-month-btn")?.addEventListener("click", () => {
    state.billingCycle = "month";
    renderPricingSection(getLang());
    syncPlanRequestModalMeta(getLang());
  });
  getEl("billing-year-btn")?.addEventListener("click", () => {
    state.billingCycle = "year";
    renderPricingSection(getLang());
    syncPlanRequestModalMeta(getLang());
  });
  getEl("pricing-free-start-btn")?.addEventListener("click", () => {
    switchMode("sanitize");
    const raw = getEl("raw-prompt-input");
    raw?.scrollIntoView({ behavior: "smooth", block: "center" });
    raw?.focus({ preventScroll: true });
  });
  getEl("open-pro-modal-btn")?.addEventListener("click", (event) => {
    openPlanRequestModal("pro", event.currentTarget);
  });
  getEl("open-team-modal-btn")?.addEventListener("click", (event) => {
    openPlanRequestModal("team", event.currentTarget);
  });

  getEl("plan-request-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    hideInlineAlert("plan-request-alert");
    const lang = getLang();
    const isTeam = state.activeRequestPlan === "team";
    const nameVal = (getEl("plan-req-name")?.value || "").trim();
    const contactVal = (getEl("plan-req-contact")?.value || "").trim();
    const seatsInputRaw = (getEl("plan-req-seats")?.value ?? "").trim();
    const seatsRaw = seatsInputRaw === "" ? NaN : Number(seatsInputRaw);
    const noteVal = (getEl("plan-req-note")?.value || "").trim();

    if (!nameVal) {
      showInlineAlert("plan-request-alert", "request.errorName");
      getEl("plan-req-name")?.focus();
      return;
    }
    if (!isValidContactInput(contactVal)) {
      showInlineAlert("plan-request-alert", "request.errorContact");
      getEl("plan-req-contact")?.focus();
      return;
    }
    if (isTeam && (!Number.isInteger(seatsRaw) || seatsRaw < 1 || seatsRaw > 5000)) {
      showInlineAlert("plan-request-alert", "request.errorSeats");
      getEl("plan-req-seats")?.focus();
      return;
    }

    const pricing = getPlanPricing(state.activeRequestPlan, state.billingCycle, lang);
    const cycleLabel = t(
      state.billingCycle === "year" ? "pricing.toggleYear" : "pricing.toggleMonth",
      {},
      lang
    );
    const lines = [
      `${t("request.summaryPlan", {}, lang)}: ${pricing.planName} (${pricing.price} ${pricing.period})`,
      `${t("request.summaryBilling", {}, lang)}: ${cycleLabel}`,
      `${t("request.summaryName", {}, lang)}: ${nameVal}`,
      `${t("request.summaryContact", {}, lang)}: ${contactVal}`,
    ];
    if (isTeam) {
      lines.push(`${t("request.summarySeats", {}, lang)}: ${seatsRaw}`);
    }
    if (noteVal) {
      lines.push(`${t("request.summaryNote", {}, lang)}: ${noteVal}`);
    }
    const summaryText = lines.join("\n");
    state.lastRequestSummary = summaryText;

    const previewEl = getEl("plan-request-preview");
    const resultBox = getEl("plan-request-result");
    const mailtoLink = getEl("plan-req-mailto-link");
    if (previewEl) previewEl.textContent = summaryText;
    if (mailtoLink) {
      const subject = t(
        isTeam ? "request.mailSubjectTeam" : "request.mailSubjectPro",
        {},
        lang
      );
      mailtoLink.setAttribute("href", buildMailtoHref(SITE_CONTACTS.email, subject, summaryText));
    }
    if (resultBox) resultBox.hidden = false;
  });

  getEl("plan-req-copy-btn")?.addEventListener("click", async () => {
    const text = state.lastRequestSummary || getEl("plan-request-preview")?.textContent || "";
    const ok = await copyTextToClipboard(text);
    if (ok) {
      showCopyFeedback(
        getEl("plan-req-copy-btn"),
        t("action.copiedFeedback"),
        () => t("request.copyBtn")
      );
    }
    showStatusBanner(ok ? "banner.copied" : "banner.copyFailed", {}, !ok);
  });

  // Footer contact copy buttons
  const bindContactCopy = (btnId, value) => {
    getEl(btnId)?.addEventListener("click", async () => {
      const ok = await copyTextToClipboard(value);
      if (ok) {
        showCopyFeedback(
          getEl(btnId),
          t("action.copiedFeedback"),
          () => t("action.copy")
        );
      }
      showStatusBanner(ok ? "banner.copied" : "banner.copyFailed", {}, !ok);
    });
  };
  bindContactCopy("copy-contact-telegram-btn", SITE_CONTACTS.telegramHandle);
  bindContactCopy("copy-contact-email-btn", SITE_CONTACTS.email);
  bindContactCopy("copy-contact-github-btn", SITE_CONTACTS.githubDisplay);

  document.addEventListener("click", (event) => {
    if (!state.pinnedToken) return;
    const target = event.target;
    if (
      target instanceof Element &&
      target.closest(
        '#sanitized-output mark[data-token], #entity-vault-list [data-testid="vault-item"]'
      )
    ) {
      return;
    }
    const prev = state.pinnedToken;
    state.pinnedToken = "";
    setTokenHighlight(prev, false);
  });

  document.addEventListener("keydown", (event) => {
    const openDialogEl = getOpenDialogEl();
    handleDrawerKeydown(event, openDialogEl, () => closeDrawers(true, state));
  });

  window.addEventListener("pagehide", () => {
    resetSessionToZero({ silent: true });
  });

  window.addEventListener("pageshow", (event) => {
    if (event.persisted) {
      resetSessionToZero({ silent: true });
    }
  });

  // Rulebook Form & Export/Import
  getEl("add-rule-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    hideInlineAlert("rulebook-alert");
    const termInput = getEl("rule-term-input");
    const catInput = getEl("rule-category-input");
    const caseInput = getEl("rule-case-input");

    const term = (termInput?.value || "").trim();
    if (!term) {
      showInlineAlert("rulebook-alert", "rulebook.errorEmpty");
      return;
    }

    const newRule = {
      id: createRuleId(),
      term,
      category: catInput?.value || "CUSTOM",
      caseSensitive: Boolean(caseInput?.checked),
      enabled: true,
    };

    const existingKeys = new Set(state.rules.map(makeRuleDedupKey));
    if (existingKeys.has(makeRuleDedupKey(newRule))) {
      showInlineAlert("rulebook-alert", "rulebook.errorDuplicate");
      return;
    }

    state.rules = saveRules([...state.rules, newRule]);
    if (termInput) termInput.value = "";
    if (caseInput) caseInput.checked = false;
    refreshDrawersUi();
    runSanitizePipeline(false);
    showInlineAlert("rulebook-alert", "rulebook.added", { term }, "success");
  });

  getEl("export-rules-btn")?.addEventListener("click", () => {
    const json = exportRulesJson(state.rules);
    downloadTextFile("promptveil-rules.json", json, "application/json;charset=utf-8");
    showInlineAlert("rulebook-alert", "rulebook.exported", {}, "success");
  });

  const importInput = getEl("import-rules-input");
  getEl("import-rules-btn")?.addEventListener("click", () => importInput?.click());
  importInput?.addEventListener("change", (event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    hideInlineAlert("rulebook-alert");

    const lowerName = file.name.toLowerCase();
    const dotIdx = lowerName.lastIndexOf(".");
    const ext = dotIdx >= 0 ? lowerName.slice(dotIdx) : "";
    if (ext !== ".json") {
      showInlineAlert("rulebook-alert", "rulebook.importInvalidExt", {
        ext: ext || "—",
      });
      return;
    }

    if (file.size > MAX_FILE_BYTES) {
      showInlineAlert("rulebook-alert", "rulebook.importTooLarge", { name: file.name });
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const { rules, addedCount, skippedCount } = importRulesJson(
          String(reader.result || ""),
          state.rules
        );
        state.rules = rules;
        refreshDrawersUi();
        runSanitizePipeline(false);
        showInlineAlert(
          "rulebook-alert",
          "rulebook.imported",
          { added: addedCount, skipped: skippedCount },
          "success"
        );
      } catch (err) {
        showInlineAlert("rulebook-alert", translateImportError(err));
      }
    };
    reader.onerror = () => {
      showInlineAlert("rulebook-alert", "rulebook.importReadError");
    };
    reader.readAsText(file, "UTF-8");
  });

  // Audit Export & Clear
  getEl("export-audit-btn")?.addEventListener("click", () => {
    const json = exportAuditJson(state.auditLog);
    downloadTextFile("promptveil-audit.json", json, "application/json;charset=utf-8");
    showStatusBanner("audit.exported");
  });

  getEl("clear-audit-btn")?.addEventListener("click", () => {
    if (!window.confirm(t("audit.confirmClear"))) {
      return;
    }
    cancelPendingLiveAudit();
    state.auditLog = clearAuditLog();
    refreshDrawersUi();
    showStatusBanner("audit.cleared");
  });
}

export function init() {
  attachCspViolationTracker();
  onStorageWarning(() => {
    showStatusBanner("banner.storageWarning", {}, true);
  });
  state.lang = loadLanguage();
  state.rules = loadRules();
  state.auditLog = loadAuditLog();
  bindEvents();
  applyLanguage(state.lang, {
    onAfterApply: () => {
      runSanitizePipeline(false);
      refreshDrawersUi();
      renderPricingSection(getLang());
      renderContactsAndPolicy(getLang());
    },
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
