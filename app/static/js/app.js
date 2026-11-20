/**
 * PromptVeil Thin UI Coordinator.
 * Strict browser-local processing, zero external network requests, zero unsafe HTML sinks.
 */

import { SessionVault } from "./vault.js";
import { attachCspViolationTracker } from "./privacy-proof.js";
import {
  copyTextToClipboard,
  copyWithFeedback,
  createFileController,
  downloadTextFile,
  readClipboardForInput,
} from "./clipboard.js";
import {
  applyTheme,
  bindModalAndThemeEvents,
  registerOfflineServiceWorker,
  renderContactsAndPolicy,
  renderPrivacyProofModal,
  resolveInitialTheme,
  updateThemeToggleButton,
} from "./modals.js";
import {
  bindPricingEvents,
  renderPricingSection,
  syncPlanRequestModalMeta,
} from "./pricing.js";
import {
  createRuleId,
  makeRuleDedupKey,
  loadRules,
  saveRules,
  exportRulesJson,
  loadAuditLog,
  appendAuditReceipt,
  exportAuditJson,
  clearAuditLog,
  isAuditPersistenceEnabled,
  purgeUnoptedAuditStorage,
  setAuditPersistenceEnabled,
  loadLanguage,
  saveLanguage,
  onStorageWarning,
} from "./storage.js";
import { PRESETS, getLocalizedPreset, getPresetById } from "./presets.js";
import { applyLanguage, getLang, setLang, t } from "./i18n.js";
import { clearCopyFeedback, createEl, getEl } from "./dom.js";
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
import { renderAuditList, renderRulebookList } from "./render-drawers.js";

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
  auditPersist: false,
  detectUuid: false,
  vault: new SessionVault(),
  lastFocusedTrigger: null,
  billingCycle: "month",
  activeRequestPlan: "pro",
  lastRequestSummary: "",
  theme: "light",
};

let liveAuditTimer = null;
let liveSanitizeTimer = null;
let statusBannerTimer = null;
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

const fileController = createFileController({
  getRules: () => state.rules,
  showStatusBanner,
  showInlineAlert,
  hideInlineAlert,
  cancelPendingLiveSanitize,
  cancelPendingLiveAudit,
  onPromptFileLoaded: (text, fileName) => {
    state.vault.reset();
    state.activePresetId = "";
    state.showAllCategories = false;
    state.highlightedToken = "";
    state.pinnedToken = "";
    state.rawText = text;
    const rawInput = getEl("raw-prompt-input");
    if (rawInput) rawInput.value = state.rawText;
    runSanitizePipeline(true);
    showStatusBanner("banner.fileLoaded", { name: fileName });
  },
  onRulesImported: ({ rules, addedCount, skippedCount }) => {
    state.rules = rules;
    refreshDrawersUi();
    runSanitizePipeline(false);
    showInlineAlert(
      "rulebook-alert",
      "rulebook.imported",
      { added: addedCount, skipped: skippedCount },
      "success"
    );
  },
});

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
  const maskedCount = result?.maskedCount ?? 0;
  const hasVaultEntries = state.vault.tokenToEntry.size > 0;

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
      maskedCount,
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
      maskedCount,
      hasVaultEntries,
      lang,
    }
  );
  refreshPresetsUi();
  const launchersBar = getEl("ai-launchers-bar");
  if (launchersBar) {
    launchersBar.classList.toggle(
      "is-ready",
      Boolean(state.rawText.trim() && result?.sanitizedText)
    );
  }
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
        hideInlineAlert("rulebook-alert");
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
  const persistToggle = getEl("audit-persist-toggle");
  if (persistToggle) {
    persistToggle.checked = Boolean(state.auditPersist);
  }
}

function resetSessionToZero({ silent = false, wipeDomOnly = false } = {}) {
  fileController.cancelPendingFileRead();
  cancelPendingLiveSanitize();
  cancelPendingLiveAudit();
  hideInlineAlert("input-error-banner");
  hideInlineAlert("rehydrate-error-banner");
  clearCopyFeedback(getEl("copy-sanitized-btn"), () => t("step1.copyBtn"));
  clearCopyFeedback(getEl("copy-restored-btn"), () => t("step2.copyBtn"));

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
    renderPrivacyProofModal(state, getLang());
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
  syncPlanRequestModalMeta(state, lang);
  updateThemeToggleButton(state.theme, lang);
  const proofModal = getEl("modal-privacy-proof");
  if (proofModal && !proofModal.hidden) {
    renderPrivacyProofModal(state, lang);
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
  const result = state.vault.sanitize(state.rawText, state.rules, {
    evolveTransient,
    detectUuid: Boolean(state.detectUuid),
  });
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
  fileController.cancelPendingFileRead();
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

function bindEvents() {
  getEl("lang-ru-btn")?.addEventListener("click", () => {
    state.lang = saveLanguage("ru");
    applyLanguage(state.lang, { onAfterApply: rerenderAll });
  });
  getEl("lang-en-btn")?.addEventListener("click", () => {
    state.lang = saveLanguage("en");
    applyLanguage(state.lang, { onAfterApply: rerenderAll });
  });

  // Mode tabs & navigation
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

  const detectUuidToggle = getEl("detect-uuid-toggle");
  detectUuidToggle?.addEventListener("change", () => {
    state.detectUuid = Boolean(detectUuidToggle.checked);
    runSanitizePipeline(false);
  });

  const rawInput = getEl("raw-prompt-input");
  rawInput?.addEventListener("input", () => {
    fileController.cancelPendingFileRead();
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
    fileController.cancelPendingFileRead();
    cancelPendingLiveSanitize();
    cancelPendingLiveAudit();
    hideInlineAlert("input-error-banner");
    clearCopyFeedback(getEl("copy-sanitized-btn"), () => t("step1.copyBtn"));
    state.rawText = "";
    state.activePresetId = "";
    state.showAllCategories = false;
    state.highlightedToken = "";
    state.pinnedToken = "";
    state.vault.reset();
    if (rawInput) rawInput.value = "";
    runSanitizePipeline(false);
  });

  getEl("paste-raw-btn")?.addEventListener("click", () =>
    readClipboardForInput({
      inputEl: rawInput,
      showStatusBanner,
      onTextRead: (text) => {
        fileController.cancelPendingFileRead();
        cancelPendingLiveSanitize();
        cancelPendingLiveAudit();
        hideInlineAlert("input-error-banner");
        state.vault.reset();
        state.activePresetId = "";
        state.showAllCategories = false;
        state.highlightedToken = "";
        state.pinnedToken = "";
        state.rawText = text;
        if (rawInput) rawInput.value = text;
        runSanitizePipeline(true);
      },
    })
  );

  getEl("toggle-reveal-btn")?.addEventListener("click", () => {
    state.revealVaultValues = !state.revealVaultValues;
    refreshWorkbenchUi();
  });

  getEl("copy-sanitized-btn")?.addEventListener("click", async () => {
    const text = ensureFreshSanitizedOutput();
    await copyWithFeedback({
      text,
      buttonEl: getEl("copy-sanitized-btn"),
      resetLabelGetter: () => t("step1.copyBtn"),
      showStatusBanner,
      skipEmpty: true,
    });
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
    clearCopyFeedback(getEl("copy-restored-btn"), () => t("step2.copyBtn"));
    if (llmInput) llmInput.value = "";
    state.llmReply = "";
    state.lastRehydrateResult = null;
    refreshWorkbenchUi();
  });

  getEl("paste-rehydrate-btn")?.addEventListener("click", () =>
    readClipboardForInput({
      inputEl: llmInput,
      showStatusBanner,
      onTextRead: (text) => {
        hideInlineAlert("rehydrate-error-banner");
        state.llmReply = text;
        state.lastRehydrateResult = null;
        if (llmInput) llmInput.value = text;
        refreshWorkbenchUi();
        llmInput?.focus();
      },
    })
  );

  getEl("copy-restored-btn")?.addEventListener("click", async () => {
    const text = state.lastRehydrateResult?.rehydratedText || "";
    await copyWithFeedback({
      text,
      buttonEl: getEl("copy-restored-btn"),
      resetLabelGetter: () => t("step2.copyBtn"),
      showStatusBanner,
    });
  });

  getEl("download-restored-btn")?.addEventListener("click", () => {
    const text = state.lastRehydrateResult?.rehydratedText || "";
    if (!text) return;
    downloadTextFile("promptveil-restored.txt", text);
    showStatusBanner("banner.downloaded");
  });

  // Rulebook Add & Export, File Uploads, Pricing & Modals
  getEl("rule-term-input")?.addEventListener("input", () => {
    hideInlineAlert("rulebook-alert");
  });
  getEl("rule-category-input")?.addEventListener("change", () => {
    hideInlineAlert("rulebook-alert");
  });
  getEl("rule-case-input")?.addEventListener("change", () => {
    hideInlineAlert("rulebook-alert");
  });

  getEl("add-rule-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    hideInlineAlert("rulebook-alert");
    const termInput = getEl("rule-term-input");
    const catInput = getEl("rule-category-input");
    const caseInput = getEl("rule-case-input");

    const term = (termInput?.value || "").trim();
    if (!term) {
      showInlineAlert("rulebook-alert", "rulebook.errorEmpty");
      termInput?.focus();
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
      termInput?.focus();
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

  getEl("audit-persist-toggle")?.addEventListener("change", (event) => {
    const nextEnabled = Boolean(event.currentTarget?.checked);
    state.auditPersist = setAuditPersistenceEnabled(nextEnabled, state.auditLog);
  });

  fileController.bindFileAndRuleImportEvents();

  bindPricingEvents({
    state,
    showInlineAlert,
    hideInlineAlert,
    showStatusBanner,
    onStartFree: () => {
      switchMode("sanitize");
      const raw = getEl("raw-prompt-input");
      raw?.scrollIntoView({ behavior: "smooth", block: "center" });
      raw?.focus({ preventScroll: true });
    },
  });

  bindModalAndThemeEvents({
    state,
    hideInlineAlert,
    showStatusBanner,
    onResetSession: () => resetSessionToZero(),
  });

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

  window.addEventListener("pagehide", () => {
    resetSessionToZero({ silent: true });
  });

  window.addEventListener("pageshow", (event) => {
    if (event.persisted) {
      resetSessionToZero({ silent: true });
    }
  });
}

export function init() {
  attachCspViolationTracker();
  onStorageWarning(() => {
    showStatusBanner("banner.storageWarning", {}, true);
  });
  state.lang = loadLanguage();
  setLang(state.lang);
  applyTheme(resolveInitialTheme(), state, { persist: false });
  state.rules = loadRules();
  purgeUnoptedAuditStorage();
  state.auditPersist = isAuditPersistenceEnabled();
  state.auditLog = loadAuditLog();
  const detectUuidToggle = getEl("detect-uuid-toggle");
  if (detectUuidToggle) {
    detectUuidToggle.checked = Boolean(state.detectUuid);
  }
  const persistToggle = getEl("audit-persist-toggle");
  if (persistToggle) {
    persistToggle.checked = Boolean(state.auditPersist);
  }
  bindEvents();
  applyLanguage(state.lang, {
    onAfterApply: () => {
      runSanitizePipeline(false);
      refreshDrawersUi();
      renderPricingSection(getLang());
      renderContactsAndPolicy(getLang());
      updateThemeToggleButton(state.theme, getLang());
    },
  });
  registerOfflineServiceWorker();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
