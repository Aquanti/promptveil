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
  syncProUiState,
  updateThemeToggleButton,
} from "./modals.js";
import { loadActiveProLicense } from "./pro-license.js";
import { bindPricingEvents, syncPlanRequestModalMeta } from "./pricing.js";
import {
  createPipelineController,
  getUnappliedPresetRules,
} from "./pipeline.js";
import {
  hideInlineAlert,
  refreshBannersAndAlerts,
  showInlineAlert,
  showStatusBanner,
} from "./notifications.js";
import {
  DEFAULT_PROFILE_ID,
  getActiveProfile,
  isAuditPersistenceEnabled,
  loadAuditLog,
  loadLanguage,
  loadProfilesStore,
  onStorageWarning,
  purgeUnoptedAuditStorage,
  saveLanguage,
} from "./storage.js";
import {
  PRESETS,
  getLocalizedPromptTemplate,
  getPresetById,
  getPromptTemplates,
} from "./presets.js";
import {
  applyLanguage,
  ensureDictionary,
  getLang,
  setLang,
  t,
} from "./i18n.js";
import { clearCopyFeedback, getEl } from "./dom.js";
import {
  renderBatchQueuePanel,
  renderCategoryChips,
  renderPresetRuleSuggestion,
  renderPresetsBar,
  renderPromptTemplatesBar,
  renderRawMetrics,
  renderRehydrateView,
  renderSanitizedOutput,
  renderTelemetryAndActions,
  renderVaultList,
} from "./render-workbench.js";
import {
  renderAuditList,
  renderRulebookList,
  renderRulebookProfiles,
  renderRulebookWordPacks,
} from "./render-drawers.js";

const state = {
  lang: "ru",
  mode: "sanitize",
  rawText: "",
  llmReply: "",
  activePresetId: "",
  activeTemplateId: "",
  previewTemplateId: "",
  lastSanitizeResult: null,
  lastSanitizedInput: "",
  lastRehydrateResult: null,
  revealVaultValues: true,
  mobileVaultExpanded: false,
  showAllCategories: false,
  highlightedToken: "",
  pinnedToken: "",
  profilesStore: null,
  rules: [],
  auditLog: [],
  auditPersist: false,
  detectUuid: false,
  sensitivity: "normal",
  vault: new SessionVault(),
  lastFocusedTrigger: null,
  activeRequestPlan: "pro",
  lastRequestSummary: "",
  theme: "light",
  proLicense: null,
  batchItems: [],
};

let fileController = null;
const pipeline = createPipelineController({
  state,
  getFileController: () => fileController,
  refreshWorkbenchUi,
  refreshDrawersUi,
  renderPrivacyProofModal,
});

fileController = createFileController({
  getRules: () => state.rules,
  isProActive: () => Boolean(state.proLicense?.isPro),
  showStatusBanner,
  showInlineAlert,
  hideInlineAlert,
  showProUpgradePrompt: pipeline.showProUpgradePrompt,
  hideProUpgradePrompt: pipeline.hideProUpgradePrompt,
  cancelPendingLiveSanitize: pipeline.cancelPendingLiveSanitize,
  cancelPendingLiveAudit: pipeline.cancelPendingLiveAudit,
  onPromptFileLoaded: (text, fileName) => {
    state.batchItems = [];
    state.vault.reset();
    state.activePresetId = "";
    state.activeTemplateId = "";
    state.previewTemplateId = "";
    state.showAllCategories = false;
    state.highlightedToken = "";
    state.pinnedToken = "";
    state.rawText = text;
    const rawInput = getEl("raw-prompt-input");
    if (rawInput) rawInput.value = state.rawText;
    pipeline.runSanitizePipeline(true);
    showStatusBanner("banner.fileLoaded", { name: fileName });
  },
  onBatchFilesLoaded: pipeline.loadBatchFiles,
  onRulesImported: pipeline.handleRulesImported,
});

function refreshPresetsUi() {
  const lang = getLang();
  renderPresetsBar(getEl("preset-bar"), PRESETS, state.activePresetId, lang, pipeline.loadPresetById);
  const preset = getPresetById(state.activePresetId);
  renderPresetRuleSuggestion(getEl("apply-preset-rules-btn"), getEl("preset-rule-hint"), getUnappliedPresetRules(preset, state.rules), lang);
  renderPromptTemplatesBar(getEl("prompt-templates-bar"), getPromptTemplates(lang), {
    isPro: Boolean(state.proLicense?.isPro),
    activeTemplateId: state.activeTemplateId,
    previewTemplateId: state.previewTemplateId,
    lang,
    onSelectTemplate: pipeline.selectPromptTemplate,
  });
}

function refreshWorkbenchUi() {
  const lang = getLang();
  const result = state.lastSanitizeResult;
  const maskedCount = result?.maskedCount ?? 0;
  const hasVaultEntries = state.vault.tokenToEntry.size > 0;

  renderRawMetrics(getEl("raw-metrics"), state.rawText, lang);
  renderSanitizedOutput(getEl("sanitized-output"), state.rawText, result, lang, {
    highlightedToken: state.highlightedToken,
    onTokenHover: pipeline.handleTokenHover,
    onTokenClick: pipeline.scrollToVaultItem,
  });
  renderCategoryChips(
    getEl("category-chips"),
    result,
    state.vault,
    state.showAllCategories,
    lang,
    {
      onToggleCategory: pipeline.toggleCategoryFilter,
      onResetCategories: pipeline.resetCategoryFilters,
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
    onToggleEntity: pipeline.toggleVaultEntity,
    onSelectToken: pipeline.scrollToVaultItem,
    onTokenHover: pipeline.handleTokenHover,
    onVaultItemBlur: pipeline.handleVaultItemBlur,
  });
  renderTelemetryAndActions(
    {
      sanitizedMetricsEl: getEl("sanitized-metrics"),
      rehydrateBadgeEl: getEl("rehydrate-ready-badge"),
      vaultReadyMetaEl: getEl("vault-ready-meta"),
      copySanitizedBtn: getEl("copy-sanitized-btn"),
      mobileStickyCopyBtn: getEl("mobile-sticky-copy-btn"),
      downloadSanitizedBtn: getEl("download-sanitized-btn"),
      copyGoStep2Btn: getEl("copy-goto-step2-btn"),
      toggleRevealBtn: getEl("toggle-reveal-btn"),
    },
    { rawText: state.rawText, result, maskedCount, revealValues: state.revealVaultValues, lang }
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
    { llmReply: state.llmReply, result: state.lastRehydrateResult, maskedCount, hasVaultEntries, lang }
  );
  refreshPresetsUi();
  renderBatchQueuePanel({}, { batchItems: state.batchItems, isPro: Boolean(state.proLicense?.isPro), lang });
  pipeline.renderVaultCollapseState(lang);
  const launchersBar = getEl("ai-launchers-bar");
  if (launchersBar) {
    launchersBar.classList.toggle(
      "is-ready",
      Boolean(state.rawText.trim() && result?.sanitizedText)
    );
  }
  const isStrict = state.sensitivity === "strict";
  for (const [btnId, active] of [
    ["sensitivity-normal-btn", !isStrict],
    ["sensitivity-strict-btn", isStrict],
  ]) {
    const sBtn = getEl(btnId);
    if (sBtn) {
      sBtn.classList.toggle("is-active", active);
      sBtn.setAttribute("aria-pressed", active ? "true" : "false");
    }
  }
  const uuidToggle = getEl("detect-uuid-toggle");
  if (uuidToggle) {
    uuidToggle.checked = Boolean(state.detectUuid || isStrict);
    uuidToggle.disabled = isStrict;
  }
}

function refreshDrawersUi() {
  const lang = getLang();
  const isPro = Boolean(state.proLicense?.isPro);
  renderRulebookProfiles(
    {},
    {
      profiles: state.profilesStore?.profiles || [],
      activeProfileId: state.profilesStore?.activeProfileId || DEFAULT_PROFILE_ID,
      isPro,
      lang,
    }
  );
  renderRulebookWordPacks(null, { isPro });
  renderRulebookList(
    {
      listEl: getEl("rulebook-list"),
      emptyEl: getEl("rulebook-empty"),
      countBadgeEl: getEl("rulebook-count"),
    },
    state.rules,
    lang,
    {
      onToggleRule: pipeline.toggleRuleById,
      onDeleteRule: pipeline.deleteRuleById,
    }
  );
  const mobileRulebookCount = getEl("mobile-rulebook-count");
  if (mobileRulebookCount) {
    mobileRulebookCount.textContent = String(state.rules.length);
  }
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
  const mobileAuditCount = getEl("mobile-audit-count");
  if (mobileAuditCount) {
    const validAuditCount = Array.isArray(state.auditLog)
      ? state.auditLog.filter(
          (receipt) => receipt && typeof receipt === "object" && !Array.isArray(receipt)
        ).length
      : 0;
    mobileAuditCount.textContent = String(validAuditCount);
    mobileAuditCount.hidden = validAuditCount === 0;
  }
  const persistToggle = getEl("audit-persist-toggle");
  if (persistToggle) {
    persistToggle.checked = Boolean(state.auditPersist);
  }
}

function rerenderAll() {
  const lang = getLang();
  refreshWorkbenchUi();
  refreshDrawersUi();
  refreshBannersAndAlerts(lang);
  renderContactsAndPolicy(lang);
  syncPlanRequestModalMeta(state, lang);
  syncProUiState(state, lang);
  updateThemeToggleButton(state.theme, lang);
  const proofModal = getEl("modal-privacy-proof");
  if (proofModal && !proofModal.hidden) {
    renderPrivacyProofModal(state, lang);
  }
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
  if (!isSanitize && state.rawText.trim() && state.rawText !== state.lastSanitizedInput && getEl("live-sanitize-toggle")?.checked) {
    pipeline.ensureFreshSanitizedOutput();
  }
  refreshWorkbenchUi();
}

function bindEvents() {
  getEl("lang-ru-btn")?.addEventListener("click", async () => {
    state.lang = saveLanguage("ru");
    await applyLanguage(state.lang, { onAfterApply: rerenderAll });
  });
  getEl("lang-en-btn")?.addEventListener("click", async () => {
    state.lang = saveLanguage("en");
    await applyLanguage(state.lang, { onAfterApply: rerenderAll });
  });
  getEl("lang-mobile-toggle")?.addEventListener("click", async () => {
    const nextLang = getLang() === "en" ? "ru" : "en";
    state.lang = saveLanguage(nextLang);
    await applyLanguage(state.lang, { onAfterApply: rerenderAll });
  });

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
    const text = pipeline.ensureFreshSanitizedOutput();
    if (!text) return;
    const ok = await copyTextToClipboard(text);
    showStatusBanner(ok ? "banner.copied" : "banner.copyFailed", {}, !ok);
    switchMode("rehydrate");
    getEl("llm-reply-input")?.focus();
  });
  getEl("back-to-sanitize-btn")?.addEventListener("click", () => switchMode("sanitize"));
  getEl("quick-reset-session-btn")?.addEventListener("click", () =>
    pipeline.resetSessionToZero()
  );

  const liveToggle = getEl("live-sanitize-toggle");
  liveToggle?.addEventListener("change", () => {
    if (!liveToggle.checked) {
      pipeline.cancelPendingLiveSanitize();
      pipeline.cancelPendingLiveAudit();
    }
  });

  const detectUuidToggle = getEl("detect-uuid-toggle");
  detectUuidToggle?.addEventListener("change", () => {
    state.detectUuid = Boolean(detectUuidToggle.checked);
    pipeline.runSanitizePipeline(false);
  });

  for (const [btnId, mode] of [
    ["sensitivity-normal-btn", "normal"],
    ["sensitivity-strict-btn", "strict"],
  ]) {
    getEl(btnId)?.addEventListener("click", () => {
      if (state.sensitivity === mode) return;
      state.sensitivity = mode;
      pipeline.runSanitizePipeline(false);
    });
  }

  const rawInput = getEl("raw-prompt-input");
  rawInput?.addEventListener("input", () => {
    fileController.cancelPendingFileRead();
    hideInlineAlert("input-error-banner");
    state.rawText = rawInput.value;
    renderRawMetrics(getEl("raw-metrics"), state.rawText, getLang());

    if (state.rawText.trim().length === 0) {
      pipeline.cancelPendingLiveSanitize();
      pipeline.cancelPendingLiveAudit();
      state.activePresetId = "";
      state.activeTemplateId = "";
      state.showAllCategories = false;
      state.highlightedToken = "";
      state.pinnedToken = "";
      pipeline.runSanitizePipeline(false);
      return;
    }

    if (state.activePresetId) {
      const activePreset = getPresetById(state.activePresetId);
      if (!activePreset || state.rawText !== activePreset.text) {
        state.activePresetId = "";
        refreshPresetsUi();
      }
    }
    if (state.activeTemplateId) {
      const activeTpl = getLocalizedPromptTemplate(state.activeTemplateId, getLang());
      if (!activeTpl || state.rawText !== activeTpl.text) {
        state.activeTemplateId = "";
        refreshPresetsUi();
      }
    }

    if (liveToggle && liveToggle.checked) {
      pipeline.scheduleLiveSanitize(state.rawText, () => Boolean(liveToggle.checked));
    }
  });

  getEl("sanitize-now-btn")?.addEventListener("click", () => {
    pipeline.cancelPendingLiveSanitize();
    pipeline.cancelPendingLiveAudit();
    hideInlineAlert("input-error-banner");
    if (rawInput) state.rawText = rawInput.value;
    pipeline.runSanitizePipeline(true);
  });

  getEl("clear-raw-btn")?.addEventListener("click", () => {
    fileController.cancelPendingFileRead();
    pipeline.cancelPendingLiveSanitize();
    pipeline.cancelPendingLiveAudit();
    hideInlineAlert("input-error-banner");
    pipeline.hideProUpgradePrompt();
    clearCopyFeedback(getEl("copy-sanitized-btn"), () => t("step1.copyBtn"));
    clearCopyFeedback(getEl("mobile-sticky-copy-btn"), () => t("step1.mobileStickyCta"));
    state.batchItems = [];
    state.rawText = "";
    state.activePresetId = "";
    state.activeTemplateId = "";
    state.previewTemplateId = "";
    state.showAllCategories = false;
    state.highlightedToken = "";
    state.pinnedToken = "";
    state.vault.reset();
    if (rawInput) rawInput.value = "";
    pipeline.runSanitizePipeline(false);
  });

  getEl("paste-raw-btn")?.addEventListener("click", () =>
    readClipboardForInput({
      inputEl: rawInput,
      showStatusBanner,
      onTextRead: (text) => {
        fileController.cancelPendingFileRead();
        pipeline.cancelPendingLiveSanitize();
        pipeline.cancelPendingLiveAudit();
        hideInlineAlert("input-error-banner");
        pipeline.hideProUpgradePrompt();
        state.batchItems = [];
        state.vault.reset();
        state.activePresetId = "";
        state.activeTemplateId = "";
        state.previewTemplateId = "";
        state.showAllCategories = false;
        state.highlightedToken = "";
        state.pinnedToken = "";
        state.rawText = text;
        if (rawInput) rawInput.value = text;
        pipeline.runSanitizePipeline(true);
      },
    })
  );

  getEl("toggle-reveal-btn")?.addEventListener("click", () => {
    state.revealVaultValues = !state.revealVaultValues;
    refreshWorkbenchUi();
  });

  getEl("vault-collapse-btn")?.addEventListener("click", () => {
    state.mobileVaultExpanded = !state.mobileVaultExpanded;
    pipeline.renderVaultCollapseState(getLang());
  });

  getEl("copy-sanitized-btn")?.addEventListener("click", async () => {
    const text = pipeline.ensureFreshSanitizedOutput();
    await copyWithFeedback({
      text,
      buttonEl: getEl("copy-sanitized-btn"),
      resetLabelGetter: () => t("step1.copyBtn"),
      showStatusBanner,
      skipEmpty: true,
    });
  });

  getEl("mobile-sticky-copy-btn")?.addEventListener("click", async () => {
    const text = pipeline.ensureFreshSanitizedOutput();
    if (!text) return;
    await copyWithFeedback({
      text,
      buttonEl: getEl("mobile-sticky-copy-btn"),
      resetLabelGetter: () => t("step1.mobileStickyCta"),
      showStatusBanner,
      skipEmpty: true,
    });
    const prefersReducedMotion =
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    getEl("ai-launchers-bar")?.scrollIntoView({
      behavior: prefersReducedMotion ? "auto" : "smooth",
      block: "center",
    });
  });

  getEl("download-sanitized-btn")?.addEventListener("click", () => {
    const text = pipeline.ensureFreshSanitizedOutput();
    if (!text) return;
    downloadTextFile("promptveil-sanitized.txt", text);
    showStatusBanner("banner.downloaded");
  });

  getEl("ai-launchers-bar")?.addEventListener("click", (event) => {
    const pill =
      event.target instanceof Element ? event.target.closest("a.ai-launcher-pill") : null;
    if (!pill) return;
    const text = pipeline.ensureFreshSanitizedOutput();
    if (!text.trim()) return;
    showStatusBanner("banner.copiedForAi");
    void copyTextToClipboard(text).then((ok) => {
      if (!ok) {
        showStatusBanner("banner.copyFailed", {}, true);
      }
    });
  });

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
    pipeline.runRehydratePipeline(llmInput?.value || "");
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

  pipeline.bindRulebookAndAuditEvents(downloadTextFile);
  pipeline.bindBatchEvents({ downloadTextFile, switchMode, isProActive: () => Boolean(state.proLicense?.isPro) });
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
    showInlineAlert,
    hideInlineAlert,
    showStatusBanner,
    onResetSession: () => pipeline.resetSessionToZero(),
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
    pipeline.setTokenHighlight(prev, false);
  });

  window.addEventListener("pagehide", () => {
    pipeline.resetSessionToZero({ silent: true });
  });

  window.addEventListener("pageshow", (event) => {
    if (event.persisted) {
      pipeline.resetSessionToZero({ silent: true });
    }
  });
}

export async function init() {
  attachCspViolationTracker();
  onStorageWarning(() => {
    showStatusBanner("banner.storageWarning", {}, true);
  });
  state.lang = loadLanguage();
  setLang(state.lang);
  await ensureDictionary(state.lang);
  applyTheme(resolveInitialTheme(), state, { persist: false });
  purgeUnoptedAuditStorage();
  state.auditPersist = isAuditPersistenceEnabled();
  state.auditLog = loadAuditLog();
  state.proLicense = await loadActiveProLicense();
  state.profilesStore = loadProfilesStore(state.lang);
  if (!state.proLicense?.isPro && state.profilesStore.activeProfileId !== DEFAULT_PROFILE_ID) {
    state.profilesStore = { ...state.profilesStore, activeProfileId: DEFAULT_PROFILE_ID };
  }
  state.rules = getActiveProfile(state.profilesStore).rules;
  const detectUuidToggle = getEl("detect-uuid-toggle");
  if (detectUuidToggle) {
    detectUuidToggle.checked = Boolean(state.detectUuid);
  }
  const persistToggle = getEl("audit-persist-toggle");
  if (persistToggle) {
    persistToggle.checked = Boolean(state.auditPersist);
  }
  bindEvents();
  await applyLanguage(state.lang, {
    onAfterApply: () => {
      pipeline.runSanitizePipeline(false);
      refreshDrawersUi();
      renderContactsAndPolicy(getLang());
      syncProUiState(state, getLang());
      updateThemeToggleButton(state.theme, getLang());
    },
  });
  registerOfflineServiceWorker();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    void init();
  });
} else {
  void init();
}
