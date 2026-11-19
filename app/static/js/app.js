/**
 * PromptVeil Thin UI Coordinator.
 * Strict browser-local processing, zero external network requests, zero unsafe HTML sinks.
 */

import { SessionVault } from "./vault.js";
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
  copyTextToClipboard,
  createEl,
  downloadTextFile,
  getEl,
  handleDrawerKeydown,
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
  lastRehydrateResult: null,
  revealVaultValues: true,
  showAllCategories: false,
  highlightedToken: "",
  pinnedToken: "",
  rules: [],
  auditLog: [],
  vault: new SessionVault(),
  lastFocusedTrigger: null,
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

function rerenderAll() {
  refreshWorkbenchUi();
  refreshDrawersUi();
  refreshBannersAndAlerts();
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
  getEl("back-to-sanitize-btn")?.addEventListener("click", () => switchMode("sanitize"));

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
    const text = state.lastSanitizeResult?.sanitizedText || "";
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
    const text = state.lastSanitizeResult?.sanitizedText || "";
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

  // Drawers
  getEl("open-rulebook-btn")?.addEventListener("click", (event) => {
    hideInlineAlert("rulebook-alert");
    openDrawer("drawer-rulebook", event.currentTarget, state);
  });
  getEl("open-audit-btn")?.addEventListener("click", (event) => {
    openDrawer("drawer-audit", event.currentTarget, state);
  });
  getEl("close-rulebook-btn")?.addEventListener("click", () => closeDrawers(true, state));
  getEl("close-audit-btn")?.addEventListener("click", () => closeDrawers(true, state));
  getEl("drawer-backdrop")?.addEventListener("click", () => closeDrawers(true, state));

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
    const ruleDrawer = getEl("drawer-rulebook");
    const auditDrawer = getEl("drawer-audit");
    const openDrawerEl =
      ruleDrawer && !ruleDrawer.hidden
        ? ruleDrawer
        : auditDrawer && !auditDrawer.hidden
          ? auditDrawer
          : null;
    handleDrawerKeydown(event, openDrawerEl, () => closeDrawers(true, state));
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
    },
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
