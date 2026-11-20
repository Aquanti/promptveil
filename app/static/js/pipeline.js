/**
 * Sanitize / Rehydrate execution pipeline, live debounce timers, presets, and rulebook/audit actions.
 */

import { clearCopyFeedback, getEl } from "./dom.js";
import { getLang, t } from "./i18n.js";
import { hideInlineAlert, showInlineAlert, showStatusBanner } from "./notifications.js";
import { getLocalizedPreset } from "./presets.js";
import {
  appendAuditReceipt,
  clearAuditLog,
  createRuleId,
  exportAuditJson,
  exportRulesJson,
  makeRuleDedupKey,
  saveRules,
  setAuditPersistenceEnabled,
} from "./storage.js";

function getTimerHost() {
  return typeof window !== "undefined" ? window : globalThis;
}

export function getUnappliedPresetRules(preset, rules = []) {
  if (!preset || !Array.isArray(preset.suggestedRules) || preset.suggestedRules.length === 0) {
    return [];
  }
  const existingKeys = new Set(rules.map(makeRuleDedupKey));
  return preset.suggestedRules.filter((rule) => !existingKeys.has(makeRuleDedupKey(rule)));
}

export function createPipelineController({
  state,
  getFileController,
  refreshWorkbenchUi,
  refreshDrawersUi,
  renderPrivacyProofModal,
}) {
  let liveAuditTimer = null;
  let liveSanitizeTimer = null;

  function cancelPendingLiveAudit() {
    if (liveAuditTimer !== null) {
      getTimerHost().clearTimeout(liveAuditTimer);
      liveAuditTimer = null;
    }
  }

  function cancelPendingLiveSanitize() {
    if (liveSanitizeTimer !== null) {
      getTimerHost().clearTimeout(liveSanitizeTimer);
      liveSanitizeTimer = null;
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
      void recordAuditEntry(
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

  function scheduleLiveSanitize(snapshotText, isLiveEnabledFn) {
    const timerHost = getTimerHost();
    cancelPendingLiveSanitize();
    cancelPendingLiveAudit();
    liveSanitizeTimer = timerHost.setTimeout(() => {
      liveSanitizeTimer = null;
      if (state.rawText === snapshotText && isLiveEnabledFn()) {
        runSanitizePipeline(false, { evolveTransient: true });
      }
    }, 140);
    liveAuditTimer = timerHost.setTimeout(() => {
      liveAuditTimer = null;
      if (
        isLiveEnabledFn() &&
        state.rawText === snapshotText &&
        state.rawText.trim().length > 0 &&
        state.lastSanitizeResult
      ) {
        void recordAuditEntry(
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

  function runRehydratePipeline(reply) {
    if (!reply.trim()) {
      state.llmReply = "";
      state.lastRehydrateResult = null;
      refreshWorkbenchUi();
      showInlineAlert("rehydrate-error-banner", "step2.emptyInputError");
      return null;
    }
    hideInlineAlert("rehydrate-error-banner");
    state.llmReply = reply;
    const res = state.vault.rehydrate(reply);
    state.lastRehydrateResult = res;
    refreshWorkbenchUi();
    void recordAuditEntry("REHYDRATE", reply, res.rehydratedText, [], res.replacedCount, {});
    return res;
  }

  function loadPresetById(presetId) {
    const preset = getLocalizedPreset(presetId, getLang());
    if (!preset) return;
    getFileController()?.cancelPendingFileRead();
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

  function resetSessionToZero({ silent = false, wipeDomOnly = false } = {}) {
    getFileController()?.cancelPendingFileRead();
    cancelPendingLiveSanitize();
    cancelPendingLiveAudit();
    hideInlineAlert("input-error-banner");
    hideInlineAlert("rehydrate-error-banner");
    clearCopyFeedback(getEl("copy-sanitized-btn"), () => t("step1.copyBtn"));
    clearCopyFeedback(getEl("mobile-sticky-copy-btn"), () => t("step1.mobileStickyCta"));
    clearCopyFeedback(getEl("copy-restored-btn"), () => t("step2.copyBtn"));

    state.rawText = "";
    state.llmReply = "";
    state.activePresetId = "";
    state.lastSanitizeResult = null;
    state.lastSanitizedInput = "";
    state.lastRehydrateResult = null;
    state.mobileVaultExpanded = false;
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
    if (proofModal && !proofModal.hidden && renderPrivacyProofModal) {
      renderPrivacyProofModal(state, getLang());
    }
    if (!silent) {
      showStatusBanner("banner.sessionReset");
    }
  }

  function bindRulebookAndAuditEvents(downloadTextFile) {
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
  }

  function renderVaultCollapseState(lang = getLang()) {
    const vaultSection = getEl("vault-section");
    const collapseBtn = getEl("vault-collapse-btn");
    const expanded = Boolean(state.mobileVaultExpanded);
    if (vaultSection) {
      vaultSection.classList.toggle("is-mobile-collapsed", !expanded);
    }
    if (collapseBtn) {
      collapseBtn.setAttribute("aria-expanded", expanded ? "true" : "false");
      collapseBtn.textContent = expanded
        ? t("step1.vaultCollapseBtn", {}, lang)
        : t("step1.vaultExpandBtn", {}, lang);
    }
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
    if (!state.mobileVaultExpanded) {
      state.mobileVaultExpanded = true;
      renderVaultCollapseState();
    }
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
          block: "center",
        });
        item.focus({ preventScroll: true });
        break;
      }
    }
  }

  return {
    cancelPendingLiveAudit,
    cancelPendingLiveSanitize,
    recordAuditEntry,
    runSanitizePipeline,
    ensureFreshSanitizedOutput,
    scheduleLiveSanitize,
    runRehydratePipeline,
    loadPresetById,
    resetSessionToZero,
    bindRulebookAndAuditEvents,
    renderVaultCollapseState,
    setTokenHighlight,
    handleTokenHover,
    handleVaultItemBlur,
    scrollToVaultItem,
  };
}
