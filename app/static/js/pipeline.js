/**
 * Sanitize / Rehydrate execution pipeline, live debounce timers, presets, and rulebook/audit actions.
 */

import { clearCopyFeedback, getEl } from "./dom.js";
import { getLang, t } from "./i18n.js";
import { hideInlineAlert, showInlineAlert, showStatusBanner } from "./notifications.js";
import {
  getLocalizedPreset,
  getLocalizedPromptTemplate,
  getLocalizedWordPack,
  getPresetById,
} from "./presets.js";
import {
  DEFAULT_PROFILE_ID,
  appendAuditReceipt,
  clearAuditLog,
  createProfile,
  createRuleId,
  deleteProfile,
  exportAuditJson,
  exportProfileRulesJson,
  exportRulesJson,
  getActiveProfile,
  makeRuleDedupKey,
  renameProfile,
  saveRules,
  setActiveProfileRules,
  setAuditPersistenceEnabled,
  switchProfile,
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

  function showProUpgradePrompt(reason = "format") {
    const banner = getEl("file-pro-upgrade-banner");
    const textEl = getEl("file-pro-upgrade-text");
    const key =
      reason === "size"
        ? "pro.fileUpgradeSize"
        : reason === "batch"
          ? "pro.fileUpgradeBatch"
          : "pro.fileUpgradeFormat";
    if (textEl) {
      textEl.setAttribute("data-i18n", key);
      textEl.textContent = t(key, {}, getLang());
    }
    if (banner) {
      banner.hidden = false;
    }
  }

  function hideProUpgradePrompt() {
    const banner = getEl("file-pro-upgrade-banner");
    if (banner) {
      banner.hidden = true;
    }
  }

  function showRulebookProUpgradeBanner(
    key = "rulebook.profilesProRequired",
    title = "",
    packKey = ""
  ) {
    const banner = getEl("rulebook-pro-upgrade-banner");
    const textEl = getEl("rulebook-pro-upgrade-text");
    if (textEl) {
      textEl.textContent = t(key, title ? { title } : {}, getLang());
    }
    if (banner) {
      banner.setAttribute("data-upgrade-key", key);
      banner.setAttribute("data-upgrade-title", title || "");
      banner.setAttribute("data-upgrade-pack-key", packKey || "");
      banner.hidden = false;
    }
  }

  function hideRulebookProUpgradeBanner() {
    const banner = getEl("rulebook-pro-upgrade-banner");
    if (banner) {
      banner.hidden = true;
    }
  }

  function commitActiveRules(nextRules) {
    if (state.profilesStore && Array.isArray(state.profilesStore.profiles)) {
      const res = setActiveProfileRules(state.profilesStore, nextRules, { lang: getLang() });
      state.profilesStore = res.store;
      state.rules = res.rules;
    } else {
      state.rules = saveRules(nextRules);
    }
    return state.rules;
  }

  function toggleRuleById(ruleId) {
    commitActiveRules(
      state.rules.map((r) => (r.id === ruleId ? { ...r, enabled: r.enabled === false } : r))
    );
    refreshDrawersUi();
    runSanitizePipeline(false);
  }

  function deleteRuleById(ruleId) {
    hideInlineAlert("rulebook-alert");
    commitActiveRules(state.rules.filter((r) => r.id !== ruleId));
    refreshDrawersUi();
    runSanitizePipeline(false);
  }

  function handleRulesImported({ rules, addedCount, skippedCount }) {
    if (state.profilesStore && Array.isArray(state.profilesStore.profiles)) {
      const defaultProf = state.profilesStore.profiles.find(
        (p) => p.id === DEFAULT_PROFILE_ID || p.isDefault
      );
      const prevDefaultRules = defaultProf ? defaultProf.rules : [];
      const activeBefore = getActiveProfile(state.profilesStore);
      commitActiveRules(rules);
      if (activeBefore.id !== DEFAULT_PROFILE_ID && !activeBefore.isDefault) {
        saveRules(prevDefaultRules);
      }
    } else {
      state.rules = rules;
    }
    refreshDrawersUi();
    runSanitizePipeline(false);
    showInlineAlert(
      "rulebook-alert",
      "rulebook.imported",
      { added: addedCount, skipped: skippedCount },
      "success"
    );
  }

  function applyPresetSuggestedRules() {
    const preset = getPresetById(state.activePresetId);
    const unapplied = getUnappliedPresetRules(preset, state.rules);
    if (unapplied.length === 0) return;

    const toAdd = unapplied.map((r) => ({
      id: createRuleId(),
      term: r.term,
      category: r.category || "CUSTOM",
      caseSensitive: Boolean(r.caseSensitive),
      enabled: true,
    }));
    commitActiveRules([...state.rules, ...toAdd]);
    refreshDrawersUi();
    runSanitizePipeline(false);
    showStatusBanner("banner.presetRulesAdded", { count: toAdd.length });
  }

  function sanitizeBatchItems() {
    if (!Array.isArray(state.batchItems) || state.batchItems.length === 0) {
      return;
    }
    const opts = {
      resetOnEmpty: false,
      detectUuid: Boolean(state.detectUuid),
      sensitivity: state.sensitivity === "strict" ? "strict" : "normal",
    };
    for (const item of state.batchItems) {
      if (item.status === "ok" && !item.isScannedPdf && String(item.text || "").trim().length > 0) {
        const itemRes = state.vault.sanitize(item.text, state.rules, opts);
        item.sanitizedText = itemRes.sanitizedText;
        item.maskedCount = itemRes.maskedCount;
      } else {
        item.sanitizedText = "";
        item.maskedCount = 0;
      }
    }
  }

  function runSanitizePipeline(recordAudit = false, { evolveTransient = false } = {}) {
    const hasBatch = Array.isArray(state.batchItems) && state.batchItems.length > 0;
    if (hasBatch) {
      sanitizeBatchItems();
    }
    const result = state.vault.sanitize(state.rawText, state.rules, {
      evolveTransient,
      resetOnEmpty: !hasBatch,
      detectUuid: Boolean(state.detectUuid),
      sensitivity: state.sensitivity === "strict" ? "strict" : "normal",
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
    hideProUpgradePrompt();
    state.batchItems = [];
    state.vault.reset();
    state.showAllCategories = false;
    state.highlightedToken = "";
    state.pinnedToken = "";
    state.activeTemplateId = "";
    state.previewTemplateId = "";
    state.activePresetId = preset.id;
    state.rawText = preset.text;
    const rawInput = getEl("raw-prompt-input");
    if (rawInput) rawInput.value = preset.text;
    runSanitizePipeline(true);
    showStatusBanner("banner.presetLoaded", (lang) => ({
      title: getLocalizedPreset(preset.id, lang)?.title || preset.title,
    }));
  }

  function selectPromptTemplate(templateId) {
    const lang = getLang();
    const tpl = getLocalizedPromptTemplate(templateId, lang);
    if (!tpl) return;
    if (!state.proLicense?.isPro) {
      state.previewTemplateId = tpl.id;
      refreshWorkbenchUi();
      showStatusBanner("templates.proRequired");
      return;
    }
    getFileController()?.cancelPendingFileRead();
    cancelPendingLiveSanitize();
    cancelPendingLiveAudit();
    hideInlineAlert("input-error-banner");
    hideProUpgradePrompt();
    state.batchItems = [];
    state.vault.reset();
    state.showAllCategories = false;
    state.highlightedToken = "";
    state.pinnedToken = "";
    state.activePresetId = "";
    state.previewTemplateId = "";
    state.activeTemplateId = tpl.id;
    state.rawText = tpl.text;
    const rawInput = getEl("raw-prompt-input");
    if (rawInput) rawInput.value = tpl.text;
    runSanitizePipeline(true);
    showStatusBanner("banner.templateLoaded", (curLang) => ({
      title: getLocalizedPromptTemplate(tpl.id, curLang)?.title || tpl.title,
    }));
  }

  function resetSessionToZero({ silent = false, wipeDomOnly = false } = {}) {
    getFileController()?.cancelPendingFileRead();
    cancelPendingLiveSanitize();
    cancelPendingLiveAudit();
    hideInlineAlert("input-error-banner");
    hideInlineAlert("rehydrate-error-banner");
    hideProUpgradePrompt();
    clearCopyFeedback(getEl("copy-sanitized-btn"), () => t("step1.copyBtn"));
    clearCopyFeedback(getEl("mobile-sticky-copy-btn"), () => t("step1.mobileStickyCta"));
    clearCopyFeedback(getEl("copy-restored-btn"), () => t("step2.copyBtn"));

    state.batchItems = [];
    state.rawText = "";
    state.llmReply = "";
    state.activePresetId = "";
    state.activeTemplateId = "";
    state.previewTemplateId = "";
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

  function applyIndustryWordPack(packKey) {
    const lang = getLang();
    const pack = getLocalizedWordPack(packKey, lang);
    if (!pack) return 0;

    if (pack.isPro && !state.proLicense?.isPro) {
      showRulebookProUpgradeBanner("rulebook.proPackRequired", pack.title, packKey);
      showInlineAlert(
        "rulebook-alert",
        "rulebook.proPackRequired",
        (curLang) => ({ title: getLocalizedWordPack(packKey, curLang)?.title || pack.title }),
        "warn"
      );
      return 0;
    }

    const existingKeys = new Set(state.rules.map(makeRuleDedupKey));
    const toAdd = [];
    for (const rawTerm of pack.terms) {
      const term = String(rawTerm || "").trim();
      if (!term) continue;
      const candidate = {
        id: createRuleId(),
        term,
        category: pack.category || "CUSTOM",
        caseSensitive: false,
        enabled: true,
      };
      const key = makeRuleDedupKey(candidate);
      if (existingKeys.has(key)) continue;
      existingKeys.add(key);
      toAdd.push(candidate);
    }

    if (toAdd.length === 0) {
      showInlineAlert(
        "rulebook-alert",
        "rulebook.packAlreadyApplied",
        (curLang) => ({ title: getLocalizedWordPack(packKey, curLang)?.title || pack.title }),
        "info"
      );
      return 0;
    }

    commitActiveRules([...state.rules, ...toAdd]);
    refreshDrawersUi();
    runSanitizePipeline(false);
    showInlineAlert(
      "rulebook-alert",
      "rulebook.packApplied",
      (curLang) => ({
        title: getLocalizedWordPack(packKey, curLang)?.title || pack.title,
        added: toAdd.length,
      }),
      "success"
    );
    return toAdd.length;
  }

  function bindRulebookAndAuditEvents(downloadTextFile) {
    getEl("apply-preset-rules-btn")?.addEventListener("click", applyPresetSuggestedRules);
    getEl("rule-term-input")?.addEventListener("input", () => {
      hideInlineAlert("rulebook-alert");
    });
    getEl("rule-category-input")?.addEventListener("change", () => {
      hideInlineAlert("rulebook-alert");
    });
    getEl("rule-case-input")?.addEventListener("change", () => {
      hideInlineAlert("rulebook-alert");
    });
    getEl("profile-name-input")?.addEventListener("input", () => {
      hideInlineAlert("rulebook-alert");
    });

    getEl("profile-select")?.addEventListener("change", (event) => {
      hideInlineAlert("rulebook-alert");
      hideRulebookProUpgradeBanner();
      const targetId = String(event.currentTarget?.value || DEFAULT_PROFILE_ID);
      const res = switchProfile(state.profilesStore, targetId, {
        isPro: Boolean(state.proLicense?.isPro),
        lang: getLang(),
      });
      if (!res.ok) {
        if (res.error === "pro_required") {
          showRulebookProUpgradeBanner("rulebook.profilesProRequired");
          showInlineAlert("rulebook-alert", "rulebook.profilesProRequired", {}, "warn");
        }
        refreshDrawersUi();
        return;
      }
      state.profilesStore = res.store;
      state.rules = res.profile.rules;
      refreshDrawersUi();
      runSanitizePipeline(false);
      showInlineAlert(
        "rulebook-alert",
        "rulebook.profileSwitched",
        (curLang) => ({
          name: res.profile.isDefault
            ? t("rulebook.defaultProfileName", {}, curLang)
            : res.profile.name,
        }),
        "info"
      );
    });

    getEl("profile-create-btn")?.addEventListener("click", () => {
      hideInlineAlert("rulebook-alert");
      if (!state.proLicense?.isPro) {
        showRulebookProUpgradeBanner("rulebook.profilesProRequired");
        showInlineAlert("rulebook-alert", "rulebook.profilesProRequired", {}, "warn");
        return;
      }
      const nameInput = getEl("profile-name-input");
      const res = createProfile(state.profilesStore, nameInput?.value || "", {
        isPro: true,
        lang: getLang(),
      });
      if (!res.ok) {
        const errKey =
          res.error === "duplicate" ? "rulebook.profileErrorDuplicate" : "rulebook.profileErrorEmpty";
        showInlineAlert("rulebook-alert", errKey, {}, "error");
        nameInput?.focus();
        return;
      }
      state.profilesStore = res.store;
      state.rules = res.profile.rules;
      if (nameInput) nameInput.value = "";
      hideRulebookProUpgradeBanner();
      refreshDrawersUi();
      runSanitizePipeline(false);
      showInlineAlert(
        "rulebook-alert",
        "rulebook.profileCreated",
        { name: res.profile.name },
        "success"
      );
    });

    getEl("profile-rename-btn")?.addEventListener("click", () => {
      hideInlineAlert("rulebook-alert");
      if (!state.proLicense?.isPro) {
        showRulebookProUpgradeBanner("rulebook.profilesProRequired");
        showInlineAlert("rulebook-alert", "rulebook.profilesProRequired", {}, "warn");
        return;
      }
      const active = getActiveProfile(state.profilesStore);
      const nameInput = getEl("profile-name-input");
      const res = renameProfile(state.profilesStore, active.id, nameInput?.value || "", {
        isPro: true,
        lang: getLang(),
      });
      if (!res.ok) {
        const errKey =
          res.error === "default_protected"
            ? "rulebook.profileErrorRenameDefault"
            : res.error === "duplicate"
              ? "rulebook.profileErrorDuplicate"
              : "rulebook.profileErrorEmpty";
        showInlineAlert("rulebook-alert", errKey, {}, "error");
        nameInput?.focus();
        return;
      }
      state.profilesStore = res.store;
      if (nameInput) nameInput.value = "";
      refreshDrawersUi();
      showInlineAlert(
        "rulebook-alert",
        "rulebook.profileRenamed",
        { name: res.profile.name },
        "success"
      );
    });

    getEl("profile-delete-btn")?.addEventListener("click", () => {
      hideInlineAlert("rulebook-alert");
      if (!state.proLicense?.isPro) {
        showRulebookProUpgradeBanner("rulebook.profilesProRequired");
        showInlineAlert("rulebook-alert", "rulebook.profilesProRequired", {}, "warn");
        return;
      }
      const active = getActiveProfile(state.profilesStore);
      const res = deleteProfile(state.profilesStore, active.id, {
        isPro: true,
        lang: getLang(),
      });
      if (!res.ok) {
        showInlineAlert("rulebook-alert", "rulebook.profileErrorDeleteDefault", {}, "error");
        return;
      }
      state.profilesStore = res.store;
      state.rules = getActiveProfile(res.store).rules;
      refreshDrawersUi();
      runSanitizePipeline(false);
      showInlineAlert(
        "rulebook-alert",
        "rulebook.profileDeleted",
        { name: res.deletedProfile?.name || "" },
        "success"
      );
    });

    getEl("rulebook-pro-upgrade-btn")?.addEventListener("click", () => {
      getEl("open-pro-license-btn")?.click();
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

      commitActiveRules([...state.rules, newRule]);
      if (termInput) termInput.value = "";
      if (caseInput) caseInput.checked = false;
      refreshDrawersUi();
      runSanitizePipeline(false);
      showInlineAlert("rulebook-alert", "rulebook.added", { term }, "success");
    });

    getEl("export-rules-btn")?.addEventListener("click", () => {
      const json =
        state.profilesStore && Array.isArray(state.profilesStore.profiles)
          ? exportProfileRulesJson(getActiveProfile(state.profilesStore))
          : exportRulesJson(state.rules);
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

    for (const packBtn of document.querySelectorAll(".word-pack-btn[data-pack]")) {
      packBtn.addEventListener("click", () => {
        const packKey = packBtn.getAttribute("data-pack");
        if (packKey) {
          applyIndustryWordPack(packKey);
        }
      });
    }
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

  function toggleCategoryFilter(category) {
    state.pinnedToken = "";
    state.highlightedToken = "";
    state.vault.toggleCategory(category);
    runSanitizePipeline(false);
  }

  function resetCategoryFilters() {
    state.pinnedToken = "";
    state.highlightedToken = "";
    state.vault.disabledCategories.clear();
    runSanitizePipeline(false);
  }

  function toggleVaultEntity(entry) {
    state.pinnedToken = "";
    state.highlightedToken = "";
    state.vault.toggleValue(entry.category, entry.value, !entry.enabled);
    runSanitizePipeline(false);
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

  function loadBatchFiles(parsedItems = []) {
    cancelPendingLiveSanitize();
    cancelPendingLiveAudit();
    hideProUpgradePrompt();
    state.vault.reset();
    state.activePresetId = "";
    state.activeTemplateId = "";
    state.previewTemplateId = "";
    state.showAllCategories = false;
    state.highlightedToken = "";
    state.pinnedToken = "";
    state.batchItems = Array.isArray(parsedItems) ? parsedItems.map((it) => ({ ...it })) : [];
    const combinedRaw = state.batchItems
      .filter((it) => it.status === "ok" && !it.isScannedPdf && String(it.text || "").trim().length > 0)
      .map((it) => it.text)
      .join("\n\n");
    state.rawText = combinedRaw;
    const rawInput = getEl("raw-prompt-input");
    if (rawInput) rawInput.value = combinedRaw;

    const result = runSanitizePipeline(true);
    const scannedItem = state.batchItems.find((it) => it.status === "ok" && it.isScannedPdf);
    if (scannedItem) {
      showInlineAlert(
        "input-error-banner",
        "banner.pdfScannedNotice",
        { name: scannedItem.name },
        "warn"
      );
    }
    const totalMasked = state.batchItems.reduce(
      (sum, it) => sum + Number(it.maskedCount || 0),
      0
    );
    showStatusBanner("banner.batchLoaded", {
      count: state.batchItems.length,
      masked: totalMasked || result?.maskedCount || 0,
    });
  }

  function clearBatchQueue({ silent = false } = {}) {
    resetSessionToZero({ silent: true });
    if (!silent) {
      showStatusBanner("banner.batchCleared");
    }
  }

  function buildBatchCombinedSanitizedText() {
    if (!Array.isArray(state.batchItems) || state.batchItems.length === 0) {
      return ensureFreshSanitizedOutput();
    }
    return state.batchItems
      .filter((it) => it.status === "ok" && !it.isScannedPdf && String(it.sanitizedText || "").trim().length > 0)
      .map((it) => `=== ${it.name} ===\n${it.sanitizedText}`)
      .join("\n\n");
  }

  function downloadBatchCombinedTxt(downloadTextFile) {
    ensureFreshSanitizedOutput();
    const combined = buildBatchCombinedSanitizedText();
    if (!combined) return;
    downloadTextFile("promptveil-batch-sanitized.txt", combined, "text/plain;charset=utf-8");
    showStatusBanner("banner.batchTxtDownloaded");
  }

  async function downloadBatchZip(downloadTextFile) {
    ensureFreshSanitizedOutput();
    const okItems = (state.batchItems || []).filter(
      (it) => it.status === "ok" && !it.isScannedPdf && String(it.sanitizedText || "").trim().length > 0
    );
    if (okItems.length === 0) return;

    const usedNames = new Map();
    const entries = okItems.map((it) => {
      const base = String(it.name || "document.txt").replace(/[\\/]/g, "_");
      const dotIdx = base.lastIndexOf(".");
      const stem = dotIdx > 0 ? base.slice(0, dotIdx) : base;
      let candidate = `${stem}.sanitized.txt`;
      const seen = usedNames.get(candidate) || 0;
      usedNames.set(candidate, seen + 1);
      if (seen > 0) {
        candidate = `${stem}.sanitized (${seen + 1}).txt`;
      }
      return { name: candidate, data: it.sanitizedText };
    });

    const { buildZipArchive } = await import("./pro-documents.js");
    const zipBytes = buildZipArchive(entries);
    downloadTextFile("promptveil-batch-sanitized.zip", zipBytes, "application/zip");
    showStatusBanner("banner.batchZipDownloaded");
  }

  function rehydrateBatchAndOpenStep2(switchMode) {
    ensureFreshSanitizedOutput();
    const combined = buildBatchCombinedSanitizedText();
    switchMode?.("rehydrate");
    const llmInput = getEl("llm-reply-input");
    const existingReply = llmInput ? llmInput.value : state.llmReply || "";
    const targetReply = existingReply.trim().length > 0 ? existingReply : combined;
    if (targetReply && targetReply.trim().length > 0) {
      if (llmInput && existingReply.trim().length === 0) {
        llmInput.value = targetReply;
      }
      runRehydratePipeline(targetReply);
    }
    showStatusBanner("banner.batchRehydrateReady");
    llmInput?.focus();
  }

  function bindBatchEvents({ downloadTextFile, switchMode, isProActive } = {}) {
    getEl("file-pro-upgrade-btn")?.addEventListener("click", () => {
      getEl("open-pro-license-btn")?.click();
    });
    getEl("prompt-template-upgrade-btn")?.addEventListener("click", () => {
      getEl("open-pro-license-btn")?.click();
    });
    getEl("batch-clear-btn")?.addEventListener("click", () => clearBatchQueue());
    getEl("batch-download-txt-btn")?.addEventListener("click", () =>
      downloadBatchCombinedTxt(downloadTextFile)
    );
    getEl("batch-download-zip-btn")?.addEventListener("click", () => {
      void downloadBatchZip(downloadTextFile);
    });
    getEl("batch-rehydrate-btn")?.addEventListener("click", () =>
      rehydrateBatchAndOpenStep2(switchMode)
    );

    const proBtn = getEl("open-pro-license-btn");
    if (proBtn && typeof MutationObserver === "function") {
      const observer = new MutationObserver((records) => {
        const currentState = proBtn.getAttribute("data-pro-state");
        const stateChanged = records.some((r) => r.oldValue !== currentState);
        if (!stateChanged) return;
        if (isProActive?.()) {
          hideProUpgradePrompt();
          hideRulebookProUpgradeBanner();
          hideInlineAlert("input-error-banner");
          state.previewTemplateId = "";
        } else {
          state.batchItems = [];
          if (
            state.profilesStore &&
            state.profilesStore.activeProfileId !== DEFAULT_PROFILE_ID
          ) {
            state.profilesStore = {
              ...state.profilesStore,
              activeProfileId: DEFAULT_PROFILE_ID,
            };
            state.rules = getActiveProfile(state.profilesStore).rules;
          }
        }
        runSanitizePipeline(false);
        refreshDrawersUi();
      });
      observer.observe(proBtn, {
        attributes: true,
        attributeFilter: ["data-pro-state"],
        attributeOldValue: true,
      });
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
    selectPromptTemplate,
    applyIndustryWordPack,
    toggleRuleById,
    deleteRuleById,
    handleRulesImported,
    resetSessionToZero,
    bindRulebookAndAuditEvents,
    renderVaultCollapseState,
    setTokenHighlight,
    handleTokenHover,
    handleVaultItemBlur,
    toggleCategoryFilter,
    resetCategoryFilters,
    toggleVaultEntity,
    scrollToVaultItem,
    showProUpgradePrompt,
    hideProUpgradePrompt,
    loadBatchFiles,
    clearBatchQueue,
    downloadBatchCombinedTxt,
    downloadBatchZip,
    rehydrateBatchAndOpenStep2,
    bindBatchEvents,
  };
}
