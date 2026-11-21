/**
 * Step 1 & Step 2 Workbench DOM Renderers (XSS-safe createElement / textContent only).
 */

import { CATEGORIES } from "./detector.js";
import { clearCopyFeedback, clearEl, createEl, getEl } from "./dom.js";
import { getDocumentErrorI18nKey } from "./pro-documents.js";
import {
  getCategoryLabel,
  getCustomRuleTagLabel,
  getDetectionReasonLabel,
  pluralizeRu,
  t,
} from "./i18n.js";

export function renderPresetsBar(container, presets, activePresetId, lang, onSelectPreset) {
  if (!container) return;
  for (const preset of presets) {
    const btn = container.querySelector(`[data-testid="preset-btn-${preset.id}"]`);
    if (!btn) continue;
    const title = preset.titleByLang?.[lang] || preset.title;
    const desc = preset.descriptionByLang?.[lang] || "";
    btn.textContent = title;
    if (desc) {
      btn.setAttribute("title", desc);
    }
    const isActive = activePresetId === preset.id;
    btn.classList.toggle("is-active", isActive);
    btn.setAttribute("aria-pressed", isActive ? "true" : "false");
    if (!btn.dataset.boundPreset) {
      btn.dataset.boundPreset = "1";
      btn.addEventListener("click", () => {
        if (typeof onSelectPreset === "function") {
          onSelectPreset(preset.id);
        }
      });
    }
  }
}

export function renderPresetRuleSuggestion(btnEl, hintEl, unappliedRules, lang) {
  if (!btnEl) return;
  if (Array.isArray(unappliedRules) && unappliedRules.length > 0) {
    btnEl.textContent = t("presets.applyRulesBtn", { count: unappliedRules.length }, lang);
    btnEl.hidden = false;
    if (hintEl) {
      const terms = unappliedRules.map((r) => r.term).join(", ");
      hintEl.textContent = t("presets.applyRulesHint", { terms }, lang);
      hintEl.hidden = false;
    }
  } else {
    btnEl.hidden = true;
    if (hintEl) {
      hintEl.textContent = "";
      hintEl.hidden = true;
    }
  }
}

export function renderRawMetrics(el, text, lang) {
  if (!el) return;
  const charCount = text.length;
  const lineCount = text.length === 0 ? 0 : text.split(/\r?\n/).length;
  if (lang === "en") {
    const charWord = charCount === 1 ? "char" : "chars";
    const lineWord = lineCount === 1 ? "line" : "lines";
    el.textContent = `${charCount} ${charWord} • ${lineCount} ${lineWord}`;
  } else {
    const charWord = pluralizeRu(charCount, "символ", "символа", "символов");
    const lineWord = pluralizeRu(lineCount, "строка", "строки", "строк");
    el.textContent = `${charCount} ${charWord} • ${lineCount} ${lineWord}`;
  }
}

export function renderSanitizedOutput(
  container,
  rawText,
  result,
  lang,
  { highlightedToken = "", onTokenHover, onTokenClick } = {}
) {
  if (!container) return;
  clearEl(container);

  if (!rawText || rawText.trim().length === 0) {
    return;
  }

  const segments = Array.isArray(result?.segments) ? result.segments : [];
  if (segments.length === 0) {
    container.appendChild(document.createTextNode(result?.sanitizedText ?? rawText));
    return;
  }

  for (const seg of segments) {
    if (seg.type === "token") {
      const tokenStr = seg.token || seg.text;
      const segLabel =
        seg.category === "CUSTOM" && seg.ruleCategory
          ? getCustomRuleTagLabel(seg.ruleCategory, lang)
          : getCategoryLabel(seg.category, lang);

      const markClass =
        highlightedToken && highlightedToken === tokenStr
          ? "token-chip token-chip--redact is-highlighted"
          : "token-chip token-chip--redact";
      const mark = createEl("mark", markClass, seg.text, {
        "data-token": tokenStr,
        "data-category": seg.category || "",
        tabindex: "0",
        title: t("step1.tokenTooltip", { label: segLabel }, lang),
      });

      mark.addEventListener("mouseenter", () => onTokenHover?.(tokenStr, true));
      mark.addEventListener("mouseleave", () => onTokenHover?.(tokenStr, false));
      mark.addEventListener("focus", () => onTokenHover?.(tokenStr, true));
      mark.addEventListener("blur", () => onTokenHover?.(tokenStr, false));
      mark.addEventListener("click", () => onTokenClick?.(tokenStr));
      mark.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onTokenClick?.(tokenStr);
        }
      });

      container.appendChild(mark);
    } else {
      container.appendChild(document.createTextNode(seg.text));
    }
  }
}

export function renderCategoryChips(
  container,
  result,
  vault,
  showAllCategories,
  lang,
  { onToggleCategory, onResetCategories, onToggleShowAll } = {}
) {
  if (!container) return;
  clearEl(container);

  const countsByCategory = result?.countsByCategory || {};
  const maskedCount = Number(result?.maskedCount ?? 0);

  const allChip = createEl("button", "cat-chip", null, {
    type: "button",
    "data-category": "ALL",
    "data-count": String(maskedCount),
    "aria-pressed": vault.disabledCategories.size === 0 ? "true" : "false",
  });
  allChip.appendChild(createEl("span", "", t("step1.allCategories", {}, lang)));
  allChip.appendChild(createEl("span", "cat-chip-count tabular-nums", String(maskedCount)));
  allChip.addEventListener("click", () => onResetCategories?.());
  container.appendChild(allChip);

  let unusedCount = 0;

  for (const meta of CATEGORIES) {
    const count = Number(countsByCategory[meta.category] || 0);
    const isDisabled = vault.disabledCategories.has(meta.category);
    const isVisible = count > 0 || isDisabled || showAllCategories;
    if (count === 0 && !isDisabled) {
      unusedCount += 1;
    }

    const classes = ["cat-chip"];
    if (meta.secondary) classes.push("cat-chip--secondary");
    if (isDisabled) classes.push("cat-chip--disabled");
    const chipClass = classes.join(" ");
    const chip = createEl("button", chipClass, null, {
      type: "button",
      "data-category": meta.category,
      "data-count": String(count),
      "aria-pressed": isDisabled ? "false" : "true",
    });
    if (!isVisible) {
      chip.hidden = true;
    }
    chip.appendChild(createEl("span", "", getCategoryLabel(meta.category, lang)));
    chip.appendChild(createEl("span", "cat-chip-count tabular-nums", String(count)));
    chip.addEventListener("click", () => onToggleCategory?.(meta.category));
    container.appendChild(chip);
  }

  if (unusedCount > 0) {
    const label = showAllCategories
      ? t("step1.hideEmptyCategories", {}, lang)
      : t("step1.showAllCategories", { count: unusedCount }, lang);
    const toggleAllBtn = createEl("button", "cat-chip cat-chip--toggle-all", label, {
      type: "button",
      "data-testid": "toggle-all-categories-btn",
      "aria-expanded": showAllCategories ? "true" : "false",
      "aria-pressed": showAllCategories ? "true" : "false",
    });
    toggleAllBtn.addEventListener("click", () => onToggleShowAll?.());
    container.appendChild(toggleAllBtn);
  }
}

export function renderVaultList(
  container,
  result,
  {
    revealValues,
    highlightedToken,
    lang,
    onToggleEntity,
    onSelectToken,
    onTokenHover,
    onVaultItemBlur,
  } = {}
) {
  if (!container) return;
  clearEl(container);

  const allEntries = Array.isArray(result?.vaultEntries) ? result.vaultEntries : [];
  if (allEntries.length === 0) {
    const emptyItem = createEl(
      "li",
      "vault-empty empty-state",
      t("step1.vaultEmpty", {}, lang),
      {
        id: "vault-empty-state",
        "data-empty": "true",
      }
    );
    container.appendChild(emptyItem);
    return;
  }

  for (const entry of allEntries) {
    const isHighlighted = Boolean(highlightedToken && highlightedToken === entry.token);
    const reasonText = getDetectionReasonLabel(entry, lang);
    const rowClasses = ["vault-row"];
    if (!entry.enabled) rowClasses.push("is-unmasked");
    if (isHighlighted) rowClasses.push("is-highlighted");

    const li = createEl("li", rowClasses.join(" "), null, {
      "data-testid": "vault-item",
      "data-token": entry.token,
      "data-category": entry.category,
      "data-value": entry.value,
      "data-enabled": entry.enabled ? "true" : "false",
      "data-reason": reasonText,
      title: reasonText,
      tabindex: "-1",
    });

    li.addEventListener("mouseenter", () => onTokenHover?.(entry.token, true));
    li.addEventListener("mouseleave", () => onTokenHover?.(entry.token, false));
    li.addEventListener("focusout", (event) => {
      if (!li.contains(event.relatedTarget)) {
        onVaultItemBlur?.(entry.token);
      }
    });

    const displayCategory =
      entry.category === "CUSTOM" && entry.ruleCategory
        ? getCustomRuleTagLabel(entry.ruleCategory, lang)
        : getCategoryLabel(entry.category, lang);

    const tokenCol = createEl("div", "vault-token-col");
    const tokenChip = createEl("code", "vault-token-code", entry.token, {
      "data-testid": "vault-token",
    });
    tokenChip.addEventListener("click", () => onSelectToken?.(entry.token));
    tokenCol.appendChild(tokenChip);
    tokenCol.appendChild(createEl("span", "vault-category-tag", displayCategory));
    li.appendChild(tokenCol);

    const valueCol = createEl("div", "vault-value-col");
    const valSpan = createEl(
      "span",
      revealValues ? "vault-value-text" : "vault-value-text vault-value--obfuscated",
      revealValues ? entry.value : "••••••••",
      {
        "data-testid": "vault-value",
      }
    );
    valueCol.appendChild(valSpan);
    valueCol.appendChild(
      createEl(
        "span",
        "vault-hits-badge tabular-nums",
        t("step1.hits", { count: entry.count }, lang)
      )
    );
    valueCol.appendChild(
      createEl("span", "vault-reason", reasonText, {
        "data-testid": "vault-reason",
        "data-reason": reasonText,
        title: reasonText,
      })
    );
    li.appendChild(valueCol);

    const actionsCol = createEl("div", "vault-actions-col");
    const switchBtn = createEl(
      "button",
      "switch-btn",
      entry.enabled ? t("step1.itemOn", {}, lang) : t("step1.itemOff", {}, lang),
      {
        type: "button",
        role: "switch",
        "aria-checked": entry.enabled ? "true" : "false",
        "aria-label": `${entry.token} (${displayCategory})`,
        "data-testid": "vault-item-toggle",
      }
    );
    switchBtn.addEventListener("click", () => onToggleEntity?.(entry));
    actionsCol.appendChild(switchBtn);
    li.appendChild(actionsCol);

    container.appendChild(li);
  }
}

export function renderTelemetryAndActions(
  {
    sanitizedMetricsEl,
    rehydrateBadgeEl,
    vaultReadyMetaEl,
    copySanitizedBtn,
    mobileStickyCopyBtn,
    downloadSanitizedBtn,
    copyGoStep2Btn,
    toggleRevealBtn,
  },
  { rawText, result, maskedCount = 0, revealValues, lang }
) {
  if (sanitizedMetricsEl) {
    sanitizedMetricsEl.setAttribute("data-count", String(maskedCount));
    sanitizedMetricsEl.textContent = t("step1.maskedCount", { count: maskedCount }, lang);
  }
  if (rehydrateBadgeEl) {
    rehydrateBadgeEl.textContent = String(maskedCount);
    rehydrateBadgeEl.hidden = maskedCount === 0;
  }
  if (vaultReadyMetaEl) {
    vaultReadyMetaEl.textContent = t("step2.vaultReady", { count: maskedCount }, lang);
  }

  const hasOutput = Boolean(rawText && rawText.trim().length > 0 && result);
  if (copySanitizedBtn) {
    copySanitizedBtn.disabled = !hasOutput;
    if (!hasOutput) {
      clearCopyFeedback(copySanitizedBtn, () => t("step1.copyBtn", {}, lang));
    } else if (!copySanitizedBtn.hasAttribute("data-copied")) {
      copySanitizedBtn.textContent = t("step1.copyBtn", {}, lang);
    }
  }
  if (mobileStickyCopyBtn) {
    mobileStickyCopyBtn.disabled = !hasOutput;
    if (!hasOutput) {
      clearCopyFeedback(mobileStickyCopyBtn, () => t("step1.mobileStickyCta", {}, lang));
    } else if (!mobileStickyCopyBtn.hasAttribute("data-copied")) {
      mobileStickyCopyBtn.textContent = t("step1.mobileStickyCta", {}, lang);
    }
  }
  if (downloadSanitizedBtn) {
    downloadSanitizedBtn.disabled = !hasOutput;
  }
  if (copyGoStep2Btn) {
    copyGoStep2Btn.disabled = !hasOutput;
  }
  if (toggleRevealBtn) {
    toggleRevealBtn.setAttribute("aria-pressed", revealValues ? "false" : "true");
    toggleRevealBtn.textContent = revealValues
      ? t("step1.hideValues", {}, lang)
      : t("step1.showValues", {}, lang);
  }
}

export function renderRehydrateView(
  {
    outputEl,
    warningEl,
    metricsEl,
    sessionNoticeEl,
    copyBtn,
    downloadBtn,
  },
  { llmReply, result, maskedCount = 0, hasVaultEntries = false, lang }
) {
  if (sessionNoticeEl) {
    sessionNoticeEl.hidden = Boolean(hasVaultEntries || maskedCount > 0);
    sessionNoticeEl.textContent = t("step2.emptySessionNotice", {}, lang);
  }

  if (!outputEl) return;
  clearEl(outputEl);

  if (!result || !llmReply || llmReply.trim().length === 0) {
    if (warningEl) {
      clearEl(warningEl);
      warningEl.hidden = true;
    }
    if (metricsEl) {
      metricsEl.textContent = t("step2.restoredCount", { count: 0 }, lang);
    }
    if (copyBtn) {
      copyBtn.disabled = true;
      clearCopyFeedback(copyBtn, () => t("step2.copyBtn", {}, lang));
    }
    if (downloadBtn) downloadBtn.disabled = true;
    return;
  }

  if (warningEl) {
    clearEl(warningEl);
    if (Array.isArray(result.unresolvedTokens) && result.unresolvedTokens.length > 0) {
      warningEl.appendChild(
        document.createTextNode(t("step2.unresolvedWarning", {}, lang))
      );
      for (const tok of result.unresolvedTokens) {
        warningEl.appendChild(createEl("code", "unresolved-chip", tok));
      }
      warningEl.hidden = false;
    } else {
      warningEl.hidden = true;
    }
  }

  const segments = Array.isArray(result.segments) ? result.segments : [];
  if (segments.length === 0) {
    outputEl.appendChild(document.createTextNode(result.rehydratedText || ""));
  } else {
    for (const seg of segments) {
      if (seg.type === "restored") {
        const mark = createEl(
          "mark",
          "token-chip token-chip--restore restored-token",
          seg.text,
          {
            title: t("step2.restoredTooltip", { token: seg.token || "token" }, lang),
          }
        );
        outputEl.appendChild(mark);
      } else {
        outputEl.appendChild(document.createTextNode(seg.text));
      }
    }
  }

  if (metricsEl) {
    metricsEl.textContent = t(
      "step2.restoredCount",
      { count: result.replacedCount || 0 },
      lang
    );
  }
  const hasRestoredText = Boolean(result.rehydratedText && result.rehydratedText.length > 0);
  if (copyBtn) {
    copyBtn.disabled = !hasRestoredText;
    if (!hasRestoredText) {
      clearCopyFeedback(copyBtn, () => t("step2.copyBtn", {}, lang));
    } else if (!copyBtn.hasAttribute("data-copied")) {
      copyBtn.textContent = t("step2.copyBtn", {}, lang);
    }
  }
  if (downloadBtn) {
    downloadBtn.disabled = !hasRestoredText;
  }
}

export function renderBatchQueuePanel(
  els = {},
  { batchItems = [], isPro = false, lang = "ru" } = {}
) {
  const panelEl = els.panelEl || getEl("batch-queue-panel");
  const listEl = els.listEl || getEl("batch-queue-list");
  const metaEl = els.metaEl || getEl("batch-queue-meta");
  const downloadTxtBtn = els.downloadTxtBtn || getEl("batch-download-txt-btn");
  const downloadZipBtn = els.downloadZipBtn || getEl("batch-download-zip-btn");
  const rehydrateBtn = els.rehydrateBtn || getEl("batch-rehydrate-btn");

  if (!panelEl || !listEl) return;
  const items = Array.isArray(batchItems) ? batchItems : [];
  if (!isPro || items.length === 0) {
    panelEl.hidden = true;
    clearEl(listEl);
    if (metaEl) metaEl.textContent = "";
    if (downloadTxtBtn) downloadTxtBtn.disabled = true;
    if (downloadZipBtn) downloadZipBtn.disabled = true;
    if (rehydrateBtn) rehydrateBtn.disabled = true;
    return;
  }

  panelEl.hidden = false;
  clearEl(listEl);

  let totalMasked = 0;
  let hasDownloadable = false;

  for (const item of items) {
    const isErr = item.status === "error";
    const isScanned = Boolean(item.isScannedPdf);
    const maskedCount = Number(item.maskedCount || 0);
    if (!isErr) totalMasked += maskedCount;
    if (!isErr && !isScanned && String(item.sanitizedText || "").trim().length > 0) {
      hasDownloadable = true;
    }

    const rowClasses = ["batch-queue-item"];
    if (isErr) rowClasses.push("is-error");
    else if (isScanned) rowClasses.push("is-warning");

    const li = createEl("li", rowClasses.join(" "), null, {
      "data-testid": "batch-queue-item",
      "data-status": isErr ? "error" : isScanned ? "scanned" : "ok",
    });

    const head = createEl("div", "batch-queue-item-head");
    const titleGroup = createEl("div", "batch-queue-item-title-group");
    titleGroup.appendChild(createEl("span", "batch-queue-name", item.name || ""));
    const extBadge = String(item.ext || "").replace(/^\./, "").toUpperCase() || "FILE";
    titleGroup.appendChild(createEl("span", "batch-queue-ext", extBadge));
    head.appendChild(titleGroup);

    if (isErr) {
      const reason = t(getDocumentErrorI18nKey(item.errorCode), {}, lang);
      head.appendChild(
        createEl(
          "span",
          "batch-queue-badge batch-queue-badge--error",
          t("batch.itemError", { reason }, lang)
        )
      );
    } else if (isScanned) {
      head.appendChild(
        createEl(
          "span",
          "batch-queue-badge batch-queue-badge--warn",
          t("batch.itemScannedPdf", {}, lang)
        )
      );
    } else {
      head.appendChild(
        createEl(
          "span",
          "batch-queue-badge tabular-nums",
          t("batch.itemMasked", { count: maskedCount }, lang)
        )
      );
    }
    li.appendChild(head);

    let previewText = "";
    if (isErr) {
      previewText = t(getDocumentErrorI18nKey(item.errorCode), {}, lang);
    } else if (isScanned) {
      previewText = t("batch.itemScannedPdf", {}, lang);
    } else {
      const collapsed = String(item.sanitizedText || "").replace(/\s+/g, " ").trim();
      previewText = collapsed
        ? collapsed.length > 180
          ? `${collapsed.slice(0, 177)}...`
          : collapsed
        : t("batch.itemEmpty", {}, lang);
    }
    li.appendChild(createEl("p", "batch-queue-preview", previewText));
    listEl.appendChild(li);
  }

  if (metaEl) {
    metaEl.textContent = t(
      "batch.metaSummary",
      { files: items.length, masked: totalMasked },
      lang
    );
  }
  if (downloadTxtBtn) downloadTxtBtn.disabled = !hasDownloadable;
  if (downloadZipBtn) downloadZipBtn.disabled = !hasDownloadable;
  if (rehydrateBtn) rehydrateBtn.disabled = !hasDownloadable;
}
