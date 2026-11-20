/**
 * Slide-Over Drawer Renderers & Lifecycle («Свои слова» & «Журнал проверок»).
 */

import { clearEl, createEl, getEl, getVisibleFocusableElements } from "./dom.js";
import { getCustomRuleTagLabel, t } from "./i18n.js";

export function renderRulebookList(
  { listEl, emptyEl, countBadgeEl },
  rules,
  lang,
  { onToggleRule, onDeleteRule } = {}
) {
  if (countBadgeEl) {
    countBadgeEl.textContent = String(rules.length);
  }
  if (!listEl || !emptyEl) return;
  clearEl(listEl);

  if (rules.length === 0) {
    emptyEl.hidden = false;
    return;
  }
  emptyEl.hidden = true;

  for (const rule of rules) {
    const li = createEl("li", "drawer-item");

    const topRow = createEl("div", "drawer-item-top");
    topRow.appendChild(createEl("span", "rule-term-text", rule.term));

    const actions = createEl("div", "pane-actions");
    const isEnabled = rule.enabled !== false;
    const toggleBtn = createEl(
      "button",
      "switch-btn",
      isEnabled ? t("step1.itemOn", {}, lang) : t("step1.itemOff", {}, lang),
      {
        type: "button",
        role: "switch",
        "aria-checked": isEnabled ? "true" : "false",
        "aria-label": `${rule.term}`,
      }
    );
    toggleBtn.addEventListener("click", () => onToggleRule?.(rule.id));
    actions.appendChild(toggleBtn);

    const deleteBtn = createEl("button", "btn-danger-ghost", t("common.delete", {}, lang), {
      type: "button",
    });
    deleteBtn.addEventListener("click", () => onDeleteRule?.(rule.id));
    actions.appendChild(deleteBtn);

    topRow.appendChild(actions);
    li.appendChild(topRow);

    const metaRow = createEl("div", "drawer-item-meta");
    metaRow.appendChild(
      createEl("span", "vault-category-tag", getCustomRuleTagLabel(rule.category, lang))
    );
    metaRow.appendChild(
      createEl(
        "span",
        "",
        rule.caseSensitive
          ? t("rulebook.caseSensitive", {}, lang)
          : t("rulebook.caseInsensitive", {}, lang)
      )
    );
    li.appendChild(metaRow);

    listEl.appendChild(li);
  }
}

function formatAuditTimestamp(isoString, lang) {
  const raw = String(isoString || "").trim();
  if (!raw) return "";
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return raw;
  }
  const locale = lang === "en" ? "en-US" : "ru-RU";
  try {
    return new Intl.DateTimeFormat(locale, {
      dateStyle: "short",
      timeStyle: "medium",
    }).format(parsed);
  } catch {
    return parsed.toLocaleString(locale);
  }
}

export function renderAuditList(
  { listEl, emptyEl, countBadgeEl, clearBtnEl, exportBtnEl },
  auditLog,
  lang
) {
  const validLog = Array.isArray(auditLog)
    ? auditLog.filter(
        (receipt) => receipt && typeof receipt === "object" && !Array.isArray(receipt)
      )
    : [];

  if (countBadgeEl) {
    countBadgeEl.textContent = String(validLog.length);
    countBadgeEl.hidden = validLog.length === 0;
  }
  if (clearBtnEl) {
    clearBtnEl.disabled = validLog.length === 0;
  }
  if (exportBtnEl) {
    exportBtnEl.disabled = validLog.length === 0;
  }

  if (!listEl || !emptyEl) return;
  clearEl(listEl);

  if (validLog.length === 0) {
    emptyEl.hidden = false;
    return;
  }
  emptyEl.hidden = true;

  for (const receipt of validLog) {
    const li = createEl("li", "drawer-item");

    const actionCode = receipt.action === "REHYDRATE" ? "REHYDRATE" : "SANITIZE";
    const actionLabel = t(`audit.action.${actionCode}`, {}, lang);

    const topRow = createEl("div", "drawer-item-top");
    topRow.appendChild(createEl("span", "vault-category-tag", actionLabel));
    topRow.appendChild(
      createEl("span", "pane-meta tabular-nums", formatAuditTimestamp(receipt.timestamp, lang))
    );
    li.appendChild(topRow);

    li.appendChild(
      createEl(
        "div",
        "audit-hash-row",
        t(
          "audit.hashLine",
          {
            inHash: String(receipt.inputSha256 || ""),
            outHash: String(receipt.outputSha256 || ""),
          },
          lang
        )
      )
    );

    const detailText =
      actionCode === "REHYDRATE"
        ? t("audit.detailRehydrate", { count: receipt.replacedCount || 0 }, lang)
        : t("audit.detailSanitize", { count: receipt.entityCount || 0 }, lang);
    li.appendChild(createEl("div", "drawer-item-meta", detailText));

    listEl.appendChild(li);
  }
}

export const DIALOG_IDS = Object.freeze([
  "drawer-rulebook",
  "drawer-audit",
  "modal-privacy-proof",
  "modal-plan-request",
  "modal-privacy-policy",
]);

export function getOpenDialogEl() {
  for (const id of DIALOG_IDS) {
    const el = getEl(id);
    if (el && !el.hidden) {
      return el;
    }
  }
  return null;
}

export function closeDrawers(restoreFocus, state) {
  const backdrop = getEl("drawer-backdrop");
  const openRuleBtn = getEl("open-rulebook-btn");
  const openAuditBtn = getEl("open-audit-btn");
  const openProofBtn = getEl("open-proof-btn");
  const footerProofBtn = getEl("footer-open-proof-btn");

  if (openRuleBtn) openRuleBtn.setAttribute("aria-expanded", "false");
  if (openAuditBtn) openAuditBtn.setAttribute("aria-expanded", "false");
  if (openProofBtn) openProofBtn.setAttribute("aria-expanded", "false");
  if (footerProofBtn) footerProofBtn.setAttribute("aria-expanded", "false");
  if (backdrop) backdrop.hidden = true;
  for (const id of DIALOG_IDS) {
    const dlg = getEl(id);
    if (dlg) dlg.hidden = true;
  }

  if (
    restoreFocus &&
    state?.lastFocusedTrigger &&
    typeof state.lastFocusedTrigger.focus === "function"
  ) {
    state.lastFocusedTrigger.focus();
    state.lastFocusedTrigger = null;
  }
}

export function openDrawer(drawerId, triggerEl, state) {
  closeDrawers(false, state);
  if (state) {
    state.lastFocusedTrigger = triggerEl || document.activeElement;
  }
  const backdrop = getEl("drawer-backdrop");
  const drawer = getEl(drawerId);
  const openRuleBtn = getEl("open-rulebook-btn");
  const openAuditBtn = getEl("open-audit-btn");
  const openProofBtn = getEl("open-proof-btn");
  const footerProofBtn = getEl("footer-open-proof-btn");

  if (openRuleBtn) {
    openRuleBtn.setAttribute(
      "aria-expanded",
      drawerId === "drawer-rulebook" ? "true" : "false"
    );
  }
  if (openAuditBtn) {
    openAuditBtn.setAttribute(
      "aria-expanded",
      drawerId === "drawer-audit" ? "true" : "false"
    );
  }
  if (openProofBtn) {
    openProofBtn.setAttribute(
      "aria-expanded",
      drawerId === "modal-privacy-proof" ? "true" : "false"
    );
  }
  if (footerProofBtn) {
    footerProofBtn.setAttribute(
      "aria-expanded",
      drawerId === "modal-privacy-proof" ? "true" : "false"
    );
  }
  if (backdrop) backdrop.hidden = false;
  if (drawer) {
    drawer.hidden = false;
    const focusables = getVisibleFocusableElements(drawer);
    if (focusables.length > 0) {
      focusables[0].focus();
    }
  }
}
