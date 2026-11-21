/**
 * Slide-Over Drawer Renderers & Lifecycle («Свои слова» & «Журнал проверок»).
 */

import { clearEl, createEl, getEl, getVisibleFocusableElements } from "./dom.js";
import { getCustomRuleTagLabel, t } from "./i18n.js";
import { getLocalizedWordPack } from "./presets.js";
import { DEFAULT_PROFILE_ID } from "./storage.js";

export function renderRulebookProfiles(
  els = {},
  { profiles = [], activeProfileId = DEFAULT_PROFILE_ID, isPro = false, lang = "ru" } = {}
) {
  const selectEl = els.selectEl || getEl("profile-select");
  const deleteBtnEl = els.deleteBtnEl || getEl("profile-delete-btn");
  const tierBadgeEl = els.tierBadgeEl || getEl("profiles-tier-badge");
  const upgradeBannerEl = els.upgradeBannerEl || getEl("rulebook-pro-upgrade-banner");
  const upgradeTextEl = els.upgradeTextEl || getEl("rulebook-pro-upgrade-text");

  const safeProfiles = Array.isArray(profiles) && profiles.length > 0
    ? profiles
    : [{ id: DEFAULT_PROFILE_ID, name: t("rulebook.defaultProfileName", {}, lang), isDefault: true, rules: [] }];

  const visibleProfiles = isPro
    ? safeProfiles
    : safeProfiles.filter((p) => p.isDefault || p.id === DEFAULT_PROFILE_ID);
  const renderedProfiles = visibleProfiles.length > 0 ? visibleProfiles : [safeProfiles[0]];
  const effectiveActiveId = isPro
    ? (renderedProfiles.some((p) => p.id === activeProfileId) ? activeProfileId : renderedProfiles[0].id)
    : renderedProfiles[0].id;

  if (selectEl) {
    clearEl(selectEl);
    for (const profile of renderedProfiles) {
      const displayName =
        profile.isDefault || profile.id === DEFAULT_PROFILE_ID
          ? t("rulebook.defaultProfileName", {}, lang)
          : String(profile.name || "");
      selectEl.appendChild(createEl("option", "", displayName, { value: profile.id }));
    }
    selectEl.value = effectiveActiveId;
  }

  const activeProfile =
    renderedProfiles.find((p) => p.id === effectiveActiveId) || renderedProfiles[0];

  if (tierBadgeEl) {
    tierBadgeEl.hidden = Boolean(isPro);
  }
  if (deleteBtnEl) {
    deleteBtnEl.disabled =
      !isPro || Boolean(activeProfile?.isDefault) || activeProfile?.id === DEFAULT_PROFILE_ID || safeProfiles.length <= 1;
  }
  if (upgradeBannerEl) {
    if (isPro) {
      upgradeBannerEl.hidden = true;
    } else if (!upgradeBannerEl.hidden && upgradeTextEl) {
      const reasonKey = upgradeBannerEl.getAttribute("data-upgrade-key") || "rulebook.profilesProRequired";
      const packKey = upgradeBannerEl.getAttribute("data-upgrade-pack-key") || "";
      const reasonTitle =
        (packKey ? getLocalizedWordPack(packKey, lang)?.title : "") ||
        upgradeBannerEl.getAttribute("data-upgrade-title") ||
        "";
      upgradeTextEl.textContent = t(reasonKey, reasonTitle ? { title: reasonTitle } : {}, lang);
    }
  }
}

export function renderRulebookWordPacks(boxEl = null, { isPro = false } = {}) {
  const box =
    boxEl ||
    (typeof document !== "undefined"
      ? document.querySelector('[data-testid="word-packs-box"]')
      : null);
  const tierBadge = getEl("pro-packs-tier-badge");
  if (tierBadge) {
    tierBadge.hidden = Boolean(isPro);
  }
  if (!box || typeof box.querySelectorAll !== "function") {
    return;
  }
  for (const btn of box.querySelectorAll(".word-pack-btn--pro")) {
    btn.classList.toggle("is-locked", !isPro);
    const lockPill = btn.querySelector(".word-pack-lock");
    if (lockPill) {
      lockPill.hidden = Boolean(isPro);
    }
  }
}

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
    topRow.appendChild(createEl("span", "rule-term-text", rule.term, { "data-term": rule.term }));

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
  "modal-terms",
  "modal-pro-license",
  "modal-pro-downloads",
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
  const openProLicenseBtn = getEl("open-pro-license-btn");
  const openProDownloadsBtn = getEl("open-pro-downloads-btn");

  if (openRuleBtn) openRuleBtn.setAttribute("aria-expanded", "false");
  if (openAuditBtn) openAuditBtn.setAttribute("aria-expanded", "false");
  if (openProofBtn) openProofBtn.setAttribute("aria-expanded", "false");
  if (footerProofBtn) footerProofBtn.setAttribute("aria-expanded", "false");
  if (openProLicenseBtn) openProLicenseBtn.setAttribute("aria-expanded", "false");
  if (openProDownloadsBtn) openProDownloadsBtn.setAttribute("aria-expanded", "false");
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
