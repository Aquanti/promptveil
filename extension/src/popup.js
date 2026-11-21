/**
 * PromptVeil Extension Popup Controller.
 * Safe DOM APIs only, zero inline styles, chrome.storage.local only, zero network egress.
 */

import { CATEGORIES } from "../../app/static/js/detector.js";
import { getLocalizedWordPack, INDUSTRY_WORD_PACKS } from "../../app/static/js/presets.js";
import { createFreeLicenseState, verifyProLicenseToken } from "../../app/static/js/pro-license.js";
import { createRuleId, makeRuleDedupKey, normalizeRule } from "../../app/static/js/storage.js";
import { detectSupportedHost, getHostLabel } from "./adapters.js";
import { getCategoryLabel, t } from "./i18n-ext.js";
import {
  clearExtProLicenseToken,
  FREE_CUSTOM_RULE_LIMIT,
  getChromeStorageLocal,
  loadExtProLicenseToken,
  loadExtSettings,
  saveExtProLicenseToken,
  saveExtSettings,
  subscribeExtStorageChanges,
} from "./storage-ext.js";

const TOGGLEABLE_CATEGORIES = CATEGORIES.filter((cat) => cat.category !== "CUSTOM");

function queryActiveTab(tabsApi) {
  if (!tabsApi || typeof tabsApi.query !== "function") {
    return Promise.resolve(null);
  }
  return new Promise((resolve) => {
    let settled = false;
    const done = (tabs) => {
      if (settled) return;
      settled = true;
      resolve(Array.isArray(tabs) && tabs.length > 0 ? tabs[0] : null);
    };
    try {
      const maybePromise = tabsApi.query({ active: true, currentWindow: true }, done);
      if (maybePromise && typeof maybePromise.then === "function") {
        maybePromise.then(done, () => {
          if (!settled) {
            settled = true;
            resolve(null);
          }
        });
      }
    } catch {
      if (!settled) {
        settled = true;
        resolve(null);
      }
    }
  });
}

function formatIsoDate(iso, lang) {
  if (!iso) return "";
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return String(iso);
  try {
    return new Intl.DateTimeFormat(lang === "en" ? "en-US" : "ru-RU", {
      year: "numeric",
      month: "short",
      day: "numeric",
    }).format(new Date(ms));
  } catch {
    return String(iso).slice(0, 10);
  }
}

export async function initPopupController({
  doc = globalThis.document,
  storageArea = getChromeStorageLocal(),
  tabsApi = globalThis.chrome?.tabs,
  storageEvents = globalThis.chrome?.storage?.onChanged,
  publicKeyB64U,
} = {}) {
  if (!doc || !doc.getElementById("pv-popup-root")) {
    return null;
  }

  const els = {
    rootHtml: doc.documentElement,
    brandTitle: doc.getElementById("popup-brand-title"),
    brandTagline: doc.getElementById("popup-brand-tagline"),
    proBadge: doc.getElementById("popup-pro-badge"),
    langRu: doc.getElementById("popup-lang-ru"),
    langEn: doc.getElementById("popup-lang-en"),
    themeBtn: doc.getElementById("popup-theme-btn"),
    themeMoon: doc.getElementById("popup-theme-icon-moon"),
    themeSun: doc.getElementById("popup-theme-icon-sun"),

    siteDot: doc.getElementById("popup-site-dot"),
    siteStatus: doc.getElementById("popup-site-status"),
    siteHosts: doc.getElementById("popup-site-hosts"),

    controlsTitle: doc.getElementById("popup-controls-title"),
    overlayLabel: doc.getElementById("popup-overlay-label"),
    overlayToggle: doc.getElementById("popup-overlay-toggle"),
    sensitivityLabel: doc.getElementById("popup-sensitivity-label"),
    sensNormal: doc.getElementById("popup-sens-normal"),
    sensStrict: doc.getElementById("popup-sens-strict"),
    uuidToggle: doc.getElementById("popup-uuid-toggle"),
    uuidLabel: doc.getElementById("popup-uuid-label"),
    uuidStrictHint: doc.getElementById("popup-uuid-strict-hint"),

    categoriesTitle: doc.getElementById("popup-categories-title"),
    categoriesLock: doc.getElementById("popup-categories-lock"),
    categoriesReset: doc.getElementById("popup-categories-reset"),
    categoriesSummary: doc.getElementById("popup-categories-summary"),
    categoriesProHint: doc.getElementById("popup-categories-pro-hint"),
    categoriesGrid: doc.getElementById("popup-categories-grid"),

    rulesTitle: doc.getElementById("popup-rules-title"),
    customCounter: doc.getElementById("popup-custom-counter"),
    customForm: doc.getElementById("popup-custom-form"),
    customTerm: doc.getElementById("popup-custom-term"),
    customCategory: doc.getElementById("popup-custom-category"),
    customAddBtn: doc.getElementById("popup-custom-add-btn"),
    customAlert: doc.getElementById("popup-custom-alert"),
    customEmpty: doc.getElementById("popup-custom-empty"),
    customList: doc.getElementById("popup-custom-list"),

    packsTitle: doc.getElementById("popup-packs-title"),
    packsLock: doc.getElementById("popup-packs-lock"),
    packsList: doc.getElementById("popup-packs-list"),

    proSection: doc.getElementById("popup-pro-section"),
    proTitle: doc.getElementById("popup-pro-title"),
    proStatusCard: doc.getElementById("popup-pro-status-card"),
    proStatusTitle: doc.getElementById("popup-pro-status-title"),
    proStatusDesc: doc.getElementById("popup-pro-status-desc"),
    proMetaList: doc.getElementById("popup-pro-meta-list"),
    proKeyInput: doc.getElementById("popup-pro-key-input"),
    proAlert: doc.getElementById("popup-pro-alert"),
    proActivateBtn: doc.getElementById("popup-pro-activate-btn"),
    proRemoveBtn: doc.getElementById("popup-pro-remove-btn"),

    footerText: doc.getElementById("popup-footer-text"),
  };

  const state = {
    settings: await loadExtSettings(storageArea),
    license: createFreeLicenseState("none"),
    activeTabHostname: "",
    activeTabAdapter: null,
    customFeedback: null,
    proFeedback: null,
  };

  async function refreshLicenseFromStorage() {
    const rawToken = await loadExtProLicenseToken(storageArea);
    if (!rawToken) {
      state.license = createFreeLicenseState("empty");
      return;
    }
    state.license = await verifyProLicenseToken(
      rawToken,
      publicKeyB64U ? { publicKeyB64U } : undefined
    );
  }

  async function refreshActiveTab() {
    const tab = await queryActiveTab(tabsApi);
    let hostname = "";
    if (tab && typeof tab.url === "string" && tab.url.length > 0) {
      try {
        hostname = new URL(tab.url).hostname;
      } catch {
        hostname = "";
      }
    }
    state.activeTabHostname = hostname;
    state.activeTabAdapter = detectSupportedHost(hostname);
  }

  function showCustomAlert(text, tone = "warn") {
    state.customFeedback = { text, tone };
    renderCustomAlert();
  }

  function clearCustomAlert() {
    state.customFeedback = null;
    renderCustomAlert();
  }

  function showProAlert(text, tone = "error") {
    state.proFeedback = { text, tone };
    renderProAlert();
  }

  function renderCustomAlert() {
    if (!state.customFeedback) {
      els.customAlert.hidden = true;
      els.customAlert.textContent = "";
      els.customAlert.className = "pv-inline-alert";
      return;
    }
    els.customAlert.hidden = false;
    els.customAlert.textContent = state.customFeedback.text;
    els.customAlert.className = `pv-inline-alert ${
      state.customFeedback.tone === "success"
        ? "is-success"
        : state.customFeedback.tone === "warn"
          ? "is-warn"
          : ""
    }`.trim();
  }

  function renderProAlert() {
    if (!state.proFeedback) {
      els.proAlert.hidden = true;
      els.proAlert.textContent = "";
      els.proAlert.className = "pv-inline-alert";
      return;
    }
    els.proAlert.hidden = false;
    els.proAlert.textContent = state.proFeedback.text;
    els.proAlert.className = `pv-inline-alert ${
      state.proFeedback.tone === "success"
        ? "is-success"
        : state.proFeedback.tone === "warn"
          ? "is-warn"
          : ""
    }`.trim();
  }

  function renderStaticCopy() {
    const lang = state.settings.lang;
    els.rootHtml.lang = lang;
    els.rootHtml.setAttribute("data-theme", state.settings.theme);

    els.brandTitle.textContent = t(lang, "ext.name");
    els.brandTagline.textContent = t(lang, "ext.tagline");
    els.langRu.textContent = t(lang, "ext.langRu");
    els.langEn.textContent = t(lang, "ext.langEn");
    els.langRu.classList.toggle("is-active", lang === "ru");
    els.langEn.classList.toggle("is-active", lang === "en");

    const isDark = state.settings.theme === "dark";
    const themeLabel = t(lang, isDark ? "ext.themeToLight" : "ext.themeToDark");
    els.themeBtn.setAttribute("aria-label", themeLabel);
    els.themeBtn.setAttribute("title", themeLabel);
    els.themeMoon.hidden = isDark;
    els.themeSun.hidden = !isDark;

    if (state.activeTabAdapter) {
      els.siteDot.classList.add("is-active");
      els.siteStatus.textContent = t(lang, "site.active", {
        host: getHostLabel(state.activeTabAdapter, lang),
      });
    } else {
      els.siteDot.classList.remove("is-active");
      els.siteStatus.textContent = state.activeTabHostname
        ? t(lang, "site.unsupported")
        : t(lang, "site.unknownTab");
    }
    els.siteHosts.textContent = t(lang, "site.hostsList");

    els.controlsTitle.textContent = t(lang, "controls.title");
    els.overlayLabel.textContent = t(lang, "controls.overlayLabel");
    els.overlayToggle.setAttribute("aria-checked", state.settings.overlayVisible ? "true" : "false");

    els.sensitivityLabel.textContent = t(lang, "controls.sensitivityLabel");
    els.sensNormal.textContent = t(lang, "controls.sensitivityNormal");
    els.sensStrict.textContent = t(lang, "controls.sensitivityStrict");
    const isStrict = state.settings.sensitivity === "strict";
    els.sensNormal.classList.toggle("is-active", !isStrict);
    els.sensStrict.classList.toggle("is-active", isStrict);

    els.uuidLabel.textContent = t(lang, "controls.uuidLabel");
    els.uuidStrictHint.textContent = t(lang, "controls.uuidStrictHint");
    els.uuidStrictHint.hidden = !isStrict;
    els.uuidToggle.checked = isStrict ? true : Boolean(state.settings.detectUuid);
    els.uuidToggle.disabled = isStrict;

    els.rulesTitle.textContent = t(lang, "rules.title");
    els.customTerm.setAttribute("placeholder", t(lang, "rules.placeholder"));
    els.customAddBtn.textContent = t(lang, "rules.addBtn");
    els.customEmpty.textContent = t(lang, "rules.empty");

    for (const option of els.customCategory.options) {
      option.textContent = t(lang, `rules.cat.${option.value}`);
    }

    els.packsTitle.textContent = t(lang, "packs.title");
    els.packsLock.textContent = t(lang, "packs.proBadge");

    els.proTitle.textContent = t(lang, "pro.sectionTitle");
    els.proKeyInput.setAttribute("placeholder", t(lang, "pro.inputPlaceholder"));
    els.proActivateBtn.textContent = t(lang, "pro.activateBtn");
    els.proRemoveBtn.textContent = t(lang, "pro.removeBtn");

    els.footerText.textContent = t(lang, "footer.zeroRetention");
  }

  function renderCategories() {
    const lang = state.settings.lang;
    const isPro = state.license.isPro;
    const disabledSet = new Set(isPro ? state.settings.disabledCategories : []);
    const total = TOGGLEABLE_CATEGORIES.length;
    const enabledCount = total - disabledSet.size;

    els.categoriesTitle.textContent = t(lang, "categories.title");
    els.categoriesLock.textContent = t(lang, "categories.proLockBadge");
    els.categoriesLock.hidden = isPro;
    els.categoriesProHint.textContent = t(lang, "categories.proHint");
    els.categoriesProHint.hidden = isPro;
    els.categoriesReset.textContent = t(lang, "categories.reset");
    els.categoriesReset.disabled = !isPro || disabledSet.size === 0;
    els.categoriesSummary.textContent = t(lang, "categories.activeSummary", {
      enabled: enabledCount,
      total,
    });

    const buttons = TOGGLEABLE_CATEGORIES.map((cat) => {
      const btn = doc.createElement("button");
      btn.type = "button";
      const isDisabled = disabledSet.has(cat.category);
      btn.className = `pv-cat-chip${isDisabled ? " is-disabled" : ""}${isPro ? "" : " is-locked"}`;
      btn.setAttribute("data-category", cat.category);
      btn.setAttribute("aria-pressed", isDisabled ? "false" : "true");
      if (!isPro) {
        btn.setAttribute("aria-disabled", "true");
      }
      btn.textContent = getCategoryLabel(lang, cat.category);
      btn.addEventListener("click", async () => {
        if (!state.license.isPro) {
          showProAlert(t(state.settings.lang, "categories.proHint"), "warn");
          els.proKeyInput.focus();
          return;
        }
        const nextDisabled = new Set(state.settings.disabledCategories);
        if (nextDisabled.has(cat.category)) {
          nextDisabled.delete(cat.category);
        } else {
          nextDisabled.add(cat.category);
        }
        state.settings = await saveExtSettings(
          { ...state.settings, disabledCategories: Array.from(nextDisabled) },
          storageArea
        );
        renderCategories();
      });
      return btn;
    });

    els.categoriesGrid.replaceChildren(...buttons);
  }

  function renderCustomRulesAndPacks() {
    const lang = state.settings.lang;
    const isPro = state.license.isPro;
    const rules = state.settings.customRules;

    els.customCounter.textContent = isPro
      ? t(lang, "rules.counterPro", { count: rules.length })
      : t(lang, "rules.counterFree", { count: rules.length, limit: FREE_CUSTOM_RULE_LIMIT });

    els.customEmpty.hidden = rules.length > 0;

    const items = rules.map((rule) => {
      const li = doc.createElement("li");
      li.className = `pv-rule-item${rule.enabled === false ? " is-disabled" : ""}`;

      const left = doc.createElement("div");
      left.className = "pv-rule-left";

      const checkbox = doc.createElement("input");
      checkbox.type = "checkbox";
      checkbox.className = "pv-checkbox";
      checkbox.checked = rule.enabled !== false;
      checkbox.setAttribute("aria-label", t(lang, "rules.toggleAria"));
      checkbox.addEventListener("change", async () => {
        const nextRules = state.settings.customRules.map((item) =>
          item.id === rule.id ? { ...item, enabled: checkbox.checked } : item
        );
        state.settings = await saveExtSettings(
          { ...state.settings, customRules: nextRules },
          storageArea
        );
        renderCustomRulesAndPacks();
      });

      const termSpan = doc.createElement("span");
      termSpan.className = "pv-rule-term";
      termSpan.textContent = rule.term;

      const tagSpan = doc.createElement("span");
      tagSpan.className = "pv-rule-tag";
      tagSpan.textContent = t(lang, `rules.cat.${rule.category || "CUSTOM"}`);

      left.append(checkbox, termSpan, tagSpan);

      const delBtn = doc.createElement("button");
      delBtn.type = "button";
      delBtn.className = "pv-rule-del";
      delBtn.setAttribute("aria-label", t(lang, "rules.removeAria"));
      delBtn.textContent = "×";
      delBtn.addEventListener("click", async () => {
        const nextRules = state.settings.customRules.filter((item) => item.id !== rule.id);
        state.settings = await saveExtSettings(
          { ...state.settings, customRules: nextRules },
          storageArea
        );
        clearCustomAlert();
        renderCustomRulesAndPacks();
      });

      li.append(left, delBtn);
      return li;
    });

    els.customList.replaceChildren(...items);
    els.packsLock.hidden = isPro;

    const packButtons = INDUSTRY_WORD_PACKS.map((packMeta) => {
      const pack = getLocalizedWordPack(packMeta.id, lang);
      const btn = doc.createElement("button");
      btn.type = "button";
      btn.className = `pv-pack-btn${isPro ? "" : " is-locked"}`;
      btn.setAttribute("data-pack-id", pack.id);
      btn.textContent = isPro ? `+ ${pack.title}` : `🔒 ${pack.title}`;
      btn.addEventListener("click", async () => {
        if (!state.license.isPro) {
          showCustomAlert(t(state.settings.lang, "packs.lockedNotice"), "warn");
          els.proKeyInput.focus();
          return;
        }
        const existingKeys = new Set(state.settings.customRules.map(makeRuleDedupKey));
        const additions = [];
        for (const term of pack.terms) {
          const rule = normalizeRule({
            id: createRuleId(),
            term,
            category: pack.category || "CUSTOM",
            caseSensitive: false,
            enabled: true,
          });
          if (!rule) continue;
          const key = makeRuleDedupKey(rule);
          if (!existingKeys.has(key)) {
            existingKeys.add(key);
            additions.push(rule);
          }
        }
        if (additions.length === 0) {
          showCustomAlert(
            t(state.settings.lang, "packs.alreadyAdded", { title: pack.title }),
            "warn"
          );
          return;
        }
        state.settings = await saveExtSettings(
          {
            ...state.settings,
            customRules: [...state.settings.customRules, ...additions],
          },
          storageArea
        );
        showCustomAlert(
          t(state.settings.lang, "packs.imported", {
            title: pack.title,
            added: additions.length,
          }),
          "success"
        );
        renderCustomRulesAndPacks();
      });
      return btn;
    });

    els.packsList.replaceChildren(...packButtons);
    renderCustomAlert();
  }

  function renderProStatus() {
    const lang = state.settings.lang;
    const lic = state.license;

    els.proBadge.classList.toggle("is-pro", lic.isPro);
    els.proBadge.classList.toggle("is-owner", lic.isOwner);
    els.proBadge.textContent = lic.isOwner
      ? t(lang, "pro.badgeOwner")
      : lic.isPro
        ? t(lang, "pro.badgePro")
        : t(lang, "pro.badgeFree");

    els.proStatusCard.classList.toggle("is-active", lic.isPro);
    els.proStatusCard.classList.toggle("is-owner", lic.isOwner);
    els.proRemoveBtn.disabled = !lic.isPro;

    if (!lic.isPro) {
      els.proStatusTitle.textContent = t(lang, "pro.statusTitleFree");
      els.proStatusDesc.hidden = false;
      els.proStatusDesc.textContent = t(lang, "pro.statusDescFree");
      els.proMetaList.hidden = true;
      els.proMetaList.replaceChildren();
    } else {
      els.proStatusTitle.textContent = lic.isOwner
        ? t(lang, "pro.statusTitleOwner")
        : t(lang, "pro.statusTitlePro");
      els.proStatusDesc.hidden = true;
      els.proMetaList.hidden = false;

      const metaRows = [
        t(lang, "pro.metaTier", { tier: lic.isOwner ? "Owner" : "Pro" }),
        t(lang, "pro.metaKeyId", { keyId: lic.keyId }),
        t(lang, "pro.metaLabel", { label: lic.label }),
        t(lang, "pro.metaIssuedAt", { date: formatIsoDate(lic.issuedAt, lang) }),
        lic.exp
          ? t(lang, "pro.metaExp", { date: formatIsoDate(lic.exp, lang) })
          : t(lang, "pro.metaExpNever"),
      ];

      const items = metaRows.map((row) => {
        const li = doc.createElement("li");
        li.textContent = row;
        return li;
      });
      els.proMetaList.replaceChildren(...items);
    }

    renderProAlert();
  }

  function renderAll() {
    renderStaticCopy();
    renderCategories();
    renderCustomRulesAndPacks();
    renderProStatus();
  }

  els.langRu.addEventListener("click", async () => {
    if (state.settings.lang === "ru") return;
    state.settings = await saveExtSettings({ ...state.settings, lang: "ru" }, storageArea);
    renderAll();
  });

  els.langEn.addEventListener("click", async () => {
    if (state.settings.lang === "en") return;
    state.settings = await saveExtSettings({ ...state.settings, lang: "en" }, storageArea);
    renderAll();
  });

  els.themeBtn.addEventListener("click", async () => {
    const nextTheme = state.settings.theme === "dark" ? "light" : "dark";
    state.settings = await saveExtSettings({ ...state.settings, theme: nextTheme }, storageArea);
    renderAll();
  });

  els.proBadge.addEventListener("click", () => {
    els.proSection.scrollIntoView?.({ behavior: "smooth", block: "nearest" });
    els.proKeyInput.focus();
  });

  els.overlayToggle.addEventListener("click", async () => {
    state.settings = await saveExtSettings(
      { ...state.settings, overlayVisible: !state.settings.overlayVisible },
      storageArea
    );
    renderStaticCopy();
  });

  els.sensNormal.addEventListener("click", async () => {
    if (state.settings.sensitivity === "normal") return;
    state.settings = await saveExtSettings(
      { ...state.settings, sensitivity: "normal", detectUuid: false },
      storageArea
    );
    renderStaticCopy();
  });

  els.sensStrict.addEventListener("click", async () => {
    if (state.settings.sensitivity === "strict") return;
    state.settings = await saveExtSettings(
      { ...state.settings, sensitivity: "strict", detectUuid: true },
      storageArea
    );
    renderStaticCopy();
  });

  els.uuidToggle.addEventListener("change", async () => {
    if (state.settings.sensitivity === "strict") return;
    state.settings = await saveExtSettings(
      { ...state.settings, detectUuid: els.uuidToggle.checked },
      storageArea
    );
    renderStaticCopy();
  });

  els.categoriesReset.addEventListener("click", async () => {
    if (!state.license.isPro) return;
    state.settings = await saveExtSettings(
      { ...state.settings, disabledCategories: [] },
      storageArea
    );
    renderCategories();
  });

  els.customForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const lang = state.settings.lang;
    const rawTerm = String(els.customTerm.value || "").trim();
    if (!rawTerm) {
      return;
    }
    if (!state.license.isPro && state.settings.customRules.length >= FREE_CUSTOM_RULE_LIMIT) {
      showCustomAlert(
        t(lang, "rules.limitReached", { limit: FREE_CUSTOM_RULE_LIMIT }),
        "warn"
      );
      return;
    }
    const candidate = normalizeRule({
      id: createRuleId(),
      term: rawTerm,
      category: els.customCategory.value || "CUSTOM",
      caseSensitive: false,
      enabled: true,
    });
    if (!candidate) {
      return;
    }
    const key = makeRuleDedupKey(candidate);
    if (state.settings.customRules.some((r) => makeRuleDedupKey(r) === key)) {
      showCustomAlert(t(lang, "rules.duplicate"), "warn");
      return;
    }
    state.settings = await saveExtSettings(
      { ...state.settings, customRules: [...state.settings.customRules, candidate] },
      storageArea
    );
    els.customTerm.value = "";
    clearCustomAlert();
    renderCustomRulesAndPacks();
  });

  els.proActivateBtn.addEventListener("click", async () => {
    const lang = state.settings.lang;
    const candidate = String(els.proKeyInput.value || "").trim();
    if (!candidate) {
      showProAlert(t(lang, "pro.errorEmpty"), "error");
      return;
    }
    const verified = await verifyProLicenseToken(
      candidate,
      publicKeyB64U ? { publicKeyB64U } : undefined
    );
    if (!verified.valid) {
      showProAlert(
        t(lang, verified.reason === "expired" ? "pro.errorExpired" : "pro.errorInvalid"),
        "error"
      );
      return;
    }
    await saveExtProLicenseToken(verified.token, storageArea);
    state.license = verified;
    els.proKeyInput.value = "";
    clearCustomAlert();
    showProAlert(
      t(lang, "pro.activatedSuccess", {
        tier: verified.isOwner ? "Owner Pro" : "Pro",
        keyId: verified.keyId,
      }),
      "success"
    );
    renderAll();
  });

  els.proRemoveBtn.addEventListener("click", async () => {
    const lang = state.settings.lang;
    await clearExtProLicenseToken(storageArea);
    state.license = createFreeLicenseState("removed");
    showProAlert(t(lang, "pro.removedSuccess"), "warn");
    renderAll();
  });

  const unsubscribe = subscribeExtStorageChanges(async ({ settingsChanged, licenseChanged }) => {
    if (settingsChanged) {
      state.settings = await loadExtSettings(storageArea);
    }
    if (licenseChanged) {
      await refreshLicenseFromStorage();
    }
    renderAll();
  }, storageEvents);

  await Promise.all([refreshLicenseFromStorage(), refreshActiveTab()]);
  renderAll();

  return {
    getState: () => state,
    destroy: unsubscribe,
  };
}

if (
  typeof globalThis.document !== "undefined" &&
  typeof globalThis.chrome !== "undefined" &&
  Boolean(globalThis.chrome?.runtime?.id)
) {
  if (globalThis.document.readyState === "loading") {
    globalThis.document.addEventListener("DOMContentLoaded", () => {
      initPopupController();
    });
  } else {
    initPopupController();
  }
}
