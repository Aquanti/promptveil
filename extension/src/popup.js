/**
 * PromptVeil Extension Popup Controller.
 * Safe DOM APIs only, zero inline styles, chrome.storage.local only, zero network egress.
 */

import { CATEGORIES } from "../../app/static/js/detector.js";
import { getLocalizedWordPack, INDUSTRY_WORD_PACKS } from "../../app/static/js/presets.js";
import {
  PRO_PUBLIC_KEY_B64U,
  createFreeLicenseState,
  extractProToken,
  inspectProLicenseToken,
  verifyProLicenseToken,
} from "../../app/static/js/pro-license.js";
import { createRuleId, makeRuleDedupKey, normalizeRule } from "../../app/static/js/storage.js";
import { detectSupportedHost, getHostLabel } from "./adapters.js";
import { getCategoryLabel, t } from "./i18n-ext.js";
import {
  clearExtProLicenseToken,
  FREE_CUSTOM_RULE_LIMIT,
  getChromeStorageLocal,
  loadExtProLicenseToken,
  loadExtSettings,
  normalizeExtSettings,
  saveExtProLicenseToken,
  saveExtSettings,
  subscribeExtStorageChanges,
} from "./storage-ext.js";

const TOGGLEABLE_CATEGORIES = CATEGORIES.filter((cat) => cat.category !== "CUSTOM");
const MAX_PVKEY_FILE_BYTES = 256 * 1024;

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

function normalizeTimestampMs(value) {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return NaN;
    return value > 1e12 ? value : value * 1000;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return NaN;
    if (/^[+-]?\d+(?:\.\d+)?$/.test(trimmed)) {
      const num = Number(trimmed);
      if (Number.isFinite(num)) {
        return num > 1e12 ? num : num * 1000;
      }
    }
    return Date.parse(trimmed);
  }
  return NaN;
}

function hasExpClaim(exp) {
  return exp !== null && exp !== undefined && (typeof exp !== "string" || exp.trim() !== "");
}

function formatClaimDate(value, lang) {
  if (!hasExpClaim(value)) return "";
  const ms = normalizeTimestampMs(value);
  if (Number.isNaN(ms)) return String(value);
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return String(value);
  try {
    return new Intl.DateTimeFormat(lang === "en" ? "en-US" : "ru-RU", {
      year: "numeric",
      month: "short",
      day: "numeric",
      timeZone: "UTC",
    }).format(date);
  } catch {
    return date.toISOString().slice(0, 10);
  }
}

async function readUploadedFileBytes(file) {
  if (!file) return new Uint8Array(0);
  if (typeof file.arrayBuffer === "function") {
    const buf = await file.arrayBuffer();
    return new Uint8Array(buf);
  }
  if (typeof file.text === "function") {
    const txt = await file.text();
    return new TextEncoder().encode(String(txt ?? ""));
  }
  if (typeof FileReader !== "undefined") {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        if (reader.result instanceof ArrayBuffer) {
          resolve(new Uint8Array(reader.result));
        } else {
          resolve(new TextEncoder().encode(String(reader.result || "")));
        }
      };
      reader.onerror = () => reject(new Error("FILE_READ_ERROR"));
      reader.readAsArrayBuffer(file);
    });
  }
  return new Uint8Array(0);
}

function parsePvKeyUploadBytes(bytes, byteLength = null) {
  const actualLen = bytes ? bytes.length : 0;
  const size =
    typeof byteLength === "number" && Number.isFinite(byteLength) && byteLength >= 0
      ? Math.max(byteLength, actualLen)
      : actualLen;
  if (size > MAX_PVKEY_FILE_BYTES) {
    return { ok: false, reason: "file_too_large", text: "", token: "" };
  }
  if (!bytes || bytes.length === 0) {
    return { ok: false, reason: "file_empty", text: "", token: "" };
  }
  for (let i = 0; i < bytes.length; i += 1) {
    if (bytes[i] === 0) {
      return { ok: false, reason: "file_read", text: "", token: "" };
    }
  }
  let text = "";
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes).replace(/^\uFEFF/, "");
  } catch {
    return { ok: false, reason: "file_read", text: "", token: "" };
  }
  if (!text.trim()) {
    return { ok: false, reason: "file_empty", text: "", token: "" };
  }
  const token = extractProToken(text);
  if (!token) {
    return { ok: false, reason: "file_no_token", text, token: "" };
  }
  return { ok: true, reason: "", text, token };
}

function getProReasonDescriptor(info) {
  const reason = String(info?.reason || "");
  switch (reason) {
    case "empty":
      return { key: "pro.errorEmpty" };
    case "format":
      return { key: "pro.errorFormat" };
    case "encoding":
      return { key: "pro.errorEncoding" };
    case "length":
      return { key: "pro.errorLength" };
    case "signature":
      return { key: "pro.errorSignature" };
    case "payload":
      return { key: "pro.errorPayload" };
    case "expired":
      return hasExpClaim(info?.exp)
        ? { key: "pro.errorExpiredDate", exp: info.exp }
        : { key: "pro.errorExpired" };
    case "clipboard_denied":
      return { key: "pro.errorClipboardDenied" };
    case "clipboard_empty":
      return { key: "pro.errorClipboardEmpty" };
    case "clipboard_no_token":
      return { key: "pro.errorClipboardNoToken" };
    case "file_too_large":
      return { key: "pro.errorFileTooLarge" };
    case "file_empty":
      return { key: "pro.errorFileEmpty" };
    case "file_no_token":
      return { key: "pro.errorFileNoToken" };
    case "file_read":
      return { key: "pro.errorFileRead" };
    default:
      return { key: "pro.errorInvalid" };
  }
}

function resolveFeedbackVars(feedback, lang) {
  if (!feedback) return null;
  if (hasExpClaim(feedback.exp)) {
    return {
      ...(feedback.vars && typeof feedback.vars === "object" ? feedback.vars : {}),
      date: formatClaimDate(feedback.exp, lang),
    };
  }
  return feedback.vars || null;
}

function getProReasonMessage(info, lang) {
  const descriptor = getProReasonDescriptor(info);
  return t(lang, descriptor.key, resolveFeedbackVars(descriptor, lang));
}

export async function initPopupController({
  doc = globalThis.document,
  storageArea = getChromeStorageLocal(),
  tabsApi = globalThis.chrome?.tabs,
  storageEvents = globalThis.chrome?.storage?.onChanged,
  publicKeyB64U = PRO_PUBLIC_KEY_B64U,
  clipboard = globalThis.navigator?.clipboard,
  nowMs,
} = {}) {
  if (!doc || !doc.getElementById("pv-popup-root")) {
    return null;
  }

  const els = {
    rootHtml: doc.documentElement,
    brandTitle: doc.getElementById("popup-brand-title"),
    brandTagline: doc.getElementById("popup-brand-tagline"),
    proBadge: doc.getElementById("popup-pro-badge"),
    langSwitch: doc.getElementById("popup-lang-switch"),
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
    proPasteBtn: doc.getElementById("popup-pro-paste-btn"),
    proFileInput: doc.getElementById("popup-pro-file-input"),
    proFileBtn: doc.getElementById("popup-pro-file-btn"),
    proKeyInput: doc.getElementById("popup-pro-key-input"),
    proAlert: doc.getElementById("popup-pro-alert"),
    proDiagnostics: doc.getElementById("popup-pro-diagnostics"),
    proActivateBtn: doc.getElementById("popup-pro-activate-btn"),
    proVerifyBtn: doc.getElementById("popup-pro-verify-btn"),
    proRemoveBtn: doc.getElementById("popup-pro-remove-btn"),

    footerText: doc.getElementById("popup-footer-text"),
  };

  const state = {
    settings: await loadExtSettings(storageArea),
    license: createFreeLicenseState("none"),
    hasStoredLicenseToken: false,
    activeTabHostname: "",
    activeTabAdapter: null,
    customFeedback: null,
    proFeedback: null,
    proInspection: null,
  };

  function getVerifyOptions() {
    const opts = {
      publicKeyB64U: publicKeyB64U || PRO_PUBLIC_KEY_B64U,
    };
    if (typeof nowMs === "number" && Number.isFinite(nowMs)) {
      opts.nowMs = nowMs;
    }
    return opts;
  }

  let settingsSaveChain = Promise.resolve();
  let pendingSettingsSaves = 0;
  let pendingLicenseSaves = 0;
  let proActionSeq = 0;
  let licenseRefreshSeq = 0;
  let settingsRefreshSeq = 0;

  function updateSettings(updater) {
    settingsRefreshSeq += 1;
    const nextDraft =
      typeof updater === "function" ? updater(state.settings) : { ...state.settings, ...updater };
    state.settings = normalizeExtSettings(nextDraft);
    const snapshot = state.settings;
    pendingSettingsSaves += 1;
    const runSave = () =>
      saveExtSettings(snapshot, storageArea).finally(() => {
        pendingSettingsSaves = Math.max(0, pendingSettingsSaves - 1);
      });
    settingsSaveChain = settingsSaveChain.then(runSave, runSave);
    return settingsSaveChain;
  }

  async function refreshLicenseFromStorage() {
    const seq = ++licenseRefreshSeq;
    const actionSeqAtStart = proActionSeq;
    const rawToken = await loadExtProLicenseToken(storageArea);
    if (seq !== licenseRefreshSeq || actionSeqAtStart !== proActionSeq) return false;
    state.hasStoredLicenseToken = Boolean(rawToken);
    if (!rawToken) {
      state.license = createFreeLicenseState("empty");
      return true;
    }
    const candidate = extractProToken(rawToken) || rawToken;
    const verified = await verifyProLicenseToken(candidate, getVerifyOptions());
    if (seq !== licenseRefreshSeq || actionSeqAtStart !== proActionSeq) return false;
    state.license = verified;
    return true;
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

  function showCustomAlert(text, tone = "warn", extra = {}) {
    state.customFeedback = {
      text,
      tone,
      key: extra.key || "",
      vars: extra.vars || null,
      action: extra.action || "",
    };
    renderCustomAlert();
  }

  function clearCustomAlert() {
    state.customFeedback = null;
    renderCustomAlert();
  }

  function showProAlert(text, tone = "error", extra = {}) {
    state.proFeedback = {
      text,
      tone,
      key: extra.key || "",
      vars: extra.vars || null,
      exp: hasExpClaim(extra.exp) ? extra.exp : null,
    };
    renderProAlert();
  }

  function focusProActivation({
    alertTarget = "pro",
    messageKey = "",
    messageVars = null,
    tone = "warn",
  } = {}) {
    const lang = state.settings.lang;
    if (messageKey) {
      const msg = t(lang, messageKey, messageVars);
      if (alertTarget === "custom") {
        showCustomAlert(msg, tone, { key: messageKey, vars: messageVars, action: "focusPro" });
      } else {
        showProAlert(msg, tone, { key: messageKey, vars: messageVars });
      }
    }
    els.proSection?.scrollIntoView?.({ behavior: "smooth", block: "nearest" });
    els.proKeyInput?.focus?.();
  }

  function renderCustomAlert() {
    if (!state.customFeedback) {
      els.customAlert.hidden = true;
      els.customAlert.textContent = "";
      els.customAlert.className = "pv-inline-alert";
      els.customAlert.removeAttribute?.("tabindex");
      els.customAlert.removeAttribute?.("role");
      els.customAlert.setAttribute("role", "alert");
      return;
    }
    const lang = state.settings.lang;
    const isFocusPro = state.customFeedback.action === "focusPro" && !state.license.isPro;
    els.customAlert.hidden = false;
    els.customAlert.textContent = state.customFeedback.key
      ? t(lang, state.customFeedback.key, state.customFeedback.vars)
      : state.customFeedback.text;
    els.customAlert.className = `pv-inline-alert ${
      state.customFeedback.tone === "success"
        ? "is-success"
        : state.customFeedback.tone === "warn"
          ? "is-warn"
          : ""
    }${isFocusPro ? " is-actionable" : ""}`.trim();
    if (isFocusPro) {
      els.customAlert.setAttribute("tabindex", "0");
      els.customAlert.setAttribute("title", t(lang, "pro.lockJumpTitle"));
    } else {
      els.customAlert.removeAttribute?.("tabindex");
      els.customAlert.removeAttribute?.("title");
    }
  }

  function renderProAlert() {
    if (!state.proFeedback) {
      els.proAlert.hidden = true;
      els.proAlert.textContent = "";
      els.proAlert.className = "pv-inline-alert";
      return;
    }
    const lang = state.settings.lang;
    els.proAlert.hidden = false;
    els.proAlert.textContent = state.proFeedback.key
      ? t(lang, state.proFeedback.key, resolveFeedbackVars(state.proFeedback, lang))
      : state.proFeedback.text;
    els.proAlert.className = `pv-inline-alert ${
      state.proFeedback.tone === "success"
        ? "is-success"
        : state.proFeedback.tone === "warn"
          ? "is-warn"
          : ""
    }`.trim();
  }

  function renderProDiagnostics() {
    if (!els.proDiagnostics) return;
    const info = state.proInspection;
    if (!info) {
      els.proDiagnostics.hidden = true;
      els.proDiagnostics.className = "pv-pro-diagnostics";
      els.proDiagnostics.replaceChildren();
      return;
    }

    const lang = state.settings.lang;
    const isValid = Boolean(info.valid);
    const isExpired = !isValid && info.reason === "expired";
    const toneClass = isValid ? "is-valid" : isExpired ? "is-warn" : "is-error";
    els.proDiagnostics.className = `pv-pro-diagnostics ${toneClass}`;

    const nodes = [];
    const titleEl = doc.createElement("div");
    titleEl.className = "pv-pro-diag-title";
    titleEl.textContent = t(
      lang,
      isValid ? "pro.diagValidTitle" : isExpired ? "pro.diagExpiredTitle" : "pro.diagInvalidTitle"
    );
    nodes.push(titleEl);

    const detailEl = doc.createElement("p");
    detailEl.className = "pv-pro-diag-detail";
    if (isValid) {
      const tierLabel = info.isOwner ? "Owner Pro" : "Pro";
      const detailKey =
        info.mode === "activate"
          ? "pro.activatedSuccess"
          : info.mode === "verify-active"
            ? "pro.verifyActiveSuccess"
            : "pro.verifySuccess";
      detailEl.textContent = t(lang, detailKey, { tier: tierLabel, keyId: info.keyId });
    } else {
      detailEl.textContent = getProReasonMessage(info, lang);
    }
    nodes.push(detailEl);

    if (info.extractedFromText) {
      const extNote = doc.createElement("p");
      extNote.className = "pv-pro-diag-detail";
      extNote.textContent = t(lang, "pro.diagExtractedNote");
      nodes.push(extNote);
    }

    const claims = isValid
      ? info
      : info.unverifiedClaims && typeof info.unverifiedClaims === "object"
        ? info.unverifiedClaims
        : null;

    if (claims && (claims.keyId || claims.label || claims.tier || claims.issuedAt)) {
      const heading = doc.createElement("div");
      heading.className = "pv-pro-diag-claims-title";
      heading.textContent = t(
        lang,
        isValid ? "pro.diagClaimsHeading" : "pro.diagClaimsUnverifiedHeading"
      );
      nodes.push(heading);

      const list = doc.createElement("ul");
      list.className = "pv-pro-diag-list";
      const hasExp = hasExpClaim(claims.exp);
      const methodLabel = info.method
        ? t(lang, info.method === "webcrypto" ? "pro.methodWebCrypto" : "pro.methodPureJs")
        : "";
      const rows = [
        claims.tier
          ? t(lang, "pro.metaTier", {
              tier: claims.tier === "owner" ? "Owner Pro" : claims.tier === "pro" ? "Pro" : claims.tier,
            })
          : "",
        claims.keyId ? t(lang, "pro.metaKeyId", { keyId: claims.keyId }) : "",
        claims.label ? t(lang, "pro.metaLabel", { label: claims.label }) : "",
        claims.issuedAt
          ? t(lang, "pro.metaIssuedAt", { date: formatClaimDate(claims.issuedAt, lang) })
          : "",
        hasExp
          ? t(lang, "pro.metaExp", { date: formatClaimDate(claims.exp, lang) })
          : t(lang, "pro.metaExpNever"),
        methodLabel ? t(lang, "pro.metaMethod", { method: methodLabel }) : "",
      ].filter(Boolean);

      for (const row of rows) {
        const li = doc.createElement("li");
        li.textContent = row;
        list.appendChild(li);
      }
      nodes.push(list);
    }

    els.proDiagnostics.replaceChildren(...nodes);
    els.proDiagnostics.hidden = false;
  }

  function renderStaticCopy() {
    const lang = state.settings.lang;
    els.rootHtml.lang = lang;
    els.rootHtml.setAttribute("data-theme", state.settings.theme);

    els.brandTitle.textContent = t(lang, "ext.name");
    els.brandTagline.textContent = t(lang, "ext.tagline");
    els.proBadge.setAttribute("title", t(lang, "pro.badgeTitle"));
    els.langSwitch?.setAttribute("aria-label", t(lang, "ext.langSwitchAria"));
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
    els.customCategory.setAttribute("aria-label", t(lang, "rules.categoryAria"));
    els.customAddBtn.textContent = t(lang, "rules.addBtn");
    els.customEmpty.textContent = t(lang, "rules.empty");

    for (const option of els.customCategory.options) {
      option.textContent = t(lang, `rules.cat.${option.value}`);
    }

    els.packsTitle.textContent = t(lang, "packs.title");
    els.packsLock.textContent = t(lang, "packs.proBadge");
    els.packsLock.setAttribute("title", t(lang, "pro.lockJumpTitle"));

    els.proTitle.textContent = t(lang, "pro.sectionTitle");
    if (els.proPasteBtn) els.proPasteBtn.textContent = t(lang, "pro.pasteBtn");
    if (els.proFileBtn) els.proFileBtn.textContent = t(lang, "pro.fileBtn");
    els.proKeyInput.setAttribute("placeholder", t(lang, "pro.inputPlaceholder"));
    els.proActivateBtn.textContent = t(lang, "pro.activateBtn");
    if (els.proVerifyBtn) els.proVerifyBtn.textContent = t(lang, "pro.verifyBtn");
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
    els.categoriesLock.setAttribute("title", t(lang, "pro.lockJumpTitle"));
    els.categoriesLock.hidden = isPro;
    els.categoriesProHint.textContent = t(lang, "categories.proHint");
    els.categoriesProHint.hidden = isPro;
    els.categoriesProHint.classList.toggle("is-actionable", !isPro);
    if (!isPro) {
      els.categoriesProHint.setAttribute("tabindex", "0");
      els.categoriesProHint.setAttribute("role", "button");
      els.categoriesProHint.setAttribute("title", t(lang, "pro.lockJumpTitle"));
    } else {
      els.categoriesProHint.removeAttribute?.("tabindex");
      els.categoriesProHint.removeAttribute?.("role");
      els.categoriesProHint.removeAttribute?.("title");
    }
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
          focusProActivation({ alertTarget: "pro", messageKey: "categories.proHint", tone: "warn" });
          return;
        }
        const savePromise = updateSettings((prev) => {
          const nextDisabled = new Set(prev.disabledCategories);
          if (nextDisabled.has(cat.category)) {
            nextDisabled.delete(cat.category);
          } else {
            nextDisabled.add(cat.category);
          }
          return { ...prev, disabledCategories: Array.from(nextDisabled) };
        });
        renderCategories();
        await savePromise;
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

    const items = rules.map((rule, index) => {
      const isCappedPaused = !isPro && index >= FREE_CUSTOM_RULE_LIMIT;
      const li = doc.createElement("li");
      li.className = `pv-rule-item${rule.enabled === false ? " is-disabled" : ""}${
        isCappedPaused ? " is-paused" : ""
      }`;

      const left = doc.createElement("div");
      left.className = "pv-rule-left";

      const checkbox = doc.createElement("input");
      checkbox.type = "checkbox";
      checkbox.className = "pv-checkbox";
      checkbox.checked = rule.enabled !== false;
      checkbox.setAttribute("aria-label", t(lang, "rules.toggleAria"));
      checkbox.addEventListener("change", async () => {
        const savePromise = updateSettings((prev) => ({
          ...prev,
          customRules: prev.customRules.map((item) =>
            item.id === rule.id ? { ...item, enabled: checkbox.checked } : item
          ),
        }));
        renderCustomRulesAndPacks();
        await savePromise;
      });

      const termSpan = doc.createElement("span");
      termSpan.className = "pv-rule-term";
      termSpan.textContent = rule.term;

      const tagSpan = doc.createElement("span");
      tagSpan.className = "pv-rule-tag";
      tagSpan.textContent = t(lang, `rules.cat.${rule.category || "CUSTOM"}`);

      left.append(checkbox, termSpan, tagSpan);
      if (isCappedPaused) {
        const pausedSpan = doc.createElement("span");
        pausedSpan.className = "pv-rule-tag is-paused";
        pausedSpan.textContent = t(lang, "rules.freePaused");
        left.append(pausedSpan);
      }

      const delBtn = doc.createElement("button");
      delBtn.type = "button";
      delBtn.className = "pv-rule-del";
      delBtn.setAttribute("aria-label", t(lang, "rules.removeAria"));
      delBtn.textContent = "×";
      delBtn.addEventListener("click", async () => {
        const savePromise = updateSettings((prev) => ({
          ...prev,
          customRules: prev.customRules.filter((item) => item.id !== rule.id),
        }));
        clearCustomAlert();
        renderCustomRulesAndPacks();
        await savePromise;
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
          focusProActivation({ alertTarget: "custom", messageKey: "packs.lockedNotice", tone: "warn" });
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
        const savePromise = updateSettings((prev) => ({
          ...prev,
          customRules: [...prev.customRules, ...additions],
        }));
        showCustomAlert(
          t(state.settings.lang, "packs.imported", {
            title: pack.title,
            added: additions.length,
          }),
          "success"
        );
        renderCustomRulesAndPacks();
        await savePromise;
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
    els.proRemoveBtn.disabled = !lic.isPro && !state.hasStoredLicenseToken;

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
        t(lang, "pro.metaTier", { tier: lic.isOwner ? "Owner Pro" : "Pro" }),
        t(lang, "pro.metaKeyId", { keyId: lic.keyId }),
        t(lang, "pro.metaLabel", { label: lic.label }),
        t(lang, "pro.metaIssuedAt", { date: formatClaimDate(lic.issuedAt, lang) }),
        hasExpClaim(lic.exp)
          ? t(lang, "pro.metaExp", { date: formatClaimDate(lic.exp, lang) })
          : t(lang, "pro.metaExpNever"),
        lic.method
          ? t(lang, "pro.metaMethod", {
              method: t(lang, lic.method === "webcrypto" ? "pro.methodWebCrypto" : "pro.methodPureJs"),
            })
          : "",
      ].filter(Boolean);

      const items = metaRows.map((row) => {
        const li = doc.createElement("li");
        li.textContent = row;
        return li;
      });
      els.proMetaList.replaceChildren(...items);
    }

    renderProAlert();
    renderProDiagnostics();
  }

  function renderAll() {
    renderStaticCopy();
    renderCategories();
    renderCustomRulesAndPacks();
    renderProStatus();
  }

  els.langRu.addEventListener("click", async () => {
    if (state.settings.lang === "ru") return;
    const savePromise = updateSettings({ lang: "ru" });
    renderAll();
    await savePromise;
  });

  els.langEn.addEventListener("click", async () => {
    if (state.settings.lang === "en") return;
    const savePromise = updateSettings({ lang: "en" });
    renderAll();
    await savePromise;
  });

  els.themeBtn.addEventListener("click", async () => {
    const savePromise = updateSettings((prev) => ({
      ...prev,
      theme: prev.theme === "dark" ? "light" : "dark",
    }));
    renderAll();
    await savePromise;
  });

  els.proBadge.addEventListener("click", () => {
    els.proSection.scrollIntoView?.({ behavior: "smooth", block: "nearest" });
    els.proKeyInput.focus();
  });

  els.overlayToggle.addEventListener("click", async () => {
    const savePromise = updateSettings((prev) => ({
      ...prev,
      overlayVisible: !prev.overlayVisible,
    }));
    renderStaticCopy();
    await savePromise;
  });

  els.sensNormal.addEventListener("click", async () => {
    if (state.settings.sensitivity === "normal") return;
    const savePromise = updateSettings({ sensitivity: "normal", detectUuid: false });
    renderStaticCopy();
    await savePromise;
  });

  els.sensStrict.addEventListener("click", async () => {
    if (state.settings.sensitivity === "strict") return;
    const savePromise = updateSettings({ sensitivity: "strict", detectUuid: true });
    renderStaticCopy();
    await savePromise;
  });

  els.uuidToggle.addEventListener("change", async () => {
    if (state.settings.sensitivity === "strict") return;
    const savePromise = updateSettings({ detectUuid: els.uuidToggle.checked });
    renderStaticCopy();
    await savePromise;
  });

  els.categoriesReset.addEventListener("click", async () => {
    if (!state.license.isPro) return;
    const savePromise = updateSettings({ disabledCategories: [] });
    renderCategories();
    await savePromise;
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
        "warn",
        {
          key: "rules.limitReached",
          vars: { limit: FREE_CUSTOM_RULE_LIMIT },
          action: "focusPro",
        }
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
    const savePromise = updateSettings((prev) => ({
      ...prev,
      customRules: [...prev.customRules, candidate],
    }));
    els.customTerm.value = "";
    clearCustomAlert();
    renderCustomRulesAndPacks();
    await savePromise;
  });

  async function activateCandidateToken(rawText, actionSeq = ++proActionSeq) {
    const trimmedRaw = typeof rawText === "string" ? rawText.trim() : "";
    if (!trimmedRaw) {
      const lang = state.settings.lang;
      state.proInspection = null;
      showProAlert(t(lang, "pro.errorEmpty"), "error", { key: "pro.errorEmpty" });
      renderProDiagnostics();
      els.proKeyInput?.focus?.();
      return null;
    }
    const inspected = await inspectProLicenseToken(trimmedRaw, getVerifyOptions());
    if (actionSeq !== proActionSeq) {
      return null;
    }
    const lang = state.settings.lang;
    const extractedFromText = Boolean(
      inspected.extractedToken && inspected.extractedToken !== trimmedRaw
    );
    state.proInspection = { ...inspected, mode: "activate", extractedFromText };
    if (!inspected.valid) {
      const reasonDesc = getProReasonDescriptor(inspected);
      showProAlert(
        getProReasonMessage(inspected, lang),
        inspected.reason === "expired" ? "warn" : "error",
        reasonDesc
      );
      renderProDiagnostics();
      return inspected;
    }
    pendingLicenseSaves += 1;
    try {
      await saveExtProLicenseToken(inspected.token, storageArea);
    } finally {
      pendingLicenseSaves = Math.max(0, pendingLicenseSaves - 1);
    }
    if (actionSeq !== proActionSeq) {
      return null;
    }
    const currentLang = state.settings.lang;
    state.hasStoredLicenseToken = true;
    state.license = inspected;
    els.proKeyInput.value = "";
    clearCustomAlert();
    const tierLabel = inspected.isOwner ? "Owner Pro" : "Pro";
    showProAlert(
      t(currentLang, "pro.activatedSuccess", {
        tier: tierLabel,
        keyId: inspected.keyId,
      }),
      "success",
      {
        key: "pro.activatedSuccess",
        vars: { tier: tierLabel, keyId: inspected.keyId },
      }
    );
    renderAll();
    return inspected;
  }

  els.categoriesLock?.addEventListener("click", () => {
    if (!state.license.isPro) {
      focusProActivation({ alertTarget: "pro", messageKey: "categories.proHint", tone: "warn" });
    }
  });

  els.categoriesProHint?.addEventListener("click", () => {
    if (!state.license.isPro) {
      focusProActivation({ alertTarget: "pro", messageKey: "categories.proHint", tone: "warn" });
    }
  });

  els.categoriesProHint?.addEventListener("keydown", (event) => {
    if (!state.license.isPro && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault?.();
      focusProActivation({ alertTarget: "pro", messageKey: "categories.proHint", tone: "warn" });
    }
  });

  els.packsLock?.addEventListener("click", () => {
    if (!state.license.isPro) {
      focusProActivation({ alertTarget: "custom", messageKey: "packs.lockedNotice", tone: "warn" });
    }
  });

  els.customAlert?.addEventListener("click", () => {
    if (state.customFeedback?.action === "focusPro" && !state.license.isPro) {
      focusProActivation();
    }
  });

  els.customAlert?.addEventListener("keydown", (event) => {
    if (
      state.customFeedback?.action === "focusPro" &&
      !state.license.isPro &&
      (event.key === "Enter" || event.key === " ")
    ) {
      event.preventDefault?.();
      focusProActivation();
    }
  });

  els.proActivateBtn.addEventListener("click", async () => {
    const actionSeq = ++proActionSeq;
    await activateCandidateToken(els.proKeyInput.value, actionSeq);
  });

  els.proVerifyBtn?.addEventListener("click", async () => {
    const actionSeq = ++proActionSeq;
    const raw = String(els.proKeyInput.value || "").trim();
    if (!raw) {
      const storedToken = await loadExtProLicenseToken(storageArea);
      if (actionSeq !== proActionSeq) return;
      state.hasStoredLicenseToken = Boolean(storedToken);
      const storedCandidate = extractProToken(storedToken) || storedToken;
      if (storedCandidate) {
        const inspected = await inspectProLicenseToken(storedCandidate, getVerifyOptions());
        if (actionSeq !== proActionSeq) return;
        const lang = state.settings.lang;
        state.license = inspected;
        state.proInspection = {
          ...inspected,
          mode: inspected.valid ? "verify-active" : "verify",
          extractedFromText: false,
        };
        if (inspected.valid) {
          const tierLabel = inspected.isOwner ? "Owner Pro" : "Pro";
          showProAlert(
            t(lang, "pro.verifyActiveSuccess", {
              tier: tierLabel,
              keyId: inspected.keyId,
            }),
            "success",
            {
              key: "pro.verifyActiveSuccess",
              vars: { tier: tierLabel, keyId: inspected.keyId },
            }
          );
        } else {
          const reasonDesc = getProReasonDescriptor(inspected);
          showProAlert(
            getProReasonMessage(inspected, lang),
            inspected.reason === "expired" ? "warn" : "error",
            reasonDesc
          );
        }
        renderAll();
        return;
      }
      const lang = state.settings.lang;
      state.proInspection = null;
      showProAlert(t(lang, "pro.errorEmpty"), "error", { key: "pro.errorEmpty" });
      renderProStatus();
      els.proKeyInput?.focus?.();
      return;
    }

    const inspected = await inspectProLicenseToken(raw, getVerifyOptions());
    if (actionSeq !== proActionSeq) return;
    const lang = state.settings.lang;
    const extractedFromText = Boolean(inspected.extractedToken && inspected.extractedToken !== raw);
    state.proInspection = { ...inspected, mode: "verify", extractedFromText };
    if (inspected.valid) {
      const tierLabel = inspected.isOwner ? "Owner Pro" : "Pro";
      showProAlert(
        t(lang, "pro.verifySuccess", {
          tier: tierLabel,
          keyId: inspected.keyId,
        }),
        "success",
        {
          key: "pro.verifySuccess",
          vars: { tier: tierLabel, keyId: inspected.keyId },
        }
      );
    } else {
      const reasonDesc = getProReasonDescriptor(inspected);
      showProAlert(
        getProReasonMessage(inspected, lang),
        inspected.reason === "expired" ? "warn" : "error",
        reasonDesc
      );
    }
    renderProDiagnostics();
  });

  els.proPasteBtn?.addEventListener("click", async () => {
    const actionSeq = ++proActionSeq;
    if (!clipboard || typeof clipboard.readText !== "function") {
      state.proInspection = null;
      showProAlert(t(state.settings.lang, "pro.errorClipboardDenied"), "warn", {
        key: "pro.errorClipboardDenied",
      });
      renderProDiagnostics();
      els.proKeyInput?.focus?.();
      return;
    }
    let clipText = "";
    try {
      clipText = await clipboard.readText();
    } catch {
      if (actionSeq !== proActionSeq) return;
      state.proInspection = null;
      showProAlert(t(state.settings.lang, "pro.errorClipboardDenied"), "warn", {
        key: "pro.errorClipboardDenied",
      });
      renderProDiagnostics();
      els.proKeyInput?.focus?.();
      return;
    }
    if (actionSeq !== proActionSeq) return;
    const text = typeof clipText === "string" ? clipText.trim() : "";
    if (!text) {
      state.proInspection = null;
      showProAlert(t(state.settings.lang, "pro.errorClipboardEmpty"), "warn", {
        key: "pro.errorClipboardEmpty",
      });
      renderProDiagnostics();
      els.proKeyInput?.focus?.();
      return;
    }
    const extracted = extractProToken(text);
    if (extracted) {
      els.proKeyInput.value = extracted;
      await activateCandidateToken(text, actionSeq);
      return;
    }
    if (text.startsWith("PV1.")) {
      els.proKeyInput.value = text;
      await activateCandidateToken(text, actionSeq);
      return;
    }
    state.proInspection = null;
    showProAlert(t(state.settings.lang, "pro.errorClipboardNoToken"), "warn", {
      key: "pro.errorClipboardNoToken",
    });
    renderProDiagnostics();
    els.proKeyInput?.focus?.();
  });

  els.proFileBtn?.addEventListener("click", () => {
    els.proFileInput?.click?.();
  });

  els.proFileInput?.addEventListener("change", async (event) => {
    const actionSeq = ++proActionSeq;
    const inputEl = event?.target || els.proFileInput;
    const files = inputEl?.files;
    const file = files && files.length > 0 ? files[0] : null;
    if (inputEl) {
      inputEl.value = "";
    }
    if (!file) {
      return;
    }
    if (typeof file.size === "number" && file.size > MAX_PVKEY_FILE_BYTES) {
      state.proInspection = { valid: false, reason: "file_too_large", mode: "file" };
      showProAlert(t(state.settings.lang, "pro.errorFileTooLarge"), "error", {
        key: "pro.errorFileTooLarge",
      });
      renderProDiagnostics();
      return;
    }
    let parsed;
    try {
      const bytes = await readUploadedFileBytes(file);
      if (actionSeq !== proActionSeq) return;
      parsed = parsePvKeyUploadBytes(
        bytes,
        typeof file.size === "number" ? file.size : bytes.length
      );
    } catch {
      if (actionSeq !== proActionSeq) return;
      parsed = { ok: false, reason: "file_read", text: "", token: "" };
    }
    if (actionSeq !== proActionSeq) return;
    if (!parsed.ok) {
      state.proInspection = { valid: false, reason: parsed.reason, mode: "file" };
      const reasonDesc = getProReasonDescriptor({ reason: parsed.reason });
      showProAlert(getProReasonMessage({ reason: parsed.reason }, state.settings.lang), "error", reasonDesc);
      renderProDiagnostics();
      return;
    }
    els.proKeyInput.value = parsed.token;
    await activateCandidateToken(parsed.text || parsed.token, actionSeq);
  });

  els.proRemoveBtn.addEventListener("click", async () => {
    const actionSeq = ++proActionSeq;
    pendingLicenseSaves += 1;
    try {
      await clearExtProLicenseToken(storageArea);
    } finally {
      pendingLicenseSaves = Math.max(0, pendingLicenseSaves - 1);
    }
    if (actionSeq !== proActionSeq) return;
    state.hasStoredLicenseToken = false;
    state.license = createFreeLicenseState("removed");
    state.proInspection = null;
    showProAlert(t(state.settings.lang, "pro.removedSuccess"), "warn", {
      key: "pro.removedSuccess",
    });
    renderAll();
  });

  const unsubscribe = subscribeExtStorageChanges(async ({ settingsChanged, licenseChanged }) => {
    try {
      let updated = false;
      if (settingsChanged && pendingSettingsSaves === 0) {
        const seq = ++settingsRefreshSeq;
        const nextSettings = await loadExtSettings(storageArea);
        if (seq === settingsRefreshSeq && pendingSettingsSaves === 0) {
          state.settings = nextSettings;
          updated = true;
        }
      }
      if (licenseChanged && pendingLicenseSaves === 0) {
        const prevValid = Boolean(state.license?.valid);
        const prevToken = state.license?.token || "";
        const refreshed = await refreshLicenseFromStorage();
        if (refreshed) {
          updated = true;
          const nextValid = Boolean(state.license?.valid);
          const nextToken = state.license?.token || "";
          const licenseModified = prevValid !== nextValid || prevToken !== nextToken;
          const isOwnRemoveEcho =
            !nextValid &&
            !prevValid &&
            !state.hasStoredLicenseToken &&
            state.proFeedback?.key === "pro.removedSuccess";
          if ((licenseModified || !nextValid) && !isOwnRemoveEcho) {
            state.proInspection = null;
            state.proFeedback = null;
          }
        }
      }
      if (updated) {
        renderAll();
      }
    } catch {
      // Ignore storage errors if popup/extension context is closing.
    }
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
