/**
 * PromptVeil Manifest V3 Content Script (Shadow DOM Floating Pill).
 * - Uses Shadow DOM + Constructable Stylesheets (safe DOM APIs only, zero inline styles).
 * - Sanitizes & rehydrates strictly in tab RAM via SessionVault (resetOnEmpty: false).
 * - Independently verifies Pro license tokens via verifyProLicenseToken().
 */

import {
  createFreeLicenseState,
  extractProToken,
  verifyProLicenseToken,
} from "../../app/static/js/pro-license.js";
import { SessionVault } from "../../app/static/js/vault.js";
import {
  PROMPTVEIL_HOST_ID,
  findPromptBox,
  readEditorText,
  resolveRehydrateSource,
  writeEditorText,
} from "./adapters.js";
import { t } from "./i18n-ext.js";
import {
  FREE_CUSTOM_RULE_LIMIT,
  getChromeStorageLocal,
  getEffectiveMaskingConfig,
  loadExtProLicenseToken,
  loadExtSettings,
  subscribeExtStorageChanges,
} from "./storage-ext.js";

export const SHADOW_CSS = `
:host {
  all: initial;
  max-width: 100%;
  font-family: "Segoe UI Variable Display", "Segoe UI", "Inter", -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
  color: #0b130f;
}

*,
*::before,
*::after {
  box-sizing: border-box;
}

[hidden] {
  display: none !important;
}

.pv-shell {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 8px;
  max-width: 100%;
}

.pv-popover {
  width: 348px;
  max-width: 100%;
  background: #ffffff;
  color: #0b130f;
  border: 1px solid rgba(7, 47, 31, 0.16);
  border-radius: 16px;
  box-shadow: 0 18px 40px rgba(5, 28, 18, 0.24);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

:host([data-pv-theme="dark"]) .pv-popover {
  background: #0c2117;
  color: #f0f7f3;
  border-color: rgba(180, 241, 5, 0.24);
}

.pv-popover-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 9px 12px;
  background: #051c12;
  color: #ffffff;
}

.pv-popover-title {
  font-size: 12.5px;
  font-weight: 800;
}

.pv-popover-close {
  appearance: none;
  border: 1px solid rgba(255, 255, 255, 0.2);
  background: rgba(255, 255, 255, 0.08);
  color: #ffffff;
  border-radius: 9999px;
  padding: 2px 9px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
}

.pv-popover-warn {
  padding: 6px 12px;
  background: #fffbeb;
  color: #92400e;
  border-bottom: 1px solid #fde68a;
  font-size: 11.5px;
  font-weight: 600;
}

:host([data-pv-theme="dark"]) .pv-popover-warn {
  background: rgba(249, 115, 22, 0.16);
  color: #fed7aa;
  border-bottom-color: rgba(251, 146, 60, 0.35);
}

.pv-popover-body {
  padding: 10px 12px;
  max-height: 220px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 12.5px;
  line-height: 1.5;
}

.pv-mark {
  background: rgba(180, 241, 5, 0.38);
  color: inherit;
  padding: 0 3px;
  border-radius: 4px;
  font-weight: 700;
}

.pv-popover-foot {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding: 8px 12px;
  border-top: 1px solid rgba(11, 19, 15, 0.1);
}

:host([data-pv-theme="dark"]) .pv-popover-foot {
  border-top-color: rgba(255, 255, 255, 0.12);
}

.pv-toast {
  max-width: min(340px, 100%);
  padding: 7px 11px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 600;
  background: #072f1f;
  color: #ffffff;
  border: 1px solid rgba(180, 241, 5, 0.42);
  box-shadow: 0 10px 24px rgba(5, 28, 18, 0.22);
}

.pv-toast.is-warn {
  background: #fffbeb;
  color: #92400e;
  border-color: #fde68a;
}

.pv-toast.is-success {
  background: #051c12;
  color: #b4f105;
  border-color: #b4f105;
}

.pv-pill {
  display: flex;
  flex-direction: column;
  gap: 7px;
  padding: 9px 11px;
  border-radius: 16px;
  background: #051c12;
  color: #ffffff;
  border: 1px solid rgba(180, 241, 5, 0.35);
  box-shadow: 0 14px 32px rgba(5, 28, 18, 0.32);
}

.pv-pill-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.pv-pill-brand {
  display: flex;
  align-items: center;
  gap: 6px;
}

.pv-prism-mark {
  position: relative;
  width: 20px;
  height: 20px;
  border-radius: 5px;
  background: #072f1f;
  border: 1px solid rgba(180, 241, 5, 0.45);
  flex: 0 0 auto;
  display: inline-block;
}

.pv-prism-l,
.pv-prism-r,
.pv-prism-c {
  position: absolute;
  inset: 0;
  display: block;
}

.pv-prism-l {
  background: #ffffff;
  clip-path: polygon(21.875% 25%, 42.1875% 25%, 57.8125% 59.375%, 50% 78.125%);
}

.pv-prism-r {
  background: #b4f105;
  clip-path: polygon(57.8125% 25%, 78.125% 25%, 50% 78.125%, 42.1875% 59.375%);
}

.pv-prism-c {
  background: #051c12;
  clip-path: polygon(50% 42.1875%, 57.8125% 59.375%, 50% 78.125%, 42.1875% 59.375%);
}

.pv-pill-title {
  font-size: 12.5px;
  font-weight: 800;
  letter-spacing: -0.01em;
}

.pv-tier-chip {
  appearance: none;
  border: 1px solid rgba(255, 255, 255, 0.16);
  font-family: inherit;
  font-size: 10px;
  font-weight: 700;
  line-height: 1.2;
  padding: 2px 7px;
  border-radius: 9999px;
  background: rgba(255, 255, 255, 0.12);
  color: #ffffff;
  cursor: pointer;
}

.pv-tier-chip:hover {
  background: rgba(255, 255, 255, 0.2);
}

.pv-tier-chip.is-pro {
  background: #b4f105;
  border-color: #b4f105;
  color: #051c12;
}

.pv-tier-chip.is-pro:hover {
  background: #c1f824;
}

.pv-tier-chip.is-expired {
  background: #fffbeb;
  border-color: #fde68a;
  color: #92400e;
}

.pv-vault-chip {
  font-size: 10.5px;
  font-weight: 700;
  padding: 2px 7px;
  border-radius: 9999px;
  background: #072f1f;
  color: #c7d6ce;
  border: 1px solid rgba(255, 255, 255, 0.14);
}

.pv-pill-tools {
  display: flex;
  align-items: center;
  gap: 4px;
}

.pv-tool-btn {
  appearance: none;
  border: 1px solid rgba(255, 255, 255, 0.18);
  background: rgba(255, 255, 255, 0.08);
  color: #ffffff;
  border-radius: 9999px;
  width: 22px;
  height: 22px;
  font-size: 12px;
  font-weight: 700;
  line-height: 1;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.pv-pill-actions {
  display: flex;
  align-items: center;
  gap: 6px;
}

.pv-btn-sanitize {
  appearance: none;
  border: 0;
  border-radius: 9999px;
  background: #b4f105;
  color: #051c12;
  padding: 7px 12px;
  font-size: 12px;
  font-weight: 800;
  cursor: pointer;
  white-space: nowrap;
}

.pv-btn-rehydrate {
  appearance: none;
  border: 1px solid rgba(255, 255, 255, 0.24);
  border-radius: 9999px;
  background: #072f1f;
  color: #ffffff;
  padding: 7px 12px;
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
  white-space: nowrap;
}

.pv-btn-copy {
  appearance: none;
  border: 1px solid transparent;
  border-radius: 9999px;
  background: #072f1f;
  color: #ffffff;
  padding: 6px 12px;
  font-size: 11.5px;
  font-weight: 700;
  cursor: pointer;
}

:host([data-pv-theme="dark"]) .pv-btn-copy {
  background: #0f402c;
  border: 1px solid rgba(180, 241, 5, 0.35);
  color: #ffffff;
}

:host([data-pv-theme="dark"]) .pv-btn-copy:hover {
  background: #18553c;
}

.pv-btn-sanitize:hover {
  background: #c1f824;
}

.pv-btn-rehydrate:hover,
.pv-tool-btn:hover {
  background: #1a3e30;
}

button:focus-visible {
  outline: 2px solid #b4f105;
  outline-offset: 2px;
}
`;

function createSparkPrismMark(doc) {
  const mark = doc.createElement("span");
  mark.className = "pv-prism-mark";
  mark.setAttribute("aria-hidden", "true");

  const left = doc.createElement("span");
  left.className = "pv-prism-l";
  const right = doc.createElement("span");
  right.className = "pv-prism-r";
  const center = doc.createElement("span");
  center.className = "pv-prism-c";

  mark.append(left, right, center);
  return mark;
}

async function copyTextSafely(text, clipboard) {
  if (!text) return false;
  if (clipboard && typeof clipboard.writeText === "function") {
    try {
      await clipboard.writeText(text);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

function normalizeLicenseTimestampMs(value) {
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

function formatLicenseExpDate(exp, lang) {
  if (exp === null || exp === undefined || exp === "") return "";
  const ms = normalizeLicenseTimestampMs(exp);
  if (Number.isNaN(ms)) return String(exp);
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return String(exp);
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

function buildTierSummary(lang, license) {
  if (license?.isPro) {
    const badgeText = license.isOwner ? t(lang, "pro.badgeOwner") : t(lang, "pro.badgePro");
    const keyId = license.keyId || "PV1";
    const hasExp =
      license.exp !== null &&
      license.exp !== undefined &&
      (typeof license.exp !== "string" || license.exp.trim() !== "");
    const toastText = hasExp
      ? t(lang, "pill.tierInfoProExp", {
          badge: badgeText,
          keyId,
          date: formatLicenseExpDate(license.exp, lang),
        })
      : t(lang, "pill.tierInfoProLifetime", {
          badge: badgeText,
          keyId,
        });
    const ariaText = t(lang, "pill.tierAriaPro", { badge: badgeText, keyId });
    return {
      badgeText,
      titleText: toastText,
      ariaText,
      toastText,
      toastTone: "success",
      isPro: true,
      isExpired: false,
    };
  }

  const badgeText = t(lang, "pro.badgeFree");
  const reason = String(license?.reason || "");

  if (reason === "expired") {
    const keyId = license?.keyId || "PV1";
    const hasExp =
      license?.exp !== null &&
      license?.exp !== undefined &&
      (typeof license.exp !== "string" || license.exp.trim() !== "");
    const toastText = hasExp
      ? t(lang, "pill.tierHintExpired", {
          keyId,
          date: formatLicenseExpDate(license.exp, lang),
        })
      : t(lang, "pill.tierHintExpiredNoDate", { keyId });
    const ariaText = t(lang, "pill.tierAriaExpired", { keyId });
    return {
      badgeText,
      titleText: toastText,
      ariaText,
      toastText,
      toastTone: "warn",
      isPro: false,
      isExpired: true,
    };
  }

  if (reason && reason !== "empty" && reason !== "none" && reason !== "removed") {
    const toastText = t(lang, "pill.tierHintInvalid");
    const ariaText = t(lang, "pill.tierAriaInvalid");
    return {
      badgeText,
      titleText: toastText,
      ariaText,
      toastText,
      toastTone: "warn",
      isPro: false,
      isExpired: false,
    };
  }

  const toastText = t(lang, "pill.tierHintFree", { limit: FREE_CUSTOM_RULE_LIMIT });
  const ariaText = t(lang, "pill.tierAriaFree");
  return {
    badgeText,
    titleText: toastText,
    ariaText,
    toastText,
    toastTone: "info",
    isPro: false,
    isExpired: false,
  };
}

export async function createContentController({
  win = globalThis.window,
  doc = globalThis.document,
  hostname = globalThis.location?.hostname || "",
  clipboard = globalThis.navigator?.clipboard,
  storageArea = getChromeStorageLocal(),
  storageEvents = globalThis.chrome?.storage?.onChanged,
  publicKeyB64U,
  nowMs,
} = {}) {
  if (!doc || !doc.createElement) {
    return null;
  }

  const existingHost = doc.getElementById?.(PROMPTVEIL_HOST_ID);
  if (existingHost) {
    return null;
  }

  const host = doc.createElement("div");
  host.id = PROMPTVEIL_HOST_ID;
  const shadow = host.attachShadow({ mode: "open" });

  if (
    typeof globalThis.CSSStyleSheet === "function" &&
    "replaceSync" in globalThis.CSSStyleSheet.prototype &&
    Array.isArray(shadow.adoptedStyleSheets)
  ) {
    const sheet = new globalThis.CSSStyleSheet();
    sheet.replaceSync(SHADOW_CSS);
    shadow.adoptedStyleSheets = [sheet];
  }

  const shell = doc.createElement("div");
  shell.className = "pv-shell";

  const popover = doc.createElement("div");
  popover.className = "pv-popover";
  popover.hidden = true;

  const popoverHead = doc.createElement("div");
  popoverHead.className = "pv-popover-head";
  const popoverTitle = doc.createElement("span");
  popoverTitle.className = "pv-popover-title";
  const popoverCloseBtn = doc.createElement("button");
  popoverCloseBtn.type = "button";
  popoverCloseBtn.className = "pv-popover-close";
  popoverHead.append(popoverTitle, popoverCloseBtn);

  const popoverWarn = doc.createElement("div");
  popoverWarn.className = "pv-popover-warn";
  popoverWarn.hidden = true;

  const popoverBody = doc.createElement("div");
  popoverBody.className = "pv-popover-body";

  const popoverFoot = doc.createElement("div");
  popoverFoot.className = "pv-popover-foot";
  const popoverCopyBtn = doc.createElement("button");
  popoverCopyBtn.type = "button";
  popoverCopyBtn.className = "pv-btn-copy";
  popoverFoot.append(popoverCopyBtn);

  popover.append(popoverHead, popoverWarn, popoverBody, popoverFoot);

  const toast = doc.createElement("div");
  toast.className = "pv-toast";
  toast.setAttribute("role", "status");
  toast.hidden = true;

  const pill = doc.createElement("div");
  pill.className = "pv-pill";

  const pillTop = doc.createElement("div");
  pillTop.className = "pv-pill-top";

  const pillBrand = doc.createElement("div");
  pillBrand.className = "pv-pill-brand";
  const brandTitle = doc.createElement("span");
  brandTitle.className = "pv-pill-title";
  const tierChip = doc.createElement("button");
  tierChip.type = "button";
  tierChip.className = "pv-tier-chip";
  const vaultChip = doc.createElement("span");
  vaultChip.className = "pv-vault-chip";
  pillBrand.append(createSparkPrismMark(doc), brandTitle, tierChip, vaultChip);

  const pillTools = doc.createElement("div");
  pillTools.className = "pv-pill-tools";
  const resetBtn = doc.createElement("button");
  resetBtn.type = "button";
  resetBtn.className = "pv-tool-btn";
  resetBtn.textContent = "↺";
  const collapseBtn = doc.createElement("button");
  collapseBtn.type = "button";
  collapseBtn.className = "pv-tool-btn";
  collapseBtn.textContent = "−";
  pillTools.append(resetBtn, collapseBtn);

  pillTop.append(pillBrand, pillTools);

  const pillActions = doc.createElement("div");
  pillActions.className = "pv-pill-actions";
  const sanitizeBtn = doc.createElement("button");
  sanitizeBtn.type = "button";
  sanitizeBtn.className = "pv-btn-sanitize";
  sanitizeBtn.setAttribute("data-pv-action", "sanitize");
  const rehydrateBtn = doc.createElement("button");
  rehydrateBtn.type = "button";
  rehydrateBtn.className = "pv-btn-rehydrate";
  rehydrateBtn.setAttribute("data-pv-action", "rehydrate");
  pillActions.append(sanitizeBtn, rehydrateBtn);

  pill.append(pillTop, pillActions);
  shell.append(popover, toast, pill);
  shadow.append(shell);

  const mountTarget = doc.documentElement || doc.body;
  if (mountTarget && typeof mountTarget.appendChild === "function") {
    mountTarget.appendChild(host);
  }

  const tabVault = new SessionVault();
  const state = {
    settings: await loadExtSettings(storageArea),
    license: createFreeLicenseState("none"),
    collapsed: false,
    lastRehydratedText: "",
    toastTimer: null,
  };

  let licenseRefreshSeq = 0;
  let settingsRefreshSeq = 0;

  async function refreshLicense() {
    const seq = ++licenseRefreshSeq;
    const rawToken = await loadExtProLicenseToken(storageArea);
    if (seq !== licenseRefreshSeq) return;
    if (!rawToken) {
      state.license = createFreeLicenseState("empty");
      return;
    }
    const candidate = extractProToken(rawToken) || rawToken;
    const verifyOpts = {};
    if (publicKeyB64U) verifyOpts.publicKeyB64U = publicKeyB64U;
    if (typeof nowMs === "number" && Number.isFinite(nowMs)) verifyOpts.nowMs = nowMs;
    const verified = await verifyProLicenseToken(candidate, verifyOpts);
    if (seq !== licenseRefreshSeq) return;
    state.license = verified;
  }

  function showToast(text, tone = "info") {
    if (state.toastTimer) {
      clearTimeout(state.toastTimer);
      state.toastTimer = null;
    }
    toast.textContent = text;
    toast.className = `pv-toast${tone === "warn" ? " is-warn" : tone === "success" ? " is-success" : ""}`;
    toast.hidden = false;
    state.toastTimer = setTimeout(() => {
      toast.hidden = true;
      state.toastTimer = null;
    }, 4500);
  }

  function renderPill() {
    const lang = state.settings.lang;
    host.setAttribute("data-pv-theme", state.settings.theme);
    host.setAttribute("data-pv-hidden", state.settings.overlayVisible ? "false" : "true");

    brandTitle.textContent = t(lang, "pill.title");
    const tierInfo = buildTierSummary(lang, state.license);
    tierChip.classList.toggle("is-pro", tierInfo.isPro);
    tierChip.classList.toggle("is-expired", tierInfo.isExpired);
    tierChip.textContent = tierInfo.badgeText;
    tierChip.setAttribute("title", tierInfo.titleText);
    tierChip.setAttribute("aria-label", tierInfo.ariaText);
    vaultChip.textContent = t(lang, "pill.vaultCount", {
      count: tabVault.tokenToEntry.size,
    });

    sanitizeBtn.textContent = t(lang, "pill.sanitizeBtn");
    rehydrateBtn.textContent = t(lang, "pill.rehydrateBtn");
    resetBtn.setAttribute("title", t(lang, "pill.resetTitle"));
    resetBtn.setAttribute("aria-label", t(lang, "pill.resetTitle"));
    collapseBtn.setAttribute("title", t(lang, "pill.collapseTitle"));
    collapseBtn.setAttribute("aria-label", t(lang, "pill.collapseTitle"));
    collapseBtn.textContent = state.collapsed ? "+" : "−";
    pillActions.hidden = state.collapsed;

    popoverCopyBtn.textContent = t(lang, "pill.copyBtn");
    popoverCloseBtn.textContent = t(lang, "pill.closeBtn");
  }

  function renderPopover(result) {
    const lang = state.settings.lang;
    state.lastRehydratedText = result.rehydratedText || "";
    popoverTitle.textContent = t(lang, "pill.popoverTitle", { count: result.replacedCount });

    if (Array.isArray(result.unresolvedTokens) && result.unresolvedTokens.length > 0) {
      popoverWarn.hidden = false;
      popoverWarn.textContent = t(lang, "pill.unresolvedWarning", {
        tokens: result.unresolvedTokens.join(", "),
      });
    } else {
      popoverWarn.hidden = true;
      popoverWarn.textContent = "";
    }

    const fragmentNodes = (result.segments || []).map((seg) => {
      if (seg.type === "restored") {
        const mark = doc.createElement("mark");
        mark.className = "pv-mark";
        mark.textContent = seg.text;
        return mark;
      }
      return doc.createTextNode(seg.text);
    });
    if (typeof popoverBody.replaceChildren === "function") {
      popoverBody.replaceChildren(...fragmentNodes);
    } else {
      while (popoverBody.firstChild) popoverBody.removeChild(popoverBody.firstChild);
      for (const node of fragmentNodes) popoverBody.appendChild(node);
    }

    popoverCopyBtn.textContent = t(lang, "pill.copyBtn");
    popover.hidden = false;
  }

  async function handleSanitize() {
    const lang = state.settings.lang;
    const box = findPromptBox(doc, hostname);
    if (!box) {
      showToast(t(lang, "pill.noInput"), "warn");
      return { ok: false, reason: "no_input" };
    }

    const rawText = readEditorText(box);
    if (!rawText || rawText.trim().length === 0) {
      showToast(t(lang, "pill.emptyInput"), "warn");
      return { ok: false, reason: "empty_input" };
    }

    const effective = getEffectiveMaskingConfig(state.settings, state.license);
    tabVault.disabledCategories = new Set(effective.disabledCategories);

    const res = tabVault.sanitize(rawText, effective.customRules, {
      detectUuid: effective.detectUuid,
      sensitivity: effective.sensitivity,
      evolveTransient: false,
      resetOnEmpty: false,
    });

    if (res.maskedCount > 0) {
      writeEditorText(box, res.sanitizedText, doc);
      showToast(t(lang, "pill.maskedSuccess", { count: res.maskedCount }), "success");
    } else {
      showToast(t(lang, "pill.noMatches"), "info");
    }

    renderPill();
    return { ok: true, result: res };
  }

  async function handleRehydrate() {
    const lang = state.settings.lang;
    if (tabVault.tokenToEntry.size === 0) {
      showToast(t(lang, "pill.emptyVault"), "warn");
      return { ok: false, reason: "empty_vault" };
    }

    const resolved = await resolveRehydrateSource({
      win,
      doc,
      hostname,
      clipboard,
    });
    if (!resolved.text || resolved.text.trim().length === 0) {
      showToast(t(lang, "pill.noReplySource"), "warn");
      return { ok: false, reason: "no_reply" };
    }

    const res = tabVault.rehydrate(resolved.text);
    if (res.replacedCount === 0 && res.unresolvedTokens.length === 0) {
      showToast(t(lang, "pill.noTokensInReply"), "warn");
      return { ok: false, reason: "no_tokens", result: res };
    }

    renderPopover(res);
    const copied = res.replacedCount > 0 && (await copyTextSafely(res.rehydratedText, clipboard));
    showToast(
      t(lang, copied ? "pill.restoredAndCopied" : "pill.restoredOnly", {
        count: res.replacedCount,
      }),
      "success"
    );
    return { ok: true, result: res, copied };
  }

  tierChip.addEventListener("click", () => {
    const tierInfo = buildTierSummary(state.settings.lang, state.license);
    showToast(tierInfo.toastText, tierInfo.toastTone);
  });

  sanitizeBtn.addEventListener("click", () => {
    handleSanitize();
  });

  rehydrateBtn.addEventListener("click", () => {
    handleRehydrate();
  });

  resetBtn.addEventListener("click", () => {
    tabVault.reset();
    popover.hidden = true;
    state.lastRehydratedText = "";
    renderPill();
    showToast(t(state.settings.lang, "pill.vaultCleared"), "info");
  });

  collapseBtn.addEventListener("click", () => {
    state.collapsed = !state.collapsed;
    renderPill();
  });

  popoverCloseBtn.addEventListener("click", () => {
    popover.hidden = true;
  });

  popoverCopyBtn.addEventListener("click", async () => {
    const copied = await copyTextSafely(state.lastRehydratedText, clipboard);
    if (copied) {
      popoverCopyBtn.textContent = t(state.settings.lang, "pill.copiedBtn");
    }
  });

  const unsubscribe = subscribeExtStorageChanges(async ({ settingsChanged, licenseChanged }) => {
    try {
      if (settingsChanged) {
        const seq = ++settingsRefreshSeq;
        const nextSettings = await loadExtSettings(storageArea);
        if (seq === settingsRefreshSeq) {
          state.settings = nextSettings;
        }
      }
      if (licenseChanged) {
        await refreshLicense();
      }
      renderPill();
    } catch {
      // Ignore storage errors if extension context is invalidated on reload.
    }
  }, storageEvents);

  await refreshLicense();
  renderPill();

  return {
    host,
    shadow,
    tabVault,
    getState: () => state,
    handleSanitize,
    handleRehydrate,
    destroy: () => {
      if (state.toastTimer) clearTimeout(state.toastTimer);
      unsubscribe();
      host.remove?.();
    },
  };
}

if (
  typeof globalThis.document !== "undefined" &&
  typeof globalThis.chrome !== "undefined" &&
  Boolean(globalThis.chrome?.runtime?.id)
) {
  createContentController();
}
