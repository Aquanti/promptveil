/**
 * PromptVeil Pro Checkout & Offline Ed25519 Activation Terminal.
 * Zero network egress, zero unsafe HTML sinks, RAM-only buyer/order state.
 */

import { SITE_CONTACTS } from "./contacts.js";
import {
  clearCopyFeedback,
  clearEl,
  copyTextToClipboard,
  createEl,
  downloadTextFile,
  getEl,
  showCopyFeedback,
} from "./dom.js";
import {
  applyLanguage,
  ensureDictionary,
  getLang,
  normalizeLang,
  setLang,
  t,
} from "./i18n.js";
import {
  hideInlineAlert,
  refreshBannersAndAlerts,
  showInlineAlert,
  showStatusBanner,
} from "./notifications.js";
import {
  activateProLicense,
  createFreeLicenseState,
  deactivateProLicense,
  extractProToken,
  formatPvKeyFileContent,
  inspectProLicenseToken,
  loadActiveProLicense,
  saveStoredProLicenseToken,
} from "./pro-license.js";
import { loadLanguage, onStorageWarning, saveLanguage } from "./storage.js";
import { applyTheme, resolveInitialTheme, updateThemeToggleButton } from "./theme.js";

export const MAX_PVKEY_FILE_BYTES = 256 * 1024;
const boundHashHandlers = new WeakMap();

export const CHECKOUT_PLANS = Object.freeze([
  Object.freeze({
    id: "pro-monthly",
    tier: "pro",
    nameKey: "checkout.planMonthlyName",
    priceKey: "checkout.planMonthlyPrice",
    descKey: "checkout.planMonthlyDesc",
    badgeKey: "checkout.planMonthlyBadge",
    priceRu: "990 ₽ / мес",
    priceEn: "$12 / mo",
  }),
  Object.freeze({
    id: "pro-annual",
    tier: "pro",
    nameKey: "checkout.planAnnualName",
    priceKey: "checkout.planAnnualPrice",
    descKey: "checkout.planAnnualDesc",
    badgeKey: "checkout.planAnnualBadge",
    priceRu: "7 900 ₽ / год",
    priceEn: "$96 / yr",
  }),
  Object.freeze({
    id: "pro-lifetime",
    tier: "pro",
    nameKey: "checkout.planLifetimeName",
    priceKey: "checkout.planLifetimePrice",
    descKey: "checkout.planLifetimeDesc",
    badgeKey: "checkout.planLifetimeBadge",
    priceRu: "14 900 ₽",
    priceEn: "$180",
  }),
  Object.freeze({
    id: "team-pack",
    tier: "pro",
    nameKey: "checkout.planTeamName",
    priceKey: "checkout.planTeamPrice",
    descKey: "checkout.planTeamDesc",
    badgeKey: "checkout.planTeamBadge",
    priceRu: "29 900 ₽",
    priceEn: "$360",
  }),
]);

export const CHECKOUT_PAYMENT_METHODS = Object.freeze([
  Object.freeze({
    id: "card",
    titleKey: "checkout.payCardTitle",
    descKey: "checkout.payCardDesc",
    instructionKey: "checkout.orderInstructionCard",
  }),
  Object.freeze({
    id: "sbp",
    titleKey: "checkout.paySbpTitle",
    descKey: "checkout.paySbpDesc",
    instructionKey: "checkout.orderInstructionSbp",
  }),
  Object.freeze({
    id: "invoice",
    titleKey: "checkout.payInvoiceTitle",
    descKey: "checkout.payInvoiceDesc",
    instructionKey: "checkout.orderInstructionInvoice",
  }),
]);

const PLAN_MAP = new Map(CHECKOUT_PLANS.map((item) => [item.id, item]));
const PAYMENT_MAP = new Map(CHECKOUT_PAYMENT_METHODS.map((item) => [item.id, item]));
const BUYER_EMAIL_RE = /^[^\s@<>.]+(?:\.[^\s@<>.]+)*@(?:[^\s@<>.]+\.)+[^\s@<>.]{2,}$/;

export function getCheckoutPlan(planId) {
  return PLAN_MAP.get(String(planId || "").trim()) || null;
}

export function getCheckoutPaymentMethod(methodId) {
  return PAYMENT_MAP.get(String(methodId || "").trim()) || null;
}

export function isValidBuyerName(val) {
  return typeof val === "string" && val.trim().length > 0;
}

export function isValidBuyerEmail(val) {
  if (typeof val !== "string") return false;
  const trimmed = val.trim();
  return trimmed.length > 0 && BUYER_EMAIL_RE.test(trimmed);
}

export function validateCheckoutForm({
  plan = "pro-annual",
  paymentMethod = "card",
  name = "",
  email = "",
  company = "",
  acceptTerms = false,
} = {}) {
  const errors = [];
  if (!getCheckoutPlan(plan)) {
    errors.push({ field: "plan", key: "checkout.errorPlan" });
  }
  if (!getCheckoutPaymentMethod(paymentMethod)) {
    errors.push({ field: "paymentMethod", key: "checkout.errorPayment" });
  }
  if (!isValidBuyerName(name)) {
    errors.push({ field: "name", key: "checkout.errorName" });
  }
  if (!isValidBuyerEmail(email)) {
    errors.push({ field: "email", key: "checkout.errorEmail" });
  }
  if (!acceptTerms) {
    errors.push({ field: "terms", key: "checkout.errorTerms" });
  }
  return {
    valid: errors.length === 0,
    errors,
    clean: {
      plan: String(plan || "").trim(),
      paymentMethod: String(paymentMethod || "").trim(),
      name: String(name || "").trim(),
      email: String(email || "").trim(),
      company: String(company || "").trim(),
      acceptTerms: Boolean(acceptTerms),
    },
  };
}

export function generateOrderId(date = new Date()) {
  const safeDate = date instanceof Date && !Number.isNaN(date.getTime()) ? date : new Date();
  const y = String(safeDate.getUTCFullYear());
  const m = String(safeDate.getUTCMonth() + 1).padStart(2, "0");
  const d = String(safeDate.getUTCDate()).padStart(2, "0");
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let suffix = "";
  if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === "function") {
    const bytes = new Uint8Array(6);
    globalThis.crypto.getRandomValues(bytes);
    for (let i = 0; i < bytes.length; i += 1) {
      suffix += alphabet[bytes[i] % alphabet.length];
    }
  } else {
    const fallbackNum = Math.floor(Math.random() * 1e9)
      .toString(36)
      .toUpperCase()
      .padStart(6, "A")
      .slice(0, 6);
    suffix = fallbackNum;
  }
  return `PV-ORD-${y}${m}${d}-${suffix}`;
}

export function createCheckoutOrder(input, lang = "ru", date = new Date()) {
  const checked = validateCheckoutForm(input);
  if (!checked.valid) {
    const first = checked.errors[0];
    const err = new Error(first.key);
    err.field = first.field;
    err.i18nKey = first.key;
    throw err;
  }
  const planMeta = getCheckoutPlan(checked.clean.plan);
  const paymentMeta = getCheckoutPaymentMethod(checked.clean.paymentMethod);
  const normLang = normalizeLang(lang);
  const createdDate = date instanceof Date && !Number.isNaN(date.getTime()) ? date : new Date();
  return {
    orderId: generateOrderId(createdDate),
    plan: planMeta.id,
    paymentMethod: paymentMeta.id,
    name: checked.clean.name,
    email: checked.clean.email,
    company: checked.clean.company,
    createdAt: createdDate.toISOString(),
    lang: normLang,
  };
}

function getPlanLabel(planMeta, lang) {
  const norm = normalizeLang(lang);
  const translated = t(planMeta.nameKey, {}, norm);
  if (translated !== planMeta.nameKey) return translated;
  return planMeta.id;
}

function getPlanPrice(planMeta, lang) {
  const norm = normalizeLang(lang);
  const translated = t(planMeta.priceKey, {}, norm);
  if (translated !== planMeta.priceKey) return translated;
  return norm === "en" ? planMeta.priceEn : planMeta.priceRu;
}

function getPaymentLabel(paymentMeta, lang) {
  const norm = normalizeLang(lang);
  const translated = t(paymentMeta.titleKey, {}, norm);
  if (translated !== paymentMeta.titleKey) return translated;
  return paymentMeta.id;
}

export function buildCheckoutReceiptText(order, lang = "ru") {
  if (!order) return "";
  const norm = normalizeLang(lang);
  const planMeta = getCheckoutPlan(order.plan) || CHECKOUT_PLANS[1];
  const paymentMeta = getCheckoutPaymentMethod(order.paymentMethod) || CHECKOUT_PAYMENT_METHODS[0];
  const companyText =
    order.company ||
    (t("checkout.orderCompanyEmpty", {}, norm) !== "checkout.orderCompanyEmpty"
      ? t("checkout.orderCompanyEmpty", {}, norm)
      : norm === "en"
        ? "Individual"
        : "Частное лицо");

  const headerTitle =
    t("checkout.receiptTitle", {}, norm) !== "checkout.receiptTitle"
      ? t("checkout.receiptTitle", {}, norm)
      : "PROMPTVEIL PRO ORDER RECEIPT";
  const noteLine =
    t("checkout.receiptNote", {}, norm) !== "checkout.receiptNote"
      ? t("checkout.receiptNote", {}, norm)
      : "Generated locally in browser RAM.";

  const lines = [
    headerTitle,
    `========================================`,
    `${norm === "en" ? "Order ID" : "Номер заказа"}: ${order.orderId}`,
    `${norm === "en" ? "Plan" : "Тариф"}: ${getPlanLabel(planMeta, norm)} (${planMeta.id})`,
    `${norm === "en" ? "Total" : "Сумма"}: ${getPlanPrice(planMeta, norm)}`,
    `${norm === "en" ? "Payment method" : "Способ оплаты"}: ${getPaymentLabel(paymentMeta, norm)}`,
    `${norm === "en" ? "Buyer" : "Покупатель"}: ${order.name}`,
    `${norm === "en" ? "Email" : "Эл. почта"}: ${order.email}`,
    `${norm === "en" ? "Company" : "Компания"}: ${companyText}`,
    `${norm === "en" ? "Created" : "Дата"}: ${order.createdAt}`,
    `${norm === "en" ? "Contacts" : "Контакты"}: ${SITE_CONTACTS.telegramHandle} / ${SITE_CONTACTS.email}`,
    `----------------------------------------`,
    noteLine,
  ];
  return `${lines.join("\n")}\n`;
}

export function buildOrderReceiptFilename(orderId) {
  const safeId = String(orderId || "order").replace(/[^A-Za-z0-9_-]/g, "");
  return `promptveil-order-${safeId || "receipt"}.txt`;
}

export function buildPvKeyExportFilename(keyId) {
  const safeId = String(keyId || "license").replace(/[^A-Za-z0-9_-]/g, "");
  return `promptveil-pro-${safeId || "license"}.pvkey`;
}

export function extractFragmentCode(hashStr) {
  if (typeof hashStr !== "string" || !hashStr.trim()) {
    return "";
  }
  const trimmed = hashStr.replace(/^#/, "").trim();
  if (!trimmed) {
    return "";
  }
  const segments = trimmed.split("&");
  for (const seg of segments) {
    const eqIdx = seg.indexOf("=");
    if (eqIdx < 0) continue;
    const key = seg.slice(0, eqIdx).trim().toLowerCase();
    if (key !== "code") continue;
    const rawVal = seg.slice(eqIdx + 1);
    const token = extractProToken(rawVal);
    if (token) {
      return token;
    }
  }
  return extractProToken(trimmed);
}

export function parsePvKeyUploadBuffer(bufferOrBytes, byteLength = null) {
  const bytes =
    bufferOrBytes instanceof Uint8Array
      ? bufferOrBytes
      : bufferOrBytes instanceof ArrayBuffer
        ? new Uint8Array(bufferOrBytes)
        : null;
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

export async function verifyCheckoutTokenOnly(rawText, options = {}) {
  const extracted = extractProToken(rawText);
  const candidate = extracted || (typeof rawText === "string" ? rawText.trim() : "");
  const inspection = await inspectProLicenseToken(candidate, options);
  return {
    ...inspection,
    mode: "verify",
  };
}

export async function activateCheckoutToken(rawText, options = {}) {
  const extracted = extractProToken(rawText);
  const candidate = extracted || (typeof rawText === "string" ? rawText.trim() : "");
  const inspection = await inspectProLicenseToken(candidate, options);
  if (typeof options?.shouldPersist === "function" && !options.shouldPersist()) {
    return {
      ...inspection,
      extractedToken: extracted,
      mode: "activate",
      aborted: true,
    };
  }
  let persisted;
  if (inspection.valid) {
    persisted = saveStoredProLicenseToken(inspection.token);
  }
  return {
    ...inspection,
    ...(persisted !== undefined ? { persisted } : {}),
    extractedToken: extracted,
    mode: "activate",
  };
}

function normalizeCheckoutTimestamp(value) {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return NaN;
    return value > 1e12 ? value : value * 1000;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return NaN;
    return Date.parse(trimmed);
  }
  return NaN;
}

function formatCheckoutDate(value, lang) {
  const ms = normalizeCheckoutTimestamp(value);
  if (Number.isNaN(ms)) {
    return value === null || value === undefined ? "" : String(value);
  }
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) {
    return value === null || value === undefined ? "" : String(value);
  }
  const locale = normalizeLang(lang) === "en" ? "en-US" : "ru-RU";
  try {
    return new Intl.DateTimeFormat(locale, {
      year: "numeric",
      month: "short",
      day: "numeric",
      timeZone: "UTC",
    }).format(date);
  } catch {
    return date.toISOString().slice(0, 10);
  }
}

function getReasonErrorKey(reason) {
  switch (String(reason || "")) {
    case "empty":
      return "checkout.diagErrEmpty";
    case "format":
      return "checkout.diagErrFormat";
    case "encoding":
      return "checkout.diagErrEncoding";
    case "length":
      return "checkout.diagErrLength";
    case "signature":
      return "checkout.diagErrSignature";
    case "payload":
      return "checkout.diagErrPayload";
    case "expired":
      return "checkout.diagErrExpired";
    case "file_empty":
      return "checkout.diagErrFileEmpty";
    case "file_no_token":
      return "checkout.diagErrFileNoToken";
    case "file_too_large":
      return "checkout.diagErrFileTooLarge";
    case "file_read":
      return "checkout.diagErrFileRead";
    default:
      return "checkout.diagErrSignature";
  }
}

async function readUploadedFileBytes(file) {
  if (!file) return new Uint8Array(0);
  if (typeof file.arrayBuffer === "function") {
    const buf = await file.arrayBuffer();
    return new Uint8Array(buf);
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

export async function initProCheckout(options = {}) {
  if (typeof document === "undefined" || typeof window === "undefined") {
    return null;
  }

  const verifyOpts = {};
  if (options.publicKeyB64U !== undefined) {
    verifyOpts.publicKeyB64U = options.publicKeyB64U;
  }
  if (options.nowMs !== undefined) {
    verifyOpts.nowMs = options.nowMs;
  }

  const state = {
    lang: loadLanguage(),
    theme: "light",
    plan: "pro-annual",
    paymentMethod: "card",
    currentOrder: null,
    lastInspection: null,
    proLicense: createFreeLicenseState("none"),
  };
  let inspectSeq = 0;
  let licenseMutationSeq = 0;

  onStorageWarning(() => {
    showStatusBanner("banner.storageWarning", {}, true);
  });

  setLang(state.lang);
  await ensureDictionary(state.lang);
  applyTheme(resolveInitialTheme(), state, { persist: false });
  state.proLicense = await loadActiveProLicense(verifyOpts);

  function syncPlanAndPaymentButtons() {
    for (const card of document.querySelectorAll("[data-plan]")) {
      const id = card.getAttribute("data-plan");
      const active = id === state.plan;
      card.classList.toggle("is-active", active);
      card.setAttribute("aria-pressed", active ? "true" : "false");
      card.setAttribute("data-active", active ? "true" : "false");
    }
    for (const card of document.querySelectorAll("[data-payment]")) {
      const id = card.getAttribute("data-payment");
      const active = id === state.paymentMethod;
      card.classList.toggle("is-active", active);
      card.setAttribute("aria-pressed", active ? "true" : "false");
      card.setAttribute("data-active", active ? "true" : "false");
    }
  }

  function syncWorkbenchLinks(lang = state.lang) {
    const isEn = normalizeLang(lang) === "en";
    const targetHref = isEn ? "/en/" : "/";
    const pricingHref = isEn ? "/en/#pricing-section" : "/#pricing-section";
    for (const id of [
      "checkout-brand-link",
      "checkout-nav-workbench-link",
      "checkout-return-workbench-link",
    ]) {
      const el = getEl(id);
      if (el) {
        el.setAttribute("href", targetHref);
      }
    }
    for (const link of document.querySelectorAll(".footer-links-row a")) {
      const href = link.getAttribute("href") || "";
      if (href === "/" || href === "/en/") {
        link.setAttribute("href", targetHref);
      } else if (href === "/#pricing-section" || href === "/en/#pricing-section") {
        link.setAttribute("href", pricingHref);
      }
    }
  }

  function renderOrderPanel(lang = state.lang) {
    const panel = getEl("checkout-order-panel");
    if (!panel) return;
    if (!state.currentOrder) {
      panel.hidden = true;
      return;
    }

    const order = state.currentOrder;
    const planMeta = getCheckoutPlan(order.plan) || CHECKOUT_PLANS[1];
    const paymentMeta = getCheckoutPaymentMethod(order.paymentMethod) || CHECKOUT_PAYMENT_METHODS[0];

    const idEl = getEl("checkout-order-id");
    const planEl = getEl("checkout-order-plan");
    const totalEl = getEl("checkout-order-total");
    const payEl = getEl("checkout-order-payment");
    const buyerEl = getEl("checkout-order-buyer");
    const emailEl = getEl("checkout-order-email");
    const companyEl = getEl("checkout-order-company");
    const instrEl = getEl("checkout-order-instruction");
    const preEl = getEl("checkout-receipt-preview");

    if (idEl) idEl.textContent = order.orderId;
    if (planEl) planEl.textContent = getPlanLabel(planMeta, lang);
    if (totalEl) totalEl.textContent = getPlanPrice(planMeta, lang);
    if (payEl) payEl.textContent = getPaymentLabel(paymentMeta, lang);
    if (buyerEl) buyerEl.textContent = order.name;
    if (emailEl) emailEl.textContent = order.email;
    if (companyEl) {
      companyEl.textContent = order.company || t("checkout.orderCompanyEmpty", {}, lang);
    }
    if (instrEl) {
      instrEl.textContent = t(
        paymentMeta.instructionKey,
        {
          telegram: SITE_CONTACTS.telegramHandle,
          email: SITE_CONTACTS.email,
        },
        lang
      );
    }
    if (preEl) {
      preEl.textContent = buildCheckoutReceiptText(order, lang);
    }
    panel.hidden = false;
  }

  function renderDiagnostics(lang = state.lang) {
    const box = getEl("checkout-token-diagnostics");
    if (!box) return;
    const info = state.lastInspection;
    if (!info) {
      box.hidden = true;
      clearEl(box);
      return;
    }

    clearEl(box);
    const isValid = Boolean(info.valid);
    const isExpired = info.reason === "expired";
    box.classList.toggle("is-valid", isValid);
    box.classList.toggle("is-error", !isValid);

    const titleKey = isValid
      ? "checkout.diagValidTitle"
      : isExpired
        ? "checkout.diagExpiredTitle"
        : "checkout.diagInvalidTitle";
    box.appendChild(createEl("h3", "checkout-diag-title", t(titleKey, {}, lang)));

    const detailMsg = isValid
      ? t(
          info.mode === "activate" ? "checkout.diagActivatedNote" : "checkout.diagVerifiedPreview",
          {},
          lang
        )
      : t(getReasonErrorKey(info.reason), {}, lang);
    box.appendChild(createEl("p", "checkout-diag-detail", detailMsg));

    const claims = isValid
      ? info
      : info.unverifiedClaims && typeof info.unverifiedClaims === "object"
        ? info.unverifiedClaims
        : null;

    if (claims && (claims.keyId || claims.label || claims.tier)) {
      box.appendChild(
        createEl("h4", "checkout-diag-claims-title", t("checkout.diagClaimsHeading", {}, lang))
      );
      const list = createEl("ul", "checkout-diag-list");
      const tierText =
        claims.tier === "owner"
          ? "Owner Pro"
          : claims.tier
            ? String(claims.tier)
            : isValid
              ? "pro"
              : "";
      const hasNullExp = claims.exp === null || claims.exp === undefined;
      const hasEmptyStringExp = typeof claims.exp === "string" && claims.exp.trim() === "";
      const expRow = hasNullExp
        ? `${t("checkout.diagClaimExp", {}, lang)}: ${t("checkout.diagClaimExpNever", {}, lang)}`
        : hasEmptyStringExp
          ? ""
          : `${t("checkout.diagClaimExp", {}, lang)}: ${formatCheckoutDate(claims.exp, lang)}`;
      const rows = [
        tierText ? `${t("checkout.diagClaimTier", {}, lang)}: ${tierText}` : "",
        claims.keyId ? `${t("checkout.diagClaimKeyId", {}, lang)}: ${claims.keyId}` : "",
        claims.label ? `${t("checkout.diagClaimLabel", {}, lang)}: ${claims.label}` : "",
        claims.issuedAt
          ? `${t("checkout.diagClaimIssued", {}, lang)}: ${formatCheckoutDate(claims.issuedAt, lang)}`
          : "",
        expRow,
        info.method ? `${t("checkout.diagClaimMethod", {}, lang)}: ${info.method}` : "",
      ].filter(Boolean);

      for (const line of rows) {
        list.appendChild(createEl("li", "", line));
      }
      box.appendChild(list);
    }

    box.hidden = false;
  }

  function renderProStatusAndUnlocked(lang = state.lang) {
    const lic = state.proLicense || createFreeLicenseState("none");
    const isPro = Boolean(lic.isPro);
    const isOwner = Boolean(lic.isOwner);
    const proStateAttr = isOwner ? "owner" : isPro ? "pro" : "free";

    const badge = getEl("checkout-pro-status-badge");
    if (badge) {
      badge.dataset.proState = proStateAttr;
      badge.classList.toggle("is-pro", isPro && !isOwner);
      badge.classList.toggle("is-owner", isOwner);
      badge.textContent = t(
        isOwner ? "pro.badgeOwner" : isPro ? "pro.badgePro" : "pro.badgeFree",
        {},
        lang
      );
    }

    const unlockedPanel = getEl("checkout-pro-unlocked");
    if (unlockedPanel) {
      unlockedPanel.hidden = !isPro;
    }

    const summaryEl = getEl("checkout-unlocked-summary");
    if (summaryEl) {
      const tierLabel = isOwner ? "Owner Pro" : "Pro";
      summaryEl.textContent = isPro
        ? t("checkout.unlockedSummary", { tier: tierLabel, keyId: lic.keyId }, lang)
        : "";
    }
  }

  function renderContactsFooter(lang = state.lang) {
    const tgEl = getEl("contact-telegram-text");
    const emailEl = getEl("contact-email-link");
    const ghEl = getEl("contact-github-text");
    const copyrightEl = getEl("footer-copyright");
    if (tgEl) tgEl.textContent = SITE_CONTACTS.telegramHandle;
    if (emailEl) {
      emailEl.textContent = SITE_CONTACTS.email;
      emailEl.setAttribute("href", `mailto:${SITE_CONTACTS.email}`);
    }
    if (ghEl) ghEl.textContent = SITE_CONTACTS.githubDisplay;
    if (copyrightEl) {
      copyrightEl.textContent = t(
        "footer.copyright",
        { author: SITE_CONTACTS.authorSignature },
        lang
      );
    }
  }

  function rerenderCheckoutUi(lang = state.lang) {
    state.lang = lang;
    syncPlanAndPaymentButtons();
    syncWorkbenchLinks(lang);
    renderOrderPanel(lang);
    renderDiagnostics(lang);
    renderProStatusAndUnlocked(lang);
    renderContactsFooter(lang);
    updateThemeToggleButton(state.theme, lang);
    refreshBannersAndAlerts(lang);
  }

  async function handleLanguageSwitch(nextLang) {
    const saved = saveLanguage(nextLang);
    await applyLanguage(saved, {
      metaPrefix: "checkoutMeta",
      onAfterApply: rerenderCheckoutUi,
    });
  }

  async function handleHashFragment() {
    const code = extractFragmentCode(window.location?.hash || "");
    if (!code) return;
    const seq = ++inspectSeq;
    const tokenInput = getEl("checkout-token-input");
    if (tokenInput) {
      tokenInput.value = code;
    }
    const inspected = await verifyCheckoutTokenOnly(code, verifyOpts);
    if (seq !== inspectSeq) return;
    state.lastInspection = inspected;
    renderDiagnostics(state.lang);
  }

  // Bind tariff selection
  for (const planBtn of document.querySelectorAll("[data-plan]")) {
    if (planBtn.dataset?.boundCheckout === "1") continue;
    if (planBtn.dataset) planBtn.dataset.boundCheckout = "1";
    planBtn.addEventListener("click", () => {
      const nextPlan = planBtn.getAttribute("data-plan");
      if (!getCheckoutPlan(nextPlan)) return;
      state.plan = nextPlan;
      syncPlanAndPaymentButtons();
    });
  }

  // Bind payment method selection
  for (const payBtn of document.querySelectorAll("[data-payment]")) {
    if (payBtn.dataset?.boundCheckout === "1") continue;
    if (payBtn.dataset) payBtn.dataset.boundCheckout = "1";
    payBtn.addEventListener("click", () => {
      const nextPay = payBtn.getAttribute("data-payment");
      if (!getCheckoutPaymentMethod(nextPay)) return;
      state.paymentMethod = nextPay;
      syncPlanAndPaymentButtons();
    });
  }

  // Bind language and theme toggles
  const ruBtn = getEl("lang-ru-btn");
  if (ruBtn && ruBtn.dataset?.boundCheckout !== "1") {
    if (ruBtn.dataset) ruBtn.dataset.boundCheckout = "1";
    ruBtn.addEventListener("click", () => void handleLanguageSwitch("ru"));
  }
  const enBtn = getEl("lang-en-btn");
  if (enBtn && enBtn.dataset?.boundCheckout !== "1") {
    if (enBtn.dataset) enBtn.dataset.boundCheckout = "1";
    enBtn.addEventListener("click", () => void handleLanguageSwitch("en"));
  }
  const mobLangBtn = getEl("lang-mobile-toggle");
  if (mobLangBtn && mobLangBtn.dataset?.boundCheckout !== "1") {
    if (mobLangBtn.dataset) mobLangBtn.dataset.boundCheckout = "1";
    mobLangBtn.addEventListener("click", () => {
      const nextLang = getLang() === "ru" ? "en" : "ru";
      void handleLanguageSwitch(nextLang);
    });
  }
  const themeBtn = getEl("theme-toggle-btn");
  if (themeBtn && themeBtn.dataset?.boundCheckout !== "1") {
    if (themeBtn.dataset) themeBtn.dataset.boundCheckout = "1";
    themeBtn.addEventListener("click", () => {
      applyTheme(state.theme === "dark" ? "light" : "dark", state, { persist: true });
    });
  }

  // Bind buyer form validation & order creation
  const nameInput = getEl("checkout-name");
  const emailInput = getEl("checkout-email");
  const companyInput = getEl("checkout-company");
  const termsInput = getEl("checkout-terms");
  const checkoutForm = getEl("checkout-form");

  for (const fieldEl of [nameInput, emailInput, termsInput]) {
    if (fieldEl && fieldEl.dataset?.boundCheckout !== "1") {
      if (fieldEl.dataset) fieldEl.dataset.boundCheckout = "1";
      const clearValidity = () => {
        if (typeof fieldEl.setCustomValidity === "function") {
          fieldEl.setCustomValidity("");
        }
        hideInlineAlert("checkout-form-alert");
      };
      fieldEl.addEventListener("input", clearValidity);
      fieldEl.addEventListener("change", clearValidity);
    }
  }

  if (checkoutForm && checkoutForm.dataset?.boundCheckout !== "1") {
    if (checkoutForm.dataset) checkoutForm.dataset.boundCheckout = "1";
    checkoutForm.addEventListener("submit", (event) => {
      event.preventDefault();
      hideInlineAlert("checkout-form-alert");
      if (typeof nameInput?.setCustomValidity === "function") nameInput.setCustomValidity("");
      if (typeof emailInput?.setCustomValidity === "function") emailInput.setCustomValidity("");
      if (typeof termsInput?.setCustomValidity === "function") termsInput.setCustomValidity("");

      const validation = validateCheckoutForm({
        plan: state.plan,
        paymentMethod: state.paymentMethod,
        name: nameInput?.value || "",
        email: emailInput?.value || "",
        company: companyInput?.value || "",
        acceptTerms: Boolean(termsInput?.checked),
      });

      if (!validation.valid) {
        const firstErr = validation.errors[0];
        for (const err of validation.errors) {
          if (err.field === "name" && typeof nameInput?.setCustomValidity === "function") {
            nameInput.setCustomValidity(t(err.key, {}, state.lang));
          } else if (err.field === "email" && typeof emailInput?.setCustomValidity === "function") {
            emailInput.setCustomValidity(t(err.key, {}, state.lang));
          } else if (err.field === "terms" && typeof termsInput?.setCustomValidity === "function") {
            termsInput.setCustomValidity(t(err.key, {}, state.lang));
          }
        }
        showInlineAlert("checkout-form-alert", firstErr.key);
        if (firstErr.field === "name") nameInput?.focus();
        else if (firstErr.field === "email") emailInput?.focus();
        else if (firstErr.field === "terms") termsInput?.focus();
        return;
      }

      state.currentOrder = createCheckoutOrder(validation.clean, state.lang);
      clearCopyFeedback(getEl("checkout-copy-receipt-btn"), () =>
        t("checkout.copyReceiptBtn", {}, state.lang)
      );
      renderOrderPanel(state.lang);
    });
  }

  // Bind receipt copy & download
  const copyReceiptBtn = getEl("checkout-copy-receipt-btn");
  if (copyReceiptBtn && copyReceiptBtn.dataset?.boundCheckout !== "1") {
    if (copyReceiptBtn.dataset) copyReceiptBtn.dataset.boundCheckout = "1";
    copyReceiptBtn.addEventListener("click", async () => {
      if (!state.currentOrder) return;
      const receipt = buildCheckoutReceiptText(state.currentOrder, state.lang);
      const ok = await copyTextToClipboard(receipt);
      if (ok) {
        showCopyFeedback(copyReceiptBtn, t("action.copiedFeedback", {}, state.lang), () =>
          t("checkout.copyReceiptBtn", {}, state.lang)
        );
        showStatusBanner("checkout.receiptCopiedBanner");
      } else {
        showStatusBanner("banner.copyFailed", {}, true);
      }
    });
  }

  const dlReceiptBtn = getEl("checkout-download-receipt-btn");
  if (dlReceiptBtn && dlReceiptBtn.dataset?.boundCheckout !== "1") {
    if (dlReceiptBtn.dataset) dlReceiptBtn.dataset.boundCheckout = "1";
    dlReceiptBtn.addEventListener("click", () => {
      if (!state.currentOrder) return;
      const receipt = buildCheckoutReceiptText(state.currentOrder, state.lang);
      downloadTextFile(buildOrderReceiptFilename(state.currentOrder.orderId), receipt);
      showStatusBanner("checkout.receiptDownloadedBanner");
    });
  }

  // Bind activation terminal controls
  const tokenInput = getEl("checkout-token-input");
  const verifyBtn = getEl("checkout-verify-only-btn");
  if (verifyBtn && verifyBtn.dataset?.boundCheckout !== "1") {
    if (verifyBtn.dataset) verifyBtn.dataset.boundCheckout = "1";
    verifyBtn.addEventListener("click", async () => {
      const seq = ++inspectSeq;
      const raw = tokenInput?.value || "";
      const inspected = await verifyCheckoutTokenOnly(raw, verifyOpts);
      if (seq !== inspectSeq) return;
      state.lastInspection = inspected;
      renderDiagnostics(state.lang);
    });
  }

  const activateBtn = getEl("checkout-activate-btn");
  if (activateBtn && activateBtn.dataset?.boundCheckout !== "1") {
    if (activateBtn.dataset) activateBtn.dataset.boundCheckout = "1";
    activateBtn.addEventListener("click", async () => {
      const inspSeq = ++inspectSeq;
      const mutSeq = ++licenseMutationSeq;
      const raw = tokenInput?.value || "";
      const result = await activateCheckoutToken(raw, {
        ...verifyOpts,
        shouldPersist: () => mutSeq === licenseMutationSeq,
      });
      if (result.aborted || mutSeq !== licenseMutationSeq) {
        return;
      }
      if (inspSeq === inspectSeq) {
        state.lastInspection = result;
        renderDiagnostics(state.lang);
      }
      if (result.valid) {
        state.proLicense = result;
        if (result.persisted === false) {
          showStatusBanner("banner.storageWarning", {}, true);
        } else {
          showStatusBanner("pro.activatedSuccess", {
            tier: result.isOwner ? "Owner Pro" : "Pro",
            keyId: result.keyId,
          });
        }
      }
      renderProStatusAndUnlocked(state.lang);
    });
  }

  const pvkeyUploadBtn = getEl("checkout-pvkey-upload-btn");
  const pvkeyFileInput = getEl("checkout-pvkey-file-input");
  if (pvkeyUploadBtn && pvkeyUploadBtn.dataset?.boundCheckout !== "1") {
    if (pvkeyUploadBtn.dataset) pvkeyUploadBtn.dataset.boundCheckout = "1";
    pvkeyUploadBtn.addEventListener("click", () => pvkeyFileInput?.click());
  }
  if (pvkeyFileInput && pvkeyFileInput.dataset?.boundCheckout !== "1") {
    if (pvkeyFileInput.dataset) pvkeyFileInput.dataset.boundCheckout = "1";
    pvkeyFileInput.addEventListener("change", async (event) => {
      const seq = ++inspectSeq;
      const file = event.target?.files?.[0];
      if (event.target) {
        event.target.value = "";
      }
      if (!file) return;
      if (
        typeof file.size === "number" &&
        Number.isFinite(file.size) &&
        file.size > MAX_PVKEY_FILE_BYTES
      ) {
        if (seq !== inspectSeq) return;
        state.lastInspection = {
          ...createFreeLicenseState("file_too_large"),
          mode: "verify",
          extractedToken: "",
          unverifiedClaims: null,
        };
        renderDiagnostics(state.lang);
        return;
      }
      try {
        const bytes = await readUploadedFileBytes(file);
        if (seq !== inspectSeq) return;
        const parsed = parsePvKeyUploadBuffer(bytes, file.size);
        if (!parsed.ok) {
          state.lastInspection = {
            ...createFreeLicenseState(parsed.reason),
            mode: "verify",
            extractedToken: "",
            unverifiedClaims: null,
          };
          renderDiagnostics(state.lang);
          return;
        }
        if (tokenInput) {
          tokenInput.value = parsed.token;
        }
        const inspected = await verifyCheckoutTokenOnly(parsed.token, verifyOpts);
        if (seq !== inspectSeq) return;
        state.lastInspection = inspected;
        renderDiagnostics(state.lang);
      } catch {
        if (seq !== inspectSeq) return;
        state.lastInspection = {
          ...createFreeLicenseState("file_read"),
          mode: "verify",
          extractedToken: "",
          unverifiedClaims: null,
        };
        renderDiagnostics(state.lang);
      }
    });
  }

  // Bind unlocked panel controls
  const dlPvkeyBtn = getEl("checkout-download-pvkey-btn");
  if (dlPvkeyBtn && dlPvkeyBtn.dataset?.boundCheckout !== "1") {
    if (dlPvkeyBtn.dataset) dlPvkeyBtn.dataset.boundCheckout = "1";
    dlPvkeyBtn.addEventListener("click", () => {
      const lic = state.proLicense;
      if (!lic?.isPro || !lic?.token) return;
      const content = formatPvKeyFileContent(lic.token, {
        keyId: lic.keyId,
        tier: lic.tier,
        label: lic.label,
        issuedAt: lic.issuedAt,
        exp: lic.exp,
        plan: state.currentOrder?.plan || "",
        orderId: state.currentOrder?.orderId || "",
      });
      downloadTextFile(buildPvKeyExportFilename(lic.keyId), content);
      showStatusBanner("checkout.pvkeyDownloadedBanner");
    });
  }

  const deactivateBtn = getEl("checkout-deactivate-btn");
  if (deactivateBtn && deactivateBtn.dataset?.boundCheckout !== "1") {
    if (deactivateBtn.dataset) deactivateBtn.dataset.boundCheckout = "1";
    deactivateBtn.addEventListener("click", () => {
      licenseMutationSeq += 1;
      inspectSeq += 1;
      state.proLicense = deactivateProLicense();
      state.lastInspection = null;
      renderDiagnostics(state.lang);
      renderProStatusAndUnlocked(state.lang);
      showStatusBanner("checkout.deactivatedBanner");
    });
  }

  // Bind footer contact copy buttons
  const contactCopyTargets = [
    ["copy-contact-telegram-btn", SITE_CONTACTS.telegramHandle],
    ["copy-contact-email-btn", SITE_CONTACTS.email],
    ["copy-contact-github-btn", SITE_CONTACTS.githubDisplay],
  ];
  for (const [btnId, value] of contactCopyTargets) {
    const btn = getEl(btnId);
    if (btn && btn.dataset?.boundCheckout !== "1") {
      if (btn.dataset) btn.dataset.boundCheckout = "1";
      btn.addEventListener("click", async () => {
        const ok = await copyTextToClipboard(value);
        if (ok) {
          showCopyFeedback(btn, t("action.copiedFeedback", {}, state.lang), () =>
            t("action.copy", {}, state.lang)
          );
          showStatusBanner("banner.copied");
        } else {
          showStatusBanner("banner.copyFailed", {}, true);
        }
      });
    }
  }

  // Apply language + initial UI + hash fragment hydration
  await applyLanguage(state.lang, {
    metaPrefix: "checkoutMeta",
    onAfterApply: rerenderCheckoutUi,
  });

  if (state.proLicense?.isPro && !extractFragmentCode(window.location?.hash || "")) {
    state.lastInspection = {
      ...(await inspectProLicenseToken(state.proLicense.token, verifyOpts)),
      mode: "activate",
    };
    renderDiagnostics(state.lang);
  }

  await handleHashFragment();

  if (typeof window.addEventListener === "function") {
    const firstBind = !boundHashHandlers.has(window);
    boundHashHandlers.set(window, handleHashFragment);
    if (firstBind) {
      window.addEventListener("hashchange", () => {
        void boundHashHandlers.get(window)?.();
      });
    }
  }

  if (typeof navigator !== "undefined" && navigator.serviceWorker?.register) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }

  return { state };
}

if (typeof document !== "undefined" && typeof window !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      void initProCheckout();
    });
  } else {
    void initProCheckout();
  }
}
