import test, { afterEach, beforeEach, describe } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import {
  PRO_LICENSE_STORAGE_KEY,
  deactivateProLicense,
  formatPvKeyFileContent,
  loadActiveProLicense,
} from "../../app/static/js/pro-license.js";
import { resetNotifications } from "../../app/static/js/notifications.js";
import {
  CHECKOUT_PAYMENT_METHODS,
  CHECKOUT_PLANS,
  activateCheckoutToken,
  buildCheckoutReceiptText,
  buildOrderReceiptFilename,
  buildPvKeyExportFilename,
  createCheckoutOrder,
  extractFragmentCode,
  initProCheckout,
  isValidBuyerEmail,
  isValidBuyerName,
  parsePvKeyUploadBuffer,
  validateCheckoutForm,
  verifyCheckoutTokenOnly,
} from "../../app/static/js/pro-checkout.js";
import { extractRawPublicKeyB64U, signProToken } from "../../scripts/issue-pro-key.mjs";

function createMemoryLocalStorage() {
  const map = new Map();
  return {
    get length() {
      return map.size;
    },
    key(idx) {
      return Array.from(map.keys())[idx] ?? null;
    },
    getItem(k) {
      return map.has(k) ? map.get(k) : null;
    },
    setItem(k, v) {
      map.set(String(k), String(v));
    },
    removeItem(k) {
      map.delete(String(k));
    },
    clear() {
      map.clear();
    },
  };
}

function createMockClassList() {
  const set = new Set();
  return {
    add(c) {
      set.add(c);
    },
    remove(c) {
      set.delete(c);
    },
    contains(c) {
      return set.has(c);
    },
    toggle(c, force) {
      if (force === undefined) {
        if (set.has(c)) {
          set.delete(c);
          return false;
        }
        set.add(c);
        return true;
      }
      if (force) set.add(c);
      else set.delete(c);
      return Boolean(force);
    },
  };
}

function createMockElement(tag = "div", id = "", attrs = {}) {
  const attrMap = new Map(Object.entries(attrs));
  const listeners = new Map();
  const children = [];
  const el = {
    tagName: tag.toUpperCase(),
    id,
    hidden: Boolean(attrs.hidden),
    value: "",
    checked: Boolean(attrs.checked),
    textContent: "",
    placeholder: "",
    customValidity: "",
    children,
    dataset: {},
    classList: createMockClassList(),
    setAttribute(k, v) {
      attrMap.set(k, String(v));
    },
    getAttribute(k) {
      return attrMap.has(k) ? attrMap.get(k) : null;
    },
    hasAttribute(k) {
      return attrMap.has(k);
    },
    removeAttribute(k) {
      attrMap.delete(k);
    },
    setCustomValidity(msg) {
      el.customValidity = String(msg || "");
    },
    checkValidity() {
      return el.customValidity === "";
    },
    focus() {},
    addEventListener(type, fn) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    },
    async dispatch(type, event = {}) {
      const list = listeners.get(type) || [];
      for (const fn of list) {
        await fn({ currentTarget: el, target: el, preventDefault() {}, ...event });
      }
    },
    appendChild(child) {
      children.push(child);
      return child;
    },
    replaceChildren(...nodes) {
      children.length = 0;
      children.push(...nodes);
    },
    querySelector() {
      return null;
    },
  };
  return el;
}

describe("PromptVeil M2 Pro Checkout & Activation Terminal", () => {
  let prevWindow;
  let prevDocument;
  let keyPairA;
  let keyPairB;
  let pubA;

  beforeEach(() => {
    prevWindow = globalThis.window;
    prevDocument = globalThis.document;
    keyPairA = generateKeyPairSync("ed25519");
    keyPairB = generateKeyPairSync("ed25519");
    pubA = extractRawPublicKeyB64U(keyPairA.publicKey);
    globalThis.window = {
      localStorage: createMemoryLocalStorage(),
      location: { pathname: "/pro/", hash: "" },
      setTimeout,
      clearTimeout,
      addEventListener() {},
    };
  });

  afterEach(() => {
    resetNotifications();
    deactivateProLicense();
    globalThis.window = prevWindow;
    globalThis.document = prevDocument;
  });

  test("catalog exposes 4 plans & 3 payment methods with zero forbidden legacy strings", () => {
    assert.deepEqual(
      CHECKOUT_PLANS.map((p) => p.id),
      ["pro-monthly", "pro-annual", "pro-lifetime", "team-pack"]
    );
    assert.deepEqual(
      CHECKOUT_PAYMENT_METHODS.map((m) => m.id),
      ["card", "sbp", "invoice"]
    );

    const serialized = JSON.stringify({ CHECKOUT_PLANS, CHECKOUT_PAYMENT_METHODS });
    for (const forbidden of [
      "490 ₽",
      "390 ₽",
      "1 990 ₽",
      "1 590 ₽",
      "30 дней бесплатно",
      "30 days free",
      "billing-month-btn",
    ]) {
      assert.equal(serialized.includes(forbidden), false);
    }
  });

  test("buyer validation rejects whitespace-only names, bad emails, unchecked terms, and unknown options", () => {
    assert.equal(isValidBuyerName(""), false);
    assert.equal(isValidBuyerName("   \t "), false);
    assert.equal(isValidBuyerName("Анна"), true);

    assert.equal(isValidBuyerEmail(""), false);
    assert.equal(isValidBuyerEmail("not-an-email"), false);
    assert.equal(isValidBuyerEmail("user@"), false);
    assert.equal(isValidBuyerEmail("@domain.com"), false);
    assert.equal(isValidBuyerEmail("bad space@example.com"), false);
    assert.equal(isValidBuyerEmail("a@b..com"), false);
    assert.equal(isValidBuyerEmail(".@b.com"), false);
    assert.equal(isValidBuyerEmail("a.@b.com"), false);
    assert.equal(isValidBuyerEmail("a..b@c.com"), false);
    assert.equal(isValidBuyerEmail("a@.b.com"), false);
    assert.equal(isValidBuyerEmail("a@b.com."), false);
    assert.equal(isValidBuyerEmail("buyer@example.com"), true);
    assert.equal(isValidBuyerEmail("ivan.petrov+test@sub.company.ru"), true);

    const bad = validateCheckoutForm({
      plan: "unknown-plan",
      paymentMethod: "crypto",
      name: "   ",
      email: "bad@",
      acceptTerms: false,
    });
    assert.equal(bad.valid, false);
    assert.deepEqual(
      bad.errors.map((e) => e.field),
      ["plan", "paymentMethod", "name", "email", "terms"]
    );

    const good = validateCheckoutForm({
      plan: "pro-annual",
      paymentMethod: "sbp",
      name: "Иван Петров",
      email: "ivan@company.ru",
      company: "ООО «Вектор»",
      acceptTerms: true,
    });
    assert.equal(good.valid, true);
  });

  test("RAM-only order & receipt generation leaves localStorage completely empty", () => {
    const order = createCheckoutOrder(
      {
        plan: "pro-lifetime",
        paymentMethod: "invoice",
        name: "Elena Smirnova",
        email: "elena@acme.test",
        company: "Acme Corp",
        acceptTerms: true,
      },
      "en",
      new Date("2026-11-23T10:00:00.000Z")
    );
    assert.match(order.orderId, /^PV-ORD-20261123-[A-Z0-9]{6}$/);
    const receipt = buildCheckoutReceiptText(order, "en");
    assert.ok(receipt.includes(order.orderId));
    assert.ok(receipt.includes("elena@acme.test"));
    assert.ok(receipt.includes("Acme Corp"));
    assert.equal(buildOrderReceiptFilename(order.orderId), `promptveil-order-${order.orderId}.txt`);
    assert.equal(buildPvKeyExportFilename("PV-TEST-01"), "promptveil-pro-PV-TEST-01.pvkey");
    assert.equal(globalThis.window.localStorage.length, 0);
  });

  test("in-page verification & activation uses ephemeral Ed25519 keys without touching wrong/tampered/expired tokens", async () => {
    const tok = signProToken(
      {
        tier: "pro",
        keyId: "PV-M2-TEST-01",
        label: "Checkout Buyer",
        issuedAt: "2026-11-23T00:00:00.000Z",
      },
      keyPairA.privateKey
    );
    const pvkeyText = formatPvKeyFileContent(tok, { plan: "pro-annual", orderId: "PV-ORD-123" });

    // Verify-only does NOT persist to localStorage
    const verifyRes = await verifyCheckoutTokenOnly(pvkeyText, { publicKeyB64U: pubA });
    assert.equal(verifyRes.valid, true);
    assert.equal(verifyRes.mode, "verify");
    assert.equal(verifyRes.keyId, "PV-M2-TEST-01");
    assert.equal(globalThis.window.localStorage.getItem(PRO_LICENSE_STORAGE_KEY), null);

    // Wrong key rejected
    const wrongTok = signProToken(
      {
        tier: "owner",
        keyId: "PV-M2-WRONG",
        label: "Wrong Key",
        issuedAt: "2026-11-23T00:00:00.000Z",
      },
      keyPairB.privateKey
    );
    const wrongRes = await activateCheckoutToken(wrongTok, { publicKeyB64U: pubA });
    assert.equal(wrongRes.valid, false);
    assert.equal(wrongRes.reason, "signature");
    assert.equal(globalThis.window.localStorage.getItem(PRO_LICENSE_STORAGE_KEY), null);

    // Expired token rejected
    const expTok = signProToken(
      {
        tier: "pro",
        keyId: "PV-M2-EXP",
        label: "Expired",
        issuedAt: "2020-01-01T00:00:00.000Z",
        exp: "2021-01-01T00:00:00.000Z",
      },
      keyPairA.privateKey
    );
    const expRes = await activateCheckoutToken(expTok, {
      publicKeyB64U: pubA,
      nowMs: Date.parse("2026-11-23T00:00:00.000Z"),
    });
    assert.equal(expRes.valid, false);
    assert.equal(expRes.reason, "expired");
    assert.equal(globalThis.window.localStorage.getItem(PRO_LICENSE_STORAGE_KEY), null);

    // Valid activation stores ONLY promptveil_pro_license_v1
    const actRes = await activateCheckoutToken(pvkeyText, { publicKeyB64U: pubA });
    assert.equal(actRes.valid, true);
    assert.equal(actRes.mode, "activate");
    assert.equal(globalThis.window.localStorage.getItem(PRO_LICENSE_STORAGE_KEY), tok);
    assert.equal(globalThis.window.localStorage.length, 1);

    const active = await loadActiveProLicense({ publicKeyB64U: pubA });
    assert.equal(active.isPro, true);
    assert.equal(active.keyId, "PV-M2-TEST-01");
  });

  test("parsePvKeyUploadBuffer & extractFragmentCode reject corrupt/empty inputs and decode #code=PV1...", () => {
    const tok = signProToken(
      {
        tier: "pro",
        keyId: "PV-FRAG-01",
        label: "Frag",
        issuedAt: "2026-11-23T00:00:00.000Z",
      },
      keyPairA.privateKey
    );

    assert.equal(extractFragmentCode(`#code=${tok}`), tok);
    assert.equal(extractFragmentCode(`#lang=en&code=${encodeURIComponent(tok)}`), tok);
    assert.equal(extractFragmentCode("#code=<img src=x onerror=alert(1)>"), "");
    assert.equal(extractFragmentCode(""), "");

    assert.equal(parsePvKeyUploadBuffer(new Uint8Array(0), 0).reason, "file_empty");
    assert.equal(
      parsePvKeyUploadBuffer(new TextEncoder().encode("# comment\nno token here\n"), 24).reason,
      "file_no_token"
    );
    assert.equal(
      parsePvKeyUploadBuffer(new Uint8Array([0x00, 0xff, 0xfe, 0x89]), 4).reason,
      "file_read"
    );
    assert.equal(
      parsePvKeyUploadBuffer(new Uint8Array(10), 300 * 1024).reason,
      "file_too_large"
    );
    assert.equal(
      parsePvKeyUploadBuffer(new Uint8Array(256 * 1024 + 1), undefined).reason,
      "file_too_large"
    );
    assert.equal(
      parsePvKeyUploadBuffer(new Uint8Array(256 * 1024 + 1), Number.NaN).reason,
      "file_too_large"
    );

    const pvText = formatPvKeyFileContent(tok);
    const okParsed = parsePvKeyUploadBuffer(new TextEncoder().encode(pvText), pvText.length);
    assert.equal(okParsed.ok, true);
    assert.equal(okParsed.token, tok);
  });

  test("initProCheckout DOM controller handles order creation, verify-only, and activation end-to-end", async () => {
    const elements = new Map();
    const register = (id, tag = "div", attrs = {}) => {
      const el = createMockElement(tag, id, attrs);
      elements.set(id, el);
      return el;
    };

    const planMonthly = register("plan-monthly", "button", { "data-plan": "pro-monthly" });
    const planAnnual = register("plan-annual", "button", { "data-plan": "pro-annual" });
    const paySbp = register("pay-sbp", "button", { "data-payment": "sbp" });
    const payCard = register("pay-card", "button", { "data-payment": "card" });

    const nameEl = register("checkout-name", "input");
    const emailEl = register("checkout-email", "input");
    const companyEl = register("checkout-company", "input");
    const termsEl = register("checkout-terms", "input");
    const formEl = register("checkout-form", "form");
    const alertEl = register("checkout-form-alert", "div", { hidden: true });
    const orderPanel = register("checkout-order-panel", "section", { hidden: true });
    const orderIdEl = register("checkout-order-id", "span");
    const orderCompanyEl = register("checkout-order-company", "span");
    const tokenInput = register("checkout-token-input", "textarea");
    const verifyBtn = register("checkout-verify-only-btn", "button");
    const activateBtn = register("checkout-activate-btn", "button");
    const diagEl = register("checkout-token-diagnostics", "div", { hidden: true });
    const unlockedEl = register("checkout-pro-unlocked", "section", { hidden: true });
    const statusBadge = register("checkout-pro-status-badge", "span");

    globalThis.document = {
      readyState: "complete",
      documentElement: { lang: "ru", dataset: {} },
      title: "",
      getElementById(id) {
        return elements.get(id) || null;
      },
      querySelector(sel) {
        if (sel === '[data-testid="lang-ru"]') return elements.get("lang-ru-btn") || null;
        if (sel === '[data-testid="lang-en"]') return elements.get("lang-en-btn") || null;
        return null;
      },
      querySelectorAll(sel) {
        if (sel === "[data-plan]") return [planMonthly, planAnnual];
        if (sel === "[data-payment]") return [payCard, paySbp];
        return [];
      },
      createElement(tag) {
        return createMockElement(tag);
      },
    };

    const ctrl = await initProCheckout({ publicKeyB64U: pubA });
    assert.ok(ctrl);
    assert.equal(orderPanel.hidden, true);
    assert.equal(unlockedEl.hidden, true);

    await planMonthly.dispatch("click");
    await paySbp.dispatch("click");
    assert.equal(ctrl.state.plan, "pro-monthly");
    assert.equal(ctrl.state.paymentMethod, "sbp");

    // Whitespace-only name must fail validation and keep order panel hidden
    nameEl.value = "   ";
    emailEl.value = "buyer@example.ru";
    termsEl.checked = true;
    await formEl.dispatch("submit");
    assert.equal(orderPanel.hidden, true);
    assert.equal(alertEl.hidden, false);
    assert.equal(nameEl.checkValidity(), false);

    // Valid submit reveals order panel without writing localStorage
    nameEl.value = "Дарья";
    companyEl.value = "ООО Тест";
    await formEl.dispatch("submit");
    assert.equal(orderPanel.hidden, false);
    assert.match(orderIdEl.textContent, /^PV-ORD-/);
    assert.equal(orderCompanyEl.textContent, "ООО Тест");
    assert.equal(globalThis.window.localStorage.getItem(PRO_LICENSE_STORAGE_KEY), null);

    // Verify-only reveals diagnostics without unlocking or storing key
    const tok = signProToken(
      {
        tier: "pro",
        keyId: "PV-DOM-01",
        label: "DOM Buyer",
        issuedAt: "2026-11-23T00:00:00.000Z",
      },
      keyPairA.privateKey
    );
    tokenInput.value = tok;
    await verifyBtn.dispatch("click");
    assert.equal(diagEl.hidden, false);
    assert.equal(unlockedEl.hidden, true);
    assert.equal(globalThis.window.localStorage.getItem(PRO_LICENSE_STORAGE_KEY), null);

    // Activate persists key and unlocks panel
    await activateBtn.dispatch("click");
    assert.equal(unlockedEl.hidden, false);
    assert.equal(statusBadge.dataset.proState, "pro");
    assert.equal(globalThis.window.localStorage.getItem(PRO_LICENSE_STORAGE_KEY), tok);
  });

  test("diagnostics render numeric Unix-seconds exp=1800000000 as 2027 and exp=0 as 1970 (not lifetime)", async () => {
    const elements = new Map();
    const register = (id, tag = "div", attrs = {}) => {
      const el = createMockElement(tag, id, attrs);
      elements.set(id, el);
      return el;
    };

    const tokenInput = register("checkout-token-input", "textarea");
    const verifyBtn = register("checkout-verify-only-btn", "button");
    const diagEl = register("checkout-token-diagnostics", "div", { hidden: true });
    register("checkout-pro-status-badge", "span");
    register("checkout-pro-unlocked", "section", { hidden: true });

    globalThis.document = {
      readyState: "complete",
      documentElement: { lang: "en", dataset: {} },
      title: "",
      getElementById(id) {
        return elements.get(id) || null;
      },
      querySelector() {
        return null;
      },
      querySelectorAll() {
        return [];
      },
      createElement(tag) {
        return createMockElement(tag);
      },
    };
    globalThis.window.location = { pathname: "/en/pro/", hash: "" };

    const collectText = (node) =>
      [node?.textContent || "", ...(node?.children || []).map(collectText)].join(" ");

    const ctrl = await initProCheckout({
      publicKeyB64U: pubA,
      nowMs: Date.parse("2026-11-23T00:00:00.000Z"),
    });
    assert.ok(ctrl);

    const tokNumSec = signProToken(
      {
        tier: "pro",
        keyId: "PV-NUMSEC-2027",
        label: "Numeric Sec Exp",
        issuedAt: "2026-11-23T00:00:00.000Z",
        exp: 1800000000,
      },
      keyPairA.privateKey
    );
    tokenInput.value = tokNumSec;
    await verifyBtn.dispatch("click");
    const text2027 = collectText(diagEl);
    assert.match(text2027, /2027/);
    assert.doesNotMatch(text2027, /1970/);
    assert.doesNotMatch(text2027, /lifetime|бессрочный/i);

    const tokZeroExp = signProToken(
      {
        tier: "pro",
        keyId: "PV-ZEROEXP-1970",
        label: "Zero Exp",
        issuedAt: "2026-11-23T00:00:00.000Z",
        exp: 0,
      },
      keyPairA.privateKey
    );
    tokenInput.value = tokZeroExp;
    await verifyBtn.dispatch("click");
    const text1970 = collectText(diagEl);
    assert.match(text1970, /1970/);
    assert.doesNotMatch(text1970, /lifetime|бессрочный/i);
  });

  test("pvkeyFileInput rejects file.size > 256 KB before invoking file.arrayBuffer()", async () => {
    const elements = new Map();
    const register = (id, tag = "div", attrs = {}) => {
      const el = createMockElement(tag, id, attrs);
      elements.set(id, el);
      return el;
    };

    const fileInput = register("checkout-pvkey-file-input", "input");
    const diagEl = register("checkout-token-diagnostics", "div", { hidden: true });
    register("checkout-pro-status-badge", "span");
    register("checkout-pro-unlocked", "section", { hidden: true });

    globalThis.document = {
      readyState: "complete",
      documentElement: { lang: "en", dataset: {} },
      title: "",
      getElementById(id) {
        return elements.get(id) || null;
      },
      querySelector() {
        return null;
      },
      querySelectorAll() {
        return [];
      },
      createElement(tag) {
        return createMockElement(tag);
      },
    };
    globalThis.window.location = { pathname: "/en/pro/", hash: "" };

    const ctrl = await initProCheckout({ publicKeyB64U: pubA });
    assert.ok(ctrl);

    let arrayBufferCalls = 0;
    const oversizedFile = {
      size: 256 * 1024 + 1,
      async arrayBuffer() {
        arrayBufferCalls += 1;
        throw new Error("Should not buffer oversized file into RAM");
      },
    };

    await fileInput.dispatch("change", {
      target: {
        files: [oversizedFile],
        value: "oversized.pvkey",
      },
    });

    assert.equal(arrayBufferCalls, 0);
    assert.equal(ctrl.state.lastInspection?.reason, "file_too_large");
    assert.equal(diagEl.hidden, false);
  });

  test("B1/B2/B3/B4 regressions: async race guard, duplicate hashchange guard, QuotaExceededError warning, diagnostics coercion, and footer sync", async () => {
    const elements = new Map();
    const register = (id, tag = "div", attrs = {}) => {
      const el = createMockElement(tag, id, attrs);
      elements.set(id, el);
      return el;
    };

    const bannerEl = register("global-status-banner", "div", { hidden: true });
    const tokenInput = register("checkout-token-input", "textarea");
    const verifyBtn = register("checkout-verify-only-btn", "button");
    const activateBtn = register("checkout-activate-btn", "button");
    const deactivateBtn = register("checkout-deactivate-btn", "button");
    const diagEl = register("checkout-token-diagnostics", "div", { hidden: true });
    const unlockedEl = register("checkout-pro-unlocked", "section", { hidden: true });
    const statusBadge = register("checkout-pro-status-badge", "span");
    const langEnBtn = register("lang-en-btn", "button");
    const footerWorkLink = createMockElement("a", "", { href: "/" });
    const footerPriceLink = createMockElement("a", "", { href: "/#pricing-section" });
    const footerExtLink = createMockElement("a", "", { href: "https://github.com/Aquanti/promptveil" });

    let hashListeners = 0;
    globalThis.window = {
      localStorage: createMemoryLocalStorage(),
      location: { pathname: "/pro/", hash: "" },
      setTimeout,
      clearTimeout,
      addEventListener(type) {
        if (type === "hashchange") hashListeners += 1;
      },
    };
    globalThis.document = {
      readyState: "complete",
      documentElement: { lang: "ru", dataset: {} },
      title: "",
      getElementById(id) {
        return elements.get(id) || null;
      },
      querySelector(sel) {
        if (sel === '[data-testid="lang-en"]') return langEnBtn;
        return null;
      },
      querySelectorAll(sel) {
        if (sel === ".footer-links-row a") return [footerWorkLink, footerPriceLink, footerExtLink];
        return [];
      },
      createElement(tag) {
        return createMockElement(tag);
      },
    };

    const ctrl = await initProCheckout({ publicKeyB64U: pubA });
    await initProCheckout({ publicKeyB64U: pubA });
    assert.equal(hashListeners, 1, "hashchange must be registered only once across initProCheckout calls");

    // B4: RU -> EN updates .footer-links-row internal links while leaving external GitHub link untouched
    await langEnBtn.dispatch("click");
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(footerWorkLink.getAttribute("href"), "/en/");
    assert.equal(footerPriceLink.getAttribute("href"), "/en/#pricing-section");
    assert.equal(footerExtLink.getAttribute("href"), "https://github.com/Aquanti/promptveil");

    const tokA = signProToken(
      { tier: "pro", keyId: "PV-RACE-1", label: "Race 1", issuedAt: "2026-11-23T00:00:00.000Z" },
      keyPairA.privateKey
    );
    const tokB = signProToken(
      { tier: "pro", keyId: "PV-RACE-2", label: "Race 2", issuedAt: "2026-11-23T00:00:00.000Z" },
      keyPairA.privateKey
    );

    // B1: Slow activate(tokA) superseded by synchronous deactivateBtn must never resurrect localStorage or UI
    const prevCryptoDesc = Object.getOwnPropertyDescriptor(globalThis, "crypto");
    const origSubtle = globalThis.crypto.subtle;
    let delayFirst = true;
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: {
        subtle: {
          importKey: (...args) => origSubtle.importKey(...args),
          async verify(...args) {
            if (delayFirst) {
              delayFirst = false;
              await new Promise((r) => setTimeout(r, 60));
            }
            return origSubtle.verify(...args);
          },
        },
      },
    });

    try {
      tokenInput.value = tokA;
      const actPromise = activateBtn.dispatch("click");
      await new Promise((r) => setTimeout(r, 10));
      await deactivateBtn.dispatch("click");
      await actPromise;

      assert.equal(globalThis.window.localStorage.getItem(PRO_LICENSE_STORAGE_KEY), null);
      assert.equal(ctrl.state.proLicense.isPro, false);
      assert.equal(unlockedEl.hidden, true);
      assert.equal(statusBadge.dataset.proState, "free");

      // Slow verify(tokA) overtaken by fast verify('PV1.bad.sig') must not overwrite diagnostics
      delayFirst = true;
      tokenInput.value = tokA;
      const slowVerify = verifyBtn.dispatch("click");
      await new Promise((r) => setTimeout(r, 10));
      tokenInput.value = "PV1.bad.sig";
      await verifyBtn.dispatch("click");
      await slowVerify;
      assert.equal(ctrl.state.lastInspection?.valid, false);
      assert.equal(ctrl.state.lastInspection?.reason, "encoding");
    } finally {
      if (prevCryptoDesc) {
        Object.defineProperty(globalThis, "crypto", prevCryptoDesc);
      }
    }

    // B2: QuotaExceededError during activateBtn surfaces banner.storageWarning
    const origSetItem = globalThis.window.localStorage.setItem;
    globalThis.window.localStorage.setItem = () => {
      throw new Error("QuotaExceededError");
    };
    tokenInput.value = tokB;
    await activateBtn.dispatch("click");
    globalThis.window.localStorage.setItem = origSetItem;

    assert.equal(bannerEl.hidden, false);
    assert.equal(bannerEl.getAttribute("role"), "alert");
    assert.match(bannerEl.children[0]?.textContent || "", /storage|хранилищ/i);

    // B3: Invalid tier:123 & exp:"" & issuedAt:"0" diagnostics display consistency
    const collectText = (node) =>
      [node?.textContent || "", ...(node?.children || []).map(collectText)].join(" ");
    const { sign: nodeSign } = await import("node:crypto");
    const makeCraftedTok = (payloadObj) => {
      const p = Buffer.from(JSON.stringify(payloadObj), "utf8").toString("base64url");
      const sig = nodeSign(null, Buffer.from(`PV1.${p}`, "utf8"), keyPairA.privateKey);
      return `PV1.${p}.${Buffer.from(sig).toString("base64url")}`;
    };

    tokenInput.value = makeCraftedTok({
      v: 1,
      tier: 123,
      keyId: "PV-WEIRD-TIER",
      label: "Weird Tier",
      issuedAt: "2026-11-23T00:00:00.000Z",
    });
    await verifyBtn.dispatch("click");
    const weirdTierTxt = collectText(diagEl);
    assert.doesNotMatch(weirdTierTxt, /\btier\s*:\s*pro\b/i);

    tokenInput.value = makeCraftedTok({
      v: 1,
      tier: "pro",
      keyId: "PV-WEIRD-EXP",
      label: "Weird Exp",
      issuedAt: "0",
      exp: "",
    });
    await verifyBtn.dispatch("click");
    const weirdExpTxt = collectText(diagEl);
    assert.doesNotMatch(weirdExpTxt, /never|бессрочный/i);
    assert.doesNotMatch(weirdExpTxt, /1970/);
    assert.match(weirdExpTxt, /1999|2000/);
  });
});
