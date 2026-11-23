import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createContentController } from "../src/content.js";
import { findPromptBox, isElementVisible } from "../src/adapters.js";
import { initPopupController } from "../src/popup.js";
import {
  EXT_PRO_LICENSE_STORAGE_KEY,
  EXT_SETTINGS_STORAGE_KEY,
  FREE_CUSTOM_RULE_LIMIT,
  getEffectiveMaskingConfig,
  loadExtSettings,
  saveExtSettings,
} from "../src/storage-ext.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EXT_DIR = path.resolve(__dirname, "..");

function toB64Url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function createEphemeralKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPub = spki.subarray(spki.length - 32);
  return {
    publicKeyB64U: toB64Url(rawPub),
    signPayload(payload) {
      const payloadB64U = toB64Url(Buffer.from(JSON.stringify(payload), "utf8"));
      const msg = Buffer.from(`PV1.${payloadB64U}`, "utf8");
      const sig = crypto.sign(null, msg, privateKey);
      return `PV1.${payloadB64U}.${toB64Url(sig)}`;
    },
  };
}

function createMockChromeStorage() {
  const store = new Map();
  const listeners = new Set();

  const local = {
    get(keys, cb) {
      const list = Array.isArray(keys) ? keys : [keys];
      const out = {};
      for (const k of list) {
        if (store.has(k)) out[k] = structuredClone(store.get(k));
      }
      if (typeof cb === "function") cb(out);
      return Promise.resolve(out);
    },
    set(items, cb) {
      const changes = {};
      for (const [k, v] of Object.entries(items)) {
        const oldValue = store.has(k) ? structuredClone(store.get(k)) : undefined;
        store.set(k, structuredClone(v));
        changes[k] = { oldValue, newValue: structuredClone(v) };
      }
      if (typeof cb === "function") cb();
      for (const fn of listeners) fn(changes, "local");
      return Promise.resolve();
    },
    remove(key, cb) {
      const oldValue = store.has(key) ? structuredClone(store.get(key)) : undefined;
      store.delete(key);
      if (typeof cb === "function") cb();
      for (const fn of listeners) fn({ [key]: { oldValue, newValue: undefined } }, "local");
      return Promise.resolve();
    },
  };

  const onChanged = {
    addListener: (fn) => listeners.add(fn),
    removeListener: (fn) => listeners.delete(fn),
  };

  return { store, local, onChanged };
}

class DomText {
  constructor(text) {
    this.nodeType = 3;
    this.nodeValue = String(text);
    this.textContent = String(text);
    this.parentNode = null;
  }
}

class DomNode {
  constructor(tagName, ownerDocument, attrs = {}) {
    this.nodeType = 1;
    this.tagName = tagName.toUpperCase();
    this.ownerDocument = ownerDocument;
    this.attrs = { ...attrs };
    this.id = attrs.id || "";
    this._className = attrs.class || "";
    this.childNodes = [];
    this.parentNode = null;
    this.hidden = false;
    this.disabled = false;
    this.checked = false;
    this._value = "";
    this.files = [];
    this.listeners = new Map();
    this.shadowRoot = null;
    this.options = [];
    this.classList = {
      contains: (cls) => this._className.split(/\s+/).includes(cls),
      add: (cls) => {
        const set = new Set(this._className.split(/\s+/).filter(Boolean));
        set.add(cls);
        this._className = Array.from(set).join(" ");
      },
      remove: (cls) => {
        const set = new Set(this._className.split(/\s+/).filter(Boolean));
        set.delete(cls);
        this._className = Array.from(set).join(" ");
      },
      toggle: (cls, force) => {
        const set = new Set(this._className.split(/\s+/).filter(Boolean));
        const has = set.has(cls);
        const next = force === undefined ? !has : Boolean(force);
        if (next) set.add(cls);
        else set.delete(cls);
        this._className = Array.from(set).join(" ");
      },
    };
  }

  get value() {
    if (this.tagName === "SELECT" && !this._value && this.options.length > 0) {
      return this.options[0].value;
    }
    return this._value;
  }

  set value(v) {
    this._value = String(v);
  }

  get className() {
    return this._className;
  }

  set className(v) {
    this._className = String(v);
  }

  get textContent() {
    return this.childNodes.map((c) => c.textContent || "").join("");
  }

  set textContent(v) {
    this.childNodes = v === "" ? [] : [new DomText(v)];
    if (this.childNodes[0]) this.childNodes[0].parentNode = this;
  }

  getAttribute(name) {
    if (name === "id") return this.id || null;
    if (name === "class") return this._className || null;
    return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null;
  }

  setAttribute(name, val) {
    this.attrs[name] = String(val);
    if (name === "id") this.id = String(val);
    if (name === "class") this._className = String(val);
  }

  appendChild(node) {
    node.parentNode = this;
    this.childNodes.push(node);
    if (this.tagName === "SELECT" && node.tagName === "OPTION") {
      this.options.push(node);
    }
    return node;
  }

  append(...nodes) {
    for (const node of nodes) {
      this.appendChild(typeof node === "string" ? new DomText(node) : node);
    }
  }

  removeChild(node) {
    this.childNodes = this.childNodes.filter((c) => c !== node);
    node.parentNode = null;
  }

  replaceChildren(...nodes) {
    for (const old of this.childNodes) old.parentNode = null;
    this.childNodes = [];
    this.append(...nodes);
  }

  remove() {
    if (this.parentNode) this.parentNode.removeChild(this);
  }

  focus() {
    this.ownerDocument.activeElement = this;
  }

  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }

  dispatchEvent(evt) {
    for (const fn of this.listeners.get(evt.type) || []) {
      fn(evt);
    }
    return true;
  }

  click() {
    if (this.disabled) return;
    if (this.tagName === "INPUT" && this.attrs.type === "checkbox") {
      this.checked = !this.checked;
      this.dispatchEvent({ type: "change", preventDefault() {} });
    }
    this.dispatchEvent({ type: "click", preventDefault() {} });
  }

  attachShadow({ mode }) {
    const root = new DomNode("shadow-root", this.ownerDocument);
    root.mode = mode;
    root.host = this;
    root.adoptedStyleSheets = [];
    this.shadowRoot = root;
    return root;
  }

  matchesSelector(part) {
    const sel = part.trim();
    if (!sel) return false;
    if (sel.includes(" ")) {
      const tokens = sel.split(/\s+/);
      const last = tokens[tokens.length - 1];
      if (!this.matchesSelector(last)) return false;
      let cursor = this.parentNode;
      for (let i = tokens.length - 2; i >= 0; i -= 1) {
        while (cursor && !cursor.matchesSelector(tokens[i])) cursor = cursor.parentNode;
        if (!cursor) return false;
        cursor = cursor.parentNode;
      }
      return true;
    }
    let rest = sel;
    const tagMatch = rest.match(/^[a-zA-Z0-9-]+/);
    if (tagMatch) {
      if (this.tagName !== tagMatch[0].toUpperCase()) return false;
      rest = rest.slice(tagMatch[0].length);
    }
    for (const m of rest.matchAll(/\[([a-zA-Z0-9_-]+)(?:(\*?=)"([^"]*)")?\]/g)) {
      const [, attrName, op, attrVal] = m;
      const actual = this.getAttribute(attrName);
      if (op === "=" && actual !== attrVal) return false;
      if (op === "*=" && (!actual || !actual.includes(attrVal))) return false;
      if (!op && actual === null) return false;
      rest = rest.replace(m[0], "");
    }
    for (const m of rest.matchAll(/#([a-zA-Z0-9_-]+)/g)) {
      if (this.id !== m[1]) return false;
    }
    for (const m of rest.matchAll(/\.([a-zA-Z0-9_-]+)/g)) {
      if (!this.classList.contains(m[1])) return false;
    }
    return true;
  }

  querySelectorAll(selectorString) {
    const parts = selectorString.split(",").map((s) => s.trim()).filter(Boolean);
    const out = [];
    const walk = (node) => {
      for (const child of node.childNodes || []) {
        if (child.nodeType === 1) {
          if (parts.some((p) => child.matchesSelector(p))) out.push(child);
          walk(child);
        }
      }
    };
    walk(this);
    return out;
  }

  querySelector(sel) {
    return this.querySelectorAll(sel)[0] || null;
  }
}

function buildPopupDomFromHtml() {
  const html = fs.readFileSync(path.join(EXT_DIR, "popup.html"), "utf8");
  const doc = {
    lang: "ru",
    activeElement: null,
    documentElement: null,
    createElement(tag) {
      return new DomNode(tag, doc);
    },
    createElementNS(_ns, tag) {
      return new DomNode(tag, doc);
    },
    createTextNode(text) {
      return new DomText(text);
    },
    getElementById(id) {
      return doc.documentElement.querySelector(`#${id}`);
    },
  };
  doc.documentElement = new DomNode("html", doc);
  const stack = [doc.documentElement];

  const tokenRegex = /<(\/?)([a-zA-Z0-9-]+)([^>]*)>|([^<]+)/g;
  const voidTags = new Set(["meta", "link", "img", "input", "br"]);
  let match;
  while ((match = tokenRegex.exec(html)) !== null) {
    if (match[4]) {
      const parent = stack[stack.length - 1];
      if (parent && match[4].trim()) {
        parent.appendChild(new DomText(match[4].trim()));
      }
      continue;
    }
    const [, closing, rawTag, rawAttrs] = match;
    const tag = rawTag.toLowerCase();
    if (tag === "!doctype") continue;
    if (closing) {
      if (stack.length > 1) stack.pop();
      continue;
    }
    const attrs = {};
    for (const am of rawAttrs.matchAll(/([a-zA-Z0-9_-]+)(?:="([^"]*)")?/g)) {
      attrs[am[1]] = am[2] ?? "";
    }
    const el = new DomNode(tag, doc, attrs);
    if (Object.prototype.hasOwnProperty.call(attrs, "hidden")) el.hidden = true;
    if (Object.prototype.hasOwnProperty.call(attrs, "disabled")) el.disabled = true;
    if (tag === "option") el.value = attrs.value || "";
    stack[stack.length - 1].appendChild(el);
    if (!voidTags.has(tag) && !rawAttrs.trim().endsWith("/")) {
      stack.push(el);
    }
  }
  return doc;
}

function createContentDoc() {
  const doc = {
    activeElement: null,
    documentElement: null,
    body: null,
    defaultView: {
      Event: class {
        constructor(type, opts = {}) {
          this.type = type;
          this.bubbles = Boolean(opts.bubbles);
        }
      },
      InputEvent: class {
        constructor(type, opts = {}) {
          this.type = type;
          this.bubbles = Boolean(opts.bubbles);
          this.data = opts.data;
        }
      },
      getComputedStyle: () => ({ display: "block", visibility: "visible" }),
    },
    createElement(tag, attrs = {}) {
      return new DomNode(tag, doc, attrs);
    },
    createElementNS(_ns, tag) {
      return new DomNode(tag, doc, {});
    },
    createTextNode(text) {
      return new DomText(text);
    },
    getElementById(id) {
      return doc.documentElement.querySelector(`#${id}`);
    },
    querySelectorAll(sel) {
      return doc.documentElement.querySelectorAll(sel);
    },
    querySelector(sel) {
      return doc.documentElement.querySelector(sel);
    },
  };
  doc.documentElement = new DomNode("html", doc);
  doc.body = new DomNode("body", doc);
  doc.documentElement.appendChild(doc.body);
  return doc;
}

test("storage-ext enforces Free limits when license is invalid and strict mode forces UUID", async () => {
  const { local } = createMockChromeStorage();
  const manyRules = Array.from({ length: 8 }, (_, idx) => ({
    id: `r${idx}`,
    term: `ProjectSecret${idx}`,
    category: "CUSTOM",
    enabled: true,
  }));

  await saveExtSettings(
    {
      lang: "ru",
      theme: "dark",
      sensitivity: "strict",
      detectUuid: false,
      disabledCategories: ["EMAIL", "PHONE"],
      customRules: manyRules,
    },
    local
  );

  const loaded = await loadExtSettings(local);
  assert.equal(loaded.detectUuid, true, "strict sensitivity forces detectUuid");
  assert.equal(loaded.customRules.length, 8);

  const freeEffective = getEffectiveMaskingConfig(loaded, { isPro: false, isOwner: false });
  assert.equal(freeEffective.customRules.length, FREE_CUSTOM_RULE_LIMIT);
  assert.deepEqual(freeEffective.disabledCategories, []);

  const proEffective = getEffectiveMaskingConfig(loaded, { isPro: true, isOwner: false });
  assert.equal(proEffective.customRules.length, 8);
  assert.deepEqual(proEffective.disabledCategories, ["EMAIL", "PHONE"]);
});

test("content controller sanitizes prompt box, preserves vault across empty prompt, and rehydrates reply in RAM", async () => {
  const { local, onChanged } = createMockChromeStorage();
  const kp = createEphemeralKeypair();
  const doc = createContentDoc();
  const promptBox = doc.createElement("textarea", { id: "chat-input" });
  promptBox.value = "Напиши письмо на ivan@acme.ru, телефон +7 999 123-45-67.";
  doc.body.appendChild(promptBox);

  const copiedTexts = [];
  const clipboard = {
    writeText: async (text) => {
      copiedTexts.push(text);
    },
    readText: async () => "",
  };

  const ctrl = await createContentController({
    win: { getSelection: () => null },
    doc,
    hostname: "chat.deepseek.com",
    clipboard,
    storageArea: local,
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
  });

  // 1) Empty vault notice before sanitizing
  const emptyRes = await ctrl.handleRehydrate();
  assert.equal(emptyRes.reason, "empty_vault");

  // 2) 1-click Sanitize before send
  const sanRes = await ctrl.handleSanitize();
  assert.equal(sanRes.ok, true);
  assert.equal(sanRes.result.maskedCount, 2);
  assert.match(promptBox.value, /\[EMAIL_1\]/);
  assert.match(promptBox.value, /\[PHONE_1\]/);
  assert.equal(promptBox.value.includes("ivan@acme.ru"), false);

  // 3) Simulate submitting prompt (box cleared -> vault MUST NOT reset!)
  promptBox.value = "";
  const emptyPromptAttempt = await ctrl.handleSanitize();
  assert.equal(emptyPromptAttempt.reason, "empty_input");
  assert.equal(ctrl.tabVault.tokenToEntry.size, 2);

  // 4) Simulate assistant response appearing in DOM & 1-click Rehydrate reply
  const replyNode = doc.createElement("div", { class: "ds-markdown" });
  replyNode.textContent = "Готово! Отправил на [EMAIL_1] и позвоню на [PHONE_1].";
  doc.body.appendChild(replyNode);

  const rehRes = await ctrl.handleRehydrate();
  assert.equal(rehRes.ok, true);
  assert.equal(rehRes.result.replacedCount, 2);
  assert.equal(
    rehRes.result.rehydratedText,
    "Готово! Отправил на ivan@acme.ru и позвоню на +7 999 123-45-67."
  );
  assert.equal(copiedTexts.at(-1), rehRes.result.rehydratedText);

  // Check Shadow DOM popover rendered <mark> elements without innerHTML or <style>
  const marks = ctrl.shadow.querySelectorAll("mark.pv-mark");
  assert.equal(marks.length, 2);
  assert.equal(ctrl.shadow.querySelectorAll("style").length, 0);

  // 5) Forged/absent Pro license ignores disabledCategories in content.js; valid Pro license enforces them
  await local.set({
    [EXT_SETTINGS_STORAGE_KEY]: {
      lang: "en",
      theme: "dark",
      overlayVisible: true,
      sensitivity: "normal",
      disabledCategories: ["EMAIL"],
      customRules: [],
    },
  });
  await new Promise((r) => setTimeout(r, 15));
  ctrl.tabVault.reset();
  promptBox.value = "Contact me at test@example.com or +7 999 000-11-22";
  const freeWithDisabledCat = await ctrl.handleSanitize();
  assert.equal(freeWithDisabledCat.result.maskedCount, 2, "Free must ignore disabledCategories");

  // 6) Live storage update toggles overlay visibility and Pro badge independently, and honors disabledCategories
  const validToken = kp.signPayload({
    v: 1,
    tier: "owner",
    keyId: "PV-OWNER-01",
    label: "Owner",
    issuedAt: "2026-01-01T00:00:00Z",
  });
  await local.set({
    [EXT_PRO_LICENSE_STORAGE_KEY]: validToken,
  });
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(ctrl.getState().license.isPro, true);
  assert.equal(ctrl.getState().license.isOwner, true);
  assert.equal(ctrl.shadow.querySelector(".pv-tier-chip").textContent, "Owner Pro");

  ctrl.tabVault.reset();
  promptBox.value = "Contact me at test@example.com or +7 999 000-11-22";
  const proWithDisabledCat = await ctrl.handleSanitize();
  assert.equal(proWithDisabledCat.result.maskedCount, 1, "Pro must skip disabled EMAIL category");
  assert.equal(promptBox.value.includes("test@example.com"), true);

  await local.set({
    [EXT_SETTINGS_STORAGE_KEY]: { lang: "en", theme: "dark", overlayVisible: false },
  });
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(ctrl.host.getAttribute("data-pv-hidden"), "true");
  assert.equal(ctrl.host.getAttribute("data-pv-theme"), "dark");

  ctrl.destroy();
});

test("popup controller enforces Free 5-rule cap, rejects tampered keys, and unlocks Pro/Owner via genuine Ed25519", async () => {
  const { local, onChanged, store } = createMockChromeStorage();
  const kp = createEphemeralKeypair();
  const doc = buildPopupDomFromHtml();

  const popup = await initPopupController({
    doc,
    storageArea: local,
    tabsApi: {
      query: (_q, cb) => cb([{ url: ["https", "claude.ai/chat/123"].join("://") }]),
    },
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
  });

  assert.equal(doc.getElementById("popup-site-status").textContent, "Активно на Claude");
  assert.equal(popup.getState().license.isPro, false);
  assert.equal(doc.getElementById("popup-pro-badge").textContent, "Free");
  assert.equal(doc.getElementById("popup-categories-lock").hidden, false);

  // Add 5 custom rules in Free
  const termInput = doc.getElementById("popup-custom-term");
  const form = doc.getElementById("popup-custom-form");
  for (let i = 1; i <= 5; i += 1) {
    termInput.value = `СекретПроект${i}`;
    form.dispatchEvent({ type: "submit", preventDefault() {} });
    await new Promise((r) => setTimeout(r, 5));
  }
  assert.equal(popup.getState().settings.customRules.length, 5);

  // 6th rule blocked in Free
  termInput.value = "СекретПроект6";
  form.dispatchEvent({ type: "submit", preventDefault() {} });
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(popup.getState().settings.customRules.length, 5);
  assert.equal(doc.getElementById("popup-custom-alert").hidden, false);

  // Reject forged / tampered key
  const keyInput = doc.getElementById("popup-pro-key-input");
  const activateBtn = doc.getElementById("popup-pro-activate-btn");
  const validProToken = kp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-CLIENT-99",
    label: "Client 99",
    issuedAt: "2026-01-01T00:00:00Z",
  });
  const tamperedSuffix = validProToken.endsWith("AA") ? "QQ" : "AA";
  const tamperedToken = `${validProToken.slice(0, -2)}${tamperedSuffix}`;
  keyInput.value = tamperedToken;
  activateBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(popup.getState().license.isPro, false);
  assert.equal(doc.getElementById("popup-pro-alert").hidden, false);

  // Activate genuine Ed25519 Pro token
  keyInput.value = validProToken;
  activateBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(popup.getState().license.isPro, true);
  assert.equal(doc.getElementById("popup-pro-badge").textContent, "Pro Активен");
  assert.equal(doc.getElementById("popup-categories-lock").hidden, true);

  // 6th rule + Industry pack now work in Pro!
  termInput.value = "СекретПроект6";
  form.dispatchEvent({ type: "submit", preventDefault() {} });
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(popup.getState().settings.customRules.length, 6);

  const legalPackBtn = doc.getElementById("popup-packs-list").querySelector('[data-pack-id="legal"]');
  legalPackBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(popup.getState().settings.customRules.length > 6, true);

  // Toggle EMAIL category off in Pro
  const emailBtn = doc.getElementById("popup-categories-grid").querySelector('[data-category="EMAIL"]');
  emailBtn.click();
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(popup.getState().settings.disabledCategories.includes("EMAIL"), true);

  // Verify zero prompt text persisted in chrome.storage.local
  const serializedStorage = JSON.stringify(Array.from(store.entries()));
  assert.equal(serializedStorage.includes("ivan@acme.ru"), false);

  // Remove Pro key -> reverts to Free and marks >5 rules as paused
  doc.getElementById("popup-pro-remove-btn").click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(popup.getState().license.isPro, false);
  assert.equal(doc.getElementById("popup-pro-badge").textContent, "Free");
  const ruleItemsAfterDowngrade = doc.getElementById("popup-custom-list").querySelectorAll("li.pv-rule-item");
  assert.equal(ruleItemsAfterDowngrade.length > 5, true);
  assert.equal(ruleItemsAfterDowngrade[0].classList.contains("is-paused"), false);
  assert.equal(ruleItemsAfterDowngrade[5].classList.contains("is-paused"), true);
  assert.equal(
    ruleItemsAfterDowngrade[5].querySelector(".pv-rule-tag.is-paused")?.textContent,
    "Лимит Free (пауза)"
  );

  // Synchronous multi-click settings changes in the same event-loop tick must not overwrite each other
  doc.getElementById("popup-lang-en").click();
  doc.getElementById("popup-theme-btn").click();
  doc.getElementById("popup-sens-strict").click();
  await new Promise((r) => setTimeout(r, 25));
  assert.equal(popup.getState().settings.lang, "en");
  assert.equal(popup.getState().settings.theme, "dark");
  assert.equal(popup.getState().settings.sensitivity, "strict");
  assert.equal(popup.getState().settings.detectUuid, true);
  const storedAfterBurst = await loadExtSettings(local);
  assert.equal(storedAfterBurst.lang, "en");
  assert.equal(storedAfterBurst.theme, "dark");
  assert.equal(storedAfterBurst.sensitivity, "strict");

  // Localized static attributes update on language switch
  assert.equal(doc.getElementById("popup-pro-badge").getAttribute("title"), "Pro License");
  assert.equal(doc.getElementById("popup-lang-switch").getAttribute("aria-label"), "Language");
  assert.equal(doc.getElementById("popup-custom-category").getAttribute("aria-label"), "Category");
  assert.equal(
    doc.getElementById("popup-custom-list").querySelectorAll("li.pv-rule-item")[5]
      .querySelector(".pv-rule-tag.is-paused")?.textContent,
    "Free limit (paused)"
  );

  popup.destroy();
});

test("content controller flags digit-bearing unresolved tokens such as [IPV4_1] and [SHA256_1]", async () => {
  const { local, onChanged } = createMockChromeStorage();
  const kp = createEphemeralKeypair();
  const doc = createContentDoc();
  const promptBox = doc.createElement("textarea", { id: "chat-input" });
  promptBox.value = "Server ivan@acme.ru online";
  doc.body.appendChild(promptBox);

  const ctrl = await createContentController({
    win: { getSelection: () => null },
    doc,
    hostname: "chat.deepseek.com",
    clipboard: { writeText: async () => {}, readText: async () => "" },
    storageArea: local,
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
  });

  await ctrl.handleSanitize();
  const replyNode = doc.createElement("div", { class: "ds-markdown" });
  replyNode.textContent = "Reply referencing [IPV4_1] and [SHA256_1] only";
  doc.body.appendChild(replyNode);

  const rehRes = await ctrl.handleRehydrate();
  assert.equal(rehRes.ok, true);
  assert.deepEqual(rehRes.result.unresolvedTokens, ["[IPV4_1]", "[SHA256_1]"]);
  ctrl.destroy();
});

test("adapters.isElementVisible rejects opacity:0 and hidden/aria-hidden/display:none ancestors", () => {
  const styles = new WeakMap();
  const doc = createContentDoc();
  doc.defaultView.getComputedStyle = (node) =>
    styles.get(node) || { display: "block", visibility: "visible", opacity: "1" };

  const hiddenWrap = doc.createElement("div", { id: "hidden-wrap" });
  hiddenWrap.hidden = true;
  const hiddenTa = doc.createElement("textarea", { id: "prompt-textarea" });
  hiddenWrap.appendChild(hiddenTa);
  doc.body.appendChild(hiddenWrap);

  const ariaHiddenWrap = doc.createElement("div", { "aria-hidden": "true" });
  const ariaHiddenTa = doc.createElement("textarea", { id: "aria-hidden-ta" });
  ariaHiddenWrap.appendChild(ariaHiddenTa);
  doc.body.appendChild(ariaHiddenWrap);

  const opacityZeroTa = doc.createElement("textarea", { id: "opacity-zero" });
  styles.set(opacityZeroTa, { display: "block", visibility: "visible", opacity: "0" });
  doc.body.appendChild(opacityZeroTa);

  const visibleCe = doc.createElement("div", { id: "prompt-textarea", contenteditable: "true" });
  doc.body.appendChild(visibleCe);

  assert.equal(isElementVisible(hiddenTa), false);
  assert.equal(isElementVisible(ariaHiddenTa), false);
  assert.equal(isElementVisible(opacityZeroTa), false);
  assert.equal(isElementVisible(visibleCe), true);
  assert.equal(findPromptBox(doc, "chatgpt.com"), visibleCe);
});

test("popup smart extraction activates noisy receipts, #code= fragments, and .pvkey text without storing wrapper text", async () => {
  const { local, onChanged, store } = createMockChromeStorage();
  const kp = createEphemeralKeypair();
  const doc = buildPopupDomFromHtml();

  const popup = await initPopupController({
    doc,
    storageArea: local,
    tabsApi: { query: (_q, cb) => cb([]) },
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
  });

  const token = kp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-TEST-EXTRACT-01",
    label: "Test Receipt User",
    issuedAt: "2026-06-01T00:00:00Z",
    exp: "2099-06-01T00:00:00Z",
  });

  const receiptText = [
    "# PromptVeil Pro Offline License Key",
    "# Order: PV-ORD-TEST01",
    `Activation link: #code=${encodeURIComponent(token)}&plan=pro-annual`,
  ].join("\n");

  const keyInput = doc.getElementById("popup-pro-key-input");
  keyInput.value = receiptText;
  doc.getElementById("popup-pro-activate-btn").click();
  await new Promise((r) => setTimeout(r, 20));

  assert.equal(popup.getState().license.isPro, true);
  assert.equal(popup.getState().license.keyId, "PV-TEST-EXTRACT-01");
  assert.equal(store.get(EXT_PRO_LICENSE_STORAGE_KEY), token);
  assert.equal(keyInput.value, "");
  assert.equal(doc.getElementById("popup-pro-diagnostics").hidden, false);
  assert.equal(doc.getElementById("popup-pro-diagnostics").classList.contains("is-valid"), true);
  assert.match(doc.getElementById("popup-pro-diagnostics").textContent, /PV-TEST-EXTRACT-01/);

  popup.destroy();
});

test("popup 1-click Paste & Activate handles success, empty clipboard, non-token text, and denied permission", async () => {
  const { local, onChanged, store } = createMockChromeStorage();
  const kp = createEphemeralKeypair();

  let clipMode = "denied";
  let clipText = "";
  const clipboard = {
    readText: async () => {
      if (clipMode === "denied") {
        throw new Error("Permission denied");
      }
      return clipText;
    },
  };

  const doc = buildPopupDomFromHtml();
  const popup = await initPopupController({
    doc,
    storageArea: local,
    tabsApi: { query: (_q, cb) => cb([]) },
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
    clipboard,
  });

  const pasteBtn = doc.getElementById("popup-pro-paste-btn");
  const keyInput = doc.getElementById("popup-pro-key-input");
  const proAlert = doc.getElementById("popup-pro-alert");

  // 1) Permission denied
  pasteBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(popup.getState().license.isPro, false);
  assert.equal(proAlert.hidden, false);
  assert.equal(doc.activeElement, keyInput);

  // 2) Empty clipboard
  clipMode = "text";
  clipText = "   ";
  pasteBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(popup.getState().license.isPro, false);
  assert.equal(proAlert.hidden, false);
  assert.equal(doc.activeElement, keyInput);

  // 3) Unrelated non-token text (must not clobber input or unlock)
  clipText = "hello world order without key";
  pasteBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(popup.getState().license.isPro, false);
  assert.equal(keyInput.value, "");
  assert.equal(doc.activeElement, keyInput);

  // 4) Valid .pvkey clipboard content
  const validToken = kp.signPayload({
    v: 1,
    tier: "owner",
    keyId: "PV-TEST-PASTE-01",
    label: "Clipboard Owner",
    issuedAt: "2026-06-01T00:00:00Z",
  });
  clipText = `# PromptVeil Pro\n# Key ID: PV-TEST-PASTE-01\n${validToken}\n`;
  pasteBtn.click();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(popup.getState().license.isPro, true);
  assert.equal(popup.getState().license.isOwner, true);
  assert.equal(store.get(EXT_PRO_LICENSE_STORAGE_KEY), validToken);

  popup.destroy();
});

test("popup .pvkey file import activates valid files and rejects oversized or binary/invalid files", async () => {
  const { local, onChanged, store } = createMockChromeStorage();
  const kp = createEphemeralKeypair();
  const doc = buildPopupDomFromHtml();

  const popup = await initPopupController({
    doc,
    storageArea: local,
    tabsApi: { query: (_q, cb) => cb([]) },
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
  });

  const fileInput = doc.getElementById("popup-pro-file-input");
  const proAlert = doc.getElementById("popup-pro-alert");
  const diag = doc.getElementById("popup-pro-diagnostics");

  // 1) Oversized file (> 256 KB) rejected before reading
  let oversizedReadCalled = false;
  fileInput.files = [
    {
      name: "huge.pvkey",
      size: 300 * 1024,
      arrayBuffer: async () => {
        oversizedReadCalled = true;
        return new ArrayBuffer(0);
      },
    },
  ];
  fileInput.dispatchEvent({ type: "change", target: fileInput });
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(oversizedReadCalled, false);
  assert.equal(popup.getState().license.isPro, false);
  assert.equal(proAlert.hidden, false);
  assert.equal(diag.classList.contains("is-error"), true);

  // 2) NUL-byte binary file rejected
  fileInput.files = [
    {
      name: "binary.pvkey",
      size: 8,
      arrayBuffer: async () => new Uint8Array([0x50, 0x56, 0x00, 0x31]).buffer,
    },
  ];
  fileInput.dispatchEvent({ type: "change", target: fileInput });
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(popup.getState().license.isPro, false);
  assert.equal(diag.classList.contains("is-error"), true);

  // 3) Text file without PV1 token rejected
  const noTokBytes = new TextEncoder().encode("# empty comment file\nno key here\n");
  fileInput.files = [
    {
      name: "empty.txt",
      size: noTokBytes.length,
      arrayBuffer: async () => noTokBytes.buffer,
    },
  ];
  fileInput.dispatchEvent({ type: "change", target: fileInput });
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(popup.getState().license.isPro, false);

  // 4) Valid .pvkey file activates Pro
  const validToken = kp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-TEST-FILE-01",
    label: "File License",
    issuedAt: "2026-06-01T00:00:00Z",
    exp: "2099-12-31T00:00:00Z",
  });
  const pvkeyBytes = new TextEncoder().encode(
    `# PromptVeil Pro Offline License Key\n# Key ID: PV-TEST-FILE-01\n${validToken}\n`
  );
  fileInput.files = [
    {
      name: "license.pvkey",
      size: pvkeyBytes.length,
      arrayBuffer: async () => pvkeyBytes.buffer,
    },
  ];
  fileInput.dispatchEvent({ type: "change", target: fileInput });
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(popup.getState().license.isPro, true);
  assert.equal(popup.getState().license.keyId, "PV-TEST-FILE-01");
  assert.equal(store.get(EXT_PRO_LICENSE_STORAGE_KEY), validToken);

  popup.destroy();
});

test("popup Verify button inspects tokens without persisting and diagnoses format/encoding/signature/payload/expired", async () => {
  const { local, onChanged, store } = createMockChromeStorage();
  const kp = createEphemeralKeypair();
  const otherKp = createEphemeralKeypair();
  const doc = buildPopupDomFromHtml();
  const fixedNowMs = Date.parse("2026-07-01T00:00:00Z");

  const popup = await initPopupController({
    doc,
    storageArea: local,
    tabsApi: { query: (_q, cb) => cb([]) },
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
    nowMs: fixedNowMs,
  });

  const keyInput = doc.getElementById("popup-pro-key-input");
  const verifyBtn = doc.getElementById("popup-pro-verify-btn");
  const diag = doc.getElementById("popup-pro-diagnostics");

  // 1) Format error
  keyInput.value = "NOT-A-PV1-TOKEN";
  verifyBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(diag.hidden, false);
  assert.equal(diag.classList.contains("is-error"), true);
  assert.equal(store.has(EXT_PRO_LICENSE_STORAGE_KEY), false);

  // 2) Encoding error (invalid base64url char '!')
  keyInput.value = "PV1.abc!def.sig!123";
  verifyBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(diag.classList.contains("is-error"), true);

  // 3) Length error (short signature)
  keyInput.value = `PV1.${toB64Url(Buffer.from("{}", "utf8"))}.${toB64Url(Buffer.from("short"))}`;
  verifyBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(diag.classList.contains("is-error"), true);

  // 4) Wrong-key signature error (shows unverified claims keyId)
  const wrongKeyTok = otherKp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-WRONG-KEY-01",
    label: "Wrong Key",
    issuedAt: "2026-06-01T00:00:00Z",
  });
  keyInput.value = wrongKeyTok;
  verifyBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(diag.classList.contains("is-error"), true);
  assert.match(diag.textContent, /PV-WRONG-KEY-01/);
  assert.equal(popup.getState().license.isPro, false);

  // 5) Payload error (valid signature from kp, missing required claims)
  const badPayloadTok = kp.signPayload({ v: 1, tier: "pro" });
  keyInput.value = badPayloadTok;
  verifyBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(diag.classList.contains("is-error"), true);

  // 6) Expired token (numeric timestamp in the past)
  const expiredTok = kp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-EXPIRED-01",
    label: "Expired Key",
    issuedAt: "2025-01-01T00:00:00Z",
    exp: Math.floor(Date.parse("2026-01-15T00:00:00Z") / 1000),
  });
  keyInput.value = expiredTok;
  verifyBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(diag.classList.contains("is-warn"), true);
  assert.match(diag.textContent, /PV-EXPIRED-01/);
  assert.equal(store.has(EXT_PRO_LICENSE_STORAGE_KEY), false);

  // 7) Valid token verified WITHOUT persisting to storage
  const validTok = kp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-VERIFY-ONLY-01",
    label: "Verify Only",
    issuedAt: "2026-06-01T00:00:00Z",
    exp: "2099-06-01T00:00:00Z",
  });
  keyInput.value = validTok;
  verifyBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(diag.classList.contains("is-valid"), true);
  assert.match(diag.textContent, /PV-VERIFY-ONLY-01/);
  assert.equal(popup.getState().license.isPro, false, "Verify must not activate/persist");
  assert.equal(store.has(EXT_PRO_LICENSE_STORAGE_KEY), false);

  // 8) Activate, clear input, then Verify with empty input re-verifies stored license
  doc.getElementById("popup-pro-activate-btn").click();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(popup.getState().license.isPro, true);
  assert.equal(keyInput.value, "");

  verifyBtn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(diag.classList.contains("is-valid"), true);
  assert.match(diag.textContent, /PV-VERIFY-ONLY-01/);

  popup.destroy();
});

test("popup locked Pro hints focus #popup-pro-key-input and content pill syncs & displays diagnostics on click", async () => {
  const { local, onChanged } = createMockChromeStorage();
  const kp = createEphemeralKeypair();
  const popupDoc = buildPopupDomFromHtml();
  const fixedNowMs = Date.parse("2026-07-01T00:00:00Z");

  let scrollCalls = 0;
  const proSection = popupDoc.getElementById("popup-pro-section");
  proSection.scrollIntoView = () => {
    scrollCalls += 1;
  };

  const popup = await initPopupController({
    doc: popupDoc,
    storageArea: local,
    tabsApi: { query: (_q, cb) => cb([]) },
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
    nowMs: fixedNowMs,
  });

  const keyInput = popupDoc.getElementById("popup-pro-key-input");

  // Locked category badge click focuses key input
  popupDoc.activeElement = null;
  popupDoc.getElementById("popup-categories-lock").click();
  assert.equal(popupDoc.activeElement, keyInput);
  assert.equal(scrollCalls > 0, true);

  // Locked packs badge click focuses key input
  popupDoc.activeElement = null;
  popupDoc.getElementById("popup-packs-lock").click();
  assert.equal(popupDoc.activeElement, keyInput);

  // Custom rule limit alert click focuses key input
  const termInput = popupDoc.getElementById("popup-custom-term");
  const form = popupDoc.getElementById("popup-custom-form");
  for (let i = 1; i <= 6; i += 1) {
    termInput.value = `Term${i}`;
    form.dispatchEvent({ type: "submit", preventDefault() {} });
    await new Promise((r) => setTimeout(r, 5));
  }
  popupDoc.activeElement = null;
  const customAlert = popupDoc.getElementById("popup-custom-alert");
  assert.equal(customAlert.hidden, false);
  assert.equal(customAlert.classList.contains("is-actionable"), true);
  customAlert.click();
  assert.equal(popupDoc.activeElement, keyInput);

  // Mount content controller sharing chrome.storage.local + onChanged
  const contentDoc = createContentDoc();
  const promptBox = contentDoc.createElement("textarea", { id: "chat-input" });
  contentDoc.body.appendChild(promptBox);
  const ctrl = await createContentController({
    win: { getSelection: () => null },
    doc: contentDoc,
    hostname: "chat.deepseek.com",
    clipboard: { writeText: async () => {}, readText: async () => "" },
    storageArea: local,
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
    nowMs: fixedNowMs,
  });

  const tierChip = ctrl.shadow.querySelector(".pv-tier-chip");
  const toast = ctrl.shadow.querySelector(".pv-toast");
  assert.equal(tierChip.tagName, "BUTTON");
  assert.equal(tierChip.textContent, "Free");
  assert.equal(Boolean(tierChip.getAttribute("title")), true);
  assert.equal(Boolean(tierChip.getAttribute("aria-label")), true);

  // Click Free tier chip -> info toast with toolbar activation hint
  tierChip.click();
  assert.equal(toast.hidden, false);
  assert.match(toast.textContent, /Free/);

  // Activate Pro via popup -> content pill updates live & click shows keyId
  const activeProTok = kp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-SYNC-PRO-01",
    label: "Sync Pro",
    issuedAt: "2026-06-01T00:00:00Z",
    exp: "2099-06-01T00:00:00Z",
  });
  keyInput.value = activeProTok;
  popupDoc.getElementById("popup-pro-activate-btn").click();
  await new Promise((r) => setTimeout(r, 25));

  assert.equal(ctrl.getState().license.isPro, true);
  assert.equal(tierChip.textContent, "Pro Активен");
  assert.equal(tierChip.classList.contains("is-pro"), true);
  assert.equal(tierChip.classList.contains("is-expired"), false);
  tierChip.click();
  assert.equal(toast.hidden, false);
  assert.equal(toast.classList.contains("is-success"), true);
  assert.match(toast.textContent, /PV-SYNC-PRO-01/);

  // Expired stored token in storage enforces Free gating & shows warning pill + toast
  const expiredStoredTok = kp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-EXPIRED-SYNC-02",
    label: "Expired Sync",
    issuedAt: "2025-01-01T00:00:00Z",
    exp: "2026-02-01T00:00:00Z",
  });
  await local.set({
    [EXT_PRO_LICENSE_STORAGE_KEY]: expiredStoredTok,
    [EXT_SETTINGS_STORAGE_KEY]: {
      lang: "en",
      theme: "light",
      overlayVisible: true,
      disabledCategories: ["EMAIL"],
      customRules: [],
    },
  });
  await new Promise((r) => setTimeout(r, 25));

  assert.equal(ctrl.getState().license.isPro, false);
  assert.equal(ctrl.getState().license.reason, "expired");
  assert.equal(tierChip.textContent, "Free");
  assert.equal(tierChip.classList.contains("is-pro"), false);
  assert.equal(tierChip.classList.contains("is-expired"), true);
  tierChip.click();
  assert.equal(toast.classList.contains("is-warn"), true);
  assert.match(toast.textContent, /PV-EXPIRED-SYNC-02/);

  // Verify Free gating still masks EMAIL even though disabledCategories has EMAIL
  promptBox.value = "Contact ivan@acme.ru";
  const sanRes = await ctrl.handleSanitize();
  assert.equal(sanRes.result.maskedCount, 1);

  ctrl.destroy();
  popup.destroy();
});

test("popup keeps #popup-pro-remove-btn enabled for expired and invalid stored tokens and clears storage on click", async () => {
  const { local, onChanged, store } = createMockChromeStorage();
  const kp = createEphemeralKeypair();
  const otherKp = createEphemeralKeypair();
  const doc = buildPopupDomFromHtml();
  const fixedNowMs = Date.parse("2026-07-01T00:00:00Z");

  const expiredTok = kp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-STORED-EXP-01",
    label: "Expired Stored",
    issuedAt: "2025-01-01T00:00:00Z",
    exp: "2026-02-01T00:00:00Z",
  });
  await local.set({ [EXT_PRO_LICENSE_STORAGE_KEY]: expiredTok });

  const popup = await initPopupController({
    doc,
    storageArea: local,
    tabsApi: { query: (_q, cb) => cb([]) },
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
    nowMs: fixedNowMs,
  });

  const removeBtn = doc.getElementById("popup-pro-remove-btn");
  assert.equal(popup.getState().license.isPro, false);
  assert.equal(popup.getState().license.reason, "expired");
  assert.equal(popup.getState().hasStoredLicenseToken, true);
  assert.equal(removeBtn.disabled, false);

  removeBtn.click();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(store.has(EXT_PRO_LICENSE_STORAGE_KEY), false);
  assert.equal(popup.getState().hasStoredLicenseToken, false);
  assert.equal(popup.getState().license.isPro, false);
  assert.equal(removeBtn.disabled, true);

  // Invalid signature stored token also enables #popup-pro-remove-btn
  const wrongKeyTok = otherKp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-STORED-BADSIG-01",
    label: "Invalid Stored",
    issuedAt: "2026-06-01T00:00:00Z",
  });
  await local.set({ [EXT_PRO_LICENSE_STORAGE_KEY]: wrongKeyTok });
  await new Promise((r) => setTimeout(r, 20));

  assert.equal(popup.getState().license.isPro, false);
  assert.equal(popup.getState().license.reason, "signature");
  assert.equal(popup.getState().hasStoredLicenseToken, true);
  assert.equal(removeBtn.disabled, false);

  removeBtn.click();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(store.has(EXT_PRO_LICENSE_STORAGE_KEY), false);
  assert.equal(popup.getState().hasStoredLicenseToken, false);
  assert.equal(removeBtn.disabled, true);

  popup.destroy();
});

test("popup proActionSeq drops stale slow .pvkey uploads and stale concurrent Paste clicks", async () => {
  const { local, onChanged, store } = createMockChromeStorage();
  const kp = createEphemeralKeypair();
  const doc = buildPopupDomFromHtml();

  let resolveSlowClip;
  let clipCallCount = 0;
  const tokPasteFast = kp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-PASTE-FAST-02",
    label: "Paste Fast",
    issuedAt: "2026-06-01T00:00:00Z",
  });
  const clipboard = {
    readText: () => {
      clipCallCount += 1;
      if (clipCallCount === 1) {
        return new Promise((_resolve, reject) => {
          resolveSlowClip = () => reject(new Error("NotAllowedError"));
        });
      }
      return Promise.resolve(tokPasteFast);
    },
  };

  const popup = await initPopupController({
    doc,
    storageArea: local,
    tabsApi: { query: (_q, cb) => cb([]) },
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
    clipboard,
  });

  const fileInput = doc.getElementById("popup-pro-file-input");
  const pasteBtn = doc.getElementById("popup-pro-paste-btn");
  const proAlert = doc.getElementById("popup-pro-alert");
  const diag = doc.getElementById("popup-pro-diagnostics");

  const tokFileOld = kp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-FILE-OLD-01",
    label: "File Slow",
    issuedAt: "2026-06-01T00:00:00Z",
  });
  const tokFileNew = kp.signPayload({
    v: 1,
    tier: "owner",
    keyId: "PV-FILE-NEW-02",
    label: "File Fast",
    issuedAt: "2026-06-01T00:00:00Z",
  });

  let resolveSlowFile;
  const oldBytes = new TextEncoder().encode(tokFileOld);
  const newBytes = new TextEncoder().encode(tokFileNew);

  fileInput.files = [
    {
      name: "slow.pvkey",
      size: oldBytes.length,
      arrayBuffer: () =>
        new Promise((resolve) => {
          resolveSlowFile = () => resolve(oldBytes.buffer);
        }),
    },
  ];
  fileInput.dispatchEvent({ type: "change", target: fileInput });

  fileInput.files = [
    {
      name: "fast.pvkey",
      size: newBytes.length,
      arrayBuffer: async () => newBytes.buffer,
    },
  ];
  fileInput.dispatchEvent({ type: "change", target: fileInput });

  await new Promise((r) => setTimeout(r, 20));
  assert.equal(popup.getState().license.keyId, "PV-FILE-NEW-02");
  assert.equal(store.get(EXT_PRO_LICENSE_STORAGE_KEY), tokFileNew);

  // Late resolution of slow file upload must NOT clobber newer activation
  resolveSlowFile();
  await new Promise((r) => setTimeout(r, 25));
  assert.equal(popup.getState().license.keyId, "PV-FILE-NEW-02");
  assert.equal(store.get(EXT_PRO_LICENSE_STORAGE_KEY), tokFileNew);
  assert.match(diag.textContent, /PV-FILE-NEW-02/);
  assert.match(proAlert.textContent, /PV-FILE-NEW-02/);

  // Concurrent Paste & Activate: slow denial followed by fast valid paste
  pasteBtn.click();
  pasteBtn.click();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(popup.getState().license.keyId, "PV-PASTE-FAST-02");
  assert.equal(store.get(EXT_PRO_LICENSE_STORAGE_KEY), tokPasteFast);
  assert.equal(diag.hidden, false);
  assert.equal(diag.classList.contains("is-valid"), true);
  assert.equal(proAlert.classList.contains("is-success"), true);

  resolveSlowClip();
  await new Promise((r) => setTimeout(r, 25));
  assert.equal(popup.getState().license.keyId, "PV-PASTE-FAST-02");
  assert.equal(store.get(EXT_PRO_LICENSE_STORAGE_KEY), tokPasteFast);
  assert.equal(diag.hidden, false);
  assert.equal(diag.classList.contains("is-valid"), true);
  assert.equal(proAlert.classList.contains("is-success"), true);
  assert.match(proAlert.textContent, /PV-PASTE-FAST-02/);

  popup.destroy();
});

test("popup re-translates #popup-pro-alert in lockstep with #popup-pro-diagnostics on RU/EN switch and formats exp: 0 consistently", async () => {
  const { local, onChanged } = createMockChromeStorage();
  const kp = createEphemeralKeypair();
  const otherKp = createEphemeralKeypair();
  const doc = buildPopupDomFromHtml();
  const fixedNowMs = Date.parse("2026-07-01T00:00:00Z");

  const popup = await initPopupController({
    doc,
    storageArea: local,
    tabsApi: { query: (_q, cb) => cb([]) },
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
    nowMs: fixedNowMs,
  });

  const keyInput = doc.getElementById("popup-pro-key-input");
  const verifyBtn = doc.getElementById("popup-pro-verify-btn");
  const proAlert = doc.getElementById("popup-pro-alert");
  const diag = doc.getElementById("popup-pro-diagnostics");
  const langEn = doc.getElementById("popup-lang-en");
  const langRu = doc.getElementById("popup-lang-ru");

  // 1) Expired token with exp: 0 renders 1970 UTC date in both alert and diagnostics and re-translates on RU <-> EN
  const expZeroTok = kp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-EXP-ZERO-01",
    label: "Epoch Zero",
    issuedAt: "1969-12-31T00:00:00Z",
    exp: 0,
  });
  keyInput.value = expZeroTok;
  verifyBtn.click();
  await new Promise((r) => setTimeout(r, 20));

  assert.match(proAlert.textContent, /истёк/i);
  assert.match(proAlert.textContent, /1970/);
  assert.equal((diag.textContent.match(/1970/g) || []).length >= 2, true);

  langEn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.match(proAlert.textContent, /expired/i);
  assert.match(proAlert.textContent, /Jan 1, 1970/);
  assert.equal(proAlert.textContent.includes("истёк"), false);
  assert.match(diag.textContent, /Jan 1, 1970/);

  langRu.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.match(proAlert.textContent, /истёк/i);
  assert.match(proAlert.textContent, /1970/);

  // 2) Signature error alert also re-translates on RU -> EN switch
  const wrongKeyTok = otherKp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-WRONG-LANG-01",
    label: "Wrong Key",
    issuedAt: "2026-06-01T00:00:00Z",
  });
  keyInput.value = wrongKeyTok;
  verifyBtn.click();
  await new Promise((r) => setTimeout(r, 20));
  assert.match(proAlert.textContent, /Ed25519/i);
  assert.match(proAlert.textContent, /подпис/i);

  langEn.click();
  await new Promise((r) => setTimeout(r, 15));
  assert.match(proAlert.textContent, /Ed25519 signature verification failed/i);
  assert.equal(proAlert.textContent.includes("подпис"), false);

  popup.destroy();

  // 3) Active status card with exp: 0 (when nowMs < 0) formats 1970 UTC date instead of lifetime
  const { local: local2, onChanged: onChanged2 } = createMockChromeStorage();
  const doc2 = buildPopupDomFromHtml();
  const popup2 = await initPopupController({
    doc: doc2,
    storageArea: local2,
    tabsApi: { query: (_q, cb) => cb([]) },
    storageEvents: onChanged2,
    publicKeyB64U: kp.publicKeyB64U,
    nowMs: -1000,
  });
  doc2.getElementById("popup-pro-key-input").value = expZeroTok;
  doc2.getElementById("popup-pro-activate-btn").click();
  await new Promise((r) => setTimeout(r, 20));

  const metaList = doc2.getElementById("popup-pro-meta-list");
  assert.equal(popup2.getState().license.isPro, true);
  assert.match(metaList.textContent, /1970/);
  assert.equal(metaList.textContent.includes("бессрочная"), false);

  doc2.getElementById("popup-lang-en").click();
  await new Promise((r) => setTimeout(r, 15));
  assert.match(metaList.textContent, /Jan 1, 1970/);
  assert.equal(metaList.textContent.includes("lifetime"), false);

  popup2.destroy();
});

test("content controller settingsRefreshSeq drops out-of-order settingsChanged resolutions", async () => {
  const { local, onChanged } = createMockChromeStorage();
  const kp = createEphemeralKeypair();
  const doc = createContentDoc();
  const promptBox = doc.createElement("textarea", { id: "chat-input" });
  doc.body.appendChild(promptBox);

  let settingsGetCalls = 0;
  let resolveSlowSettingsGet;
  const wrappedStorage = {
    get(keys, cb) {
      const list = Array.isArray(keys) ? keys : [keys];
      if (list.includes(EXT_SETTINGS_STORAGE_KEY)) {
        settingsGetCalls += 1;
        if (settingsGetCalls === 2) {
          return new Promise((resolve) => {
            resolveSlowSettingsGet = () => {
              const out = {
                [EXT_SETTINGS_STORAGE_KEY]: {
                  lang: "ru",
                  theme: "light",
                  overlayVisible: true,
                },
              };
              if (typeof cb === "function") cb(out);
              resolve(out);
            };
          });
        }
      }
      return local.get(keys, cb);
    },
    set: (items, cb) => local.set(items, cb),
    remove: (key, cb) => local.remove(key, cb),
  };

  const ctrl = await createContentController({
    win: { getSelection: () => null },
    doc,
    hostname: "chat.deepseek.com",
    clipboard: { writeText: async () => {}, readText: async () => "" },
    storageArea: wrappedStorage,
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
  });

  // Trigger slow settingsChanged #1 (calls wrappedStorage.get #2), then fast settingsChanged #2 (#3)
  await local.set({
    [EXT_SETTINGS_STORAGE_KEY]: { lang: "ru", theme: "light", overlayVisible: true },
  });
  await local.set({
    [EXT_SETTINGS_STORAGE_KEY]: { lang: "en", theme: "dark", overlayVisible: false },
  });
  await new Promise((r) => setTimeout(r, 20));

  assert.equal(ctrl.getState().settings.lang, "en");
  assert.equal(ctrl.getState().settings.theme, "dark");
  assert.equal(ctrl.host.getAttribute("data-pv-theme"), "dark");
  assert.equal(ctrl.host.getAttribute("data-pv-hidden"), "true");

  // Resolve slow settingsChanged #1 late -> MUST NOT revert newer EN/dark/hidden settings
  resolveSlowSettingsGet();
  await new Promise((r) => setTimeout(r, 20));

  assert.equal(ctrl.getState().settings.lang, "en");
  assert.equal(ctrl.getState().settings.theme, "dark");
  assert.equal(ctrl.host.getAttribute("data-pv-theme"), "dark");
  assert.equal(ctrl.host.getAttribute("data-pv-hidden"), "true");

  ctrl.destroy();
});

test("popup clears stale #popup-pro-diagnostics and #popup-pro-alert on external chrome.storage.onChanged downgrade", async () => {
  const { local, onChanged } = createMockChromeStorage();
  const kp = createEphemeralKeypair();
  const doc = buildPopupDomFromHtml();

  const popup = await initPopupController({
    doc,
    storageArea: local,
    tabsApi: { query: (_q, cb) => cb([]) },
    storageEvents: onChanged,
    publicKeyB64U: kp.publicKeyB64U,
  });

  const validTok = kp.signPayload({
    v: 1,
    tier: "pro",
    keyId: "PV-EXT-ONCHG-01",
    label: "OnChanged Test",
    issuedAt: "2026-06-01T00:00:00Z",
    exp: "2099-06-01T00:00:00Z",
  });

  doc.getElementById("popup-pro-key-input").value = validTok;
  doc.getElementById("popup-pro-activate-btn").click();
  await new Promise((r) => setTimeout(r, 20));

  const badge = doc.getElementById("popup-pro-badge");
  const diag = doc.getElementById("popup-pro-diagnostics");
  const alertEl = doc.getElementById("popup-pro-alert");
  assert.equal(badge.textContent, "Pro Активен");
  assert.equal(diag.hidden, false);
  assert.equal(alertEl.hidden, false);

  // External tamper / downgrade -> Free badge AND diagnostics/alert cleared
  await local.set({ [EXT_PRO_LICENSE_STORAGE_KEY]: "PV1.forged.sig" });
  await new Promise((r) => setTimeout(r, 20));

  assert.equal(popup.getState().license.isPro, false);
  assert.equal(badge.textContent, "Free");
  assert.equal(diag.hidden, true);
  assert.equal(alertEl.hidden, true);
  assert.equal(popup.getState().proInspection, null);
  assert.equal(popup.getState().proFeedback, null);

  // External activation -> Pro active, then external removal -> Free AND diagnostics/alert cleared
  await local.set({ [EXT_PRO_LICENSE_STORAGE_KEY]: validTok });
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(badge.textContent, "Pro Активен");

  await local.remove(EXT_PRO_LICENSE_STORAGE_KEY);
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(badge.textContent, "Free");
  assert.equal(diag.hidden, true);
  assert.equal(alertEl.hidden, true);

  popup.destroy();
});
