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
