import assert from "node:assert/strict";
import test from "node:test";

import {
  AI_HOST_ADAPTERS,
  PROMPTVEIL_HOST_ID,
  detectSupportedHost,
  findLatestAssistantReply,
  findPromptBox,
  readEditorText,
  resolveRehydrateSource,
  writeEditorText,
} from "../src/adapters.js";

class MockTextNode {
  constructor(value) {
    this.nodeType = 3;
    this.nodeValue = String(value);
    this.textContent = String(value);
    this.parentNode = null;
  }
}

class MockElement {
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
    this.readOnly = false;
    this._value = "";
    this.events = [];
    this.listeners = new Map();
    this.shadowRoot = null;
    this.classList = {
      contains: (cls) => this._className.split(/\s+/).includes(cls),
      add: (cls) => {
        const set = new Set(this._className.split(/\s+/).filter(Boolean));
        set.add(cls);
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
    return this._value;
  }

  set value(val) {
    this._value = String(val);
  }

  get className() {
    return this._className;
  }

  set className(val) {
    this._className = String(val);
  }

  get textContent() {
    return this.childNodes.map((c) => c.textContent || "").join("");
  }

  set textContent(val) {
    this.childNodes = val === "" ? [] : [new MockTextNode(val)];
    if (this.childNodes[0]) this.childNodes[0].parentNode = this;
  }

  getAttribute(name) {
    if (name === "id") return this.id || null;
    if (name === "class") return this._className || null;
    return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null;
  }

  setAttribute(name, value) {
    this.attrs[name] = String(value);
    if (name === "id") this.id = String(value);
    if (name === "class") this._className = String(value);
  }

  appendChild(node) {
    node.parentNode = this;
    this.childNodes.push(node);
    return node;
  }

  append(...nodes) {
    for (const node of nodes) {
      if (typeof node === "string") {
        this.appendChild(new MockTextNode(node));
      } else {
        this.appendChild(node);
      }
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

  focus() {
    this.ownerDocument.activeElement = this;
  }

  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }

  dispatchEvent(evt) {
    this.events.push(evt.type);
    const list = this.listeners.get(evt.type) || [];
    for (const fn of list) fn(evt);
    return true;
  }

  attachShadow() {
    this.shadowRoot = {
      host: this,
      activeElement: null,
      adoptedStyleSheets: [],
      childNodes: [],
      append(...nodes) {
        for (const n of nodes) this.childNodes.push(n);
      },
      querySelectorAll: () => [],
    };
    return this.shadowRoot;
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
        while (cursor && !cursor.matchesSelector(tokens[i])) {
          cursor = cursor.parentNode;
        }
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

    const attrMatches = [...rest.matchAll(/\[([a-zA-Z0-9_-]+)(?:(\*?=)"([^"]*)")?\]/g)];
    for (const m of attrMatches) {
      const [, attrName, op, attrVal] = m;
      const actual = this.getAttribute(attrName);
      if (op === "=") {
        if (actual !== attrVal) return false;
      } else if (op === "*=") {
        if (!actual || !actual.includes(attrVal)) return false;
      } else if (actual === null) {
        return false;
      }
      rest = rest.replace(m[0], "");
    }

    const idMatches = [...rest.matchAll(/#([a-zA-Z0-9_-]+)/g)];
    for (const m of idMatches) {
      if (this.id !== m[1]) return false;
    }

    const classMatches = [...rest.matchAll(/\.([a-zA-Z0-9_-]+)/g)];
    for (const m of classMatches) {
      if (!this.classList.contains(m[1])) return false;
    }

    return true;
  }

  querySelectorAll(selectorString) {
    const parts = selectorString.split(",").map((s) => s.trim()).filter(Boolean);
    const matches = [];
    const walk = (node) => {
      for (const child of node.childNodes || []) {
        if (child.nodeType === 1) {
          if (parts.some((p) => child.matchesSelector(p))) {
            matches.push(child);
          }
          walk(child);
        }
      }
    };
    walk(this);
    return matches;
  }

  querySelector(selectorString) {
    return this.querySelectorAll(selectorString)[0] || null;
  }
}

function createMockDocument() {
  const doc = {
    activeElement: null,
    documentElement: null,
    body: null,
    defaultView: {
      Event: class MockEvent {
        constructor(type, opts = {}) {
          this.type = type;
          this.bubbles = Boolean(opts.bubbles);
        }
      },
      InputEvent: class MockInputEvent {
        constructor(type, opts = {}) {
          this.type = type;
          this.bubbles = Boolean(opts.bubbles);
          this.data = opts.data;
        }
      },
      getComputedStyle: () => ({ display: "block", visibility: "visible" }),
    },
    createElement(tag, attrs = {}) {
      return new MockElement(tag, doc, attrs);
    },
    createTextNode(text) {
      return new MockTextNode(text);
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
  doc.documentElement = new MockElement("html", doc);
  doc.body = new MockElement("body", doc);
  doc.documentElement.appendChild(doc.body);
  return doc;
}

test("detectSupportedHost recognizes all 6 AI chats and rejects unknown hosts", () => {
  const expected = [
    "chatgpt.com",
    "claude.ai",
    "gemini.google.com",
    "chat.deepseek.com",
    "giga.chat",
    "alice.yandex.ru",
  ];
  assert.deepEqual(
    AI_HOST_ADAPTERS.map((a) => a.hostname),
    expected
  );
  for (const host of expected) {
    assert.equal(detectSupportedHost(host)?.hostname, host);
  }
  assert.equal(detectSupportedHost("example.com"), null);
});

test("findPromptBox resolves host-specific editors for all 6 AI chats and ignores PromptVeil host", () => {
  const cases = [
    { host: "chatgpt.com", build: (d) => d.createElement("div", { id: "prompt-textarea", contenteditable: "true", class: "ProseMirror" }) },
    { host: "claude.ai", build: (d) => d.createElement("div", { contenteditable: "true", class: "ProseMirror" }) },
    {
      host: "gemini.google.com",
      build: (d) => {
        const rt = d.createElement("rich-textarea");
        const ed = d.createElement("div", { class: "ql-editor", contenteditable: "true" });
        rt.appendChild(ed);
        return { root: rt, expected: ed };
      },
    },
    { host: "chat.deepseek.com", build: (d) => d.createElement("textarea", { id: "chat-input" }) },
    { host: "giga.chat", build: (d) => d.createElement("textarea") },
    { host: "alice.yandex.ru", build: (d) => d.createElement("div", { contenteditable: "true", role: "textbox" }) },
  ];

  for (const item of cases) {
    const doc = createMockDocument();
    const pillHost = doc.createElement("div", { id: PROMPTVEIL_HOST_ID });
    const pillTextarea = doc.createElement("textarea");
    pillHost.appendChild(pillTextarea);
    doc.body.appendChild(pillHost);

    const built = item.build(doc);
    const expectedEl = built.expected || built;
    doc.body.appendChild(built.root || built);

    const found = findPromptBox(doc, item.host);
    assert.equal(found, expectedEl, `Failed prompt box detection for ${item.host}`);
  }
});

test("writeEditorText uses native textarea value setter and dispatches input/change events", () => {
  const doc = createMockDocument();
  const textarea = doc.createElement("textarea");
  doc.body.appendChild(textarea);

  let nativeSetterCalled = false;
  const origProto = globalThis.HTMLTextAreaElement;
  globalThis.HTMLTextAreaElement = class FakeTextArea {};
  Object.defineProperty(globalThis.HTMLTextAreaElement.prototype, "value", {
    configurable: true,
    set(v) {
      nativeSetterCalled = true;
      this._value = String(v);
    },
    get() {
      return this._value;
    },
  });

  try {
    writeEditorText(textarea, "Привет [RU_FIO_1]", doc);
    assert.equal(nativeSetterCalled, true);
    assert.equal(readEditorText(textarea), "Привет [RU_FIO_1]");
    assert.deepEqual(textarea.events, ["beforeinput", "input", "change"]);
  } finally {
    globalThis.HTMLTextAreaElement = origProto;
  }
});

test("writeEditorText & readEditorText handle ProseMirror / Quill multi-paragraph editors without innerHTML", () => {
  const doc = createMockDocument();
  const editor = doc.createElement("div", {
    class: "ProseMirror",
    contenteditable: "true",
  });
  doc.body.appendChild(editor);

  writeEditorText(editor, "Строка 1: [EMAIL_1]\n\nСтрока 2: [PHONE_1]", doc);
  assert.equal(editor.childNodes.length, 3);
  assert.equal(editor.childNodes[0].tagName, "P");
  assert.equal(editor.childNodes[1].childNodes[0].tagName, "BR");
  assert.equal(
    readEditorText(editor),
    "Строка 1: [EMAIL_1]\n\nСтрока 2: [PHONE_1]"
  );
  assert.deepEqual(editor.events, ["beforeinput", "input", "change"]);
});

test("resolveRehydrateSource follows selection -> latest assistant reply -> clipboard order", async () => {
  const doc = createMockDocument();
  const msg1 = doc.createElement("div", { "data-message-author-role": "assistant" });
  msg1.textContent = "Первый ответ [EMAIL_1]";
  const msg2 = doc.createElement("div", { "data-message-author-role": "assistant" });
  const md2 = doc.createElement("div", { class: "markdown" });
  md2.textContent = "Последний ответ [RU_FIO_1]";
  msg2.appendChild(md2);
  doc.body.append(msg1, msg2);

  assert.equal(findLatestAssistantReply(doc, "chatgpt.com"), "Последний ответ [RU_FIO_1]");

  // 1) Selection outside host wins over assistant node
  const selectedRes = await resolveRehydrateSource({
    win: {
      getSelection: () => ({
        toString: () => "Выделенный фрагмент [PHONE_1]",
        anchorNode: msg1,
        focusNode: msg1,
      }),
    },
    doc,
    hostname: "chatgpt.com",
    clipboard: { readText: async () => "Буфер [INN_1]" },
  });
  assert.deepEqual(selectedRes, {
    text: "Выделенный фрагмент [PHONE_1]",
    source: "selection",
  });

  // 2) Selection inside PromptVeil host is ignored -> falls back to latest assistant reply
  const pillHost = doc.createElement("div", { id: PROMPTVEIL_HOST_ID });
  const insideNode = doc.createElement("span");
  pillHost.appendChild(insideNode);
  doc.body.appendChild(pillHost);

  const assistantRes = await resolveRehydrateSource({
    win: {
      getSelection: () => ({
        toString: () => "Текст внутри виджета",
        anchorNode: insideNode,
        focusNode: insideNode,
      }),
    },
    doc,
    hostname: "chatgpt.com",
    clipboard: { readText: async () => "Буфер [INN_1]" },
  });
  assert.deepEqual(assistantRes, {
    text: "Последний ответ [RU_FIO_1]",
    source: "assistant",
  });

  // 3) No selection & no assistant node -> clipboard fallback
  const emptyDoc = createMockDocument();
  const clipRes = await resolveRehydrateSource({
    win: { getSelection: () => null },
    doc: emptyDoc,
    hostname: "chatgpt.com",
    clipboard: { readText: async () => "Ответ из буфера [EMAIL_1]" },
  });
  assert.deepEqual(clipRes, {
    text: "Ответ из буфера [EMAIL_1]",
    source: "clipboard",
  });
});
