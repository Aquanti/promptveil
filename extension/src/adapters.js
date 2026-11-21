/**
 * PromptVeil AI Chat Host Adapters & Framework-Safe Editor I/O.
 * Uses window.location.hostname strictly (ZERO external scheme literals).
 */

export const PROMPTVEIL_HOST_ID = "promptveil-ext-host";

export const AI_HOST_ADAPTERS = Object.freeze([
  Object.freeze({
    id: "chatgpt",
    hostname: "chatgpt.com",
    labelByLang: Object.freeze({ ru: "ChatGPT", en: "ChatGPT" }),
    promptSelectors: Object.freeze([
      "#prompt-textarea",
      'div.ProseMirror[contenteditable="true"]',
      "textarea[data-id]",
      "textarea",
    ]),
    assistantSelectors: Object.freeze([
      '[data-message-author-role="assistant"] .markdown',
      '[data-message-author-role="assistant"]',
    ]),
  }),
  Object.freeze({
    id: "claude",
    hostname: "claude.ai",
    labelByLang: Object.freeze({ ru: "Claude", en: "Claude" }),
    promptSelectors: Object.freeze([
      'div.ProseMirror[contenteditable="true"]',
      '[data-testid="chat-input"]',
      'fieldset [contenteditable="true"]',
      'div[contenteditable="true"][role="textbox"]',
    ]),
    assistantSelectors: Object.freeze([
      '[data-testid="assistant-message"]',
      ".font-claude-response",
      ".font-claude-message",
    ]),
  }),
  Object.freeze({
    id: "gemini",
    hostname: "gemini.google.com",
    labelByLang: Object.freeze({ ru: "Gemini", en: "Gemini" }),
    promptSelectors: Object.freeze([
      'rich-textarea .ql-editor[contenteditable="true"]',
      '.ql-editor[contenteditable="true"]',
      'rich-textarea [contenteditable="true"]',
      "textarea",
    ]),
    assistantSelectors: Object.freeze([
      "message-content .markdown",
      "model-response message-content",
      "model-response",
    ]),
  }),
  Object.freeze({
    id: "deepseek",
    hostname: "chat.deepseek.com",
    labelByLang: Object.freeze({ ru: "DeepSeek", en: "DeepSeek" }),
    promptSelectors: Object.freeze([
      "textarea#chat-input",
      "textarea",
      'div[contenteditable="true"][role="textbox"]',
    ]),
    assistantSelectors: Object.freeze([
      ".ds-markdown",
      '[data-role="assistant"]',
    ]),
  }),
  Object.freeze({
    id: "gigachat",
    hostname: "giga.chat",
    labelByLang: Object.freeze({ ru: "GigaChat", en: "GigaChat" }),
    promptSelectors: Object.freeze([
      "textarea",
      'div[contenteditable="true"][role="textbox"]',
      'div[contenteditable="true"]',
    ]),
    assistantSelectors: Object.freeze([
      '[data-testid*="assistant"]',
      '[class*="assistant"]',
      '[class*="Assistant"]',
      ".markdown-body",
    ]),
  }),
  Object.freeze({
    id: "alice",
    hostname: "alice.yandex.ru",
    labelByLang: Object.freeze({ ru: "Алиса / YandexGPT", en: "Alice / YandexGPT" }),
    promptSelectors: Object.freeze([
      "textarea",
      'div[contenteditable="true"][role="textbox"]',
      'div[contenteditable="true"]',
    ]),
    assistantSelectors: Object.freeze([
      '[data-testid*="assistant"]',
      '[class*="assistant"]',
      '[class*="Assistant"]',
      ".markdown-body",
    ]),
  }),
]);

const GENERIC_PROMPT_SELECTORS = Object.freeze([
  "textarea",
  '.ProseMirror[contenteditable="true"]',
  '.ql-editor[contenteditable="true"]',
  '[contenteditable="true"]',
  '[contenteditable="plaintext-only"]',
  '[role="textbox"]',
]);

export function detectSupportedHost(hostname = globalThis.location?.hostname || "") {
  const normalized = String(hostname || "").trim().toLowerCase();
  if (!normalized) {
    return null;
  }
  return AI_HOST_ADAPTERS.find((entry) => entry.hostname === normalized) || null;
}

export function getHostLabel(hostAdapter, lang = "ru") {
  if (!hostAdapter) {
    return "";
  }
  const normLang = lang === "en" ? "en" : "ru";
  return hostAdapter.labelByLang[normLang] || hostAdapter.labelByLang.ru || hostAdapter.hostname;
}

export function isInsideHost(el, hostId = PROMPTVEIL_HOST_ID) {
  let cursor = el;
  while (cursor) {
    if (cursor.id === hostId) {
      return true;
    }
    if (cursor.parentNode) {
      cursor = cursor.parentNode;
    } else if (cursor.host) {
      cursor = cursor.host;
    } else {
      cursor = null;
    }
  }
  return false;
}

export function getDeepActiveElement(doc = globalThis.document) {
  let active = doc?.activeElement || null;
  const seen = new Set();
  while (active && active.shadowRoot && active.shadowRoot.activeElement) {
    if (seen.has(active)) {
      break;
    }
    seen.add(active);
    active = active.shadowRoot.activeElement;
  }
  return active;
}

function getElementTagName(el) {
  return String(el?.tagName || "").toUpperCase();
}

export function isEditableElement(el) {
  if (!el) {
    return false;
  }
  const tag = getElementTagName(el);
  if (tag === "TEXTAREA") {
    return !el.disabled && !el.readOnly;
  }
  if (tag === "INPUT") {
    const type = String(el.type || "text").toLowerCase();
    return (type === "text" || type === "search" || type === "url") && !el.disabled && !el.readOnly;
  }
  const ce = el.getAttribute?.("contenteditable");
  if (ce === "true" || ce === "" || ce === "plaintext-only" || el.isContentEditable === true) {
    return true;
  }
  if (el.classList?.contains("ProseMirror") || el.classList?.contains("ql-editor")) {
    return ce !== "false";
  }
  return false;
}

export function isElementVisible(el, hostId = PROMPTVEIL_HOST_ID) {
  if (!el || isInsideHost(el, hostId)) {
    return false;
  }
  if (el.hidden === true || el.getAttribute?.("aria-hidden") === "true") {
    return false;
  }
  if (el.disabled === true || el.readOnly === true) {
    return false;
  }
  const win = el.ownerDocument?.defaultView || globalThis.window;
  if (win && typeof win.getComputedStyle === "function") {
    try {
      const style = win.getComputedStyle(el);
      if (style && (style.display === "none" || style.visibility === "hidden")) {
        return false;
      }
    } catch {
      // Ignore computed style failures in minimal DOM environments.
    }
  }
  const rootRect = el.ownerDocument?.documentElement?.getBoundingClientRect?.();
  if (rootRect && (rootRect.width > 0 || rootRect.height > 0) && typeof el.getBoundingClientRect === "function") {
    const rect = el.getBoundingClientRect();
    if (rect && rect.width <= 0 && rect.height <= 0) {
      return false;
    }
  }
  return true;
}

export function findPromptBox(
  doc = globalThis.document,
  hostname = globalThis.location?.hostname || ""
) {
  if (!doc || typeof doc.querySelectorAll !== "function") {
    return null;
  }
  const active = getDeepActiveElement(doc);
  if (active && isEditableElement(active) && isElementVisible(active)) {
    return active;
  }

  const hostAdapter = detectSupportedHost(hostname);
  const selectors = hostAdapter
    ? [...hostAdapter.promptSelectors, ...GENERIC_PROMPT_SELECTORS]
    : [...GENERIC_PROMPT_SELECTORS];

  const seen = new Set();
  for (const selector of selectors) {
    if (seen.has(selector)) {
      continue;
    }
    seen.add(selector);
    let candidates;
    try {
      candidates = doc.querySelectorAll(selector);
    } catch {
      continue;
    }
    for (const candidate of candidates) {
      if (isEditableElement(candidate) && isElementVisible(candidate)) {
        return candidate;
      }
    }
  }
  return null;
}

function stripZeroWidth(text) {
  return String(text || "").replace(/\u200B/g, "");
}

const BLOCK_TAGS = new Set(["P", "DIV", "LI", "BLOCKQUOTE", "PRE"]);

function hasBlockElementChildren(el) {
  if (!el?.childNodes) {
    return false;
  }
  for (const child of Array.from(el.childNodes)) {
    if (child.nodeType === 1 && BLOCK_TAGS.has(getElementTagName(child))) {
      return true;
    }
  }
  return false;
}

function extractBlockText(node) {
  if (!node) {
    return "";
  }
  if (node.nodeType === 3) {
    return stripZeroWidth(node.nodeValue || "");
  }
  const tag = getElementTagName(node);
  if (tag === "BR") {
    return "\n";
  }
  const children = node.childNodes ? Array.from(node.childNodes) : [];
  if (children.length === 0) {
    return stripZeroWidth(node.textContent || "");
  }
  const isBlockTag = BLOCK_TAGS.has(tag);
  const nonEmptyChildren = children.filter(
    (child) => !(child.nodeType === 3 && stripZeroWidth(child.nodeValue || "") === "")
  );
  if (
    isBlockTag &&
    nonEmptyChildren.length === 1 &&
    nonEmptyChildren[0].nodeType === 1 &&
    getElementTagName(nonEmptyChildren[0]) === "BR"
  ) {
    return "\n";
  }
  const parts = children.map((child) => extractBlockText(child));
  const joined = parts.join("");
  if (!isBlockTag) {
    return joined;
  }
  const hasBlockChild = children.some(
    (child) => child.nodeType === 1 && BLOCK_TAGS.has(getElementTagName(child))
  );
  if (hasBlockChild && joined.endsWith("\n")) {
    return joined;
  }
  return `${joined}\n`;
}

export function normalizeEditorText(text) {
  return stripZeroWidth(text).replace(/\r\n/g, "\n").replace(/\n+$/, "");
}

export function readEditorText(el) {
  if (!el) {
    return "";
  }
  const tag = getElementTagName(el);
  if (tag === "TEXTAREA" || tag === "INPUT") {
    return typeof el.value === "string" ? el.value : "";
  }
  if (el.childNodes && el.childNodes.length > 0 && hasBlockElementChildren(el)) {
    const raw = Array.from(el.childNodes, (child) => extractBlockText(child)).join("");
    const cleaned = stripZeroWidth(raw).replace(/\r\n/g, "\n");
    return cleaned === "\n" ? "" : cleaned.replace(/\n$/, "");
  }
  if (typeof el.innerText === "string" && el.innerText.length > 0) {
    const cleaned = stripZeroWidth(el.innerText).replace(/\r\n/g, "\n");
    return cleaned === "\n" ? "" : cleaned.replace(/\n$/, "");
  }
  if (el.childNodes && el.childNodes.length > 0) {
    const raw = Array.from(el.childNodes, (child) => extractBlockText(child)).join("");
    const cleaned = stripZeroWidth(raw).replace(/\r\n/g, "\n");
    return cleaned === "\n" ? "" : cleaned.replace(/\n$/, "");
  }
  return stripZeroWidth(el.textContent || "");
}

function dispatchInputEvents(el, nextText, doc) {
  const view = doc?.defaultView || globalThis;
  const InputEventCtor = view?.InputEvent || globalThis.InputEvent;
  const EventCtor = view?.Event || globalThis.Event;

  if (typeof InputEventCtor === "function") {
    try {
      el.dispatchEvent(
        new InputEventCtor("beforeinput", {
          bubbles: true,
          cancelable: true,
          inputType: "insertReplacementText",
          data: nextText,
        })
      );
    } catch {
      // Some environments reject InputEvent options.
    }
    try {
      el.dispatchEvent(
        new InputEventCtor("input", {
          bubbles: true,
          cancelable: true,
          inputType: "insertReplacementText",
          data: nextText,
        })
      );
    } catch {
      if (typeof EventCtor === "function") {
        el.dispatchEvent(new EventCtor("input", { bubbles: true }));
      }
    }
  } else if (typeof EventCtor === "function") {
    el.dispatchEvent(new EventCtor("beforeinput", { bubbles: true, cancelable: true }));
    el.dispatchEvent(new EventCtor("input", { bubbles: true }));
  }

  if (typeof EventCtor === "function") {
    el.dispatchEvent(new EventCtor("change", { bubbles: true }));
  }
}

function writeParagraphChildren(el, nextText, doc) {
  const lines = String(nextText ?? "").replace(/\r\n/g, "\n").split("\n");
  const usesParagraphs =
    el.classList?.contains("ProseMirror") ||
    el.classList?.contains("ql-editor") ||
    Boolean(el.querySelector?.("p"));

  if (usesParagraphs) {
    const nodes = lines.map((line) => {
      const p = doc.createElement("p");
      if (line.length > 0) {
        p.textContent = line;
      } else {
        p.appendChild(doc.createElement("br"));
      }
      return p;
    });
    if (typeof el.replaceChildren === "function") {
      el.replaceChildren(...nodes);
    } else {
      while (el.firstChild) el.removeChild(el.firstChild);
      for (const node of nodes) el.appendChild(node);
    }
    return;
  }

  const nodes = [];
  lines.forEach((line, idx) => {
    if (idx > 0) {
      nodes.push(doc.createElement("br"));
    }
    nodes.push(doc.createTextNode(line));
  });
  if (typeof el.replaceChildren === "function") {
    el.replaceChildren(...nodes);
  } else {
    while (el.firstChild) el.removeChild(el.firstChild);
    for (const node of nodes) el.appendChild(node);
  }
}

export function writeEditorText(el, nextText, doc = el?.ownerDocument || globalThis.document) {
  if (!el) {
    return false;
  }
  const valueStr = String(nextText ?? "");
  const tag = getElementTagName(el);

  if (tag === "TEXTAREA" || tag === "INPUT") {
    const view = doc?.defaultView || globalThis;
    const proto =
      tag === "TEXTAREA"
        ? view?.HTMLTextAreaElement?.prototype || globalThis.HTMLTextAreaElement?.prototype
        : view?.HTMLInputElement?.prototype || globalThis.HTMLInputElement?.prototype;
    const descriptor = proto ? Object.getOwnPropertyDescriptor(proto, "value") : null;
    if (descriptor && typeof descriptor.set === "function") {
      try {
        descriptor.set.call(el, valueStr);
      } catch {
        el.value = valueStr;
      }
    } else {
      el.value = valueStr;
    }
    dispatchInputEvents(el, valueStr, doc);
    return true;
  }

  if (typeof el.focus === "function") {
    try {
      el.focus({ preventScroll: true });
    } catch {
      el.focus();
    }
  }

  let execWorked = false;
  const win = doc?.defaultView || globalThis.window;
  if (
    doc &&
    typeof doc.execCommand === "function" &&
    typeof doc.createRange === "function" &&
    win &&
    typeof win.getSelection === "function"
  ) {
    try {
      const range = doc.createRange();
      range.selectNodeContents(el);
      const sel = win.getSelection();
      if (sel) {
        sel.removeAllRanges();
        sel.addRange(range);
      }
      const inserted = doc.execCommand("insertText", false, valueStr);
      if (inserted && normalizeEditorText(readEditorText(el)) === normalizeEditorText(valueStr)) {
        execWorked = true;
      }
    } catch {
      execWorked = false;
    }
  }

  if (execWorked) {
    const view = doc?.defaultView || globalThis;
    const EventCtor = view?.Event || globalThis.Event;
    if (typeof EventCtor === "function") {
      el.dispatchEvent(new EventCtor("change", { bubbles: true }));
    }
  } else if (doc) {
    writeParagraphChildren(el, valueStr, doc);
    dispatchInputEvents(el, valueStr, doc);
  }
  return true;
}

export function getSelectionOutsideHost(
  win = globalThis.window,
  hostId = PROMPTVEIL_HOST_ID
) {
  if (!win || typeof win.getSelection !== "function") {
    return "";
  }
  const selection = win.getSelection();
  if (!selection) {
    return "";
  }
  const text = String(selection.toString() || "");
  if (text.trim().length === 0) {
    return "";
  }
  if (isInsideHost(selection.anchorNode, hostId) || isInsideHost(selection.focusNode, hostId)) {
    return "";
  }
  return text;
}

export function findLatestAssistantReply(
  doc = globalThis.document,
  hostname = globalThis.location?.hostname || ""
) {
  if (!doc || typeof doc.querySelectorAll !== "function") {
    return "";
  }
  const hostAdapter = detectSupportedHost(hostname);
  const selectors = hostAdapter
    ? hostAdapter.assistantSelectors
    : ['[data-message-author-role="assistant"]', '[data-testid*="assistant"]', ".markdown"];

  try {
    const combined = Array.from(doc.querySelectorAll(selectors.join(", "))).filter((node) =>
      isElementVisible(node)
    );
    for (let i = combined.length - 1; i >= 0; i -= 1) {
      const text = readEditorText(combined[i]).trim();
      if (text.length > 0) {
        return text;
      }
    }
  } catch {
    // Fallback to iterating selectors individually if combined selector fails.
  }

  for (const selector of selectors) {
    let nodes;
    try {
      nodes = doc.querySelectorAll(selector);
    } catch {
      continue;
    }
    const list = Array.from(nodes).filter((node) => isElementVisible(node));
    for (let i = list.length - 1; i >= 0; i -= 1) {
      const text = readEditorText(list[i]).trim();
      if (text.length > 0) {
        return text;
      }
    }
  }
  return "";
}

export async function resolveRehydrateSource({
  win = globalThis.window,
  doc = globalThis.document,
  hostname = globalThis.location?.hostname || "",
  clipboard = globalThis.navigator?.clipboard,
} = {}) {
  const selected = getSelectionOutsideHost(win);
  if (selected.trim().length > 0) {
    return { text: selected, source: "selection" };
  }

  const assistantReply = findLatestAssistantReply(doc, hostname);
  if (assistantReply.trim().length > 0) {
    return { text: assistantReply, source: "assistant" };
  }

  if (clipboard && typeof clipboard.readText === "function") {
    try {
      const clipText = await clipboard.readText();
      if (typeof clipText === "string" && clipText.trim().length > 0) {
        return { text: clipText, source: "clipboard" };
      }
    } catch {
      // Clipboard read can be denied when not user-triggered or unfocused.
    }
  }

  return { text: "", source: "none" };
}
