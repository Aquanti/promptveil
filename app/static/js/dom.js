/**
 * Strict XSS-safe DOM helpers, clipboard, local file download, and drawer focus trap.
 * Uses createElement, textContent, and replaceChildren exclusively.
 */

const copyFeedbackTimers = new WeakMap();

export function getEl(id) {
  return document.getElementById(id);
}

export function createEl(tag, className = "", text = null, attrs = null) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== null && text !== undefined) {
    node.textContent = String(text);
  }
  if (attrs && typeof attrs === "object") {
    for (const [key, val] of Object.entries(attrs)) {
      if (val === null || val === undefined || val === false) continue;
      const lowerKey = key.toLowerCase();
      if (lowerKey.startsWith("on") || lowerKey === "style") continue;
      node.setAttribute(key, val === true ? "" : String(val));
    }
  }
  return node;
}

export function clearEl(node) {
  if (node) {
    node.replaceChildren();
  }
}

export async function copyTextToClipboard(text) {
  if (!text) return false;
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fallback below for restricted headless contexts.
    }
  }
  const helper = document.createElement("textarea");
  helper.value = text;
  helper.setAttribute("readonly", "");
  helper.className = "sr-only";
  document.body.appendChild(helper);
  helper.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  document.body.removeChild(helper);
  return ok;
}

export async function readTextFromClipboard() {
  if (!navigator.clipboard || typeof navigator.clipboard.readText !== "function") {
    return { ok: false, text: "", reason: "unsupported" };
  }
  try {
    const text = await navigator.clipboard.readText();
    return { ok: true, text: String(text || ""), reason: "" };
  } catch {
    return { ok: false, text: "", reason: "blocked" };
  }
}

export function showCopyFeedback(
  buttonEl,
  feedbackText,
  defaultTextOrGetter,
  durationMs = 2000
) {
  if (!buttonEl || buttonEl.disabled) return;
  const existingTimer = copyFeedbackTimers.get(buttonEl);
  if (existingTimer) {
    window.clearTimeout(existingTimer);
  }
  buttonEl.textContent = feedbackText;
  buttonEl.setAttribute("data-copied", "true");
  const timer = window.setTimeout(() => {
    copyFeedbackTimers.delete(buttonEl);
    buttonEl.removeAttribute("data-copied");
    const resolvedDefault =
      typeof defaultTextOrGetter === "function"
        ? defaultTextOrGetter()
        : defaultTextOrGetter;
    if (resolvedDefault) {
      buttonEl.textContent = resolvedDefault;
    }
  }, durationMs);
  copyFeedbackTimers.set(buttonEl, timer);
}

export function clearCopyFeedback(buttonEl, defaultTextOrGetter = null) {
  if (!buttonEl) return;
  const existingTimer = copyFeedbackTimers.get(buttonEl);
  if (existingTimer) {
    window.clearTimeout(existingTimer);
    copyFeedbackTimers.delete(buttonEl);
  }
  buttonEl.removeAttribute("data-copied");
  const resolvedDefault =
    typeof defaultTextOrGetter === "function"
      ? defaultTextOrGetter()
      : defaultTextOrGetter;
  if (resolvedDefault) {
    buttonEl.textContent = resolvedDefault;
  }
}

export function downloadTextFile(filename, content, mimeType = "text/plain;charset=utf-8") {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function getVisibleFocusableElements(container) {
  if (!container) return [];
  const selector =
    'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  return Array.from(container.querySelectorAll(selector)).filter((el) => {
    if (el.hidden || el.closest("[hidden]")) return false;
    const style = window.getComputedStyle(el);
    return style.display !== "none" && style.visibility !== "hidden";
  });
}

export function handleDrawerKeydown(event, openDrawerEl, onClose) {
  if (!openDrawerEl || openDrawerEl.hidden) {
    return false;
  }
  if (event.key === "Escape") {
    event.preventDefault();
    if (typeof onClose === "function") onClose();
    return true;
  }
  if (event.key === "Tab") {
    const focusables = getVisibleFocusableElements(openDrawerEl);
    if (focusables.length === 0) {
      event.preventDefault();
      return true;
    }
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (event.shiftKey) {
      if (document.activeElement === first || !openDrawerEl.contains(document.activeElement)) {
        event.preventDefault();
        last.focus();
      }
    } else if (document.activeElement === last || !openDrawerEl.contains(document.activeElement)) {
      event.preventDefault();
      first.focus();
    }
    return true;
  }
  return false;
}
