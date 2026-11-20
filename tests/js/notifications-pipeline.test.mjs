import test, { afterEach, beforeEach, describe } from "node:test";
import assert from "node:assert/strict";

import { buildMailtoHref, SITE_CONTACTS } from "../../app/static/js/contacts.js";
import { ensureDictionary, setLang } from "../../app/static/js/i18n.js";
import {
  hideInlineAlert,
  refreshBannersAndAlerts,
  resetNotifications,
  showInlineAlert,
  showStatusBanner,
} from "../../app/static/js/notifications.js";
import { createPipelineController, getUnappliedPresetRules } from "../../app/static/js/pipeline.js";
import { SessionVault } from "../../app/static/js/vault.js";

function createMockElement(id = "") {
  const attrs = new Map();
  const classes = new Set();
  return {
    id,
    value: "",
    textContent: "",
    className: "",
    hidden: false,
    children: [],
    setAttribute(name, val) {
      attrs.set(name, String(val));
    },
    getAttribute(name) {
      return attrs.has(name) ? attrs.get(name) : null;
    },
    hasAttribute(name) {
      return attrs.has(name);
    },
    removeAttribute(name) {
      attrs.delete(name);
    },
    replaceChildren(...nodes) {
      this.children = nodes;
      this.textContent = nodes.map((n) => n.textContent || "").join("");
    },
    classList: {
      toggle(cls, force) {
        if (force) classes.add(cls);
        else classes.delete(cls);
      },
      contains(cls) {
        return classes.has(cls);
      },
    },
  };
}

describe("PromptVeil M4 notifications.js, pipeline.js & contacts.js (Items 25 & 26)", () => {
  let prevDocument;
  let prevWindow;
  let elements;

  beforeEach(async () => {
    await ensureDictionary("ru");
    await ensureDictionary("en");
    prevDocument = globalThis.document;
    prevWindow = globalThis.window;
    elements = new Map([
      ["global-status-banner", createMockElement("global-status-banner")],
      ["rulebook-alert", createMockElement("rulebook-alert")],
      ["raw-prompt-input", createMockElement("raw-prompt-input")],
      ["llm-reply-input", createMockElement("llm-reply-input")],
      ["file-upload-input", createMockElement("file-upload-input")],
      ["copy-sanitized-btn", createMockElement("copy-sanitized-btn")],
      ["mobile-sticky-copy-btn", createMockElement("mobile-sticky-copy-btn")],
      ["copy-restored-btn", createMockElement("copy-restored-btn")],
    ]);
    globalThis.document = {
      getElementById(id) {
        return elements.get(id) || null;
      },
      createElement(tag) {
        return createMockElement(tag);
      },
    };
    resetNotifications();
    setLang("ru");
  });

  afterEach(() => {
    resetNotifications();
    globalThis.document = prevDocument;
    globalThis.window = prevWindow;
    setLang("ru");
  });

  test("notifications show, refresh on language change, and hide alerts/banners", () => {
    let scheduledFn = null;
    globalThis.window = {
      setTimeout(fn) {
        scheduledFn = fn;
        return 1;
      },
      clearTimeout() {},
    };

    showStatusBanner("banner.copied");
    const banner = elements.get("global-status-banner");
    assert.equal(banner.hidden, false);
    assert.equal(banner.getAttribute("role"), "status");
    assert.match(banner.textContent, /скопирован/i);

    showInlineAlert("rulebook-alert", "rulebook.errorEmpty", {}, "error");
    const alert = elements.get("rulebook-alert");
    assert.equal(alert.hidden, false);
    assert.equal(alert.getAttribute("role"), "alert");
    assert.equal(alert.className, "inline-alert inline-alert--error");

    refreshBannersAndAlerts("en");
    assert.match(banner.textContent, /Copied to clipboard/i);
    assert.match(alert.textContent, /Enter a non-empty word/i);

    hideInlineAlert("rulebook-alert");
    assert.equal(alert.hidden, true);
    assert.equal(alert.textContent, "");

    scheduledFn();
    assert.equal(banner.hidden, true);
  });

  test("pipeline controller sanitizes, rehydrates, loads presets, and resets session to zero", () => {
    let workbenchRefreshes = 0;
    const state = {
      rawText: "",
      llmReply: "",
      activePresetId: "",
      lastSanitizeResult: null,
      lastSanitizedInput: "",
      lastRehydrateResult: null,
      mobileVaultExpanded: true,
      showAllCategories: true,
      highlightedToken: "[EMAIL_1]",
      pinnedToken: "[EMAIL_1]",
      rules: [],
      auditLog: [],
      detectUuid: false,
      vault: new SessionVault(),
    };

    const pipeline = createPipelineController({
      state,
      getFileController: () => ({ cancelPendingFileRead() {} }),
      refreshWorkbenchUi: () => {
        workbenchRefreshes += 1;
      },
      refreshDrawersUi: () => {},
      renderPrivacyProofModal: () => {},
    });

    elements.get("raw-prompt-input").value = "Contact alice@example.com";
    const sanitized = pipeline.ensureFreshSanitizedOutput();
    assert.equal(sanitized, "Contact [EMAIL_1]");
    assert.equal(workbenchRefreshes > 0, true);

    const restored = pipeline.runRehydratePipeline("Hello [EMAIL_1]");
    assert.equal(restored.rehydratedText, "Hello alice@example.com");

    pipeline.resetSessionToZero({ silent: true });
    assert.equal(state.rawText, "");
    assert.equal(state.llmReply, "");
    assert.equal(state.vault.tokenToEntry.size, 0);
    assert.equal(elements.get("raw-prompt-input").value, "");
    assert.equal(elements.get("llm-reply-input").value, "");
  });

  test("getUnappliedPresetRules filters duplicates and buildMailtoHref encodes parameters", () => {
    const preset = {
      suggestedRules: [
        { term: "Алексей Смирнов", caseSensitive: false },
        { term: "ООО «Вектор»", caseSensitive: true },
      ],
    };
    const unapplied = getUnappliedPresetRules(preset, [
      { term: "алексей смирнов", caseSensitive: false },
    ]);
    assert.equal(unapplied.length, 1);
    assert.equal(unapplied[0].term, "ООО «Вектор»");

    const href = buildMailtoHref(SITE_CONTACTS.email, "Waitlist Pro", "Line 1\nLine 2");
    assert.equal(
      href,
      "mailto:kilkauciha@gmail.com?subject=Waitlist%20Pro&body=Line%201%0ALine%202"
    );
  });
});
