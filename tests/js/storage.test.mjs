import test, { afterEach, beforeEach, describe } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  LANG_STORAGE_KEY,
  RULES_STORAGE_KEY,
  THEME_STORAGE_KEY,
  appendAuditReceipt,
  clearAuditLog,
  importRulesJson,
  loadAuditLog,
  loadLanguage,
  loadRules,
  loadThemePreference,
  onStorageWarning,
  saveLanguage,
  saveRules,
  saveThemePreference,
  setAuditPersistenceEnabled,
  sha256Hex,
} from "../../app/static/js/storage.js";

function createThrowingStorage() {
  return {
    getItem() {
      return null;
    },
    setItem() {
      const err = new Error("QuotaExceededError");
      err.name = "QuotaExceededError";
      throw err;
    },
    removeItem() {},
  };
}

function createMemoryLocalStorage() {
  const map = new Map();
  return {
    getItem(k) {
      return map.has(k) ? map.get(k) : null;
    },
    setItem(k, v) {
      map.set(String(k), String(v));
    },
    removeItem(k) {
      map.delete(String(k));
    },
  };
}

describe("PromptVeil Storage, SHA-256 Fallback & Audit Queue (Item 26)", () => {
  let prevWindow;
  let prevCryptoDescriptor;

  beforeEach(() => {
    prevWindow = globalThis.window;
    prevCryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
    clearAuditLog();
  });

  afterEach(() => {
    clearAuditLog();
    globalThis.window = { localStorage: createMemoryLocalStorage(), location: { pathname: "/" } };
    saveRules([]);
    saveThemePreference("light");
    saveLanguage("ru");
    globalThis.window = prevWindow;
    if (prevCryptoDescriptor) {
      Object.defineProperty(globalThis, "crypto", prevCryptoDescriptor);
    }
  });

  test("sha256Hex matches Node crypto even when crypto.subtle rejects", async () => {
    const sample = "PromptVeil Тест SHA-256 🚀";
    const expected = createHash("sha256").update(sample, "utf8").digest("hex");

    assert.equal(await sha256Hex(sample), expected);

    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: {
        subtle: {
          async digest() {
            throw new Error("Simulated non-secure context");
          },
        },
      },
    });
    assert.equal(await sha256Hex(sample), expected);
    assert.equal(await sha256Hex(""), createHash("sha256").update("", "utf8").digest("hex"));
  });

  test("QuotaExceededError triggers memoryFallbackStore and onStorageWarning listener", () => {
    globalThis.window = { localStorage: createThrowingStorage(), location: { pathname: "/" } };
    const warnings = [];
    const unsubscribe = onStorageWarning((detail) => warnings.push(detail));

    try {
      const saved = saveRules([{ id: "r1", term: "Acme", category: "ORG" }]);
      assert.equal(saved.length, 1);
      assert.equal(warnings.length, 1);
      assert.equal(warnings[0].key, RULES_STORAGE_KEY);
      assert.equal(loadRules()[0].term, "Acme");

      assert.equal(saveThemePreference("dark"), "dark");
      assert.equal(loadThemePreference(), "dark");
      assert.equal(saveLanguage("en"), "en");
      assert.equal(loadLanguage(), "en");
    } finally {
      unsubscribe();
    }
  });

  test("loadRules and importRulesJson deduplicate terms and ensure unique IDs", () => {
    const ls = createMemoryLocalStorage();
    globalThis.window = { localStorage: ls };

    ls.setItem(
      RULES_STORAGE_KEY,
      JSON.stringify([
        { id: "dup", term: "Alpha", category: "ORG", caseSensitive: false },
        { id: "dup", term: "alpha", category: "ORG", caseSensitive: false },
        { id: "dup", term: "Beta", category: "ORG", caseSensitive: false },
      ])
    );
    const loaded = loadRules();
    assert.equal(loaded.length, 2);
    assert.notEqual(loaded[0].id, loaded[1].id);

    const imported = importRulesJson(
      JSON.stringify({ rules: [{ term: "Alpha" }, { term: "Gamma", category: "SECRET" }] }),
      loaded
    );
    assert.equal(imported.addedCount, 1);
    assert.equal(imported.skippedCount, 1);
    assert.equal(imported.rules.length, 3);
  });

  test("clearAuditLog aborts in-flight appendAuditReceipt via auditEpoch", async () => {
    globalThis.window = { localStorage: createMemoryLocalStorage() };
    setAuditPersistenceEnabled(false);

    const p1 = appendAuditReceipt({
      action: "SANITIZE",
      inputText: "secret one",
      outputText: "[EMAIL_1]",
      entities: [{ category: "EMAIL", token: "[EMAIL_1]", value: "secret one" }],
      countsByCategory: { EMAIL: 1 },
    });
    clearAuditLog();
    const res1 = await p1;
    assert.equal(res1.aborted, true);
    assert.deepEqual(loadAuditLog(), []);

    const res2 = await appendAuditReceipt({
      action: "REHYDRATE",
      inputText: "[EMAIL_1]",
      outputText: "a@b.co",
      replacedCount: 1,
    });
    assert.equal(res2.aborted, false);
    assert.equal(res2.auditLog.length, 1);
    assert.equal(res2.auditLog[0].action, "REHYDRATE");
  });

  test("theme and language preference helpers normalize invalid values safely", () => {
    const ls = createMemoryLocalStorage();
    globalThis.window = { localStorage: ls, location: { pathname: "/" } };

    ls.setItem(THEME_STORAGE_KEY, "invalid");
    assert.equal(loadThemePreference(), null);
    assert.equal(saveThemePreference("DARK"), "dark");
    assert.equal(loadThemePreference(), "dark");

    ls.setItem(LANG_STORAGE_KEY, "fr");
    assert.equal(loadLanguage(), "ru");
  });
});
