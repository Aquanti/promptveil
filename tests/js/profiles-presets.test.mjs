import test, { afterEach, beforeEach, describe } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { ensureDictionary, setLang } from "../../app/static/js/i18n.js";
import { detectEntities } from "../../app/static/js/detector.js";
import { refreshBannersAndAlerts, resetNotifications } from "../../app/static/js/notifications.js";
import { createPipelineController } from "../../app/static/js/pipeline.js";
import {
  INDUSTRY_WORD_PACKS,
  PRO_INDUSTRY_WORD_PACKS,
  PROMPT_TEMPLATES,
  getIndustryWordPacks,
  getLocalizedPromptTemplate,
  getLocalizedWordPack,
  getPromptTemplates,
} from "../../app/static/js/presets.js";
import { runZeroRetentionSelfTest } from "../../app/static/js/privacy-proof.js";
import { activateProLicense, loadActiveProLicense } from "../../app/static/js/pro-license.js";
import { DIALOG_IDS, renderRulebookProfiles } from "../../app/static/js/render-drawers.js";
import { renderPromptTemplatesBar } from "../../app/static/js/render-workbench.js";
import {
  DEFAULT_PROFILE_ID,
  MAX_PROFILE_NAME_LENGTH,
  PROFILES_STORAGE_KEY,
  RULES_STORAGE_KEY,
  createProfile,
  deleteProfile,
  exportProfileRulesJson,
  getActiveProfile,
  importProfileRulesJson,
  importRulesJson,
  loadProfilesStore,
  onStorageWarning,
  renameProfile,
  saveRules,
  setActiveProfileRules,
  switchProfile,
} from "../../app/static/js/storage.js";
import { SessionVault } from "../../app/static/js/vault.js";
import { extractRawPublicKeyB64U, signProToken } from "../../scripts/issue-pro-key.mjs";

function createMemoryLocalStorage() {
  const map = new Map();
  return {
    get length() {
      return map.size;
    },
    key(index) {
      return Array.from(map.keys())[index] ?? null;
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

function createThrowingStorage() {
  return {
    length: 0,
    key() {
      return null;
    },
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

function createMockElement(tag = "div", id = "") {
  const attrs = new Map();
  const classes = new Set();
  const listeners = new Map();
  const el = {
    tagName: tag.toUpperCase(),
    id,
    value: "",
    textContent: "",
    className: "",
    hidden: false,
    disabled: false,
    dataset: {},
    children: [],
    setAttribute(name, val) {
      attrs.set(name, String(val));
      if (name === "value") this.value = String(val);
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
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    replaceChildren(...nodes) {
      this.children = nodes;
      this.textContent = nodes.map((n) => n.textContent || "").join("");
    },
    addEventListener(type, fn) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    },
    click() {
      for (const fn of listeners.get("click") || []) {
        fn({ currentTarget: el, target: el });
      }
    },
    querySelector(selector) {
      const tidMatch = selector.match(/^\[data-testid="([^"]+)"\]$/);
      if (tidMatch) {
        return this.children.find((c) => c.getAttribute("data-testid") === tidMatch[1]) || null;
      }
      if (selector === ".prompt-template-title" || selector === ".prompt-template-lock") {
        const cls = selector.slice(1);
        return this.children.find((c) => c.className.split(" ").includes(cls)) || null;
      }
      return null;
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
  return el;
}

describe("PromptVeil M3 Multi-Project Profiles, Pro Word Packs & Prompt Templates (R5)", () => {
  let prevWindow;
  let prevDocument;
  let elements;
  let ls;

  beforeEach(async () => {
    await ensureDictionary("ru");
    await ensureDictionary("en");
    prevWindow = globalThis.window;
    prevDocument = globalThis.document;
    ls = createMemoryLocalStorage();
    globalThis.window = {
      localStorage: ls,
      sessionStorage: createMemoryLocalStorage(),
      location: { pathname: "/", protocol: "https:", hostname: "promptveil.netlify.app", origin: "https://promptveil.netlify.app" },
      isSecureContext: true,
      setTimeout() {
        return 1;
      },
      clearTimeout() {},
    };
    elements = new Map([
      ["global-status-banner", createMockElement("div", "global-status-banner")],
      ["rulebook-alert", createMockElement("div", "rulebook-alert")],
      ["raw-prompt-input", createMockElement("textarea", "raw-prompt-input")],
      ["llm-reply-input", createMockElement("textarea", "llm-reply-input")],
      ["file-upload-input", createMockElement("input", "file-upload-input")],
      ["input-error-banner", createMockElement("div", "input-error-banner")],
      ["file-pro-upgrade-banner", createMockElement("div", "file-pro-upgrade-banner")],
      ["rulebook-pro-upgrade-banner", createMockElement("div", "rulebook-pro-upgrade-banner")],
      ["rulebook-pro-upgrade-text", createMockElement("span", "rulebook-pro-upgrade-text")],
      ["profile-select", createMockElement("select", "profile-select")],
      ["profile-name-input", createMockElement("input", "profile-name-input")],
      ["profile-delete-btn", createMockElement("button", "profile-delete-btn")],
      ["profiles-tier-badge", createMockElement("span", "profiles-tier-badge")],
      ["prompt-templates-tier-badge", createMockElement("span", "prompt-templates-tier-badge")],
      ["prompt-template-preview", createMockElement("div", "prompt-template-preview")],
      ["prompt-template-preview-text", createMockElement("p", "prompt-template-preview-text")],
    ]);
    globalThis.document = {
      cookie: "",
      documentElement: { lang: "ru" },
      getElementById(id) {
        return elements.get(id) || null;
      },
      createElement(tag) {
        return createMockElement(tag);
      },
      createTextNode(text) {
        return { textContent: String(text || "") };
      },
      querySelectorAll() {
        return [];
      },
      querySelector() {
        return null;
      },
    };
    resetNotifications();
    setLang("ru");
  });

  afterEach(() => {
    resetNotifications();
    globalThis.window = prevWindow;
    globalThis.document = prevDocument;
    setLang("ru");
  });

  test("default profile migrates legacy rules, avoids writing empty store, and recovers from corrupted JSON", () => {
    // Empty storage -> in-memory default without writing promptveil_profiles_v1
    const emptyStore = loadProfilesStore("ru");
    assert.equal(emptyStore.activeProfileId, DEFAULT_PROFILE_ID);
    assert.equal(emptyStore.profiles.length, 1);
    assert.equal(emptyStore.profiles[0].name, "Основной");
    assert.equal(emptyStore.profiles[0].isDefault, true);
    assert.equal(ls.getItem(PROFILES_STORAGE_KEY), null);

    // Legacy promptveil_rules_v1 migration
    saveRules([{ term: "LegacyCorp", category: "ORG" }]);
    const migrated = loadProfilesStore("en");
    assert.equal(migrated.profiles[0].name, "Default");
    assert.equal(migrated.profiles[0].rules.length, 1);
    assert.equal(migrated.profiles[0].rules[0].term, "LegacyCorp");

    // Corruption recovery
    for (const bad of ["{broken", "[null, {}]", JSON.stringify({ version: 1, profiles: [null, {}] })]) {
      ls.setItem(PROFILES_STORAGE_KEY, bad);
      const recovered = loadProfilesStore("ru");
      assert.equal(recovered.activeProfileId, DEFAULT_PROFILE_ID);
      assert.equal(recovered.profiles.length, 1);
      assert.equal(recovered.profiles[0].name, "Основной");
      assert.equal(recovered.profiles[0].rules[0].term, "LegacyCorp");
      assert.doesNotThrow(() => JSON.parse(ls.getItem(PROFILES_STORAGE_KEY)));
    }
  });

  test("Free tier blocks profile creation, rename, switch, and delete without mutating localStorage", () => {
    const store = loadProfilesStore("ru");
    const cRes = createProfile(store, "Клиент А", { isPro: false, lang: "ru" });
    assert.equal(cRes.ok, false);
    assert.equal(cRes.error, "pro_required");
    assert.equal(ls.getItem(PROFILES_STORAGE_KEY), null);

    const rRes = renameProfile(store, DEFAULT_PROFILE_ID, "NewName", { isPro: false });
    assert.equal(rRes.ok, false);
    assert.equal(rRes.error, "pro_required");
    assert.equal(ls.getItem(PROFILES_STORAGE_KEY), null);

    const sRes = switchProfile(store, "prof_other", { isPro: false });
    assert.equal(sRes.ok, false);
    assert.equal(sRes.error, "pro_required");

    const dRes = deleteProfile(store, DEFAULT_PROFILE_ID, { isPro: false });
    assert.equal(dRes.ok, false);
    assert.equal(dRes.error, "pro_required");
    assert.equal(ls.getItem(PROFILES_STORAGE_KEY), null);
  });

  test("Pro CRUD validates empty, duplicate, reserved, over-long, default-delete, QuotaExceeded, and XSS names safely", () => {
    let store = loadProfilesStore("ru");

    for (const bad of ["", "   ", "Основной", "default", "DEFAULT"]) {
      const res = createProfile(store, bad, { isPro: true, lang: "ru" });
      assert.equal(res.ok, false);
    }

    const longName = "X".repeat(MAX_PROFILE_NAME_LENGTH + 25);
    const createdA = createProfile(store, longName, { isPro: true, lang: "ru" });
    assert.equal(createdA.ok, true);
    assert.equal(createdA.profile.name.length, MAX_PROFILE_NAME_LENGTH);
    store = createdA.store;

    const dup = createProfile(store, longName.slice(0, MAX_PROFILE_NAME_LENGTH).toLowerCase(), {
      isPro: true,
      lang: "ru",
    });
    assert.equal(dup.ok, false);
    assert.equal(dup.error, "duplicate");

    const createdB = createProfile(store, "NDA Альфа", { isPro: true, lang: "ru" });
    assert.equal(createdB.ok, true);
    store = createdB.store;

    const renDefault = renameProfile(store, DEFAULT_PROFILE_ID, "Other", { isPro: true });
    assert.equal(renDefault.ok, false);
    assert.equal(renDefault.error, "default_protected");

    const renB = renameProfile(store, createdB.profile.id, "NDA Бета", { isPro: true });
    assert.equal(renB.ok, true);
    assert.equal(renB.profile.name, "NDA Бета");
    store = renB.store;

    const delDefault = deleteProfile(store, DEFAULT_PROFILE_ID, { isPro: true });
    assert.equal(delDefault.ok, false);
    assert.equal(delDefault.error, "default_protected");

    // XSS profile name stored as plain string and rendered via textContent only
    const xss = "<img src=x onerror=window.__xssProf=1>";
    const createdXss = createProfile(store, xss, { isPro: true, lang: "ru" });
    assert.equal(createdXss.ok, true);
    store = createdXss.store;
    renderRulebookProfiles(
      {
        selectEl: elements.get("profile-select"),
        deleteBtnEl: elements.get("profile-delete-btn"),
        tierBadgeEl: elements.get("profiles-tier-badge"),
      },
      { profiles: store.profiles, activeProfileId: store.activeProfileId, isPro: true, lang: "ru" }
    );
    const opts = elements.get("profile-select").children;
    assert.equal(opts.at(-1).textContent, xss);
    assert.equal(elements.get("profile-delete-btn").disabled, false);

    // Delete returns active profile to default
    const delXss = deleteProfile(store, createdXss.profile.id, { isPro: true });
    assert.equal(delXss.ok, true);
    assert.equal(delXss.store.activeProfileId, DEFAULT_PROFILE_ID);

    // QuotaExceededError fallback
    globalThis.window.localStorage = createThrowingStorage();
    const warnings = [];
    const unsub = onStorageWarning((d) => warnings.push(d));
    try {
      const qRes = setActiveProfileRules(delXss.store, [{ term: "FallbackTerm", category: "SECRET" }]);
      assert.equal(qRes.rules.length, 1);
      assert.equal(warnings.length, 2);
      assert.equal(warnings[0].key, PROFILES_STORAGE_KEY);
      assert.equal(warnings[1].key, RULES_STORAGE_KEY);
    } finally {
      unsub();
    }
  });

  test("per-profile JSON export/import and pipeline.handleRulesImported keep profiles isolated", () => {
    let store = loadProfilesStore("ru");
    store = setActiveProfileRules(store, [{ term: "DefaultOnlyRule", category: "CUSTOM" }]).store;
    const pA = createProfile(store, "Клиент А", { isPro: true, lang: "ru" });
    store = pA.store;
    store = setActiveProfileRules(store, [{ term: "IsolatedClientToken", category: "SECRET" }]).store;

    const exportedJson = exportProfileRulesJson(getActiveProfile(store));
    const parsedExport = JSON.parse(exportedJson);
    assert.equal(parsedExport.schema, "promptveil.profile.v1");
    assert.equal(parsedExport.rules.length, 1);
    assert.equal(parsedExport.rules[0].term, "IsolatedClientToken");

    const pB = createProfile(store, "Клиент Б", { isPro: true, lang: "ru" });
    store = pB.store;
    const importedDirect = importProfileRulesJson(store, exportedJson, pB.profile.id);
    assert.equal(importedDirect.addedCount, 1);
    assert.equal(
      importedDirect.store.profiles.find((p) => p.id === DEFAULT_PROFILE_ID).rules.length,
      1
    );
    assert.equal(
      importedDirect.store.profiles.find((p) => p.id === DEFAULT_PROFILE_ID).rules[0].term,
      "DefaultOnlyRule"
    );

    // Simulate clipboard.js calling importRulesJson(json, getRules()) + pipeline.handleRulesImported
    const pC = createProfile(importedDirect.store, "Клиент В", { isPro: true, lang: "ru" });
    const state = {
      rawText: "",
      llmReply: "",
      activePresetId: "",
      activeTemplateId: "",
      previewTemplateId: "",
      lastSanitizeResult: null,
      lastSanitizedInput: "",
      lastRehydrateResult: null,
      rules: [],
      profilesStore: pC.store,
      proLicense: { valid: true, isPro: true, tier: "pro" },
      auditLog: [],
      detectUuid: false,
      sensitivity: "normal",
      batchItems: [],
      vault: new SessionVault(),
    };
    const pipeline = createPipelineController({
      state,
      getFileController: () => ({ cancelPendingFileRead() {} }),
      refreshWorkbenchUi: () => {},
      refreshDrawersUi: () => {},
      renderPrivacyProofModal: () => {},
    });
    const rawImported = importRulesJson(exportedJson, state.rules);
    pipeline.handleRulesImported(rawImported);
    assert.equal(state.rules.length, 1);
    assert.equal(state.rules[0].term, "IsolatedClientToken");
    const defaultAfter = state.profilesStore.profiles.find((p) => p.id === DEFAULT_PROFILE_ID);
    assert.equal(defaultAfter.rules.length, 1);
    assert.equal(defaultAfter.rules[0].term, "DefaultOnlyRule");
    assert.equal(JSON.parse(ls.getItem(RULES_STORAGE_KEY))[0].term, "DefaultOnlyRule");
  });

  test("Pro industry word packs & prompt templates enforce Free vs Pro gating with ephemeral Ed25519 key", async () => {
    assert.deepEqual(
      INDUSTRY_WORD_PACKS.map((p) => p.id),
      ["legal", "hr", "medical", "accounting"]
    );
    assert.deepEqual(
      PRO_INDUSTRY_WORD_PACKS.map((p) => p.id),
      ["corporate_ma", "devsecops", "banking_fintech", "crossborder_nda"]
    );
    assert.equal(getIndustryWordPacks("ru").length, 8);
    assert.equal(getIndustryWordPacks("ru", { includePro: false }).length, 4);

    for (const pack of [...INDUSTRY_WORD_PACKS, ...PRO_INDUSTRY_WORD_PACKS]) {
      for (const lang of ["ru", "en"]) {
        const loc = getLocalizedWordPack(pack.id, lang);
        assert.ok(loc && loc.title && loc.terms.length === 6);
        assert.equal(loc.isPro, pack.tier === "pro");
        for (const term of loc.terms) {
          assert.match(term, /^[\p{L}\p{N}].*[\p{L}\p{N}]$/u);
        }
      }
    }

    assert.deepEqual(
      PROMPT_TEMPLATES.map((t) => t.id),
      ["contract_review", "nda_redline", "code_security_review"]
    );
    for (const lang of ["ru", "en"]) {
      const tpls = getPromptTemplates(lang);
      assert.equal(tpls.length, 3);
      for (const tpl of tpls) {
        assert.ok(tpl.title.length > 0);
        assert.ok(tpl.description.length > 0);
        assert.ok(tpl.text.length > 40);
        assert.equal(/https?:\/\//i.test(tpl.text), false);
      }
    }

    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pubB64u = extractRawPublicKeyB64U(publicKey);
    const token = signProToken(
      {
        tier: "pro",
        keyId: "PV-TEST-M3",
        label: "M3 Test",
        issuedAt: "2026-11-21T00:00:00Z",
      },
      privateKey
    );

    const state = {
      rawText: "",
      llmReply: "",
      activePresetId: "",
      activeTemplateId: "",
      previewTemplateId: "",
      lastSanitizeResult: null,
      lastSanitizedInput: "",
      lastRehydrateResult: null,
      rules: [],
      profilesStore: loadProfilesStore("ru"),
      proLicense: { valid: false, isPro: false, tier: "free" },
      auditLog: [],
      detectUuid: false,
      sensitivity: "normal",
      batchItems: [],
      vault: new SessionVault(),
    };
    let workbenchRefreshes = 0;
    const pipeline = createPipelineController({
      state,
      getFileController: () => ({ cancelPendingFileRead() {} }),
      refreshWorkbenchUi: () => {
        workbenchRefreshes += 1;
      },
      refreshDrawersUi: () => {},
      renderPrivacyProofModal: () => {},
    });

    // Free gating: Pro word pack & template do not write storage or insert rawText
    assert.equal(pipeline.applyIndustryWordPack("devsecops"), 0);
    assert.equal(state.rules.length, 0);
    assert.equal(ls.getItem(PROFILES_STORAGE_KEY), null);
    assert.equal(elements.get("rulebook-pro-upgrade-banner").hidden, false);

    pipeline.selectPromptTemplate("contract_review");
    assert.equal(state.rawText, "");
    assert.equal(state.previewTemplateId, "contract_review");
    assert.equal(ls.getItem(PROFILES_STORAGE_KEY), null);

    // Build mock templates container for renderPromptTemplatesBar preview check
    const tplBar = createMockElement("section", "prompt-templates-bar");
    for (const tpl of PROMPT_TEMPLATES) {
      const btn = createMockElement("button");
      btn.className = "prompt-template-btn";
      btn.setAttribute("data-testid", `prompt-template-${tpl.id}`);
      btn.setAttribute("data-template-id", tpl.id);
      const titleSpan = createMockElement("span");
      titleSpan.className = "prompt-template-title";
      const lockSpan = createMockElement("span");
      lockSpan.className = "pro-lock-pill prompt-template-lock";
      btn.appendChild(titleSpan);
      btn.appendChild(lockSpan);
      tplBar.appendChild(btn);
    }
    renderPromptTemplatesBar(tplBar, getPromptTemplates("ru"), {
      isPro: false,
      previewTemplateId: state.previewTemplateId,
      lang: "ru",
      onSelectTemplate: pipeline.selectPromptTemplate,
    });
    assert.equal(elements.get("prompt-template-preview").hidden, false);
    assert.match(elements.get("prompt-template-preview-text").textContent, /Аудит договора/);

    // Unlock Pro with ephemeral Ed25519 key
    const act = await activateProLicense(token, { publicKeyB64U: pubB64u });
    assert.equal(act.valid, true);
    state.proLicense = await loadActiveProLicense({ publicKeyB64U: pubB64u });
    assert.equal(state.proLicense.isPro, true);

    const added = pipeline.applyIndustryWordPack("devsecops");
    assert.equal(added, 6);
    assert.equal(state.rules.length, 6);
    const firstTerm = state.rules[0].term;
    state.rawText = `Internal note covers ${firstTerm} today.`;
    const packSanitized = pipeline.runSanitizePipeline(false);
    assert.match(packSanitized.sanitizedText, /\[CUSTOM_1\]/);
    assert.equal(packSanitized.sanitizedText.includes(firstTerm), false);

    pipeline.selectPromptTemplate("nda_redline");
    assert.equal(state.activeTemplateId, "nda_redline");
    assert.equal(state.rawText, getLocalizedPromptTemplate("nda_redline", "ru").text);
    assert.ok(workbenchRefreshes > 0);
    assert.equal(
      (ls.getItem(PROFILES_STORAGE_KEY) || "").includes(state.rawText.slice(0, 24)),
      false
    );
  });

  test("privacy-proof allows promptveil_profiles_v1 and reports 0 leaked bytes for active custom rule terms", () => {
    let store = loadProfilesStore("ru");
    const created = createProfile(store, "СекретПроект", { isPro: true, lang: "ru" });
    store = created.store;
    store = setActiveProfileRules(store, [{ term: "SecretRuleKeyword", category: "CUSTOM" }]).store;

    const vault = new SessionVault();
    const rawText = "Sensitive prompt text for proof.user@example.com and SecretRuleKeyword";
    const res = vault.sanitize(rawText, getActiveProfile(store).rules);
    assert.match(res.sanitizedText, /\[EMAIL_1\]/);
    assert.match(res.sanitizedText, /\[CUSTOM_1\]/);

    const proof = runZeroRetentionSelfTest({ rawText, llmReply: "", vault });
    assert.equal(proof.storage.unknownStorageKeys, 0);
    assert.equal(proof.storage.storedTextBytes, 0);
    assert.equal(proof.allPassed, true);
  });

  test("F-01/F-02/F-04/F-05: digit-bearing tokens, dynamic pack alert retranslation, aligned PROMPT_TEMPLATES, and DIALOG_IDS", () => {
    // F-01: SessionVault.rehydrate & detectEntities handle digit-bearing prefixes and long bracketed tokens
    const vault = new SessionVault();
    const reh = vault.rehydrate("Check [IPV4_1], [SHA256_1], and [EMAIL_1]");
    assert.deepEqual(reh.unresolvedTokens, ["[IPV4_1]", "[SHA256_1]", "[EMAIL_1]"]);

    const envProbe = detectEntities("AUTH_HOST=[IPV4_1]\nAPI_TOKEN=[API_KEY_1]\nPORT=8080", [], {
      sensitivityMode: "normal",
    });
    assert.equal(envProbe.some((e) => e.category === "ENV_SECRET"), false);

    const longNorm = detectEntities("Token [POSSIBLE_CARD_1234567] here", [], {
      sensitivityMode: "normal",
    });
    assert.equal(longNorm.length, 0);

    const longStrict = detectEntities(
      "Check [IPV4_ADDRESS_0123456789] and [EMAIL_ADDRESS_0123456789]",
      [],
      { sensitivityMode: "strict" }
    );
    assert.equal(longStrict.length, 0);

    // F-04: PROMPT_TEMPLATES use canonical detector prefixes
    assert.match(getLocalizedPromptTemplate("code_security_review", "ru").text, /\[IP_1\]/);
    assert.match(getLocalizedPromptTemplate("code_security_review", "en").text, /\[IP_1\]/);
    assert.match(getLocalizedPromptTemplate("contract_review", "ru").text, /\[INN_1\].*\[BANK_ACC_1\]/);
    assert.match(getLocalizedPromptTemplate("contract_review", "en").text, /\[FIO_1\]/);

    // F-05: DIALOG_IDS includes modal-pro-license & modal-pro-downloads
    assert.equal(DIALOG_IDS.includes("modal-pro-license"), true);
    assert.equal(DIALOG_IDS.includes("modal-pro-downloads"), true);

    // F-02: Rulebook pack upgrade banner & inline alert retranslate dynamically on RU -> EN switch
    const state = {
      rawText: "",
      llmReply: "",
      activePresetId: "",
      activeTemplateId: "",
      previewTemplateId: "",
      lastSanitizeResult: null,
      lastSanitizedInput: "",
      lastRehydrateResult: null,
      rules: [],
      profilesStore: loadProfilesStore("ru"),
      proLicense: { valid: false, isPro: false, tier: "free" },
      auditLog: [],
      detectUuid: false,
      sensitivity: "normal",
      batchItems: [],
      vault: new SessionVault(),
    };
    const pipeline = createPipelineController({
      state,
      getFileController: () => ({ cancelPendingFileRead() {} }),
      refreshWorkbenchUi: () => {},
      refreshDrawersUi: () => {},
      renderPrivacyProofModal: () => {},
    });

    setLang("ru");
    pipeline.applyIndustryWordPack("banking_fintech");
    assert.match(elements.get("rulebook-alert").textContent, /Банки и финтех/);
    assert.match(elements.get("rulebook-pro-upgrade-text").textContent, /Банки и финтех/);

    setLang("en");
    refreshBannersAndAlerts("en");
    renderRulebookProfiles(
      {
        selectEl: elements.get("profile-select"),
        deleteBtnEl: elements.get("profile-delete-btn"),
        tierBadgeEl: elements.get("profiles-tier-badge"),
        upgradeBannerEl: elements.get("rulebook-pro-upgrade-banner"),
        upgradeTextEl: elements.get("rulebook-pro-upgrade-text"),
      },
      { profiles: state.profilesStore.profiles, activeProfileId: state.profilesStore.activeProfileId, isPro: false, lang: "en" }
    );
    assert.match(elements.get("rulebook-alert").textContent, /Banking & FinTech/);
    assert.equal(elements.get("rulebook-alert").textContent.includes("Банки и финтех"), false);
    assert.match(elements.get("rulebook-pro-upgrade-text").textContent, /Banking & FinTech/);
    assert.equal(elements.get("rulebook-pro-upgrade-text").textContent.includes("Банки и финтех"), false);
  });
});
