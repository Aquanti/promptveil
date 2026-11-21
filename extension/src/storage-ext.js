/**
 * PromptVeil Extension Storage Wrapper (chrome.storage.local only).
 * Stores ONLY extension preferences, custom rule terms, and the Pro license token.
 * NEVER stores user prompt text, AI replies, or SessionVault mappings.
 * NEVER uses web page storage for cross-context state.
 */

import { CATEGORY_MAP } from "../../app/static/js/detector.js";
import { createRuleId, makeRuleDedupKey, normalizeRule } from "../../app/static/js/storage.js";

export const EXT_SETTINGS_STORAGE_KEY = "promptveil_ext_settings_v1";
export const EXT_PRO_LICENSE_STORAGE_KEY = "promptveil_pro_license_v1";
export const FREE_CUSTOM_RULE_LIMIT = 5;

export const DEFAULT_EXT_SETTINGS = Object.freeze({
  lang: "ru",
  theme: "light",
  overlayVisible: true,
  sensitivity: "normal",
  detectUuid: false,
  disabledCategories: [],
  customRules: [],
});

const memoryFallbackMap = new Map();

export function getChromeStorageLocal() {
  return globalThis.chrome?.storage?.local || null;
}

function storageGet(storageArea, keys) {
  const keyList = Array.isArray(keys) ? keys : [keys];
  if (!storageArea || typeof storageArea.get !== "function") {
    const out = {};
    for (const key of keyList) {
      if (memoryFallbackMap.has(key)) {
        out[key] = memoryFallbackMap.get(key);
      }
    }
    return Promise.resolve(out);
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      const err = globalThis.chrome?.runtime?.lastError;
      if (err) {
        reject(new Error(err.message || "chrome.storage.local.get failed"));
      } else {
        resolve(result && typeof result === "object" ? result : {});
      }
    };
    try {
      const maybePromise = storageArea.get(keyList, finish);
      if (maybePromise && typeof maybePromise.then === "function") {
        maybePromise.then(finish, (err) => {
          if (!settled) {
            settled = true;
            reject(err);
          }
        });
      }
    } catch (err) {
      if (!settled) {
        settled = true;
        reject(err);
      }
    }
  });
}

function storageSet(storageArea, items) {
  if (!storageArea || typeof storageArea.set !== "function") {
    for (const [key, value] of Object.entries(items)) {
      memoryFallbackMap.set(key, value);
    }
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      const err = globalThis.chrome?.runtime?.lastError;
      if (err) {
        reject(new Error(err.message || "chrome.storage.local.set failed"));
      } else {
        resolve();
      }
    };
    try {
      const maybePromise = storageArea.set(items, finish);
      if (maybePromise && typeof maybePromise.then === "function") {
        maybePromise.then(finish, (err) => {
          if (!settled) {
            settled = true;
            reject(err);
          }
        });
      }
    } catch (err) {
      if (!settled) {
        settled = true;
        reject(err);
      }
    }
  });
}

function storageRemove(storageArea, key) {
  if (!storageArea || typeof storageArea.remove !== "function") {
    memoryFallbackMap.delete(key);
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      const err = globalThis.chrome?.runtime?.lastError;
      if (err) {
        reject(new Error(err.message || "chrome.storage.local.remove failed"));
      } else {
        resolve();
      }
    };
    try {
      const maybePromise = storageArea.remove(key, finish);
      if (maybePromise && typeof maybePromise.then === "function") {
        maybePromise.then(finish, (err) => {
          if (!settled) {
            settled = true;
            reject(err);
          }
        });
      }
    } catch (err) {
      if (!settled) {
        settled = true;
        reject(err);
      }
    }
  });
}

export function normalizeExtSettings(raw) {
  const src = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const lang = src.lang === "en" ? "en" : "ru";
  const theme = src.theme === "dark" ? "dark" : "light";
  const overlayVisible = src.overlayVisible !== false;
  const sensitivity = src.sensitivity === "strict" ? "strict" : "normal";
  const detectUuid = Boolean(src.detectUuid) || sensitivity === "strict";

  const disabledSet = new Set();
  if (Array.isArray(src.disabledCategories)) {
    for (const cat of src.disabledCategories) {
      if (
        typeof cat === "string" &&
        Object.prototype.hasOwnProperty.call(CATEGORY_MAP, cat) &&
        cat !== "CUSTOM"
      ) {
        disabledSet.add(cat);
      }
    }
  }

  const customRules = [];
  const seenKeys = new Set();
  const seenIds = new Set();
  if (Array.isArray(src.customRules)) {
    for (const item of src.customRules) {
      const rule = normalizeRule(item);
      if (!rule) {
        continue;
      }
      const dedupKey = makeRuleDedupKey(rule);
      if (seenKeys.has(dedupKey)) {
        continue;
      }
      seenKeys.add(dedupKey);
      let id = rule.id;
      while (seenIds.has(id)) {
        id = createRuleId();
      }
      seenIds.add(id);
      customRules.push(id === rule.id ? rule : { ...rule, id });
    }
  }

  return {
    lang,
    theme,
    overlayVisible,
    sensitivity,
    detectUuid,
    disabledCategories: Array.from(disabledSet),
    customRules,
  };
}

export async function loadExtSettings(storageArea = getChromeStorageLocal()) {
  const result = await storageGet(storageArea, EXT_SETTINGS_STORAGE_KEY);
  return normalizeExtSettings(result[EXT_SETTINGS_STORAGE_KEY]);
}

export async function saveExtSettings(settings, storageArea = getChromeStorageLocal()) {
  const normalized = normalizeExtSettings(settings);
  await storageSet(storageArea, { [EXT_SETTINGS_STORAGE_KEY]: normalized });
  return normalized;
}

export async function loadExtProLicenseToken(storageArea = getChromeStorageLocal()) {
  const result = await storageGet(storageArea, EXT_PRO_LICENSE_STORAGE_KEY);
  const raw = result[EXT_PRO_LICENSE_STORAGE_KEY];
  return typeof raw === "string" ? raw.trim() : "";
}

export async function saveExtProLicenseToken(token, storageArea = getChromeStorageLocal()) {
  const trimmed = typeof token === "string" ? token.trim() : "";
  await storageSet(storageArea, { [EXT_PRO_LICENSE_STORAGE_KEY]: trimmed });
  return trimmed;
}

export async function clearExtProLicenseToken(storageArea = getChromeStorageLocal()) {
  await storageRemove(storageArea, EXT_PRO_LICENSE_STORAGE_KEY);
}

export function getEffectiveMaskingConfig(settings, licenseState) {
  const normalized = normalizeExtSettings(settings);
  const isPro = Boolean(licenseState?.isPro);
  const isOwner = Boolean(licenseState?.isOwner);
  const sensitivity = normalized.sensitivity;
  const detectUuid = Boolean(normalized.detectUuid) || sensitivity === "strict";
  const disabledCategories = isPro ? normalized.disabledCategories : [];
  const customRules = isPro
    ? normalized.customRules
    : normalized.customRules.slice(0, FREE_CUSTOM_RULE_LIMIT);
  const cappedRuleCount = isPro
    ? 0
    : Math.max(0, normalized.customRules.length - FREE_CUSTOM_RULE_LIMIT);

  return {
    isPro,
    isOwner,
    sensitivity,
    detectUuid,
    disabledCategories,
    customRules,
    cappedRuleCount,
  };
}

export function subscribeExtStorageChanges(
  handler,
  storageEvents = globalThis.chrome?.storage?.onChanged
) {
  if (typeof handler !== "function" || !storageEvents || typeof storageEvents.addListener !== "function") {
    return () => {};
  }
  const listener = (changes, areaName) => {
    if (areaName && areaName !== "local") {
      return;
    }
    if (!changes || typeof changes !== "object") {
      return;
    }
    const settingsChanged = Object.prototype.hasOwnProperty.call(
      changes,
      EXT_SETTINGS_STORAGE_KEY
    );
    const licenseChanged = Object.prototype.hasOwnProperty.call(
      changes,
      EXT_PRO_LICENSE_STORAGE_KEY
    );
    if (settingsChanged || licenseChanged) {
      handler({
        settingsChanged,
        licenseChanged,
        settingsValue: settingsChanged ? changes[EXT_SETTINGS_STORAGE_KEY].newValue : undefined,
        licenseValue: licenseChanged ? changes[EXT_PRO_LICENSE_STORAGE_KEY].newValue : undefined,
      });
    }
  };
  storageEvents.addListener(listener);
  return () => {
    if (typeof storageEvents.removeListener === "function") {
      storageEvents.removeListener(listener);
    }
  };
}
