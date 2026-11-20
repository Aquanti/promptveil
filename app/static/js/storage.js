/**
 * PromptVeil Per-User Browser Storage, Portable Rulebook Export/Import,
 * and Web Crypto SHA-256 Hash-Only Audit Receipts.
 * Zero raw PII is persisted in audit receipts.
 */

export const RULES_STORAGE_KEY = "promptveil_rules_v1";
export const AUDIT_STORAGE_KEY = "promptveil_audit_v1";
export const AUDIT_PERSIST_STORAGE_KEY = "promptveil_audit_persist_v1";
export const LANG_STORAGE_KEY = "promptveil_lang_v1";
export const THEME_STORAGE_KEY = "promptveil_theme_v1";
export const MAX_AUDIT_ENTRIES = 200;

const DEFAULT_LANGUAGE = "ru";
const VALID_LANGUAGES = new Set(["ru", "en"]);
const VALID_THEMES = new Set(["light", "dark"]);

const memoryFallbackStore = new Map();
const storageWarningListeners = new Set();

export function onStorageWarning(listener) {
  if (typeof listener !== "function") {
    return () => {};
  }
  storageWarningListeners.add(listener);
  return () => {
    storageWarningListeners.delete(listener);
  };
}

function notifyStorageWarning(err, key) {
  const detail = {
    key,
    name: err?.name || "StorageError",
    message: err?.message || "Browser localStorage write failed; using session memory fallback.",
  };
  for (const listener of storageWarningListeners) {
    try {
      listener(detail);
    } catch {
      // Ignore listener errors.
    }
  }
}

function readStorageItem(key) {
  if (memoryFallbackStore.has(key)) {
    return memoryFallbackStore.get(key) ?? null;
  }
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      return window.localStorage.getItem(key);
    }
  } catch {
    // Fallback below when storage access is blocked.
  }
  return null;
}

function writeStorageItem(key, value) {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      window.localStorage.setItem(key, value);
      memoryFallbackStore.delete(key);
      return true;
    }
  } catch (err) {
    // Fallback below when storage access is blocked or quota exceeded.
    memoryFallbackStore.set(key, value);
    notifyStorageWarning(err, key);
    return false;
  }
  memoryFallbackStore.set(key, value);
  return false;
}

function removeStorageItem(key) {
  memoryFallbackStore.delete(key);
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      window.localStorage.removeItem(key);
    }
  } catch {
    // Ignore storage removal errors in restricted environments.
  }
}

export function createRuleId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `rule_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

export function normalizeRule(raw) {
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const candidateTerm =
    typeof raw.term === "string"
      ? raw.term
      : typeof raw.phrase === "string"
        ? raw.phrase
        : "";
  const term = candidateTerm.trim();
  if (term.length === 0 || term.length > 500) {
    return null;
  }
  const category =
    typeof raw.category === "string" && raw.category.trim().length > 0
      ? raw.category.trim().toUpperCase()
      : "CUSTOM";

  return {
    id:
      typeof raw.id === "string" && raw.id.trim().length > 0
        ? raw.id.trim()
        : createRuleId(),
    term,
    category,
    caseSensitive: Boolean(raw.caseSensitive),
    enabled: raw.enabled !== false,
  };
}

export function makeRuleDedupKey(rule) {
  const normalizedTerm = rule.caseSensitive
    ? rule.term.trim()
    : rule.term.trim().toLowerCase();
  return `${normalizedTerm}\u0000${Boolean(rule.caseSensitive)}`;
}

function ensureUniqueRuleId(rule, seenIds) {
  let id = rule.id;
  while (seenIds.has(id)) {
    id = createRuleId();
  }
  seenIds.add(id);
  return id === rule.id ? rule : { ...rule, id };
}

export function loadRules() {
  const raw = readStorageItem(RULES_STORAGE_KEY);
  if (!raw) {
    return [];
  }
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    const rules = [];
    const seen = new Set();
    const seenIds = new Set();
    for (const item of parsed) {
      const normalized = normalizeRule(item);
      if (!normalized) {
        continue;
      }
      const key = makeRuleDedupKey(normalized);
      if (!seen.has(key)) {
        seen.add(key);
        rules.push(ensureUniqueRuleId(normalized, seenIds));
      }
    }
    return rules;
  } catch {
    return [];
  }
}

export function saveRules(rules) {
  const normalized = [];
  const seen = new Set();
  const seenIds = new Set();
  if (Array.isArray(rules)) {
    for (const item of rules) {
      const rule = normalizeRule(item);
      if (!rule) {
        continue;
      }
      const key = makeRuleDedupKey(rule);
      if (!seen.has(key)) {
        seen.add(key);
        normalized.push(ensureUniqueRuleId(rule, seenIds));
      }
    }
  }
  writeStorageItem(RULES_STORAGE_KEY, JSON.stringify(normalized));
  return normalized;
}

export function exportRulesJson(rules) {
  const normalized = Array.isArray(rules)
    ? rules.map(normalizeRule).filter(Boolean)
    : [];
  return JSON.stringify(
    {
      schema: "promptveil.rules.v1",
      exportedAt: new Date().toISOString(),
      rules: normalized,
    },
    null,
    2
  );
}

export function importRulesJson(jsonStr, existingRules = []) {
  if (typeof jsonStr !== "string" || jsonStr.trim().length === 0) {
    throw new Error("Rules JSON file is empty.");
  }

  let parsed;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    throw new Error("Invalid JSON syntax in rules import file.");
  }

  let rawList;
  if (Array.isArray(parsed)) {
    rawList = parsed;
  } else if (
    parsed &&
    typeof parsed === "object" &&
    Array.isArray(parsed.rules)
  ) {
    rawList = parsed.rules;
  } else {
    throw new Error(
      "Invalid rules JSON schema: Rules JSON must be an array or an object containing a 'rules' array."
    );
  }

  const merged = [];
  const seen = new Set();
  const seenIds = new Set();
  for (const existing of existingRules) {
    const normalized = normalizeRule(existing);
    if (normalized) {
      const key = makeRuleDedupKey(normalized);
      if (!seen.has(key)) {
        seen.add(key);
        merged.push(ensureUniqueRuleId(normalized, seenIds));
      }
    }
  }

  let addedCount = 0;
  let skippedCount = 0;

  for (const item of rawList) {
    const normalized = normalizeRule(item);
    if (!normalized) {
      skippedCount += 1;
      continue;
    }
    const key = makeRuleDedupKey(normalized);
    if (seen.has(key)) {
      skippedCount += 1;
      continue;
    }
    seen.add(key);
    merged.push(ensureUniqueRuleId(normalized, seenIds));
    addedCount += 1;
  }

  const saved = saveRules(merged);
  return {
    rules: saved,
    addedCount,
    skippedCount,
  };
}

// Pure-JS FIPS 180-4 SHA-256 fallback for non-secure contexts where crypto.subtle is absent.
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256FallbackHex(bytes) {
  const bitLen = bytes.length * 8;
  const paddedLen = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  const hi = Math.floor(bitLen / 0x100000000);
  const lo = bitLen >>> 0;
  view.setUint32(paddedLen - 8, hi, false);
  view.setUint32(paddedLen - 4, lo, false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i += 1) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i += 1) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map((val) => val.toString(16).padStart(8, "0"))
    .join("");
}

export async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(String(text ?? ""));
  if (
    typeof crypto !== "undefined" &&
    crypto.subtle &&
    typeof crypto.subtle.digest === "function"
  ) {
    try {
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    } catch {
      return sha256FallbackHex(bytes);
    }
  }
  return sha256FallbackHex(bytes);
}

let auditEpoch = 0;
let auditWriteQueue = Promise.resolve();
let auditMemoryLog = [];

function parseStoredAuditLog(raw) {
  if (!raw) {
    return [];
  }
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .filter(
        (item) =>
          item &&
          typeof item === "object" &&
          !Array.isArray(item) &&
          typeof item.action === "string"
      )
      .slice(0, MAX_AUDIT_ENTRIES);
  } catch {
    return [];
  }
}

export function isAuditPersistenceEnabled() {
  return readStorageItem(AUDIT_PERSIST_STORAGE_KEY) === "1";
}

export function purgeUnoptedAuditStorage() {
  if (!isAuditPersistenceEnabled()) {
    removeStorageItem(AUDIT_STORAGE_KEY);
  }
}

export function setAuditPersistenceEnabled(enabled, currentLog = null) {
  if (enabled) {
    writeStorageItem(AUDIT_PERSIST_STORAGE_KEY, "1");
    const source = Array.isArray(currentLog) ? currentLog : auditMemoryLog;
    auditMemoryLog = source
      .filter(
        (item) =>
          item &&
          typeof item === "object" &&
          !Array.isArray(item) &&
          typeof item.action === "string"
      )
      .slice(0, MAX_AUDIT_ENTRIES);
    writeStorageItem(AUDIT_STORAGE_KEY, JSON.stringify(auditMemoryLog));
    return true;
  }
  removeStorageItem(AUDIT_PERSIST_STORAGE_KEY);
  removeStorageItem(AUDIT_STORAGE_KEY);
  return false;
}

export function loadAuditLog() {
  if (isAuditPersistenceEnabled()) {
    auditMemoryLog = parseStoredAuditLog(readStorageItem(AUDIT_STORAGE_KEY));
  }
  return [...auditMemoryLog];
}

export function appendAuditReceipt({
  action = "SANITIZE",
  inputText = "",
  outputText = "",
  entities = [],
  replacedCount = 0,
  countsByCategory = {},
}) {
  const startEpoch = auditEpoch;
  const run = async () => {
    if (startEpoch !== auditEpoch) {
      return { receipt: null, auditLog: loadAuditLog(), aborted: true, storagePersisted: false };
    }

    const inputSha256 = await sha256Hex(inputText);
    const outputSha256 = await sha256Hex(outputText);
    if (startEpoch !== auditEpoch) {
      return { receipt: null, auditLog: loadAuditLog(), aborted: true, storagePersisted: false };
    }

    const uniqueKeys = new Set();
    const entityDigestPrefixes = [];
    for (const entity of entities) {
      if (!entity || !entity.category || typeof entity.value !== "string") {
        continue;
      }
      const key = `${entity.category}\u0000${entity.value}`;
      if (uniqueKeys.has(key)) {
        continue;
      }
      uniqueKeys.add(key);
      const hash = await sha256Hex(key);
      if (startEpoch !== auditEpoch) {
        return { receipt: null, auditLog: loadAuditLog(), aborted: true, storagePersisted: false };
      }
      entityDigestPrefixes.push({
        category: entity.category,
        token: entity.token || "",
        sha256Prefix: hash.slice(0, 8),
      });
    }

    const compactCounts = Object.fromEntries(
      Object.entries(countsByCategory || {}).filter(([, count]) => Number(count) > 0)
    );

    const receipt = {
      id: createRuleId(),
      timestamp: new Date().toISOString(),
      action: String(action).toUpperCase(),
      inputSha256,
      outputSha256,
      entityCount: entities.length,
      replacedCount: Number(replacedCount) || 0,
      countsByCategory: compactCounts,
      entityDigestPrefixes,
    };

    if (startEpoch !== auditEpoch) {
      return { receipt: null, auditLog: loadAuditLog(), aborted: true, storagePersisted: false };
    }

    const persist = isAuditPersistenceEnabled();
    const base = persist
      ? parseStoredAuditLog(readStorageItem(AUDIT_STORAGE_KEY))
      : auditMemoryLog;
    auditMemoryLog = [receipt, ...base].slice(0, MAX_AUDIT_ENTRIES);
    const storagePersisted = persist
      ? writeStorageItem(AUDIT_STORAGE_KEY, JSON.stringify(auditMemoryLog))
      : false;
    return { receipt, auditLog: [...auditMemoryLog], aborted: false, storagePersisted };
  };

  const next = auditWriteQueue.then(run, run);
  auditWriteQueue = next.catch(() => {});
  return next;
}

export function exportAuditJson(log) {
  const receipts = Array.isArray(log) ? log : [];
  return JSON.stringify(
    {
      schema: "promptveil.audit.v1",
      exportedAt: new Date().toISOString(),
      zeroPiiGuaranteed: true,
      receipts,
    },
    null,
    2
  );
}

export function clearAuditLog() {
  auditEpoch += 1;
  auditMemoryLog = [];
  removeStorageItem(AUDIT_STORAGE_KEY);
  return [];
}

function normalizeLanguage(lang) {
  if (typeof lang !== "string") {
    return DEFAULT_LANGUAGE;
  }
  const normalized = lang.trim().toLowerCase();
  return VALID_LANGUAGES.has(normalized) ? normalized : DEFAULT_LANGUAGE;
}

export function loadLanguage() {
  return normalizeLanguage(readStorageItem(LANG_STORAGE_KEY));
}

export function saveLanguage(lang) {
  const normalized = normalizeLanguage(lang);
  writeStorageItem(LANG_STORAGE_KEY, normalized);
  return normalized;
}

export function loadThemePreference() {
  const raw = readStorageItem(THEME_STORAGE_KEY);
  if (typeof raw === "string") {
    const clean = raw.trim().toLowerCase();
    if (VALID_THEMES.has(clean)) {
      return clean;
    }
  }
  return null;
}

export function saveThemePreference(theme) {
  const clean = typeof theme === "string" ? theme.trim().toLowerCase() : "";
  const normalized = VALID_THEMES.has(clean) ? clean : "light";
  writeStorageItem(THEME_STORAGE_KEY, normalized);
  return normalized;
}
