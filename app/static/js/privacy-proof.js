/**
 * Passive Zero-Retention Proof live telemetry scanner.
 * Inspects DOM, PerformanceResourceTiming, Web Storage, cookies, and protocol
 * with strictly zero outbound network probes and zero forbidden API literals.
 */

import { PRO_LICENSE_STORAGE_KEY } from "./pro-license.js";
import {
  AUDIT_PERSIST_STORAGE_KEY,
  AUDIT_STORAGE_KEY,
  LANG_STORAGE_KEY,
  PROFILES_STORAGE_KEY,
  RULES_STORAGE_KEY,
  THEME_STORAGE_KEY,
} from "./storage.js";

const ALLOWED_LOCAL_STORAGE_KEYS = new Set([
  LANG_STORAGE_KEY,
  RULES_STORAGE_KEY,
  PROFILES_STORAGE_KEY,
  AUDIT_STORAGE_KEY,
  AUDIT_PERSIST_STORAGE_KEY,
  THEME_STORAGE_KEY,
  PRO_LICENSE_STORAGE_KEY,
]);

let cspViolationCount = 0;
let cspListenerAttached = false;

export function attachCspViolationTracker() {
  if (cspListenerAttached || typeof document === "undefined") {
    return;
  }
  cspListenerAttached = true;
  document.addEventListener("securitypolicyviolation", () => {
    cspViolationCount += 1;
  });
}

function getUtf8ByteLength(str) {
  if (!str) return 0;
  try {
    return new TextEncoder().encode(String(str)).length;
  } catch {
    return String(str).length;
  }
}

function isSameOriginOrLocalUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return true;
  const trimmed = rawUrl.trim();
  if (
    trimmed.startsWith("data:") ||
    trimmed.startsWith("blob:") ||
    trimmed.startsWith("#")
  ) {
    return true;
  }
  try {
    const resolved = new URL(trimmed, window.location.origin);
    return resolved.origin === window.location.origin;
  } catch {
    return false;
  }
}

function collectActiveSecrets({ rawText = "", llmReply = "", vault = null } = {}) {
  const needles = [];
  const rawTrimmed = String(rawText || "").trim();
  if (rawTrimmed.length >= 6) {
    needles.push(rawTrimmed);
  }
  const replyTrimmed = String(llmReply || "").trim();
  if (replyTrimmed.length >= 6) {
    needles.push(replyTrimmed);
  }
  if (vault && vault.tokenToEntry instanceof Map) {
    for (const entry of vault.tokenToEntry.values()) {
      const val = typeof entry?.value === "string" ? entry.value.trim() : "";
      if (val.length >= 4) {
        needles.push(val);
      }
    }
  }
  return Array.from(new Set(needles));
}

export function runZeroRetentionSelfTest({
  rawText = "",
  llmReply = "",
  vault = null,
} = {}) {
  // 1. Network & CSP check (passive inspection only)
  let externalResourceCount = 0;
  let apiTextRequestCount = 0;
  if (typeof performance !== "undefined" && typeof performance.getEntriesByType === "function") {
    const entries = performance.getEntriesByType("resource") || [];
    for (const entry of entries) {
      const name = String(entry?.name || "");
      if (!name) continue;
      if (!isSameOriginOrLocalUrl(name)) {
        externalResourceCount += 1;
      }
      if (name.includes("/api/sanitize") || name.includes("/api/rehydrate")) {
        apiTextRequestCount += 1;
      }
    }
  }

  let externalDomElements = 0;
  const domResourceNodes = document.querySelectorAll(
    'script[src], link[href]:not([rel="canonical"]):not([rel="alternate"]), img[src], iframe[src]'
  );
  for (const node of domResourceNodes) {
    const attrVal = node.getAttribute("src") || node.getAttribute("href") || "";
    if (attrVal && !isSameOriginOrLocalUrl(attrVal)) {
      externalDomElements += 1;
    }
  }

  const networkTextRequests = apiTextRequestCount + externalResourceCount;

  // 2. Stored user texts / secrets scan
  let sessionStorageKeys = 0;
  let sessionStorageBytes = 0;
  try {
    if (window.sessionStorage) {
      sessionStorageKeys = window.sessionStorage.length;
      for (let i = 0; i < window.sessionStorage.length; i += 1) {
        const key = window.sessionStorage.key(i) || "";
        const val = window.sessionStorage.getItem(key) || "";
        sessionStorageBytes += getUtf8ByteLength(key) + getUtf8ByteLength(val);
      }
    }
  } catch {
    sessionStorageKeys = 0;
    sessionStorageBytes = 0;
  }

  let cookieCount = 0;
  let cookieBytes = 0;
  try {
    const rawCookie = String(document.cookie || "").trim();
    if (rawCookie.length > 0) {
      cookieCount = rawCookie.split(";").filter((part) => part.trim().length > 0).length;
      cookieBytes = getUtf8ByteLength(rawCookie);
    }
  } catch {
    cookieCount = 0;
    cookieBytes = 0;
  }

  const secretNeedles = collectActiveSecrets({ rawText, llmReply, vault });
  let unknownStorageKeys = 0;
  let leakedSecretBytes = 0;
  let allowedPrefKeysPresent = 0;

  try {
    if (window.localStorage) {
      for (let i = 0; i < window.localStorage.length; i += 1) {
        const key = window.localStorage.key(i) || "";
        const val = window.localStorage.getItem(key) || "";
        if (ALLOWED_LOCAL_STORAGE_KEYS.has(key)) {
          allowedPrefKeysPresent += 1;
        } else {
          unknownStorageKeys += 1;
        }
        for (const needle of secretNeedles) {
          if (key === RULES_STORAGE_KEY || key === PROFILES_STORAGE_KEY) {
            continue;
          }
          if (needle && val.includes(needle)) {
            leakedSecretBytes += getUtf8ByteLength(needle);
          }
        }
      }
    }
  } catch {
    // Storage access blocked -> 0 persisted bytes.
  }

  const storedTextBytes = sessionStorageBytes + cookieBytes + leakedSecretBytes;

  // 3. Trackers & protocol status
  const trackerGlobals = [
    "gtag",
    "ga",
    "ym",
    "_paq",
    "fbq",
    "mixpanel",
    "amplitude",
    "posthog",
  ];
  let trackerCount = 0;
  for (const name of trackerGlobals) {
    if (typeof window[name] !== "undefined") {
      trackerCount += 1;
    }
  }
  trackerCount += externalDomElements;

  const protocol = String(window.location?.protocol || "");
  const hostname = String(window.location?.hostname || "");
  const isHttps = protocol === "https:";
  const isLocalStand =
    hostname === "127.0.0.1" || hostname === "localhost" || hostname === "::1";

  const ramChars = String(rawText || "").length + String(llmReply || "").length;
  const ramEntities = vault && vault.tokenToEntry instanceof Map ? vault.tokenToEntry.size : 0;

  const allPassed =
    networkTextRequests === 0 &&
    cspViolationCount === 0 &&
    storedTextBytes === 0 &&
    unknownStorageKeys === 0 &&
    sessionStorageKeys === 0 &&
    cookieCount === 0 &&
    trackerCount === 0;

  return {
    checkedAt: new Date().toISOString(),
    allPassed,
    network: {
      ok: networkTextRequests === 0 && cspViolationCount === 0,
      textRequests: networkTextRequests,
      externalResourceCount,
      cspViolationCount,
      cspPolicy: "connect-src 'self'",
    },
    storage: {
      ok: storedTextBytes === 0 && unknownStorageKeys === 0 && sessionStorageKeys === 0 && cookieCount === 0,
      storedTextBytes,
      sessionStorageKeys,
      cookieCount,
      unknownStorageKeys,
      allowedPrefKeysPresent,
    },
    trackers: {
      ok: trackerCount === 0,
      trackerCount,
      isHttps,
      isLocalStand,
      isSecureContext: Boolean(window.isSecureContext),
    },
    ram: {
      ramChars,
      ramEntities,
    },
  };
}
