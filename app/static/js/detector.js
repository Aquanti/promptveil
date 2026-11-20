/**
 * PromptVeil 100% Client-Side Deterministic PII & Secret Detection Engine.
 * Runs exclusively in browser RAM with zero server egress.
 */

export const CATEGORIES = Object.freeze([
  { category: "API_KEY", tokenPrefix: "API_KEY", priority: 100, label: "API Key" },
  { category: "JWT", tokenPrefix: "JWT", priority: 95, label: "JWT Token" },
  { category: "CREDIT_CARD", tokenPrefix: "CARD", priority: 90, label: "Credit Card" },
  { category: "IBAN", tokenPrefix: "IBAN", priority: 92, label: "IBAN" },
  { category: "SSN", tokenPrefix: "SSN", priority: 85, label: "US SSN" },
  { category: "ENV_SECRET", tokenPrefix: "ENV_SECRET", priority: 82, label: ".env Secret" },
  { category: "CUSTOM", tokenPrefix: "CUSTOM", priority: 80, label: "Custom Rule" },
  { category: "EMAIL", tokenPrefix: "EMAIL", priority: 75, label: "Email" },
  { category: "PHONE", tokenPrefix: "PHONE", priority: 70, label: "Phone" },
  { category: "IPV4", tokenPrefix: "IP", priority: 60, label: "IPv4" },
  { category: "HIGH_ENTROPY", tokenPrefix: "SECRET", priority: 50, label: "High Entropy" },
]);

export const CATEGORY_MAP = Object.freeze(
  Object.fromEntries(CATEGORIES.map((item) => [item.category, item]))
);

/**
 * Escape only ECMAScript RegExp SyntaxCharacters so `new RegExp(..., "giu")`
 * never throws `SyntaxError: Invalid escape` in strict Unicode mode.
 */
export function escapeRegExp(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const IBAN_LENGTHS = Object.freeze({
  AL: 28, AD: 24, AT: 20, AZ: 28, BH: 22, BY: 28, BE: 16, BA: 20,
  BR: 29, BG: 22, CR: 22, HR: 21, CY: 28, CZ: 24, DK: 18, DO: 28,
  EG: 29, SV: 28, EE: 20, FO: 18, FI: 18, FR: 27, GE: 22, DE: 22,
  GI: 23, GR: 27, GL: 18, GT: 28, HU: 28, IS: 26, IQ: 23, IE: 22,
  IL: 23, IT: 27, JO: 30, KZ: 20, XK: 20, KW: 30, LV: 21, LB: 28,
  LY: 25, LI: 21, LT: 20, LU: 20, MK: 19, MT: 31, MR: 27, MU: 30,
  MC: 27, MD: 24, ME: 22, NL: 18, NO: 15, PK: 24, PS: 29, PL: 28,
  PT: 25, QA: 29, RO: 24, RU: 33, LC: 32, SM: 27, ST: 25, SA: 24,
  RS: 22, SC: 31, SK: 24, SI: 19, ES: 24, SD: 18, SE: 24, CH: 21,
  TL: 23, TN: 24, TR: 26, UA: 29, AE: 23, GB: 22, VA: 22, VG: 24,
});

const PLACEHOLDER_ENV_VALUES = new Set([
  "changeme",
  "change_me",
  "change-me",
  "your_key_here",
  "your-key-here",
  "your_api_key",
  "your_secret_here",
  "your_token_here",
  "placeholder",
  "example",
  "sample",
  "secret_here",
  "token_here",
  "password_here",
  "redacted",
  "undefined",
  "null",
  "none",
  "true",
  "false",
  "localhost",
  "bearer",
  "basic",
  "digest",
]);

export function luhnCheck(rawDigits) {
  const digits = String(rawDigits).replace(/[ -]/g, "");
  if (!/^\d{13,19}$/.test(digits) || /^0+$/.test(digits)) {
    return false;
  }
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = digits.charCodeAt(i) - 48;
    if (alternate) {
      n *= 2;
      if (n > 9) {
        n -= 9;
      }
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

export function isValidIban(candidate) {
  const compact = String(candidate).replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact)) {
    return false;
  }
  const expectedLen = IBAN_LENGTHS[compact.slice(0, 2)];
  if (expectedLen && compact.length !== expectedLen) {
    return false;
  }
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let numeric = "";
  for (let i = 0; i < rearranged.length; i += 1) {
    const code = rearranged.charCodeAt(i);
    numeric += code >= 65 && code <= 90 ? String(code - 55) : rearranged[i];
  }
  try {
    return BigInt(numeric) % 97n === 1n;
  } catch {
    return false;
  }
}

export function shannonEntropy(str) {
  if (!str || str.length === 0) {
    return 0;
  }
  const freq = new Map();
  for (let i = 0; i < str.length; i += 1) {
    const ch = str[i];
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isPlaceholderEnvValue(value) {
  const lower = value.toLowerCase();
  if (PLACEHOLDER_ENV_VALUES.has(lower)) {
    return true;
  }
  if (/^(?:x+|y+|z+|\*+|\.+|0+)$/i.test(value)) {
    return true;
  }
  if (
    /^(?:your[_-].+|replace[_-].+|insert[_-].+|dummy[_-].+|test[_-](?:key|token|secret|pass).*|<.+>|\$\{.+\})$/i.test(
      value
    )
  ) {
    return true;
  }
  if (/^\[[A-Z_]+_\d+\]$/.test(value)) {
    return true;
  }
  return false;
}

function hasMixedCardSeparators(value) {
  return value.includes(" ") && value.includes("-");
}

function isValidCardFormat(value) {
  if (!value || hasMixedCardSeparators(value)) {
    return false;
  }
  if (!value.includes(" ") && !value.includes("-")) {
    return /^\d{13,19}$/.test(value);
  }
  const sig = value
    .split(/[ -]/)
    .map((group) => group.length)
    .join("-");
  return (
    sig === "4-4-4-4" ||
    sig === "4-6-5" ||
    sig === "4-6-4" ||
    sig === "4-4-4-1" ||
    sig === "4-4-4-5" ||
    sig === "4-4-4-6" ||
    sig === "4-4-4-7" ||
    sig === "4-4-4-4-3"
  );
}

function resolveCardSpan(text, matchIndex, raw) {
  // 1. Prefer stripping trailing hyphen/space numeric suffixes (e.g. -99, -00, -12-34)
  //    when doing so yields a valid 13-16 digit standard card grouping, preventing
  //    10% Luhn-collision absorption of trailing tags into 17-19 digit spans.
  let candidate = raw;
  while (true) {
    let stripped = candidate;
    while (/-\d+$/.test(stripped)) {
      stripped = stripped.replace(/-\d+$/, "");
      const digitsLen = stripped.replace(/[ -]/g, "").length;
      if (digitsLen < 13) {
        break;
      }
      if (digitsLen <= 16 && isValidCardFormat(stripped) && luhnCheck(stripped)) {
        return { value: stripped, end: matchIndex + stripped.length };
      }
    }
    const lastSpace = candidate.lastIndexOf(" ");
    if (lastSpace <= 0) {
      break;
    }
    candidate = candidate.slice(0, lastSpace);
    const digitsLen = candidate.replace(/[ -]/g, "").length;
    if (digitsLen < 13) {
      break;
    }
    if (digitsLen <= 16 && isValidCardFormat(candidate) && luhnCheck(candidate)) {
      return { value: candidate, end: matchIndex + candidate.length };
    }
  }

  // 2a. Otherwise accept the full match (or space-trimmed 17-19 digit card) if structurally valid.
  candidate = raw;
  while (candidate.replace(/[ -]/g, "").length >= 13) {
    if (isValidCardFormat(candidate) && luhnCheck(candidate)) {
      return { value: candidate, end: matchIndex + candidate.length };
    }
    const lastSpace = candidate.lastIndexOf(" ");
    if (lastSpace <= 0) {
      break;
    }
    candidate = candidate.slice(0, lastSpace);
  }

  // 2b. If none matched, iteratively strip trailing -<digits> suffixes (and outer
  //     space-trimmed segments) for valid 17-18 digit PANs with hyphenated suffixes.
  candidate = raw;
  while (candidate.replace(/[ -]/g, "").length >= 17) {
    let stripped = candidate;
    while (/-\d+$/.test(stripped)) {
      stripped = stripped.replace(/-\d+$/, "");
      const digitsLen = stripped.replace(/[ -]/g, "").length;
      if (digitsLen < 17) {
        break;
      }
      if (digitsLen <= 18 && isValidCardFormat(stripped) && luhnCheck(stripped)) {
        return { value: stripped, end: matchIndex + stripped.length };
      }
    }
    const lastSpace = candidate.lastIndexOf(" ");
    if (lastSpace <= 0) {
      break;
    }
    candidate = candidate.slice(0, lastSpace);
  }
  return null;
}

function resolveIbanSpan(text, matchIndex, raw) {
  const cc = raw.slice(0, 2).toUpperCase();
  const expectedLen = IBAN_LENGTHS[cc];
  if (expectedLen) {
    let nonSpaceCount = 0;
    let cut = -1;
    for (let i = 0; i < raw.length; i += 1) {
      if (raw[i] !== " ") {
        nonSpaceCount += 1;
        if (nonSpaceCount === expectedLen) {
          cut = i + 1;
          break;
        }
      }
    }
    if (cut <= 0) {
      return null;
    }
    const nextChar = text[matchIndex + cut] || "";
    if (/[A-Za-z0-9]/.test(nextChar)) {
      return null;
    }
    const candidate = raw.slice(0, cut);
    if (!isValidIban(candidate)) {
      return null;
    }
    return { value: candidate, end: matchIndex + cut };
  }

  // Fallback for unlisted synthetic country codes: progressive trailing group trim.
  let candidate = raw;
  while (candidate.replace(/\s+/g, "").length >= 15) {
    if (isValidIban(candidate)) {
      return { value: candidate, end: matchIndex + candidate.length };
    }
    const lastSpace = candidate.lastIndexOf(" ");
    if (lastSpace <= 0) {
      break;
    }
    candidate = candidate.slice(0, lastSpace);
  }
  return null;
}

function isHighEntropySecret(token) {
  if (token.length < 20) {
    return false;
  }
  if (/^(?:https?|ftp|wss?|postgres(?:ql)?|mysql|redis|mongodb(?:\+srv)?):\/\//i.test(token)) {
    return false;
  }
  if (
    /^(?:~?\/|\.\.?\/|[A-Za-z]:\\)/.test(token) ||
    token.includes("\\") ||
    (token.includes("/") && /\.[a-z0-9]{1,5}$/i.test(token))
  ) {
    return false;
  }
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) {
    return false;
  }
  if (/^\[[A-Z_]+_\d+\]$/.test(token)) {
    return false;
  }

  let classes = 0;
  if (/[A-Z]/.test(token)) classes += 1;
  if (/[a-z]/.test(token)) classes += 1;
  if (/[0-9]/.test(token)) classes += 1;
  if (/[^A-Za-z0-9]/.test(token)) classes += 1;

  const isLongHex =
    /^[0-9a-fA-F]{32,}$/.test(token) && /[0-9]/.test(token) && /[a-fA-F]/.test(token);

  if (classes < 3 && !isLongHex) {
    return false;
  }

  return shannonEntropy(token) >= 3.8;
}

/**
 * Detect all 11 deterministic PII, credential, custom-rule, and high-entropy spans.
 * Returns non-overlapping entities sorted by start offset ascending.
 */
export function detectEntities(text, customRules = []) {
  if (typeof text !== "string" || text.length === 0) {
    return [];
  }

  const candidates = [];

  // 1. API_KEY (priority 100)
  const apiKeyRegex =
    /(?<![A-Za-z0-9_-])(?:(?:AKIA|ASIA)[0-9A-Z]{16}|sk-ant-[A-Za-z0-9_-]{20,}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}|(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[0-9A-Za-z-]{10,}|AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])/g;
  for (const m of text.matchAll(apiKeyRegex)) {
    candidates.push({
      category: "API_KEY",
      tokenPrefix: "API_KEY",
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
      priority: 100,
    });
  }

  // 2. JWT (priority 95)
  const jwtRegex =
    /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])/g;
  for (const m of text.matchAll(jwtRegex)) {
    candidates.push({
      category: "JWT",
      tokenPrefix: "JWT",
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
      priority: 95,
    });
  }

  // 3. CREDIT_CARD (priority 90, Luhn validated)
  const cardRegex =
    /(?<![A-Za-z\d+])(?<!\d[.-])(?:\d[ -]?){12,18}\d(?![A-Za-z\d])(?![.]\d)/g;
  let cardMatch;
  while ((cardMatch = cardRegex.exec(text)) !== null) {
    const resolved = resolveCardSpan(text, cardMatch.index, cardMatch[0]);
    if (resolved) {
      candidates.push({
        category: "CREDIT_CARD",
        tokenPrefix: "CARD",
        value: resolved.value,
        start: cardMatch.index,
        end: resolved.end,
        priority: 90,
      });
      cardRegex.lastIndex = resolved.end;
    } else {
      const sepIdx = cardMatch[0].search(/[ -]/);
      if (sepIdx >= 0) {
        cardRegex.lastIndex = cardMatch.index + sepIdx + 1;
      }
    }
  }

  // 4. IBAN (priority 92, ISO 7064 mod-97 via BigInt)
  const ibanRegex =
    /(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}(?![A-Za-z0-9])/g;
  let ibanMatch;
  while ((ibanMatch = ibanRegex.exec(text)) !== null) {
    const resolved = resolveIbanSpan(text, ibanMatch.index, ibanMatch[0]);
    if (resolved) {
      candidates.push({
        category: "IBAN",
        tokenPrefix: "IBAN",
        value: resolved.value,
        start: ibanMatch.index,
        end: resolved.end,
        priority: 92,
      });
      ibanRegex.lastIndex = resolved.end;
    } else {
      const spaceIdx = ibanMatch[0].indexOf(" ");
      if (spaceIdx >= 0) {
        ibanRegex.lastIndex = ibanMatch.index + spaceIdx + 1;
      }
    }
  }

  // 5. SSN (priority 85)
  const ssnRegex =
    /(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])/g;
  for (const m of text.matchAll(ssnRegex)) {
    candidates.push({
      category: "SSN",
      tokenPrefix: "SSN",
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
      priority: 85,
    });
  }

  // 6. ENV_SECRET (priority 82, RHS value only, single-line whitespace)
  const envSecretRegex =
    /^([ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|AUTH|DSN|CONNECTION_STRING)[A-Z0-9_]*[ \t]*[:=][ \t]*)(?:"((?:[^"\\\r\n]|\\.)*)"|'((?:[^'\\\r\n]|\\.)*)'|([^\s'"#\r\n][^\s\r\n]{5,}))/gim;
  for (const m of text.matchAll(envSecretRegex)) {
    const isDoubleQuoted = m[2] !== undefined;
    const isSingleQuoted = m[3] !== undefined;
    const value = isDoubleQuoted ? m[2] : isSingleQuoted ? m[3] : m[4];
    if (!value || value.length < 6 || isPlaceholderEnvValue(value)) {
      continue;
    }
    const quoteOffset = isDoubleQuoted || isSingleQuoted ? 1 : 0;
    const start = m.index + m[1].length + quoteOffset;
    const end = start + value.length;
    if (
      !isDoubleQuoted &&
      !isSingleQuoted &&
      /^[ \t]*(?:proxy-)?authorization[ \t]*:[ \t]*$/i.test(m[1]) &&
      /^(?:bearer|basic|digest|token|apikey|api-key|custom|hmac|negotiate|ntlm)$/i.test(value) &&
      /^[ \t]+[^#\s]/.test(text.slice(end))
    ) {
      continue;
    }
    candidates.push({
      category: "ENV_SECRET",
      tokenPrefix: "ENV_SECRET",
      value,
      start,
      end,
      priority: 82,
    });
  }

  // 7. CUSTOM (priority 80, Unicode Cyrillic/EN boundary + combining mark guard)
  if (Array.isArray(customRules) && customRules.length > 0) {
    const activeRules = customRules
      .filter((r) => r && r.enabled !== false && typeof r.term === "string" && r.term.trim().length > 0)
      .sort((a, b) => b.term.trim().length - a.term.trim().length);

    for (const rule of activeRules) {
      const term = rule.term.trim();
      const rawRuleCat =
        typeof rule.category === "string" ? rule.category.trim().toUpperCase() : "";
      const ruleCategory = rawRuleCat || "CUSTOM";
      const flags = rule.caseSensitive ? "gu" : "giu";
      try {
        const re = new RegExp(
          `(?<![\\p{L}\\p{N}_\\p{M}])${escapeRegExp(term)}(?![\\p{L}\\p{N}_\\p{M}])`,
          flags
        );
        for (const m of text.matchAll(re)) {
          candidates.push({
            category: "CUSTOM",
            tokenPrefix: "CUSTOM",
            value: m[0],
            start: m.index,
            end: m.index + m[0].length,
            priority: 80,
            ruleId: rule.id || undefined,
            ruleCategory,
          });
        }
      } catch {
        // Skip invalid pattern safely without crashing detection pipeline.
      }
    }
  }

  // 8. EMAIL (priority 75)
  const emailRegex =
    /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}(?![A-Za-z0-9_-])/g;
  for (const m of text.matchAll(emailRegex)) {
    candidates.push({
      category: "EMAIL",
      tokenPrefix: "EMAIL",
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
      priority: 75,
    });
  }

  // 9. PHONE (priority 70, CIS/RU + international, 10..15 digits)
  const phoneRegex =
    /(?<![\p{L}\p{N}_.])(?<![\p{L}\p{N}]-)(?:\+\d{1,3}(?:[ -]?\(?\d{1,4}\)?){1,5}|\(?8\)?[ -]?\(?\d{3,4}\)?(?:[ -]?\d{2,4}){2,4}|89\d{9}|\(\d{3,4}\)[ -]?\d{2,4}(?:[ -]?\d{2,4}){1,3}|\d{3}[ -]\d{3}[ -]\d{4})(?![\p{L}\p{N}_-])(?![.]\d)/gu;
  for (const m of text.matchAll(phoneRegex)) {
    const val = m[0];
    const openParens = (val.match(/\(/g) || []).length;
    const closeParens = (val.match(/\)/g) || []).length;
    if (openParens !== closeParens) {
      continue;
    }
    const digits = val.replace(/\D/g, "");
    if (digits.length < 10 || digits.length > 15) {
      continue;
    }
    if (/^\d{4}[-/]\d{2}[-/]\d{2}/.test(val) || /^\d{2}\.\d{2}\.\d{4}/.test(val)) {
      continue;
    }
    candidates.push({
      category: "PHONE",
      tokenPrefix: "PHONE",
      value: val,
      start: m.index,
      end: m.index + val.length,
      priority: 70,
    });
  }

  // 10. IPV4 (priority 60)
  const ipv4Regex =
    /(?<![\p{L}\p{N}_.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\p{L}\p{N}_])(?![.]\d)/gu;
  for (const m of text.matchAll(ipv4Regex)) {
    candidates.push({
      category: "IPV4",
      tokenPrefix: "IP",
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
      priority: 60,
    });
  }

  // 11. HIGH_ENTROPY (priority 50)
  const entropyRegex =
    /(?<=^|[\s"'`()[\]{}<>,;:=])([A-Za-z0-9_.~+/\\-]{20,}={0,2})(?=$|[\s"'`()[\]{}<>,;:=!?])/g;
  for (const m of text.matchAll(entropyRegex)) {
    const rawToken = m[1];
    const trimmed = rawToken.replace(/[.!?]+$/, "");
    if (!trimmed || !isHighEntropySecret(trimmed)) {
      continue;
    }
    // Ignore URL :port/path suffixes such as https://example.com:8443/v1/... or grpcs://host:9443/...
    if (m.index > 0 && text[m.index - 1] === ":" && /^\d{1,5}\//.test(trimmed)) {
      const lookback = text.slice(Math.max(0, m.index - 200), m.index);
      if (/[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/\s"'`()[\]{}<>,;=]+:$/.test(lookback)) {
        continue;
      }
    }
    candidates.push({
      category: "HIGH_ENTROPY",
      tokenPrefix: "SECRET",
      value: trimmed,
      start: m.index,
      end: m.index + trimmed.length,
      priority: 50,
    });
  }

  // Overlap resolution: priority DESC, span length DESC, start ASC.
  candidates.sort(
    (a, b) =>
      b.priority - a.priority ||
      b.end - b.start - (a.end - a.start) ||
      a.start - b.start
  );

  // Maintain accepted disjoint intervals in a deterministic AVL tree keyed by `start`
  // for O(k log k) worst-case insertion & predecessor/successor overlap checks.
  const heightOf = (node) => (node ? node.h : 0);
  const updateHeight = (node) => {
    const lh = node.left ? node.left.h : 0;
    const rh = node.right ? node.right.h : 0;
    node.h = (lh > rh ? lh : rh) + 1;
  };
  const rotateLeft = (x) => {
    const y = x.right;
    x.right = y.left;
    y.left = x;
    updateHeight(x);
    updateHeight(y);
    return y;
  };
  const rotateRight = (y) => {
    const x = y.left;
    y.left = x.right;
    x.right = y;
    updateHeight(y);
    updateHeight(x);
    return x;
  };

  let root = null;
  for (const candidate of candidates) {
    let cur = root;
    let pred = null;
    let succ = null;
    let overlaps = false;
    const path = [];

    while (cur !== null) {
      path.push(cur);
      if (candidate.start === cur.start) {
        overlaps = true;
        break;
      }
      if (candidate.start < cur.start) {
        succ = cur;
        cur = cur.left;
      } else {
        pred = cur;
        cur = cur.right;
      }
    }

    if (
      overlaps ||
      (pred !== null && pred.end > candidate.start) ||
      (succ !== null && candidate.end > succ.start)
    ) {
      continue;
    }

    const leaf = {
      start: candidate.start,
      end: candidate.end,
      item: candidate,
      left: null,
      right: null,
      h: 1,
    };
    if (path.length === 0) {
      root = leaf;
      continue;
    }

    const immediateParent = path[path.length - 1];
    if (candidate.start < immediateParent.start) {
      immediateParent.left = leaf;
    } else {
      immediateParent.right = leaf;
    }

    for (let i = path.length - 1; i >= 0; i -= 1) {
      const node = path[i];
      updateHeight(node);
      const bal = heightOf(node.left) - heightOf(node.right);
      let replacement = node;
      if (bal > 1) {
        if (candidate.start > node.left.start) {
          node.left = rotateLeft(node.left);
        }
        replacement = rotateRight(node);
      } else if (bal < -1) {
        if (candidate.start < node.right.start) {
          node.right = rotateRight(node.right);
        }
        replacement = rotateLeft(node);
      }
      if (replacement !== node) {
        if (i === 0) {
          root = replacement;
        } else {
          const parent = path[i - 1];
          if (parent.left === node) {
            parent.left = replacement;
          } else {
            parent.right = replacement;
          }
        }
        break;
      }
    }
  }

  const accepted = [];
  const stack = [];
  let cursor = root;
  while (cursor !== null || stack.length > 0) {
    while (cursor !== null) {
      stack.push(cursor);
      cursor = cursor.left;
    }
    cursor = stack.pop();
    accepted.push(cursor.item);
    cursor = cursor.right;
  }
  return accepted;
}
