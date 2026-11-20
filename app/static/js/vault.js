/**
 * PromptVeil Reversible Session Vault & Single-Pass Re-Hydrator.
 * Keeps all token <-> original secret mappings strictly in browser RAM.
 */

import { CATEGORIES, detectEntities, escapeRegExp } from "./detector.js";

export function makeEntityKey(category, value) {
  return `${category}\u0000${value}`;
}

function syncRuleMetadata(entry, span) {
  if (span.ruleCategory) {
    entry.ruleCategory = span.ruleCategory;
  } else {
    delete entry.ruleCategory;
  }
  if (span.ruleId) {
    entry.ruleId = span.ruleId;
  } else {
    delete entry.ruleId;
  }
  if (span.reasonKey) {
    entry.reasonKey = span.reasonKey;
  } else {
    delete entry.reasonKey;
  }
}

export class SessionVault {
  constructor() {
    this.valueToToken = new Map();
    this.tokenToEntry = new Map();
    this.counters = new Map();
    this.excludedValues = new Set();
    this.disabledCategories = new Set();
  }

  reset() {
    this.valueToToken.clear();
    this.tokenToEntry.clear();
    this.counters.clear();
    this.excludedValues.clear();
    this.disabledCategories.clear();
  }

  _allocateToken(span, evolveTransient = false, activeKeys = null) {
    const key = makeEntityKey(span.category, span.value);
    const existingToken = this.valueToToken.get(key);
    if (existingToken) {
      const existingEntry = this.tokenToEntry.get(existingToken);
      if (existingEntry) {
        syncRuleMetadata(existingEntry, span);
      }
      return existingToken;
    }

    if (evolveTransient && activeKeys) {
      for (const [oldToken, oldEntry] of this.tokenToEntry.entries()) {
        const oldKey = makeEntityKey(oldEntry.category, oldEntry.value);
        if (activeKeys.has(oldKey) || oldEntry.category !== span.category) {
          continue;
        }
        const isPrefixMatch =
          span.value.startsWith(oldEntry.value) || oldEntry.value.startsWith(span.value);
        if (!isPrefixMatch) {
          continue;
        }
        this.valueToToken.delete(oldKey);
        this.valueToToken.set(key, oldToken);
        oldEntry.value = span.value;
        oldEntry.priority = span.priority;
        syncRuleMetadata(oldEntry, span);
        if (this.excludedValues.has(oldKey)) {
          this.excludedValues.delete(oldKey);
          this.excludedValues.add(key);
        }
        return oldToken;
      }
    }

    const nextNumber = (this.counters.get(span.tokenPrefix) || 0) + 1;
    this.counters.set(span.tokenPrefix, nextNumber);
    const token = `[${span.tokenPrefix}_${nextNumber}]`;
    this.valueToToken.set(key, token);
    const entry = {
      token,
      category: span.category,
      tokenPrefix: span.tokenPrefix,
      value: span.value,
      priority: span.priority,
    };
    syncRuleMetadata(entry, span);
    this.tokenToEntry.set(token, entry);
    return token;
  }

  _evictInactivePrefixEntries(spans, activeKeys) {
    if (!activeKeys || spans.length === 0) {
      return;
    }

    const evicted = [];
    for (const [oldToken, oldEntry] of this.tokenToEntry.entries()) {
      const oldKey = makeEntityKey(oldEntry.category, oldEntry.value);
      if (activeKeys.has(oldKey)) {
        continue;
      }
      const isPrefixMatch = spans.some(
        (span) =>
          span.value.startsWith(oldEntry.value) || oldEntry.value.startsWith(span.value)
      );
      if (isPrefixMatch) {
        evicted.push({ oldToken, oldEntry, oldKey });
      }
    }

    if (evicted.length === 0) {
      return;
    }

    const affectedPrefixes = new Set();
    for (const { oldToken, oldEntry, oldKey } of evicted) {
      this.valueToToken.delete(oldKey);
      this.tokenToEntry.delete(oldToken);
      this.excludedValues.delete(oldKey);
      this.excludedValues.delete(oldToken);
      affectedPrefixes.add(oldEntry.tokenPrefix);
    }

    for (const prefix of affectedPrefixes) {
      let count = this.counters.get(prefix) || 0;
      while (count > 0 && !this.tokenToEntry.has(`[${prefix}_${count}]`)) {
        count -= 1;
      }
      this.counters.set(prefix, count);
    }
  }

  toggleValue(category, value, enabled) {
    const key = makeEntityKey(category, value);
    const token = this.valueToToken.get(key);
    const currentlyExcluded =
      this.excludedValues.has(key) ||
      (Boolean(token) && this.excludedValues.has(token));
    const shouldEnable = typeof enabled === "boolean" ? enabled : currentlyExcluded;
    if (shouldEnable) {
      this.excludedValues.delete(key);
      if (token) {
        this.excludedValues.delete(token);
      }
    } else {
      this.excludedValues.add(key);
    }
    return shouldEnable;
  }

  toggleToken(token, enabled) {
    const entry = this.tokenToEntry.get(token);
    if (entry) {
      return this.toggleValue(entry.category, entry.value, enabled);
    }
    const currentlyExcluded = this.excludedValues.has(token);
    const shouldEnable = typeof enabled === "boolean" ? enabled : currentlyExcluded;
    if (shouldEnable) {
      this.excludedValues.delete(token);
    } else {
      this.excludedValues.add(token);
    }
    return shouldEnable;
  }

  toggleCategory(category, enabled) {
    const currentlyDisabled = this.disabledCategories.has(category);
    const shouldEnable = typeof enabled === "boolean" ? enabled : currentlyDisabled;
    if (shouldEnable) {
      this.disabledCategories.delete(category);
    } else {
      this.disabledCategories.add(category);
    }
    return shouldEnable;
  }

  sanitize(text, customRules = [], options = {}) {
    const source = typeof text === "string" ? text : "";
    const evolveTransient = Boolean(options?.evolveTransient);
    const countsByCategory = Object.fromEntries(
      CATEGORIES.map((item) => [item.category, 0])
    );

    if (source.trim().length === 0) {
      if (options?.resetOnEmpty !== false) {
        this.reset();
      }
      return {
        sanitizedText: source,
        entities: [],
        vaultEntries: [],
        countsByCategory,
        segments: source.length > 0 ? [{ type: "text", text: source }] : [],
        maskedCount: 0,
        skippedCount: 0,
        totalCount: 0,
      };
    }

    const spans = detectEntities(source, customRules, {
      detectUuid: Boolean(options?.detectUuid),
      sensitivity: options?.sensitivity === "strict" ? "strict" : "normal",
    });
    const activeKeys = evolveTransient
      ? new Set(spans.map((s) => makeEntityKey(s.category, s.value)))
      : null;
    const entities = [];
    const entryAgg = new Map();
    const segments = [];
    let cursor = 0;

    for (const span of spans) {
      if (span.start > cursor) {
        segments.push({ type: "text", text: source.slice(cursor, span.start) });
      }

      const token = this._allocateToken(span, evolveTransient, activeKeys);
      const key = makeEntityKey(span.category, span.value);
      const categoryDisabled = this.disabledCategories.has(span.category);
      const valueExcluded =
        this.excludedValues.has(key) || this.excludedValues.has(token);
      const enabled = !categoryDisabled && !valueExcluded;

      countsByCategory[span.category] = (countsByCategory[span.category] || 0) + 1;

      const entity = {
        ...span,
        token,
        enabled,
        categoryDisabled,
        valueExcluded,
      };
      entities.push(entity);

      if (enabled) {
        segments.push({
          type: "token",
          text: token,
          token,
          category: span.category,
          value: span.value,
          ...(span.ruleCategory ? { ruleCategory: span.ruleCategory } : {}),
        });
      } else {
        segments.push({
          type: "text",
          text: span.value,
        });
      }

      const existingAgg = entryAgg.get(token);
      if (existingAgg) {
        existingAgg.count += 1;
        if (span.ruleCategory) {
          existingAgg.ruleCategory = span.ruleCategory;
        } else {
          delete existingAgg.ruleCategory;
        }
        if (span.ruleId) {
          existingAgg.ruleId = span.ruleId;
        } else {
          delete existingAgg.ruleId;
        }
        if (span.reasonKey) {
          existingAgg.reasonKey = span.reasonKey;
        } else {
          delete existingAgg.reasonKey;
        }
      } else {
        entryAgg.set(token, {
          token,
          category: span.category,
          tokenPrefix: span.tokenPrefix,
          value: span.value,
          count: 1,
          enabled,
          categoryDisabled,
          valueExcluded,
          ...(span.ruleCategory ? { ruleCategory: span.ruleCategory } : {}),
          ...(span.ruleId ? { ruleId: span.ruleId } : {}),
          ...(span.reasonKey ? { reasonKey: span.reasonKey } : {}),
        });
      }

      cursor = span.end;
    }

    if (evolveTransient && activeKeys) {
      this._evictInactivePrefixEntries(spans, activeKeys);
    }

    if (cursor < source.length) {
      segments.push({ type: "text", text: source.slice(cursor) });
    }

    const sanitizedText = segments.map((seg) => seg.text).join("");
    const totalCount = entities.length;
    const maskedCount = entities.filter((item) => item.enabled).length;
    const skippedCount = totalCount - maskedCount;
    return {
      sanitizedText,
      entities,
      vaultEntries: Array.from(entryAgg.values()),
      countsByCategory,
      segments,
      maskedCount,
      skippedCount,
      totalCount,
    };
  }

  rehydrate(llmReply) {
    const reply = typeof llmReply === "string" ? llmReply : "";
    if (reply.length === 0) {
      return {
        rehydratedText: "",
        restoredText: "",
        replacedCount: 0,
        restoredTokens: [],
        unresolvedTokens: [],
        segments: [],
      };
    }

    // Identify unresolved PromptVeil-shaped tokens directly in the LLM reply.
    const unresolvedSet = new Set();
    const tokenShapeRegex = /\[[A-Z_]+_\d+\]/g;
    for (const m of reply.matchAll(tokenShapeRegex)) {
      if (!this.tokenToEntry.has(m[0])) {
        unresolvedSet.add(m[0]);
      }
    }
    const unresolvedTokens = Array.from(unresolvedSet);

    if (this.tokenToEntry.size === 0) {
      return {
        rehydratedText: reply,
        restoredText: reply,
        replacedCount: 0,
        restoredTokens: [],
        unresolvedTokens,
        segments: [{ type: "text", text: reply }],
      };
    }

    // Single-pass longest-token-first replacement avoids [EMAIL_1] vs [EMAIL_10]
    // and double-substitution of restored secrets containing brackets or $ patterns.
    const sortedTokens = Array.from(this.tokenToEntry.keys()).sort(
      (a, b) => b.length - a.length
    );
    const tokenRegex = new RegExp(sortedTokens.map(escapeRegExp).join("|"), "g");

    const segments = [];
    const restoredSet = new Set();
    let cursor = 0;
    let replacedCount = 0;
    let match;

    while ((match = tokenRegex.exec(reply)) !== null) {
      if (match.index > cursor) {
        segments.push({ type: "text", text: reply.slice(cursor, match.index) });
      }
      const matchedToken = match[0];
      const entry = this.tokenToEntry.get(matchedToken);
      if (entry) {
        replacedCount += 1;
        restoredSet.add(matchedToken);
        segments.push({
          type: "restored",
          text: entry.value,
          token: matchedToken,
          category: entry.category,
          ...(entry.ruleCategory ? { ruleCategory: entry.ruleCategory } : {}),
        });
      } else {
        segments.push({ type: "text", text: matchedToken });
      }
      cursor = match.index + matchedToken.length;
    }

    if (cursor < reply.length) {
      segments.push({ type: "text", text: reply.slice(cursor) });
    }

    const rehydratedText = segments.map((seg) => seg.text).join("");
    return {
      rehydratedText,
      restoredText: rehydratedText,
      replacedCount,
      restoredTokens: Array.from(restoredSet),
      unresolvedTokens,
      segments,
    };
  }
}
