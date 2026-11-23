#!/usr/bin/env node
/**
 * Offline Ed25519 keypair & Pro activation key issuer for PromptVeil.
 * Never commit generated private keys or activation tokens to Git.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  base64UrlToBytes,
  extractProToken,
  formatPvKeyFileContent,
  verifyEd25519PureJs,
} from "../app/static/js/pro-license.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT_DIR = path.resolve(__dirname, "..");
export const DEFAULT_BUNDLE_PATH = path.join(ROOT_DIR, ".secrets", "pro_keys_bundle.json");
export const DEFAULT_LEDGER_PATH = path.join(ROOT_DIR, ".secrets", "issued_ledger.json");
export const PRO_LICENSE_PATH = path.join(ROOT_DIR, "app", "static", "js", "pro-license.js");

export const PLAN_PRESETS = Object.freeze({
  "pro-monthly": Object.freeze({
    tier: "pro",
    days: 30,
    label: "PromptVeil Pro Monthly",
    prefix: "PV-PRO-M",
  }),
  "pro-annual": Object.freeze({
    tier: "pro",
    days: 365,
    label: "PromptVeil Pro Annual",
    prefix: "PV-PRO-A",
  }),
  "pro-lifetime": Object.freeze({
    tier: "pro",
    days: null,
    label: "PromptVeil Pro Lifetime",
    prefix: "PV-PRO-L",
  }),
  "team-pack": Object.freeze({
    tier: "pro",
    days: 365,
    label: "PromptVeil Team Pack",
    prefix: "PV-TEAM",
  }),
});

const BOOLEAN_FLAGS = new Set([
  "generate-bundle",
  "issue",
  "inspect-bundle",
  "verify-bundle",
  "append-ledger",
  "redact",
  "json",
  "help",
]);

function parseExpirationMs(exp) {
  if (exp === undefined || exp === null) {
    return null;
  }
  if (typeof exp === "number" && Number.isFinite(exp)) {
    return exp > 1e12 ? exp : exp * 1000;
  }
  if (typeof exp === "string" && exp.trim().length > 0) {
    const parsed = Date.parse(exp);
    return Number.isNaN(parsed) ? NaN : parsed;
  }
  return NaN;
}

function isValidProPayloadObject(payload) {
  return Boolean(
    payload &&
      typeof payload === "object" &&
      !Array.isArray(payload) &&
      payload.v === 1 &&
      (payload.tier === "pro" || payload.tier === "owner") &&
      typeof payload.keyId === "string" &&
      payload.keyId.trim().length > 0 &&
      typeof payload.label === "string" &&
      payload.label.trim().length > 0 &&
      typeof payload.issuedAt === "string" &&
      !Number.isNaN(Date.parse(payload.issuedAt))
  );
}

export function extractRawPublicKeyB64U(publicKey) {
  const spki = publicKey.export({ type: "spki", format: "der" });
  const raw = spki.subarray(spki.length - 32);
  if (raw.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${raw.length}`);
  }
  return raw.toString("base64url");
}

export function signProToken(payload, privateKey) {
  const cleanPayload = {
    v: 1,
    tier: payload.tier === "owner" ? "owner" : "pro",
    keyId: String(payload.keyId),
    label: String(payload.label),
    issuedAt: String(payload.issuedAt || new Date().toISOString()),
  };
  if (payload.exp !== undefined && payload.exp !== null && payload.exp !== "") {
    cleanPayload.exp = payload.exp;
  }
  const payloadB64U = Buffer.from(JSON.stringify(cleanPayload), "utf8").toString("base64url");
  const signingInput = Buffer.from(`PV1.${payloadB64U}`, "utf8");
  const signature = crypto.sign(null, signingInput, privateKey);
  return `PV1.${payloadB64U}.${signature.toString("base64url")}`;
}

export function verifyTokenWithRawPublicKey(token, publicKeyB64U, options = {}) {
  const nowMs = options?.nowMs ?? Date.now();
  if (!Number.isFinite(nowMs)) {
    throw new Error(`Invalid nowMs option: ${options?.nowMs}`);
  }

  const trimmed = typeof token === "string" ? token.trim() : "";
  if (!trimmed) {
    return { valid: false, reason: "empty" };
  }

  const parts = trimmed.split(".");
  if (parts.length !== 3 || parts[0] !== "PV1") {
    return { valid: false, reason: "format" };
  }

  const [, payloadB64U, sigB64U] = parts;
  const payloadBytes = base64UrlToBytes(payloadB64U);
  const sigBytes = base64UrlToBytes(sigB64U);
  const pubBytes = base64UrlToBytes(publicKeyB64U);
  if (!payloadBytes || !sigBytes || !pubBytes) {
    return { valid: false, reason: "encoding" };
  }

  if (sigBytes.length !== 64 || pubBytes.length !== 32) {
    return { valid: false, reason: "length" };
  }

  const msgBytes = Buffer.from(`PV1.${payloadB64U}`, "utf8");
  let cryptoOk = false;
  try {
    const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const pubKeyObj = crypto.createPublicKey({
      key: Buffer.concat([spkiPrefix, Buffer.from(pubBytes)]),
      format: "der",
      type: "spki",
    });
    cryptoOk = crypto.verify(null, msgBytes, pubKeyObj, Buffer.from(sigBytes));
  } catch {
    cryptoOk = false;
  }

  // Enforce RFC 8032 + small-subgroup / identity rejection parity with pro-license.js.
  const pureJsOk = verifyEd25519PureJs(new Uint8Array(msgBytes), sigBytes, pubBytes);
  if (!cryptoOk || !pureJsOk) {
    return { valid: false, reason: "signature" };
  }

  let payload;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes));
  } catch {
    return { valid: false, reason: "payload" };
  }

  if (!isValidProPayloadObject(payload)) {
    return { valid: false, reason: "payload" };
  }

  const expMs = parseExpirationMs(payload.exp);
  if (expMs !== null) {
    if (Number.isNaN(expMs)) {
      return { valid: false, reason: "payload" };
    }
    if (expMs <= nowMs) {
      return { valid: false, reason: "expired", payload };
    }
  }

  return { valid: true, reason: "valid", payload };
}

export function readPublicKeyFromLicenseJs(licensePath = PRO_LICENSE_PATH) {
  const src = fs.readFileSync(licensePath, "utf8");
  const match = src.match(/export const PRO_PUBLIC_KEY_B64U\s*=\s*"([A-Za-z0-9_-]{43})"/);
  if (!match) {
    throw new Error(`Could not find 43-char PRO_PUBLIC_KEY_B64U in ${licensePath}`);
  }
  return match[1];
}

export function redactToken(token) {
  const clean = typeof token === "string" ? token.trim() : "";
  if (!clean) return "";
  const parts = clean.split(".");
  if (parts.length !== 3 || parts[0] !== "PV1") {
    return clean.length <= 8 ? "***" : `${clean.slice(0, 4)}...${clean.slice(-4)}`;
  }
  const p = parts[1];
  const s = parts[2];
  const pHead = p.slice(0, Math.min(6, p.length));
  const sTail = s.slice(Math.max(0, s.length - 6));
  return `PV1.${pHead}...${sTail}`;
}

export function formatPvKeyContent(token, meta = {}) {
  return formatPvKeyFileContent(token, meta);
}

function derivePublicKeyFromBundlePrivateKey(bundle) {
  if (!bundle || typeof bundle.privateKeyPkcs8Pem !== "string" || !bundle.privateKeyPkcs8Pem.trim()) {
    throw new Error("Bundle is missing privateKeyPkcs8Pem");
  }
  const privateKey = crypto.createPrivateKey(bundle.privateKeyPkcs8Pem);
  const publicKey = crypto.createPublicKey(privateKey);
  const derivedPubB64U = extractRawPublicKeyB64U(publicKey);
  return { privateKey, derivedPubB64U };
}

export function verifyBundleObject(
  bundle,
  { expectedPublicKeyB64U = readPublicKeyFromLicenseJs(), nowMs = Date.now(), strictCodeMatch = true } = {}
) {
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) {
    throw new Error("Bundle must be a JSON object");
  }
  const pubBytes = base64UrlToBytes(bundle.publicKeyB64U);
  if (!pubBytes || pubBytes.length !== 32) {
    throw new Error("Bundle publicKeyB64U is invalid (expected 32-byte unpadded base64url)");
  }

  let privateKeyMatchesPublic = false;
  let privateKeyError = "";
  try {
    const { derivedPubB64U } = derivePublicKeyFromBundlePrivateKey(bundle);
    privateKeyMatchesPublic = derivedPubB64U === bundle.publicKeyB64U;
    if (!privateKeyMatchesPublic) {
      privateKeyError = `Bundle private key derives ${derivedPubB64U}, expected ${bundle.publicKeyB64U}`;
    }
  } catch (err) {
    privateKeyError = err.message;
  }

  const publicKeyMatchesCode = bundle.publicKeyB64U === expectedPublicKeyB64U;

  const entries = [];
  if (bundle.ownerKey) {
    entries.push({ kind: "ownerKey", entry: bundle.ownerKey });
  }
  const clientKeysInvalid = bundle.clientKeys !== undefined && !Array.isArray(bundle.clientKeys);
  if (Array.isArray(bundle.clientKeys)) {
    for (let i = 0; i < bundle.clientKeys.length; i += 1) {
      entries.push({ kind: `clientKeys[${i}]`, entry: bundle.clientKeys[i] });
    }
  }

  const verifiedEntries = [];
  const failures = [];

  if (clientKeysInvalid) {
    failures.push({ kind: "clientKeys", keyId: "", reason: "invalid_clientKeys" });
  }

  for (const { kind, entry } of entries) {
    if (!entry || typeof entry !== "object" || typeof entry.token !== "string") {
      failures.push({ kind, keyId: entry?.keyId || "", reason: "missing_token" });
      continue;
    }
    const res = verifyTokenWithRawPublicKey(entry.token, bundle.publicKeyB64U, { nowMs });
    let reason = res.reason;
    let valid = res.valid;
    if (valid && entry.keyId && res.payload.keyId !== entry.keyId) {
      valid = false;
      reason = "keyId_mismatch";
    }
    if (valid && entry.tier && res.payload.tier !== entry.tier) {
      valid = false;
      reason = "tier_mismatch";
    }
    const record = {
      kind,
      keyId: entry.keyId || res.payload?.keyId || "",
      tier: entry.tier || res.payload?.tier || "",
      label: entry.label || res.payload?.label || "",
      issuedAt: entry.issuedAt || res.payload?.issuedAt || "",
      exp: entry.exp ?? res.payload?.exp ?? null,
      valid,
      reason,
      token: entry.token,
    };
    verifiedEntries.push(record);
    if (!valid) {
      failures.push({ kind, keyId: record.keyId, reason });
    }
  }

  if (verifiedEntries.length === 0) {
    failures.push({
      kind: "bundle",
      keyId: "",
      reason: "empty_bundle",
    });
  }
  if (!privateKeyMatchesPublic) {
    failures.unshift({ kind: "privateKey", keyId: "", reason: privateKeyError || "private_key_mismatch" });
  }
  if (strictCodeMatch && !publicKeyMatchesCode) {
    failures.unshift({
      kind: "publicKeyMatchesCode",
      keyId: "",
      reason: `Bundle publicKeyB64U (${bundle.publicKeyB64U}) does not match PRO_PUBLIC_KEY_B64U (${expectedPublicKeyB64U}). Pass --pub to override.`,
    });
  }

  return {
    ok: failures.length === 0,
    bundlePublicKeyB64U: bundle.publicKeyB64U,
    expectedPublicKeyB64U,
    publicKeyMatchesCode,
    privateKeyMatchesPublic,
    hasPrivateKey: typeof bundle.privateKeyPkcs8Pem === "string" && bundle.privateKeyPkcs8Pem.trim().length > 0,
    totalEntries: verifiedEntries.length,
    validEntries: verifiedEntries.filter((e) => e.valid).length,
    failures,
    entries: verifiedEntries,
  };
}

export function appendLedgerEntries(
  ledgerPath,
  items,
  { publicKeyB64U, nowIso = new Date().toISOString() } = {}
) {
  let ledger = {
    format: "PV1-LEDGER",
    updatedAt: nowIso,
    publicKeyB64U: publicKeyB64U || "",
    entries: [],
  };

  if (fs.existsSync(ledgerPath)) {
    const raw = fs.readFileSync(ledgerPath, "utf8");
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      const err = new Error("Invalid ledger JSON format");
      err.statusCode = 409;
      throw err;
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.entries)) {
      const err = new Error("Invalid ledger schema: expected object with entries array");
      err.statusCode = 409;
      throw err;
    }
    ledger = parsed;
  }

  for (const item of items) {
    const tokenSha256 = crypto.createHash("sha256").update(item.token, "utf8").digest("hex");
    ledger.entries.push({
      keyId: item.keyId,
      tier: item.tier,
      plan: item.plan || "",
      orderId: item.orderId || "",
      label: item.label,
      issuedAt: item.issuedAt,
      exp: item.exp ?? null,
      tokenSha256,
      token: item.token,
    });
  }
  ledger.updatedAt = nowIso;
  if (publicKeyB64U) {
    ledger.publicKeyB64U = publicKeyB64U;
  }

  fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
  fs.writeFileSync(ledgerPath, `${JSON.stringify(ledger, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return ledger;
}

function csvEscape(value) {
  const s = value === undefined || value === null ? "" : String(value);
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function formatIssuedTable(items, format = "md", { redact = false } = {}) {
  const fmt = String(format || "md").toLowerCase();
  const rows = items.map((item) => ({
    keyId: item.keyId,
    tier: item.tier,
    plan: item.plan || "",
    orderId: item.orderId || "",
    label: item.label,
    issuedAt: item.issuedAt,
    exp: item.exp ?? "never",
    token: redact ? redactToken(item.token) : item.token,
  }));

  if (fmt === "json") {
    return `${JSON.stringify(rows, null, 2)}\n`;
  }
  if (fmt === "csv") {
    const header = ["keyId", "tier", "plan", "orderId", "label", "issuedAt", "exp", "token"].join(",");
    const lines = rows.map((r) =>
      [r.keyId, r.tier, r.plan, r.orderId, r.label, r.issuedAt, r.exp, r.token].map(csvEscape).join(",")
    );
    return `${[header, ...lines].join("\n")}\n`;
  }
  if (fmt === "md") {
    const header = "| Key ID | Tier | Plan | Order | Label | Issued At | Expires At | Token |";
    const sep = "|---|---|---|---|---|---|---|---|";
    const lines = rows.map(
      (r) =>
        `| \`${r.keyId}\` | \`${r.tier}\` | ${r.plan || "-"} | ${r.orderId || "-"} | ${String(r.label).replace(/\|/g, "\\|")} | ${r.issuedAt} | ${r.exp} | \`${r.token}\` |`
    );
    return `${[header, sep, ...lines].join("\n")}\n`;
  }
  throw new Error(`Unsupported table format "${format}". Use md, csv, or json.`);
}

export function generateBundle({ outPath = DEFAULT_BUNDLE_PATH, handoffDir = null, expectedPublicKeyB64U } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyB64U = extractRawPublicKeyB64U(publicKey);
  const publicKeySpkiPem = publicKey.export({ type: "spki", format: "pem" });
  const privateKeyPkcs8Pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const issuedAt = new Date().toISOString();

  const ownerPayload = {
    v: 1,
    tier: "owner",
    keyId: "PV-OWNER-01",
    label: "PromptVeil Owner Master",
    issuedAt,
  };
  const ownerKey = {
    ...ownerPayload,
    token: signProToken(ownerPayload, privateKey),
  };

  const clientKeys = [];
  for (let i = 1; i <= 20; i += 1) {
    const num = String(i).padStart(2, "0");
    const payload = {
      v: 1,
      tier: "pro",
      keyId: `PV-CLIENT-${num}`,
      label: `PromptVeil Pro Client #${num}`,
      issuedAt,
    };
    clientKeys.push({
      ...payload,
      token: signProToken(payload, privateKey),
    });
  }

  for (const item of [ownerKey, ...clientKeys]) {
    const check = verifyTokenWithRawPublicKey(item.token, publicKeyB64U);
    if (!check.valid) {
      throw new Error(`Self-verification failed for ${item.keyId}: ${check.reason}`);
    }
  }

  const bundle = {
    format: "PV1",
    algorithm: "Ed25519",
    generatedAt: issuedAt,
    publicKeyB64U,
    publicKeySpkiPem,
    privateKeyPkcs8Pem,
    ownerKey,
    clientKeys,
  };

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(bundle, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });

  if (handoffDir) {
    fs.mkdirSync(handoffDir, { recursive: true });
    fs.writeFileSync(
      path.join(handoffDir, "pro_keys_backup.json"),
      `${JSON.stringify(bundle, null, 2)}\n`,
      { encoding: "utf8", mode: 0o600 }
    );

    const rows = [
      "# PromptVeil Pro Keys Handoff",
      "",
      `- **Generated At**: ${issuedAt}`,
      `- **Algorithm**: Ed25519 (\`PV1\`)`,
      `- **Public Key (base64url)**: \`${publicKeyB64U}\``,
      `- **Local Secrets Bundle**: \`${outPath}\``,
      "",
      "## Owner Master Key",
      "",
      `| Key ID | Tier | Label | Activation Token |`,
      `|---|---|---|---|`,
      `| \`${ownerKey.keyId}\` | \`${ownerKey.tier}\` | ${ownerKey.label} | \`${ownerKey.token}\` |`,
      "",
      "## Client Pro Keys (20)",
      "",
      `| # | Key ID | Tier | Label | Activation Token |`,
      `|---|---|---|---|---|`,
      ...clientKeys.map(
        (k, idx) => `| ${idx + 1} | \`${k.keyId}\` | \`${k.tier}\` | ${k.label} | \`${k.token}\` |`
      ),
      "",
    ];
    fs.writeFileSync(path.join(handoffDir, "PRO_KEYS_TABLE.md"), rows.join("\n"), "utf8");
  }

  let codePub = expectedPublicKeyB64U;
  if (!codePub) {
    try {
      codePub = readPublicKeyFromLicenseJs();
    } catch {
      codePub = "";
    }
  }

  return {
    ok: true,
    outPath,
    handoffDir: handoffDir || null,
    publicKeyB64U,
    publicKeyMatchesCode: Boolean(codePub && publicKeyB64U === codePub),
    ownerKeysCount: 1,
    clientKeysCount: clientKeys.length,
  };
}

function clientInputError(message) {
  const err = new Error(message);
  err.statusCode = 400;
  return err;
}

function parseNowMs(nowValue) {
  if (nowValue === undefined || nowValue === null || nowValue === "") {
    return Date.now();
  }
  const ms = Date.parse(String(nowValue));
  if (Number.isNaN(ms)) {
    throw clientInputError(`Invalid --now timestamp: ${nowValue}`);
  }
  return ms;
}

function safeFileSegment(name) {
  return String(name).replace(/[^A-Za-z0-9._-]+/g, "_");
}

export function issueTokens(options = {}) {
  const bundlePath = path.resolve(String(options.bundlePath || DEFAULT_BUNDLE_PATH));
  const bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
  const { privateKey, derivedPubB64U } = derivePublicKeyFromBundlePrivateKey(bundle);
  if (derivedPubB64U !== bundle.publicKeyB64U) {
    throw new Error(
      `Bundle private key mismatch: derived public key ${derivedPubB64U} does not match bundle.publicKeyB64U ${bundle.publicKeyB64U}`
    );
  }

  const expectedPub = options.expectedPublicKeyB64U
    ? String(options.expectedPublicKeyB64U)
    : readPublicKeyFromLicenseJs();
  if (bundle.publicKeyB64U !== expectedPub) {
    throw new Error(
      `Bundle public key mismatch against PRO_PUBLIC_KEY_B64U: bundle=${bundle.publicKeyB64U}, expected=${expectedPub}. Pass --pub to override.`
    );
  }

  for (const field of ["plan", "tier", "keyId", "prefix", "label", "orderId"]) {
    if (options[field] !== undefined && options[field] !== null) {
      if (typeof options[field] !== "string") {
        throw clientInputError(`${field} must be a string`);
      }
      if (options[field].trim() === "") {
        throw clientInputError(`${field} cannot be empty`);
      }
    }
  }

  const planName = options.plan ? String(options.plan).trim() : "";
  let preset = null;
  if (planName) {
    preset = PLAN_PRESETS[planName];
    if (!preset) {
      throw clientInputError(
        `Unknown --plan "${planName}". Allowed: ${Object.keys(PLAN_PRESETS).join(", ")}`
      );
    }
  }

  const tier = options.tier ? String(options.tier).trim() : preset?.tier || "pro";
  if (tier !== "pro" && tier !== "owner") {
    throw clientInputError(`Invalid --tier "${tier}". Allowed: pro, owner`);
  }

  if (
    options.count !== undefined &&
    options.count !== null &&
    typeof options.count !== "number" &&
    typeof options.count !== "string"
  ) {
    throw clientInputError(`Invalid --count "${options.count}". Must be an integer between 1 and 1000.`);
  }
  const count = options.count === undefined ? 1 : Number(options.count);
  if (!Number.isInteger(count) || count < 1 || count > 1000) {
    throw clientInputError(`Invalid --count "${options.count}". Must be an integer between 1 and 1000.`);
  }

  if (count > 1 && options.keyId) {
    throw clientInputError("Use --prefix instead of --key-id when --count > 1");
  }

  const hasDays = options.days !== undefined && options.days !== null && options.days !== "";
  const hasExp = options.exp !== undefined && options.exp !== null && options.exp !== "";
  if (hasDays && hasExp) {
    throw clientInputError("Cannot specify both --days and --exp");
  }

  const nowMs = options.nowMs !== undefined ? options.nowMs : parseNowMs(options.now);
  if (typeof nowMs !== "number" || !Number.isFinite(nowMs) || Math.abs(nowMs) > 8.64e15) {
    throw clientInputError(`Invalid nowMs timestamp: ${nowMs}`);
  }
  const issuedAt = new Date(nowMs).toISOString();

  let itemExp;
  if (hasDays) {
    if (typeof options.days !== "number" && typeof options.days !== "string") {
      throw clientInputError(`Invalid --days "${options.days}". Must be a positive number.`);
    }
    const daysNum = Number(options.days);
    if (!Number.isFinite(daysNum) || daysNum <= 0) {
      throw clientInputError(`Invalid --days "${options.days}". Must be a positive number.`);
    }
    const expMs = nowMs + daysNum * 86400000;
    if (!Number.isFinite(expMs) || Math.abs(expMs) > 8.64e15) {
      throw clientInputError("Invalid --days: expiration timestamp out of range");
    }
    const truncatedExpMs = new Date(expMs).getTime();
    if (!Number.isFinite(truncatedExpMs) || truncatedExpMs <= nowMs) {
      throw clientInputError(`Invalid --days "${options.days}": expiration timestamp must be in the future.`);
    }
    itemExp = new Date(truncatedExpMs).toISOString();
  } else if (hasExp) {
    if (typeof options.exp !== "number" && typeof options.exp !== "string") {
      throw clientInputError(`Invalid --exp "${options.exp}".`);
    }
    const rawExp = options.exp;
    const expMs = parseExpirationMs(rawExp);
    if (expMs === null || !Number.isFinite(expMs) || Math.abs(expMs) > 8.64e15) {
      throw clientInputError(`Invalid --exp "${rawExp}".`);
    }
    if (expMs <= nowMs) {
      throw clientInputError(`Invalid --exp "${rawExp}": expiration timestamp must be in the future.`);
    }
    itemExp = typeof rawExp === "number" ? rawExp : new Date(expMs).toISOString();
  } else if (preset && preset.days !== null) {
    const expMs = nowMs + preset.days * 86400000;
    if (!Number.isFinite(expMs) || Math.abs(expMs) > 8.64e15) {
      throw clientInputError("Invalid --days: expiration timestamp out of range");
    }
    itemExp = new Date(expMs).toISOString();
  }

  const orderId = options.orderId ? String(options.orderId).trim() : "";
  const baseLabel = options.label
    ? String(options.label).trim()
    : preset?.label || (tier === "owner" ? "PromptVeil Owner Custom" : "PromptVeil Pro Custom");
  if (!baseLabel) {
    throw clientInputError("Label cannot be empty");
  }
  const finalLabel = orderId && !baseLabel.includes(orderId) ? `${baseLabel} (${orderId})` : baseLabel;

  const prefix = options.prefix
    ? String(options.prefix).trim()
    : preset?.prefix || (tier === "owner" ? "PV-OWNER" : "PV-CUSTOM");
  if (!prefix) {
    throw clientInputError("Prefix cannot be empty");
  }

  if (options.keyId !== undefined && options.keyId !== null && options.keyId !== "" && !String(options.keyId).trim()) {
    throw clientInputError("Key ID cannot be empty");
  }

  const padWidth = Math.max(2, String(count).length);
  const items = [];
  for (let i = 1; i <= count; i += 1) {
    const itemKeyId =
      count === 1 && options.keyId
        ? String(options.keyId).trim()
        : count > 1
          ? `${prefix}-${String(i).padStart(padWidth, "0")}`
          : `${prefix}-${nowMs}`;

    const payload = {
      v: 1,
      tier,
      keyId: itemKeyId,
      label: finalLabel,
      issuedAt,
      ...(itemExp !== undefined ? { exp: itemExp } : {}),
    };
    const token = signProToken(payload, privateKey);
    const check = verifyTokenWithRawPublicKey(token, bundle.publicKeyB64U, { nowMs });
    if (!check.valid) {
      throw new Error(`Issued token failed self-check for ${itemKeyId}: ${check.reason}`);
    }
    const pvkeyContent = formatPvKeyContent(token, {
      keyId: itemKeyId,
      tier,
      label: finalLabel,
      plan: planName,
      orderId,
      issuedAt,
      exp: itemExp ?? null,
    });
    items.push({
      keyId: itemKeyId,
      tier,
      plan: planName,
      orderId,
      label: finalLabel,
      issuedAt,
      exp: itemExp ?? null,
      token,
      redactedToken: redactToken(token),
      pvkeyContent,
    });
  }

  const writtenPvKeys = [];
  if (options.outPvkey) {
    const rawTarget = path.resolve(String(options.outPvkey));
    const targetExists = fs.existsSync(rawTarget);
    const isExistingDir = targetExists && fs.statSync(rawTarget).isDirectory();
    const isExistingFile = targetExists && fs.statSync(rawTarget).isFile();
    const endsWithSep = String(options.outPvkey).endsWith("/") || String(options.outPvkey).endsWith("\\");

    if (count > 1) {
      if (isExistingFile) {
        throw new Error(`--out-pvkey must be a directory when --count > 1 (got file: ${rawTarget})`);
      }
      fs.mkdirSync(rawTarget, { recursive: true });
      for (const item of items) {
        const filePath = path.join(rawTarget, `${safeFileSegment(item.keyId)}.pvkey`);
        fs.writeFileSync(filePath, item.pvkeyContent, { encoding: "utf8", mode: 0o600 });
        writtenPvKeys.push(filePath);
      }
    } else {
      const targetFile =
        isExistingDir || endsWithSep
          ? path.join(rawTarget, `${safeFileSegment(items[0].keyId)}.pvkey`)
          : rawTarget;
      fs.mkdirSync(path.dirname(targetFile), { recursive: true });
      fs.writeFileSync(targetFile, items[0].pvkeyContent, { encoding: "utf8", mode: 0o600 });
      writtenPvKeys.push(targetFile);
    }
  }

  let tableOutput = "";
  let outTablePath = null;
  if (options.outTable) {
    const tableArg = String(options.outTable).trim();
    const lower = tableArg.toLowerCase();
    if (lower === "md" || lower === "csv" || lower === "json") {
      tableOutput = formatIssuedTable(items, lower, { redact: Boolean(options.redact) });
    } else {
      const resolvedTablePath = path.resolve(tableArg);
      const ext = path.extname(resolvedTablePath).toLowerCase();
      const fmt = ext === ".csv" ? "csv" : ext === ".json" ? "json" : "md";
      tableOutput = formatIssuedTable(items, fmt, { redact: Boolean(options.redact) });
      fs.mkdirSync(path.dirname(resolvedTablePath), { recursive: true });
      fs.writeFileSync(resolvedTablePath, tableOutput, "utf8");
      outTablePath = resolvedTablePath;
    }
  }

  let ledgerPath = null;
  if (options.appendLedger) {
    ledgerPath = path.resolve(String(options.ledgerPath || DEFAULT_LEDGER_PATH));
    appendLedgerEntries(ledgerPath, items, {
      publicKeyB64U: bundle.publicKeyB64U,
      nowIso: issuedAt,
    });
  }

  return {
    ok: true,
    bundlePath,
    publicKeyB64U: bundle.publicKeyB64U,
    count: items.length,
    plan: planName || null,
    orderId: orderId || null,
    writtenPvKeys,
    outTablePath,
    tableOutput: outTablePath ? null : tableOutput || null,
    ledgerPath,
    items,
  };
}

export function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const raw = argv[i];
    if (raw === "-h") {
      args.help = true;
      continue;
    }
    if (raw.startsWith("--")) {
      const eqIdx = raw.indexOf("=");
      if (eqIdx !== -1) {
        const key = raw.slice(2, eqIdx);
        const val = raw.slice(eqIdx + 1);
        args[key] = BOOLEAN_FLAGS.has(key) ? val !== "false" && val !== "0" : val;
        continue;
      }
      const key = raw.slice(2);
      if (BOOLEAN_FLAGS.has(key)) {
        args[key] = true;
        continue;
      }
      const next = argv[i + 1];
      if (!next || next.startsWith("--")) {
        args[key] = true;
      } else {
        args[key] = next;
        i += 1;
      }
    } else {
      args._.push(raw);
    }
  }
  return args;
}

function getUsageText() {
  return [
    "PromptVeil Offline Ed25519 Pro Key Tool",
    "",
    "Usage:",
    "  node scripts/issue-pro-key.mjs --generate-bundle [--out <path>] [--handoff-dir <dir>] [--json]",
    "  node scripts/issue-pro-key.mjs --issue [--bundle <path>] [--pub <b64u>] [--plan <pro-monthly|pro-annual|pro-lifetime|team-pack>] [--tier pro|owner] [--key-id <id>] [--prefix <prefix>] [--count <n>] [--label <label>] [--order <id>] [--days <n> | --exp <iso>] [--now <iso>] [--out-pvkey <path|dir>] [--out-table <md|csv|json|path>] [--append-ledger] [--ledger <path>] [--redact] [--json]",
    "  node scripts/issue-pro-key.mjs --verify [<token>] [--file <path>] [--pub <b64u>] [--now <iso>] [--redact] [--json]",
    "  node scripts/issue-pro-key.mjs --inspect-bundle [--bundle <path>] [--pub <b64u>] [--now <iso>] [--redact] [--json]",
    "  node scripts/issue-pro-key.mjs --verify-bundle [--bundle <path>] [--pub <b64u>] [--now <iso>] [--redact] [--json]",
  ].join("\n");
}

function formatIssueResponseForDisplay(result, redact) {
  return {
    ok: result.ok,
    bundlePath: result.bundlePath,
    publicKeyB64U: result.publicKeyB64U,
    count: result.count,
    plan: result.plan,
    orderId: result.orderId,
    writtenPvKeys: result.writtenPvKeys,
    outTablePath: result.outTablePath,
    ...(result.tableOutput ? { tableOutput: result.tableOutput } : {}),
    ledgerPath: result.ledgerPath,
    items: result.items.map((item) => ({
      keyId: item.keyId,
      tier: item.tier,
      plan: item.plan,
      orderId: item.orderId,
      label: item.label,
      issuedAt: item.issuedAt,
      exp: item.exp,
      token: redact ? item.redactedToken : item.token,
      redactedToken: item.redactedToken,
    })),
  };
}

export function runCli(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const asJson = Boolean(args.json);
  const redact = Boolean(args.redact);

  try {
    if (args.help) {
      console.log(getUsageText());
      return 0;
    }

    const VALUE_FLAGS = [
      "out",
      "handoff-dir",
      "bundle",
      "pub",
      "plan",
      "tier",
      "key-id",
      "prefix",
      "count",
      "label",
      "order",
      "days",
      "exp",
      "now",
      "out-pvkey",
      "out-table",
      "ledger",
      "file",
    ];
    for (const flag of VALUE_FLAGS) {
      if (args[flag] === true || (typeof args[flag] === "string" && args[flag].trim() === "")) {
        throw clientInputError(`Missing value for --${flag}`);
      }
    }

    if (args["generate-bundle"]) {
      const result = generateBundle({
        outPath: path.resolve(String(args.out || DEFAULT_BUNDLE_PATH)),
        handoffDir: args["handoff-dir"] ? path.resolve(String(args["handoff-dir"])) : null,
        expectedPublicKeyB64U: args.pub ? String(args.pub) : undefined,
      });
      if (asJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(`Generated Ed25519 bundle at ${result.outPath}`);
        console.log(`PRO_PUBLIC_KEY_B64U=${result.publicKeyB64U}`);
        console.log(`Owner keys: ${result.ownerKeysCount}, Client keys: ${result.clientKeysCount}`);
        if (!result.publicKeyMatchesCode) {
          console.log(
            "Note: Generated public key differs from PRO_PUBLIC_KEY_B64U in app/static/js/pro-license.js."
          );
        }
      }
      return 0;
    }

    if (args.issue) {
      const result = issueTokens({
        bundlePath: args.bundle ? String(args.bundle) : DEFAULT_BUNDLE_PATH,
        expectedPublicKeyB64U: args.pub ? String(args.pub) : undefined,
        plan: typeof args.plan === "string" ? args.plan : undefined,
        tier: typeof args.tier === "string" ? args.tier : undefined,
        keyId: typeof args["key-id"] === "string" ? args["key-id"] : undefined,
        prefix: typeof args.prefix === "string" ? args.prefix : undefined,
        count: args.count,
        label: typeof args.label === "string" ? args.label : undefined,
        orderId: typeof args.order === "string" ? args.order : undefined,
        days: args.days,
        exp: args.exp,
        now: args.now,
        outPvkey: typeof args["out-pvkey"] === "string" ? args["out-pvkey"] : undefined,
        outTable: typeof args["out-table"] === "string" ? args["out-table"] : undefined,
        appendLedger: Boolean(args["append-ledger"]),
        ledgerPath: typeof args.ledger === "string" ? args.ledger : undefined,
        redact,
      });

      if (asJson) {
        console.log(JSON.stringify(formatIssueResponseForDisplay(result, redact), null, 2));
      } else if (result.tableOutput) {
        process.stdout.write(result.tableOutput);
      } else {
        for (const item of result.items) {
          console.log(redact ? item.redactedToken : item.token);
        }
      }
      return 0;
    }

    if (args.verify !== undefined) {
      const nowMs = parseNowMs(args.now);
      let rawInput = typeof args.verify === "string" ? args.verify : args._[0] || "";
      if (typeof args.file === "string") {
        const fileText = fs.readFileSync(path.resolve(args.file), "utf8");
        rawInput = extractProToken(fileText) || fileText.trim();
      } else if (rawInput) {
        const extracted = extractProToken(rawInput);
        if (extracted) {
          rawInput = extracted;
        }
      }
      const pub = args.pub ? String(args.pub) : readPublicKeyFromLicenseJs();
      const res = verifyTokenWithRawPublicKey(rawInput, pub, { nowMs });
      const output = {
        ...res,
        publicKeyB64U: pub,
        ...(rawInput ? { token: redact ? redactToken(rawInput) : rawInput } : {}),
      };
      console.log(JSON.stringify(output));
      return res.valid ? 0 : 1;
    }

    if (args["inspect-bundle"] || args["verify-bundle"]) {
      const strictCodeMatch = Boolean(args["verify-bundle"]);
      const bundlePath = path.resolve(String(args.bundle || DEFAULT_BUNDLE_PATH));
      const bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
      const expectedPub = args.pub ? String(args.pub) : readPublicKeyFromLicenseJs();
      const nowMs = parseNowMs(args.now);
      const report = verifyBundleObject(bundle, {
        expectedPublicKeyB64U: expectedPub,
        nowMs,
        strictCodeMatch,
      });

      const formatted = {
        ok: report.ok,
        bundlePath,
        publicKeyB64U: report.bundlePublicKeyB64U,
        expectedPublicKeyB64U: report.expectedPublicKeyB64U,
        publicKeyMatchesCode: report.publicKeyMatchesCode,
        privateKeyMatchesPublic: report.privateKeyMatchesPublic,
        hasPrivateKey: report.hasPrivateKey,
        totalEntries: report.totalEntries,
        validEntries: report.validEntries,
        failures: report.failures,
        entries: report.entries.map((entry) => ({
          kind: entry.kind,
          keyId: entry.keyId,
          tier: entry.tier,
          label: entry.label,
          issuedAt: entry.issuedAt,
          exp: entry.exp,
          valid: entry.valid,
          reason: entry.reason,
          token: redact ? redactToken(entry.token) : entry.token,
        })),
      };

      if (asJson) {
        console.log(JSON.stringify(formatted, null, 2));
      } else {
        console.log(`Bundle: ${bundlePath}`);
        console.log(`Public Key: ${formatted.publicKeyB64U}`);
        console.log(`Matches PRO_PUBLIC_KEY_B64U: ${formatted.publicKeyMatchesCode}`);
        console.log(`Private Key Consistent: ${formatted.privateKeyMatchesPublic}`);
        console.log(`Entries Valid: ${formatted.validEntries}/${formatted.totalEntries}`);
        if (formatted.failures.length > 0) {
          for (const f of formatted.failures) {
            console.log(`FAIL [${f.kind}] ${f.keyId}: ${f.reason}`);
          }
        }
      }
      return strictCodeMatch && !report.ok ? 1 : 0;
    }

    if (asJson) {
      console.log(JSON.stringify({ ok: false, error: "No command specified. Use --help." }));
    } else {
      console.error(getUsageText());
    }
    return 1;
  } catch (err) {
    if (asJson) {
      console.log(JSON.stringify({ ok: false, error: err.message }));
    } else {
      console.error(`Error: ${err.message}`);
    }
    return 1;
  }
}

function isMainModule(metaUrl) {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync(path.resolve(process.argv[1])) === fs.realpathSync(fileURLToPath(metaUrl));
  } catch {
    return path.resolve(process.argv[1]) === fileURLToPath(metaUrl);
  }
}

if (isMainModule(import.meta.url)) {
  const code = runCli(process.argv.slice(2));
  if (code !== 0) {
    process.exit(code);
  }
}
