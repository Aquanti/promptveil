#!/usr/bin/env node
/**
 * Local-only PromptVeil Owner Key Console (loopback HTTP server + CSP-strict UI).
 * Strictly bound to 127.0.0.1 / localhost / ::1 and kept outside app/static/.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  PRO_PUBLIC_KEY_B64U,
  decodeProTokenPayloadUnsafe,
  extractProToken,
  formatPvKeyFileContent,
  verifyProLicenseToken,
} from "../app/static/js/pro-license.js";
import {
  DEFAULT_BUNDLE_PATH,
  DEFAULT_LEDGER_PATH,
  PLAN_PRESETS,
  extractRawPublicKeyB64U,
  issueTokens,
  parseArgs,
  redactToken,
  verifyTokenWithRawPublicKey,
} from "./issue-pro-key.mjs";

export const OWNER_CONSOLE_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);
const MAX_BODY_BYTES = 64 * 1024;
const DEFAULT_ACTIVATION_URL_RU = "https://promptveil.netlify.app/pro/";
const DEFAULT_ACTIVATION_URL_EN = "https://promptveil.netlify.app/en/pro/";

export function assertLoopbackHost(host = "127.0.0.1") {
  let normalized = String(host ?? "").trim();
  if (normalized === "[::1]") {
    normalized = "::1";
  }
  if (normalized.toLowerCase() === "localhost") {
    normalized = "localhost";
  }
  if (!LOOPBACK_HOSTS.has(normalized)) {
    throw new Error(
      `Refusing non-loopback host "${host}". Owner console allows only 127.0.0.1, localhost, or ::1.`
    );
  }
  return normalized;
}

function isAllowedHostHeader(hostHeader) {
  if (typeof hostHeader !== "string" || !hostHeader.trim()) {
    return false;
  }
  const value = hostHeader.trim().toLowerCase();
  return (
    /^127\.0\.0\.1(?::\d{1,5})?$/.test(value) ||
    /^localhost(?::\d{1,5})?$/.test(value) ||
    /^\[::1\](?::\d{1,5})?$/.test(value)
  );
}

function normalizeLoopbackHostname(raw) {
  return String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, "");
}

function parseLoopbackHostHeader(hostHeader) {
  if (typeof hostHeader !== "string") {
    return null;
  }
  const value = hostHeader.trim().toLowerCase();
  const ipv6Match = value.match(/^\[(::1)\](?::(\d{1,5}))?$/);
  if (ipv6Match) {
    return { hostname: ipv6Match[1], port: ipv6Match[2] || "80" };
  }
  const v4OrLocalMatch = value.match(/^(127\.0\.0\.1|localhost)(?::(\d{1,5}))?$/);
  if (v4OrLocalMatch) {
    return { hostname: v4OrLocalMatch[1], port: v4OrLocalMatch[2] || "80" };
  }
  return null;
}

function isAllowedLoopbackUrlHeader(urlHeader, hostHeader) {
  if (typeof urlHeader !== "string" || !urlHeader.trim() || urlHeader === "null") {
    return false;
  }
  const hostInfo = parseLoopbackHostHeader(hostHeader);
  if (!hostInfo) {
    return false;
  }
  try {
    const parsed = new URL(urlHeader);
    if (parsed.protocol !== "http:") {
      return false;
    }
    const hostname = normalizeLoopbackHostname(parsed.hostname);
    if (!LOOPBACK_HOSTS.has(hostname) || hostname !== hostInfo.hostname) {
      return false;
    }
    const port = parsed.port || "80";
    if (port !== hostInfo.port) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function isAllowedOriginHeader(originHeader, hostHeader) {
  if (originHeader === undefined) {
    return true;
  }
  return isAllowedLoopbackUrlHeader(originHeader, hostHeader);
}

function isAllowedRefererHeader(refererHeader, hostHeader) {
  if (refererHeader === undefined) {
    return true;
  }
  return isAllowedLoopbackUrlHeader(refererHeader, hostHeader);
}

function isAllowedStateChangingRequest(req) {
  if (req.headers.origin !== undefined) {
    return isAllowedOriginHeader(req.headers.origin, req.headers.host);
  }
  return isAllowedRefererHeader(req.headers.referer, req.headers.host);
}

export function loadOwnerBundleStatus(
  bundlePath = DEFAULT_BUNDLE_PATH,
  { expectedPublicKeyB64U = PRO_PUBLIC_KEY_B64U, redact = true } = {}
) {
  const resolvedPath = path.resolve(String(bundlePath || DEFAULT_BUNDLE_PATH));
  if (!fs.existsSync(resolvedPath)) {
    return {
      loaded: false,
      bundlePath: resolvedPath,
      expectedPublicKeyB64U,
      publicKeyB64U: "",
      publicKeyMatchesApp: false,
      privateKeyMatchesPublic: false,
      hasPrivateKey: false,
      redacted: Boolean(redact),
      ownerKey: null,
      clientKeys: [],
      clientCount: 0,
      error: `Bundle file not found: ${resolvedPath}`,
    };
  }

  let bundle;
  try {
    bundle = JSON.parse(fs.readFileSync(resolvedPath, "utf8"));
  } catch (err) {
    return {
      loaded: false,
      bundlePath: resolvedPath,
      expectedPublicKeyB64U,
      publicKeyB64U: "",
      publicKeyMatchesApp: false,
      privateKeyMatchesPublic: false,
      hasPrivateKey: false,
      redacted: Boolean(redact),
      ownerKey: null,
      clientKeys: [],
      clientCount: 0,
      error: `Invalid bundle JSON: ${err.message}`,
    };
  }

  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) {
    return {
      loaded: false,
      bundlePath: resolvedPath,
      expectedPublicKeyB64U,
      publicKeyB64U: "",
      publicKeyMatchesApp: false,
      privateKeyMatchesPublic: false,
      hasPrivateKey: false,
      redacted: Boolean(redact),
      ownerKey: null,
      clientKeys: [],
      clientCount: 0,
      error: "Invalid bundle JSON: expected JSON object",
    };
  }

  const publicKeyB64U = typeof bundle?.publicKeyB64U === "string" ? bundle.publicKeyB64U : "";
  const hasPrivateKey =
    typeof bundle?.privateKeyPkcs8Pem === "string" && bundle.privateKeyPkcs8Pem.trim().length > 0;
  let privateKeyMatchesPublic = false;
  let keyError = "";

  if (hasPrivateKey) {
    try {
      const priv = crypto.createPrivateKey(bundle.privateKeyPkcs8Pem);
      const pub = crypto.createPublicKey(priv);
      const derived = extractRawPublicKeyB64U(pub);
      privateKeyMatchesPublic = derived === publicKeyB64U;
      if (!privateKeyMatchesPublic) {
        keyError = `Private key derives ${derived}, expected ${publicKeyB64U}`;
      }
    } catch (err) {
      keyError = `Invalid privateKeyPkcs8Pem: ${err.message}`;
    }
  } else {
    keyError = "Bundle is missing privateKeyPkcs8Pem";
  }

  const mapEntry = (entry, kind) => {
    if (!entry || typeof entry !== "object") return null;
    const rawToken = typeof entry.token === "string" ? entry.token : "";
    const masked = redactToken(rawToken);
    const check = rawToken
      ? verifyTokenWithRawPublicKey(rawToken, publicKeyB64U)
      : { valid: false, reason: "empty" };
    return {
      kind,
      keyId: String(entry.keyId || ""),
      tier: String(entry.tier || ""),
      label: String(entry.label || ""),
      issuedAt: String(entry.issuedAt || ""),
      exp: entry.exp ?? null,
      valid: Boolean(check.valid),
      reason: check.reason || (check.valid ? "valid" : "invalid"),
      redactedToken: masked,
      token: redact ? masked : rawToken,
      ...(redact ? {} : { pvkeyContent: formatPvKeyFileContent(rawToken, entry) }),
    };
  };

  const ownerKey = mapEntry(bundle.ownerKey, "owner");
  const clientKeys = Array.isArray(bundle.clientKeys)
    ? bundle.clientKeys.map((item, idx) => mapEntry(item, `client-${idx + 1}`)).filter(Boolean)
    : [];

  return {
    loaded: true,
    bundlePath: resolvedPath,
    format: String(bundle.format || "PV1"),
    algorithm: String(bundle.algorithm || "Ed25519"),
    generatedAt: String(bundle.generatedAt || ""),
    expectedPublicKeyB64U,
    publicKeyB64U,
    publicKeyMatchesApp: Boolean(publicKeyB64U && publicKeyB64U === expectedPublicKeyB64U),
    privateKeyMatchesPublic,
    hasPrivateKey,
    redacted: Boolean(redact),
    ownerKey,
    clientKeys,
    clientCount: clientKeys.length,
    ...(keyError ? { error: keyError } : {}),
  };
}

function buildSecurityHeaders(contentType) {
  return {
    "Content-Type": contentType,
    "Content-Security-Policy": OWNER_CONSOLE_CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
  };
}

function sendText(res, status, contentType, body, method = "GET", extraHeaders = {}) {
  const buf = Buffer.from(body, "utf8");
  res.writeHead(status, {
    ...buildSecurityHeaders(contentType),
    "Content-Length": String(buf.length),
    ...extraHeaders,
  });
  if (method === "HEAD") {
    res.end();
  } else {
    res.end(buf);
  }
}

function sendJson(res, status, data, method = "GET", extraHeaders = {}) {
  sendText(res, status, "application/json; charset=utf-8", `${JSON.stringify(data, null, 2)}\n`, method, extraHeaders);
}

async function readJsonBody(req) {
  return await new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;

    req.on("data", (chunk) => {
      if (settled) return;
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        settled = true;
        const err = new Error("Request body exceeds 64 KB limit");
        err.statusCode = 413;
        reject(err);
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (settled) return;
      settled = true;
      const raw = Buffer.concat(chunks).toString("utf8").trim();
      if (!raw) {
        resolve({});
        return;
      }
      try {
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          const err = new Error("JSON body must be an object");
          err.statusCode = 400;
          reject(err);
          return;
        }
        resolve(parsed);
      } catch {
        const err = new Error("Invalid JSON body");
        err.statusCode = 400;
        reject(err);
      }
    });
    req.on("error", (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
  });
}

const OWNER_CONSOLE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PromptVeil Owner Key Console (Local Loopback)</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div>
        <p class="eyebrow">Localhost Only · Zero Network Egress</p>
        <h1>PromptVeil Owner Key Console</h1>
      </div>
      <div class="topbar-actions">
        <span id="health-pill" class="badge badge-neutral">Connecting…</span>
        <button id="toggle-redact-btn" type="button" class="btn btn-secondary">Reveal Tokens</button>
      </div>
    </div>
  </header>

  <main class="container">
    <section class="card" aria-labelledby="bundle-heading">
      <div class="card-head">
        <h2 id="bundle-heading">Signing Bundle &amp; Public Key Parity</h2>
        <button id="refresh-status-btn" type="button" class="btn btn-ghost">Refresh</button>
      </div>
      <dl class="status-grid">
        <div><dt>Bundle Path</dt><dd id="status-bundle-path" class="mono">—</dd></div>
        <div><dt>Bundle State</dt><dd id="status-loaded">—</dd></div>
        <div><dt>App Public Key</dt><dd id="status-app-pub" class="mono">—</dd></div>
        <div><dt>Bundle Public Key</dt><dd id="status-bundle-pub" class="mono">—</dd></div>
        <div><dt>Key Parity</dt><dd id="status-match">—</dd></div>
        <div><dt>Private Key Check</dt><dd id="status-priv-check">—</dd></div>
      </dl>
      <p id="status-error" class="alert alert-warn" hidden></p>
    </section>

    <section class="grid-two">
      <section class="card" aria-labelledby="issue-heading">
        <h2 id="issue-heading">Issue Single / Batch Pro Keys</h2>
        <form id="issue-form" class="form-stack">
          <div class="form-row">
            <label for="issue-plan">Plan Preset</label>
            <select id="issue-plan" name="plan">
              <option value="pro-annual">pro-annual (365d)</option>
              <option value="pro-monthly">pro-monthly (30d)</option>
              <option value="pro-lifetime">pro-lifetime (no expiry)</option>
              <option value="team-pack">team-pack (365d)</option>
              <option value="custom">custom</option>
            </select>
          </div>
          <div class="form-grid-2">
            <div class="form-row">
              <label for="issue-tier">Tier</label>
              <select id="issue-tier" name="tier">
                <option value="pro">pro</option>
                <option value="owner">owner</option>
              </select>
            </div>
            <div class="form-row">
              <label for="issue-count">Count (1–100)</label>
              <input id="issue-count" name="count" type="number" min="1" max="100" value="1">
            </div>
          </div>
          <div class="form-grid-2">
            <div class="form-row">
              <label for="issue-key-id">Key ID (single only)</label>
              <input id="issue-key-id" name="keyId" type="text" placeholder="Auto from prefix if empty">
            </div>
            <div class="form-row">
              <label for="issue-prefix">Prefix (batch / auto)</label>
              <input id="issue-prefix" name="prefix" type="text" placeholder="PV-PRO-A">
            </div>
          </div>
          <div class="form-grid-2">
            <div class="form-row">
              <label for="issue-label">Customer / License Label</label>
              <input id="issue-label" name="label" type="text" placeholder="PromptVeil Pro Annual">
            </div>
            <div class="form-row">
              <label for="issue-order">Order Reference</label>
              <input id="issue-order" name="orderId" type="text" placeholder="PV-ORD-2026-001">
            </div>
          </div>
          <div class="form-grid-2">
            <div class="form-row">
              <label for="issue-days">Days Override</label>
              <input id="issue-days" name="days" type="number" min="1" placeholder="Optional">
            </div>
            <div class="form-row">
              <label for="issue-exp">Explicit Expires ISO</label>
              <input id="issue-exp" name="exp" type="text" placeholder="Optional ISO-8601">
            </div>
          </div>
          <label class="checkbox-row">
            <input id="issue-append-ledger" type="checkbox" checked>
            <span>Append issued record(s) to local <code>.secrets/issued_ledger.json</code></span>
          </label>
          <div class="actions-row">
            <button id="issue-submit-btn" type="submit" class="btn btn-primary">Issue Token(s)</button>
            <span id="issue-feedback" class="feedback" aria-live="polite"></span>
          </div>
        </form>
        <div id="issued-results" class="results-list"></div>
      </section>

      <section class="card" aria-labelledby="verify-heading">
        <h2 id="verify-heading">Token Validator &amp; Decoder</h2>
        <form id="verify-form" class="form-stack">
          <div class="form-row">
            <label for="verify-input">Paste PV1 Token, Order Receipt, #code= URL, or .pvkey Text</label>
            <textarea id="verify-input" rows="4" placeholder="PV1.... or https://promptveil.netlify.app/pro/#code=PV1..."></textarea>
          </div>
          <div class="form-row">
            <label for="verify-file">Or Load .pvkey / .txt File</label>
            <input id="verify-file" type="file" accept=".pvkey,.txt">
          </div>
          <div class="form-grid-2">
            <div class="form-row">
              <label for="verify-pub-mode">Verification Public Key</label>
              <select id="verify-pub-mode">
                <option value="app">App PRO_PUBLIC_KEY_B64U</option>
                <option value="bundle">Loaded Bundle Public Key</option>
                <option value="custom">Custom Public Key (b64u)</option>
              </select>
            </div>
            <div class="form-row">
              <label for="verify-now">Simulated Now (ISO optional)</label>
              <input id="verify-now" type="text" placeholder="2026-12-01T00:00:00Z">
            </div>
          </div>
          <div class="form-row" id="verify-custom-pub-wrap" hidden>
            <label for="verify-custom-pub">Custom Ed25519 Public Key (43-char base64url)</label>
            <input id="verify-custom-pub" type="text" class="mono" placeholder="43-char base64url">
          </div>
          <div class="actions-row">
            <button id="verify-submit-btn" type="submit" class="btn btn-primary">Verify &amp; Decode</button>
            <button id="verify-clear-btn" type="button" class="btn btn-ghost">Clear</button>
          </div>
        </form>
        <div id="verify-output" class="verify-box" hidden></div>
      </section>
    </section>

    <section class="card" aria-labelledby="keys-heading">
      <div class="card-head">
        <h2 id="keys-heading">Pre-Generated Bundle Keys</h2>
        <span id="keys-summary" class="muted">0 keys</span>
      </div>
      <div class="table-wrap">
        <table class="keys-table">
          <thead>
            <tr>
              <th>Key ID</th>
              <th>Tier</th>
              <th>Status</th>
              <th>Token</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="bundle-keys-tbody"></tbody>
        </table>
      </div>
    </section>
  </main>

  <script type="module" src="/app.js"></script>
</body>
</html>
`;

const OWNER_CONSOLE_CSS = `:root {
  --bg: #f6f8fb;
  --surface: #ffffff;
  --surface-muted: #f0f4f9;
  --border: #d7e0ec;
  --text: #0f172a;
  --muted: #475569;
  --primary: #0f766e;
  --primary-hover: #0d5e58;
  --ok-bg: #dcfce7;
  --ok-text: #166534;
  --warn-bg: #fef3c7;
  --warn-text: #92400e;
  --err-bg: #fee2e2;
  --err-text: #991b1b;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  line-height: 1.5;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  word-break: break-all;
}

.topbar {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 16px 20px;
}

.topbar-inner {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
}

.eyebrow {
  margin: 0 0 4px;
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--primary);
}

h1 {
  margin: 0;
  font-size: 22px;
}

h2 {
  margin: 0 0 12px;
  font-size: 17px;
}

.topbar-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}

.container {
  max-width: 1200px;
  margin: 20px auto 40px;
  padding: 0 16px;
  display: grid;
  gap: 16px;
}

.grid-two {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 16px;
}

.card {
  min-width: 0;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px;
}

.card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.card-head h2 {
  margin: 0;
}

.status-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
  margin: 0;
}

.status-grid dt {
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 2px;
}

.status-grid dd {
  min-width: 0;
  overflow-wrap: anywhere;
  margin: 0;
  font-size: 13px;
  font-weight: 600;
}

.form-stack {
  display: grid;
  gap: 12px;
}

.form-grid-2 {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px;
}

.form-row {
  min-width: 0;
  display: grid;
  gap: 4px;
}

label {
  font-size: 13px;
  font-weight: 600;
  color: var(--muted);
}

input[type="text"],
input[type="number"],
select,
textarea {
  width: 100%;
  padding: 8px 10px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
  color: var(--text);
  font: inherit;
  font-size: 13px;
}

.checkbox-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 500;
}

.checkbox-row input {
  width: auto;
}

.actions-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.btn {
  appearance: none;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 7px 12px;
  font: inherit;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  background: var(--surface);
  color: var(--text);
}

.btn-primary {
  background: var(--primary);
  border-color: var(--primary);
  color: #ffffff;
}

.btn-primary:hover {
  background: var(--primary-hover);
}

.btn-secondary {
  background: var(--surface-muted);
}

.btn-ghost {
  background: transparent;
}

.btn-sm {
  padding: 4px 8px;
  font-size: 12px;
}

.badge {
  display: inline-block;
  padding: 3px 9px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
}

.badge-ok {
  background: var(--ok-bg);
  color: var(--ok-text);
}

.badge-warn {
  background: var(--warn-bg);
  color: var(--warn-text);
}

.badge-err {
  background: var(--err-bg);
  color: var(--err-text);
}

.badge-neutral {
  background: var(--surface-muted);
  color: var(--muted);
}

.alert {
  margin: 12px 0 0;
  padding: 10px 12px;
  border-radius: 8px;
  font-size: 13px;
}

.alert-warn {
  background: var(--warn-bg);
  color: var(--warn-text);
}

.feedback {
  font-size: 13px;
  color: var(--muted);
}

.results-list {
  min-width: 0;
  margin-top: 14px;
  display: grid;
  gap: 10px;
}

.issued-item,
.verify-box {
  min-width: 0;
  max-width: 100%;
  overflow-wrap: anywhere;
  margin-top: 12px;
  padding: 12px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--surface-muted);
}

.issued-item pre,
.verify-box pre {
  margin: 8px 0 0;
  padding: 8px;
  border-radius: 6px;
  background: var(--surface);
  border: 1px solid var(--border);
  overflow-x: auto;
  font-size: 12px;
}

.table-wrap {
  overflow-x: auto;
}

.keys-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

.keys-table th,
.keys-table td {
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}

.keys-table th {
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
}

.muted {
  color: var(--muted);
  font-size: 13px;
}
`;

const OWNER_CONSOLE_JS = `let revealTokens = false;
let lastStatus = null;

function createBadge(text, kind = "neutral") {
  const span = document.createElement("span");
  span.className = "badge badge-" + kind;
  span.textContent = text;
  return span;
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    if (btn) {
      const prev = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(() => {
        btn.textContent = prev;
      }, 1200);
    }
  } catch {
    // Clipboard blocked; leave UI responsive without throwing.
  }
}

function downloadPvKey(keyId, content) {
  const safeName = (keyId || "promptveil-pro").replace(/[^A-Za-z0-9._-]+/g, "_");
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = safeName + ".pvkey";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function makeActionBtn(label, onClick) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-sm";
  btn.textContent = label;
  btn.addEventListener("click", () => onClick(btn));
  return btn;
}

function renderStatus(status) {
  lastStatus = status;
  document.getElementById("status-bundle-path").textContent = status.bundlePath || "—";
  document.getElementById("status-app-pub").textContent = status.expectedPublicKeyB64U || "—";
  document.getElementById("status-bundle-pub").textContent = status.publicKeyB64U || "—";

  const loadedEl = document.getElementById("status-loaded");
  loadedEl.replaceChildren(
    createBadge(status.loaded ? "Loaded" : "Missing", status.loaded ? "ok" : "err")
  );

  const matchEl = document.getElementById("status-match");
  matchEl.replaceChildren(
    createBadge(
      status.publicKeyMatchesApp ? "Matches PRO_PUBLIC_KEY_B64U" : "Mismatch",
      status.publicKeyMatchesApp ? "ok" : "warn"
    )
  );

  const privEl = document.getElementById("status-priv-check");
  privEl.replaceChildren(
    createBadge(
      status.privateKeyMatchesPublic ? "Private Key Verified" : "Unavailable / Mismatch",
      status.privateKeyMatchesPublic ? "ok" : "err"
    )
  );

  const errEl = document.getElementById("status-error");
  if (status.error) {
    errEl.hidden = false;
    errEl.textContent = status.error;
  } else {
    errEl.hidden = true;
    errEl.textContent = "";
  }

  const tbody = document.getElementById("bundle-keys-tbody");
  const allKeys = [];
  if (status.ownerKey) allKeys.push(status.ownerKey);
  if (Array.isArray(status.clientKeys)) allKeys.push(...status.clientKeys);
  document.getElementById("keys-summary").textContent = allKeys.length + " keys";

  const rows = allKeys.map((entry) => {
    const tr = document.createElement("tr");

    const tdId = document.createElement("td");
    tdId.className = "mono";
    tdId.textContent = entry.keyId;

    const tdTier = document.createElement("td");
    tdTier.textContent = entry.tier;

    const tdStatus = document.createElement("td");
    tdStatus.replaceChildren(
      createBadge(entry.valid ? "valid" : entry.reason, entry.valid ? "ok" : "err")
    );

    const tdToken = document.createElement("td");
    tdToken.className = "mono";
    tdToken.textContent = entry.token || entry.redactedToken;

    const tdActions = document.createElement("td");
    const actWrap = document.createElement("div");
    actWrap.className = "actions-row";

    actWrap.appendChild(
      makeActionBtn("Verify", () => {
        if (entry.token && !status.redacted) {
          document.getElementById("verify-input").value = entry.token;
          document.getElementById("verify-pub-mode").value = "bundle";
          runVerify();
        } else {
          document.getElementById("verify-input").value = "";
          alertRevealNeeded();
        }
      })
    );

    if (!status.redacted && entry.token) {
      actWrap.appendChild(makeActionBtn("Copy Token", (btn) => copyText(entry.token, btn)));
      actWrap.appendChild(
        makeActionBtn("Copy #code Link", (btn) =>
          copyText(status.activationBaseUrl + "#code=" + entry.token, btn)
        )
      );
      actWrap.appendChild(
        makeActionBtn("Download .pvkey", () =>
          downloadPvKey(entry.keyId, entry.pvkeyContent || entry.token + "\\n")
        )
      );
    }

    tdActions.appendChild(actWrap);
    tr.append(tdId, tdTier, tdStatus, tdToken, tdActions);
    return tr;
  });

  tbody.replaceChildren(...rows);
}

function alertRevealNeeded() {
  const box = document.getElementById("verify-output");
  box.hidden = false;
  box.replaceChildren(
    createBadge("Click Reveal Tokens first to load raw token into Validator", "warn")
  );
}

async function refreshStatus() {
  const toggleBtn = document.getElementById("toggle-redact-btn");
  toggleBtn.textContent = revealTokens ? "Redact Tokens" : "Reveal Tokens";
  const res = await fetch("/api/status?reveal=" + (revealTokens ? "1" : "0"));
  const data = await res.json();
  renderStatus(data);
}

async function checkHealth() {
  const pill = document.getElementById("health-pill");
  try {
    const res = await fetch("/api/health");
    const data = await res.json();
    if (res.ok && data.status === "ok") {
      pill.className = "badge badge-ok";
      pill.textContent = "Loopback Active";
      return;
    }
  } catch {
    // Handled below.
  }
  pill.className = "badge badge-err";
  pill.textContent = "Offline";
}

function renderIssuedItems(data) {
  const root = document.getElementById("issued-results");
  if (!data.ok) {
    root.replaceChildren(createBadge(data.error || "Issue failed", "err"));
    return;
  }

  const cards = data.items.map((item) => {
    const box = document.createElement("div");
    box.className = "issued-item";

    const head = document.createElement("div");
    head.className = "actions-row";
    head.appendChild(createBadge(item.keyId, "ok"));
    head.appendChild(createBadge(item.tier, "neutral"));
    if (item.orderId) head.appendChild(createBadge(item.orderId, "neutral"));

    const tokenPre = document.createElement("pre");
    tokenPre.className = "mono";
    tokenPre.textContent = item.token;

    const actions = document.createElement("div");
    actions.className = "actions-row";
    actions.appendChild(makeActionBtn("Copy Token", (btn) => copyText(item.token, btn)));
    actions.appendChild(makeActionBtn("Copy RU #code", (btn) => copyText(item.activationUrlRu, btn)));
    actions.appendChild(makeActionBtn("Copy EN #code", (btn) => copyText(item.activationUrlEn, btn)));
    actions.appendChild(makeActionBtn("Download .pvkey", () => downloadPvKey(item.keyId, item.pvkeyContent)));
    actions.appendChild(
      makeActionBtn("Send to Validator", () => {
        document.getElementById("verify-input").value = item.token;
        document.getElementById("verify-pub-mode").value = data.publicKeyMatchesApp ? "app" : "bundle";
        runVerify();
      })
    );

    box.append(head, tokenPre, actions);
    return box;
  });

  root.replaceChildren(...cards);
}

async function runVerify() {
  const rawText = document.getElementById("verify-input").value;
  const mode = document.getElementById("verify-pub-mode").value;
  const nowIso = document.getElementById("verify-now").value.trim();

  let publicKeyB64U = "";
  if (mode === "bundle" && lastStatus?.publicKeyB64U) {
    publicKeyB64U = lastStatus.publicKeyB64U;
  } else if (mode === "custom") {
    publicKeyB64U = document.getElementById("verify-custom-pub").value.trim();
  } else if (lastStatus?.expectedPublicKeyB64U) {
    publicKeyB64U = lastStatus.expectedPublicKeyB64U;
  }

  const res = await fetch("/api/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rawText, publicKeyB64U, nowIso }),
  });
  const data = await res.json();
  const out = document.getElementById("verify-output");
  out.hidden = false;

  if (!res.ok || !data.ok) {
    out.replaceChildren(createBadge(data.error || "Verification request failed", "err"));
    return;
  }

  const summary = document.createElement("div");
  summary.className = "actions-row";
  summary.appendChild(
    createBadge(
      data.result.valid ? "VALID (" + data.result.tier + ")" : "INVALID: " + data.result.reason,
      data.result.valid ? "ok" : "err"
    )
  );
  summary.appendChild(
    createBadge(
      data.matchesAppPublicKey ? "Key = App Key" : "Key != App Key",
      data.matchesAppPublicKey ? "ok" : "warn"
    )
  );

  const pre = document.createElement("pre");
  pre.className = "mono";
  pre.textContent = JSON.stringify(
    {
      extractedToken: data.extractedToken,
      result: data.result,
      decodedPayload: data.decodedPayload,
    },
    null,
    2
  );

  out.replaceChildren(summary, pre);
}

document.getElementById("toggle-redact-btn").addEventListener("click", () => {
  revealTokens = !revealTokens;
  refreshStatus();
});

document.getElementById("refresh-status-btn").addEventListener("click", () => {
  refreshStatus();
});

document.getElementById("verify-pub-mode").addEventListener("change", (ev) => {
  document.getElementById("verify-custom-pub-wrap").hidden = ev.target.value !== "custom";
});

document.getElementById("verify-file").addEventListener("change", async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  document.getElementById("verify-input").value = await file.text();
  runVerify();
});

document.getElementById("verify-clear-btn").addEventListener("click", () => {
  document.getElementById("verify-input").value = "";
  document.getElementById("verify-output").hidden = true;
});

document.getElementById("verify-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  runVerify();
});

document.getElementById("issue-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const feedback = document.getElementById("issue-feedback");
  feedback.textContent = "Issuing…";
  const planVal = document.getElementById("issue-plan").value;
  const payload = {
    plan: planVal === "custom" ? "" : planVal,
    tier: document.getElementById("issue-tier").value,
    count: Number(document.getElementById("issue-count").value || 1),
    keyId: document.getElementById("issue-key-id").value.trim(),
    prefix: document.getElementById("issue-prefix").value.trim(),
    label: document.getElementById("issue-label").value.trim(),
    orderId: document.getElementById("issue-order").value.trim(),
    days: document.getElementById("issue-days").value.trim(),
    exp: document.getElementById("issue-exp").value.trim(),
    appendLedger: document.getElementById("issue-append-ledger").checked,
  };

  const res = await fetch("/api/issue", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  feedback.textContent = data.ok ? "Issued " + data.count + " key(s)" : data.error || "Failed";
  renderIssuedItems(data);
});

checkHealth();
refreshStatus();
`;

export function createOwnerConsoleHandler(options = {}) {
  const bundlePath = path.resolve(String(options.bundlePath || DEFAULT_BUNDLE_PATH));
  const ledgerPath = path.resolve(String(options.ledgerPath || DEFAULT_LEDGER_PATH));
  const expectedPublicKeyB64U = String(options.expectedPublicKeyB64U || PRO_PUBLIC_KEY_B64U);
  const activationBaseUrl = String(options.activationBaseUrl || DEFAULT_ACTIVATION_URL_RU);
  const activationBaseUrlEn = String(options.activationBaseUrlEn || DEFAULT_ACTIVATION_URL_EN);

  return async function ownerConsoleHandler(req, res) {
    const method = (req.method || "GET").toUpperCase();
    try {
      if (!isAllowedHostHeader(req.headers.host)) {
        sendJson(res, 403, { ok: false, error: "Forbidden Host header; loopback required" }, method);
        return;
      }

      const secFetchSite = req.headers["sec-fetch-site"];
      if (typeof secFetchSite === "string" && secFetchSite.toLowerCase() === "cross-site") {
        sendJson(res, 403, { ok: false, error: "Forbidden cross-site request" }, method);
        return;
      }

      const rawUrl = typeof req.url === "string" ? req.url : "/";
      if (!rawUrl.startsWith("/") || rawUrl.startsWith("//") || rawUrl.startsWith("/\\")) {
        sendJson(res, 400, { ok: false, error: "Invalid request target" }, method);
        return;
      }
      let url;
      try {
        url = new URL(rawUrl, "http://127.0.0.1");
      } catch {
        sendJson(res, 400, { ok: false, error: "Invalid request target" }, method);
        return;
      }
      if (url.origin !== "http://127.0.0.1") {
        sendJson(res, 400, { ok: false, error: "Invalid request target" }, method);
        return;
      }
      const pathname = url.pathname;

      if (pathname === "/favicon.ico") {
        if (method !== "GET" && method !== "HEAD") {
          sendJson(res, 405, { ok: false, error: "Method Not Allowed" }, method, { Allow: "GET, HEAD" });
          return;
        }
        res.writeHead(204, buildSecurityHeaders("image/x-icon"));
        res.end();
        return;
      }

      if (pathname === "/") {
        if (method !== "GET" && method !== "HEAD") {
          sendJson(res, 405, { ok: false, error: "Method Not Allowed" }, method, { Allow: "GET, HEAD" });
          return;
        }
        sendText(res, 200, "text/html; charset=utf-8", OWNER_CONSOLE_HTML, method);
        return;
      }

      if (pathname === "/styles.css") {
        if (method !== "GET" && method !== "HEAD") {
          sendJson(res, 405, { ok: false, error: "Method Not Allowed" }, method, { Allow: "GET, HEAD" });
          return;
        }
        sendText(res, 200, "text/css; charset=utf-8", OWNER_CONSOLE_CSS, method);
        return;
      }

      if (pathname === "/app.js") {
        if (method !== "GET" && method !== "HEAD") {
          sendJson(res, 405, { ok: false, error: "Method Not Allowed" }, method, { Allow: "GET, HEAD" });
          return;
        }
        sendText(res, 200, "text/javascript; charset=utf-8", OWNER_CONSOLE_JS, method);
        return;
      }

      if (pathname === "/api/health") {
        if (method !== "GET" && method !== "HEAD") {
          sendJson(res, 405, { ok: false, error: "Method Not Allowed" }, method, { Allow: "GET, HEAD" });
          return;
        }
        sendJson(
          res,
          200,
          {
            status: "ok",
            mode: "local-owner-console",
            expectedPublicKeyB64U,
          },
          method
        );
        return;
      }

      if (pathname === "/api/status") {
        if (method !== "GET" && method !== "HEAD") {
          sendJson(res, 405, { ok: false, error: "Method Not Allowed" }, method, { Allow: "GET, HEAD" });
          return;
        }
        const reveal = url.searchParams.get("reveal") === "1";
        const status = loadOwnerBundleStatus(bundlePath, {
          expectedPublicKeyB64U,
          redact: !reveal,
        });
        sendJson(
          res,
          200,
          {
            ok: true,
            activationBaseUrl,
            activationBaseUrlEn,
            plans: Object.keys(PLAN_PRESETS),
            ...status,
          },
          method
        );
        return;
      }

      if (pathname === "/api/issue") {
        if (method !== "POST") {
          sendJson(res, 405, { ok: false, error: "Method Not Allowed" }, method, { Allow: "POST" });
          return;
        }
        if (!isAllowedStateChangingRequest(req)) {
          sendJson(res, 403, { ok: false, error: "Forbidden Origin or Referer header" }, method);
          return;
        }

        const body = await readJsonBody(req);
        const status = loadOwnerBundleStatus(bundlePath, {
          expectedPublicKeyB64U,
          redact: true,
        });
        if (!status.loaded || !status.privateKeyMatchesPublic) {
          sendJson(
            res,
            400,
            { ok: false, error: status.error || "Signing bundle is not ready" },
            method
          );
          return;
        }

        for (const field of ["plan", "tier", "keyId", "prefix", "label", "orderId"]) {
          if (body[field] !== undefined && body[field] !== null && typeof body[field] !== "string") {
            sendJson(res, 400, { ok: false, error: `${field} must be a string` }, method);
            return;
          }
        }

        for (const field of ["count", "days", "exp"]) {
          const val = body[field];
          if (
            val !== undefined &&
            val !== null &&
            typeof val !== "number" &&
            typeof val !== "string"
          ) {
            sendJson(res, 400, { ok: false, error: `${field} must be a number or string` }, method);
            return;
          }
        }

        const count = body.count === undefined ? 1 : Number(body.count);
        if (!Number.isInteger(count) || count < 1 || count > 100) {
          sendJson(res, 400, { ok: false, error: "count must be an integer between 1 and 100" }, method);
          return;
        }

        const issued = issueTokens({
          bundlePath,
          expectedPublicKeyB64U: status.publicKeyB64U,
          plan: body.plan || undefined,
          tier: body.tier || undefined,
          keyId: body.keyId || undefined,
          prefix: body.prefix || undefined,
          count,
          label: body.label || undefined,
          orderId: body.orderId || undefined,
          days: body.days !== undefined && body.days !== "" ? body.days : undefined,
          exp: body.exp !== undefined && body.exp !== "" ? body.exp : undefined,
          appendLedger: Boolean(body.appendLedger),
          ledgerPath,
        });

        const items = [];
        for (const item of issued.items) {
          const webCheck = await verifyProLicenseToken(item.token, {
            publicKeyB64U: status.publicKeyB64U,
          });
          if (!webCheck.valid) {
            throw new Error(`Issued token failed pro-license.js check: ${webCheck.reason}`);
          }
          items.push({
            ...item,
            activationUrlRu: `${activationBaseUrl}#code=${item.token}`,
            activationUrlEn: `${activationBaseUrlEn}#code=${item.token}`,
          });
        }

        sendJson(
          res,
          200,
          {
            ok: true,
            count: items.length,
            publicKeyMatchesApp: status.publicKeyMatchesApp,
            bundlePublicKeyB64U: status.publicKeyB64U,
            expectedPublicKeyB64U,
            ledgerPath: issued.ledgerPath,
            items,
          },
          method
        );
        return;
      }

      if (pathname === "/api/verify") {
        if (method !== "POST") {
          sendJson(res, 405, { ok: false, error: "Method Not Allowed" }, method, { Allow: "POST" });
          return;
        }
        if (!isAllowedStateChangingRequest(req)) {
          sendJson(res, 403, { ok: false, error: "Forbidden Origin or Referer header" }, method);
          return;
        }

        const body = await readJsonBody(req);
        const rawText = typeof body.rawText === "string" ? body.rawText : "";
        const extractedToken = extractProToken(rawText);
        const candidate = extractedToken || rawText.trim();

        let nowMs = Date.now();
        if (typeof body.nowIso === "string" && body.nowIso.trim()) {
          nowMs = Date.parse(body.nowIso.trim());
          if (Number.isNaN(nowMs)) {
            sendJson(res, 400, { ok: false, error: `Invalid nowIso: ${body.nowIso}` }, method);
            return;
          }
        }

        const targetPub =
          typeof body.publicKeyB64U === "string" && body.publicKeyB64U.trim()
            ? body.publicKeyB64U.trim()
            : expectedPublicKeyB64U;

        const bundleStatus = loadOwnerBundleStatus(bundlePath, {
          expectedPublicKeyB64U,
          redact: true,
        });

        const result = await verifyProLicenseToken(candidate, { publicKeyB64U: targetPub, nowMs });
        const cliResult = verifyTokenWithRawPublicKey(candidate, targetPub, { nowMs });
        const decodedPayload = decodeProTokenPayloadUnsafe(candidate);

        sendJson(
          res,
          200,
          {
            ok: true,
            extractedToken,
            candidateToken: candidate,
            publicKeyB64U: targetPub,
            matchesAppPublicKey: targetPub === expectedPublicKeyB64U,
            matchesBundlePublicKey: Boolean(
              bundleStatus.publicKeyB64U && targetPub === bundleStatus.publicKeyB64U
            ),
            result,
            cliResult,
            decodedPayload,
          },
          method
        );
        return;
      }

      sendJson(res, 404, { ok: false, error: "Not Found" }, method);
    } catch (err) {
      const code = err?.statusCode || (err?.message?.includes("Cannot specify") || err?.message?.includes("Invalid") || err?.message?.includes("Unknown") ? 400 : 500);
      sendJson(res, code, { ok: false, error: err?.message || "Internal Server Error" }, method);
    }
  };
}

export function createOwnerConsoleServer(options = {}) {
  const host = assertLoopbackHost(options.host ?? "127.0.0.1");
  const port = options.port === undefined ? 0 : Number(options.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`Invalid port "${options.port}". Must be an integer 0..65535.`);
  }

  const handler = createOwnerConsoleHandler(options);
  const server = http.createServer(handler);

  const start = () =>
    new Promise((resolve, reject) => {
      const onError = (err) => {
        server.off("listening", onListening);
        reject(err);
      };
      const onListening = () => {
        server.off("error", onError);
        const addr = server.address();
        const boundPort = typeof addr === "object" && addr ? addr.port : port;
        const formattedHost = host === "::1" ? "[::1]" : host;
        resolve({
          host,
          port: boundPort,
          url: `http://${formattedHost}:${boundPort}/`,
        });
      };
      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(port, host);
    });

  const stop = () =>
    new Promise((resolve, reject) => {
      if (!server.listening) {
        resolve();
        return;
      }
      server.closeAllConnections?.();
      server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

  return {
    server,
    handler,
    host,
    start,
    stop,
    close: stop,
  };
}

export async function startOwnerConsole(options = {}) {
  const instance = createOwnerConsoleServer(options);
  const info = await instance.start();
  return {
    ...instance,
    ...info,
  };
}

function getConsoleUsage() {
  return [
    "PromptVeil Local Owner Key Console",
    "",
    "Usage:",
    "  node scripts/owner-console.mjs [--host 127.0.0.1|localhost|::1] [--port <0..65535>] [--bundle <path>] [--ledger <path>] [--pub <b64u>]",
  ].join("\n");
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
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(getConsoleUsage());
    process.exit(0);
  }

  try {
    const started = await startOwnerConsole({
      host: typeof args.host === "string" ? args.host : "127.0.0.1",
      port: args.port !== undefined ? Number(args.port) : 0,
      bundlePath: typeof args.bundle === "string" ? args.bundle : DEFAULT_BUNDLE_PATH,
      ledgerPath: typeof args.ledger === "string" ? args.ledger : DEFAULT_LEDGER_PATH,
      expectedPublicKeyB64U: typeof args.pub === "string" ? args.pub : PRO_PUBLIC_KEY_B64U,
    });
    const status = loadOwnerBundleStatus(
      typeof args.bundle === "string" ? args.bundle : DEFAULT_BUNDLE_PATH,
      {
        expectedPublicKeyB64U: typeof args.pub === "string" ? args.pub : PRO_PUBLIC_KEY_B64U,
        redact: true,
      }
    );
    console.log(`PromptVeil Owner Console listening at ${started.url}`);
    console.log(`Bundle loaded: ${status.loaded}, Matches app public key: ${status.publicKeyMatchesApp}`);

    const shutdown = async () => {
      await started.stop();
      process.exit(0);
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}
