/**
 * PromptVeil Offline Ed25519 Pro License Verifier & Resilient Storage.
 * Zero network calls, zero unsafe HTML sinks, zero runtime test backdoors.
 * Verifies via WebCrypto Ed25519 with pure-JS RFC 8032 Ed25519 + SHA-512 fallback.
 */

export const PRO_LICENSE_STORAGE_KEY = "promptveil_pro_license_v1";
export const PRO_PUBLIC_KEY_B64U = "Fsb_LKEZCuhkazGVQd18WiV34EQmpUUkxR9-Rc20YCY";

let memoryFallbackToken = "";

const MASK64 = 0xffffffffffffffffn;
const ED25519_P = (1n << 255n) - 19n;
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;

const SHA512_IV = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n,
];

const SHA512_K = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
  0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
  0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
  0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
];

function rotr64(x, n) {
  return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64;
}

function sha512Bytes(inputBytes) {
  const len = inputBytes.length;
  const bitLen = BigInt(len) * 8n;
  const totalLen = Math.ceil((len + 17) / 128) * 128;
  const padded = new Uint8Array(totalLen);
  padded.set(inputBytes, 0);
  padded[len] = 0x80;
  for (let i = 0; i < 8; i += 1) {
    padded[totalLen - 1 - i] = Number((bitLen >> BigInt(i * 8)) & 0xffn);
  }

  const h = SHA512_IV.slice();
  const w = new Array(80);

  for (let offset = 0; offset < totalLen; offset += 128) {
    for (let i = 0; i < 16; i += 1) {
      let word = 0n;
      const base = offset + i * 8;
      for (let j = 0; j < 8; j += 1) {
        word = (word << 8n) | BigInt(padded[base + j]);
      }
      w[i] = word;
    }
    for (let i = 16; i < 80; i += 1) {
      const s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7n);
      const s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6n);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK64;
    }

    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 80; i += 1) {
      const S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
      const ch = (e & f) ^ ((~e & MASK64) & g);
      const temp1 = (hh + S1 + ch + SHA512_K[i] + w[i]) & MASK64;
      const S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) & MASK64;

      hh = g;
      g = f;
      f = e;
      e = (d + temp1) & MASK64;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & MASK64;
    }

    h[0] = (h[0] + a) & MASK64;
    h[1] = (h[1] + b) & MASK64;
    h[2] = (h[2] + c) & MASK64;
    h[3] = (h[3] + d) & MASK64;
    h[4] = (h[4] + e) & MASK64;
    h[5] = (h[5] + f) & MASK64;
    h[6] = (h[6] + g) & MASK64;
    h[7] = (h[7] + hh) & MASK64;
  }

  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i += 1) {
    const val = h[i];
    for (let j = 0; j < 8; j += 1) {
      out[i * 8 + (7 - j)] = Number((val >> BigInt(j * 8)) & 0xffn);
    }
  }
  return out;
}

function mod(a, m = ED25519_P) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base, exp, m = ED25519_P) {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % m;
    }
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

function modInv(a, m = ED25519_P) {
  return modPow(a, m - 2n, m);
}

const ED25519_D = mod(-121665n * modInv(121666n));
const ED25519_I = modPow(2n, (ED25519_P - 1n) / 4n);
const ED25519_G_Y = mod(4n * modInv(5n));
const ED25519_G_X = (() => {
  const y2 = mod(ED25519_G_Y * ED25519_G_Y);
  const u = mod(y2 - 1n);
  const v = mod(ED25519_D * y2 + 1n);
  const uv7 = mod(u * modPow(v, 7n));
  let x = mod(u * modPow(v, 3n) * modPow(uv7, (ED25519_P - 5n) / 8n));
  if (mod(v * x * x) !== u) {
    x = mod(x * ED25519_I);
  }
  if ((x & 1n) === 1n) {
    x = mod(-x);
  }
  return x;
})();
const ED25519_G = [ED25519_G_X, ED25519_G_Y, 1n, mod(ED25519_G_X * ED25519_G_Y)];
const ED25519_ZERO = [0n, 1n, 1n, 0n];

function bytesToBigIntLE(bytes) {
  let val = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    val = (val << 8n) | BigInt(bytes[i]);
  }
  return val;
}

function decodeEd25519Point(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    return null;
  }
  const yBits = bytesToBigIntLE(bytes);
  const sign = Number((yBits >> 255n) & 1n);
  const y = yBits & ((1n << 255n) - 1n);
  if (y >= ED25519_P) {
    return null;
  }

  const y2 = mod(y * y);
  const u = mod(y2 - 1n);
  const v = mod(ED25519_D * y2 + 1n);
  const uv7 = mod(u * modPow(v, 7n));
  let x = mod(u * modPow(v, 3n) * modPow(uv7, (ED25519_P - 5n) / 8n));

  const vx2 = mod(v * x * x);
  if (vx2 !== u) {
    if (vx2 === mod(-u)) {
      x = mod(x * ED25519_I);
    } else {
      return null;
    }
  }
  if (x === 0n && sign === 1) {
    return null;
  }
  if (Number(x & 1n) !== sign) {
    x = mod(-x);
  }
  return [x, y, 1n, mod(x * y)];
}

function pointAdd(p1, p2) {
  const [X1, Y1, Z1, T1] = p1;
  const [X2, Y2, Z2, T2] = p2;
  const A = mod((Y1 - X1) * (Y2 - X2));
  const B = mod((Y1 + X1) * (Y2 + X2));
  const C = mod(2n * ED25519_D * T1 * T2);
  const D = mod(2n * Z1 * Z2);
  const E = mod(B - A);
  const F = mod(D - C);
  const G = mod(D + C);
  const H = mod(B + A);
  return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)];
}

function scalarMult(point, scalar) {
  let acc = ED25519_ZERO;
  let cur = point;
  let k = scalar;
  while (k > 0n) {
    if (k & 1n) {
      acc = pointAdd(acc, cur);
    }
    cur = pointAdd(cur, cur);
    k >>= 1n;
  }
  return acc;
}

function pointEqual(p1, p2) {
  return (
    mod(p1[0] * p2[2] - p2[0] * p1[2]) === 0n &&
    mod(p1[1] * p2[2] - p2[1] * p1[2]) === 0n
  );
}

export function verifyEd25519PureJs(messageBytes, signatureBytes, publicKeyBytes) {
  if (
    !(messageBytes instanceof Uint8Array) ||
    !(signatureBytes instanceof Uint8Array) ||
    !(publicKeyBytes instanceof Uint8Array)
  ) {
    return false;
  }
  if (signatureBytes.length !== 64 || publicKeyBytes.length !== 32) {
    return false;
  }
  const A = decodeEd25519Point(publicKeyBytes);
  if (!A) {
    return false;
  }
  if (pointEqual(A, ED25519_ZERO) || pointEqual(scalarMult(A, 8n), ED25519_ZERO)) {
    return false;
  }
  const Rbytes = signatureBytes.subarray(0, 32);
  const Sbytes = signatureBytes.subarray(32, 64);
  const R = decodeEd25519Point(Rbytes);
  if (!R) {
    return false;
  }
  const s = bytesToBigIntLE(Sbytes);
  if (s >= ED25519_L) {
    return false;
  }

  const digestInput = new Uint8Array(64 + messageBytes.length);
  digestInput.set(Rbytes, 0);
  digestInput.set(publicKeyBytes, 32);
  digestInput.set(messageBytes, 64);
  const k = bytesToBigIntLE(sha512Bytes(digestInput)) % ED25519_L;

  const lhs = scalarMult(ED25519_G, s);
  const rhs = pointAdd(R, scalarMult(A, k));
  return pointEqual(lhs, rhs);
}

const B64U_RE = /^[A-Za-z0-9_-]+$/;
const B64U_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64U_LOOKUP = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64U_ALPHABET.length; i += 1) {
    table[B64U_ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

export function base64UrlToBytes(b64u) {
  if (typeof b64u !== "string" || b64u.length === 0 || !B64U_RE.test(b64u)) {
    return null;
  }
  const mod4 = b64u.length % 4;
  if (mod4 === 1) {
    return null;
  }
  const outLen = Math.floor((b64u.length * 3) / 4);
  const out = new Uint8Array(outLen);
  let outIdx = 0;

  for (let i = 0; i < b64u.length; i += 4) {
    const c0 = B64U_LOOKUP[b64u.charCodeAt(i)];
    const c1 = B64U_LOOKUP[b64u.charCodeAt(i + 1)];
    const c2 = i + 2 < b64u.length ? B64U_LOOKUP[b64u.charCodeAt(i + 2)] : 0;
    const c3 = i + 3 < b64u.length ? B64U_LOOKUP[b64u.charCodeAt(i + 3)] : 0;
    if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) {
      return null;
    }
    const triple = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
    out[outIdx++] = (triple >> 16) & 0xff;
    if (i + 2 < b64u.length) {
      out[outIdx++] = (triple >> 8) & 0xff;
    }
    if (i + 3 < b64u.length) {
      out[outIdx++] = triple & 0xff;
    } else if (i + 2 < b64u.length) {
      if ((c2 & 0x03) !== 0) return null;
    } else if ((c1 & 0x0f) !== 0) {
      return null;
    }
  }
  return out;
}

const PV1_EXTRACT_RE =
  /(?:^|[^A-Za-z0-9_-])(PV1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)(?![A-Za-z0-9_=-]|\.[A-Za-z0-9_-])/;

function safeDecodePercentSequences(text) {
  return text.replace(/%(?:[0-9A-Fa-f]{2})+/g, (seq) => {
    try {
      return decodeURIComponent(seq);
    } catch {
      return seq;
    }
  });
}

export function extractProToken(rawText) {
  if (typeof rawText !== "string" || rawText.trim().length === 0) {
    return "";
  }
  const directMatch = rawText.match(PV1_EXTRACT_RE);
  if (directMatch) {
    return directMatch[1];
  }
  if (rawText.includes("%")) {
    let decoded = "";
    try {
      decoded = decodeURIComponent(rawText);
    } catch {
      decoded = safeDecodePercentSequences(rawText);
    }
    const decodedMatch = decoded.match(PV1_EXTRACT_RE);
    if (decodedMatch) {
      return decodedMatch[1];
    }
  }
  return "";
}

export function createFreeLicenseState(reason = "none") {
  return {
    valid: false,
    tier: "free",
    isPro: false,
    isOwner: false,
    keyId: "",
    label: "",
    issuedAt: "",
    exp: null,
    token: "",
    method: "",
    reason,
  };
}

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

export function decodeProTokenPayloadUnsafe(rawText) {
  const extracted = extractProToken(rawText);
  const candidate = extracted || (typeof rawText === "string" ? rawText.trim() : "");
  if (!candidate) {
    return { ok: false, token: "", payload: null, claims: null, reason: "empty" };
  }

  const parts = candidate.split(".");
  if (parts.length !== 3 || parts[0] !== "PV1") {
    return { ok: false, token: "", payload: null, claims: null, reason: "format" };
  }
  const [, payloadB64U, sigB64U] = parts;
  const payloadBytes = base64UrlToBytes(payloadB64U);
  const sigBytes = base64UrlToBytes(sigB64U);
  if (!payloadBytes || !sigBytes) {
    return { ok: false, token: "", payload: null, claims: null, reason: "encoding" };
  }
  if (sigBytes.length !== 64) {
    return { ok: false, token: "", payload: null, claims: null, reason: "length" };
  }

  let payload;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes));
  } catch {
    return { ok: false, token: "", payload: null, claims: null, reason: "payload" };
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return { ok: false, token: "", payload: null, claims: null, reason: "payload" };
  }

  const expMs = parseExpirationMs(payload.exp);
  const schemaValid = isValidProPayloadObject(payload) && (expMs === null || !Number.isNaN(expMs));

  return {
    ok: true,
    token: candidate,
    payload,
    claims: {
      v: payload.v ?? null,
      tier: typeof payload.tier === "string" ? payload.tier : "",
      keyId: typeof payload.keyId === "string" ? payload.keyId.trim() : "",
      label: typeof payload.label === "string" ? payload.label.trim() : "",
      issuedAt: typeof payload.issuedAt === "string" ? payload.issuedAt : "",
      exp: payload.exp ?? null,
      plan: typeof payload.plan === "string" ? payload.plan.trim() : "",
      orderId: typeof payload.orderId === "string" ? payload.orderId.trim() : "",
      schemaValid,
    },
    reason: "unverified",
  };
}

function sanitizePvKeyHeaderValue(value) {
  if (value === undefined || value === null) {
    return "";
  }
  return String(value)
    .replace(/[\r\n]+/g, " ")
    .replace(/PV1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "[REDACTED]")
    .trim();
}

export function formatPvKeyFileContent(token, meta = {}) {
  const cleanToken = extractProToken(token);
  if (!cleanToken) {
    return "";
  }
  const decoded = decodeProTokenPayloadUnsafe(cleanToken);
  const claims = decoded.ok && decoded.claims ? decoded.claims : {};

  const keyId = sanitizePvKeyHeaderValue(meta.keyId ?? claims.keyId);
  const tier = sanitizePvKeyHeaderValue(meta.tier ?? claims.tier);
  const label = sanitizePvKeyHeaderValue(meta.label ?? claims.label);
  const plan = sanitizePvKeyHeaderValue(meta.plan ?? claims.plan);
  const orderId = sanitizePvKeyHeaderValue(meta.orderId ?? claims.orderId);
  const issuedAt = sanitizePvKeyHeaderValue(meta.issuedAt ?? claims.issuedAt);
  const rawExp = meta.exp !== undefined ? meta.exp : claims.exp;
  const expText =
    rawExp === undefined || rawExp === null || rawExp === ""
      ? "never"
      : sanitizePvKeyHeaderValue(rawExp);
  const note = sanitizePvKeyHeaderValue(meta.note);

  const lines = [
    "# PromptVeil Pro Offline License Key",
    "# Format: PromptVeil Offline License (PV1)",
  ];
  if (keyId) lines.push(`# Key ID: ${keyId}`);
  if (tier) lines.push(`# Tier: ${tier}`);
  if (label) lines.push(`# Label: ${label}`);
  if (plan) lines.push(`# Plan: ${plan}`);
  if (orderId) lines.push(`# Order: ${orderId}`);
  if (issuedAt) lines.push(`# Issued At: ${issuedAt}`);
  lines.push(`# Expires At: ${expText}`);
  if (note) lines.push(`# Note: ${note}`);
  lines.push(cleanToken);
  return `${lines.join("\n")}\n`;
}

export async function verifyProLicenseToken(token, options = {}) {
  const safeOptions = options && typeof options === "object" ? options : {};
  const publicKeyB64U =
    safeOptions.publicKeyB64U === undefined ? PRO_PUBLIC_KEY_B64U : safeOptions.publicKeyB64U;
  const nowMs = safeOptions.nowMs === undefined ? Date.now() : safeOptions.nowMs;
  if (typeof nowMs !== "number" || !Number.isFinite(nowMs) || Math.abs(nowMs) > 8.64e15) {
    return createFreeLicenseState("invalid_now");
  }

  const trimmed = typeof token === "string" ? token.trim() : "";
  if (!trimmed) {
    return createFreeLicenseState("empty");
  }

  const parts = trimmed.split(".");
  if (parts.length !== 3 || parts[0] !== "PV1") {
    return createFreeLicenseState("format");
  }
  const [, payloadB64U, sigB64U] = parts;
  const payloadBytes = base64UrlToBytes(payloadB64U);
  const sigBytes = base64UrlToBytes(sigB64U);
  const pubBytes = base64UrlToBytes(publicKeyB64U);
  if (!payloadBytes || !sigBytes || !pubBytes) {
    return createFreeLicenseState("encoding");
  }
  if (sigBytes.length !== 64 || pubBytes.length !== 32) {
    return createFreeLicenseState("length");
  }

  const msgBytes = new TextEncoder().encode(`PV1.${payloadB64U}`);
  let sigValid = false;
  let method = "";

  const subtle = globalThis.crypto?.subtle;
  if (
    subtle &&
    typeof subtle.importKey === "function" &&
    typeof subtle.verify === "function"
  ) {
    try {
      const cryptoKey = await subtle.importKey("raw", pubBytes, "Ed25519", false, ["verify"]);
      const verified = await subtle.verify("Ed25519", cryptoKey, sigBytes, msgBytes);
      if (verified === true) {
        sigValid = true;
        method = "webcrypto";
      } else {
        return createFreeLicenseState("signature");
      }
    } catch {
      sigValid = verifyEd25519PureJs(msgBytes, sigBytes, pubBytes);
      method = "pure-js";
    }
  } else {
    sigValid = verifyEd25519PureJs(msgBytes, sigBytes, pubBytes);
    method = "pure-js";
  }

  if (!sigValid) {
    return createFreeLicenseState("signature");
  }

  let payload;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes));
  } catch {
    return createFreeLicenseState("payload");
  }

  if (!isValidProPayloadObject(payload)) {
    return createFreeLicenseState("payload");
  }

  const expMs = parseExpirationMs(payload.exp);
  if (expMs !== null) {
    if (Number.isNaN(expMs)) {
      return createFreeLicenseState("payload");
    }
    if (expMs <= nowMs) {
      return {
        ...createFreeLicenseState("expired"),
        keyId: payload.keyId.trim(),
        label: payload.label.trim(),
        issuedAt: payload.issuedAt,
        exp: payload.exp,
        method,
      };
    }
  }

  return {
    valid: true,
    tier: payload.tier,
    isPro: true,
    isOwner: payload.tier === "owner",
    keyId: payload.keyId.trim(),
    label: payload.label.trim(),
    issuedAt: payload.issuedAt,
    exp: payload.exp ?? null,
    token: trimmed,
    method,
    reason: "valid",
  };
}

export async function inspectProLicenseToken(rawText, options = {}) {
  const extractedToken = extractProToken(rawText);
  const candidate = extractedToken || (typeof rawText === "string" ? rawText.trim() : "");
  const verification = await verifyProLicenseToken(candidate, options);
  const decoded = candidate ? decodeProTokenPayloadUnsafe(candidate) : null;
  return {
    ...verification,
    extractedToken,
    unverifiedClaims: decoded?.ok ? decoded.claims : null,
  };
}

export function loadStoredProLicenseToken() {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      const val = window.localStorage.getItem(PRO_LICENSE_STORAGE_KEY);
      return typeof val === "string" ? val : "";
    }
  } catch {
    // Fallback to RAM token if localStorage is blocked.
  }
  return memoryFallbackToken;
}

export function saveStoredProLicenseToken(token) {
  const clean = typeof token === "string" ? token.trim() : "";
  memoryFallbackToken = clean;
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      if (clean) {
        window.localStorage.setItem(PRO_LICENSE_STORAGE_KEY, clean);
      } else {
        window.localStorage.removeItem(PRO_LICENSE_STORAGE_KEY);
      }
      return true;
    }
  } catch {
    // Ignore storage quota/security error; keep memoryFallbackToken.
  }
  return false;
}

export function clearStoredProLicenseToken() {
  memoryFallbackToken = "";
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      window.localStorage.removeItem(PRO_LICENSE_STORAGE_KEY);
    }
  } catch {
    // Ignore storage error.
  }
}

export async function loadActiveProLicense(options = {}) {
  const stored = loadStoredProLicenseToken();
  if (!stored) {
    return createFreeLicenseState("none");
  }
  const result = await verifyProLicenseToken(stored, options);
  if (!result.valid) {
    clearStoredProLicenseToken();
  }
  return result;
}

export async function activateProLicense(token, options = {}) {
  const result = await verifyProLicenseToken(token, options);
  if (result.valid) {
    const persisted = saveStoredProLicenseToken(result.token);
    return {
      ...result,
      persisted,
    };
  }
  return result;
}

export function deactivateProLicense() {
  clearStoredProLicenseToken();
  return createFreeLicenseState("removed");
}
