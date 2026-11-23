import test, { afterEach, beforeEach, describe } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  PRO_LICENSE_STORAGE_KEY,
  PRO_PUBLIC_KEY_B64U,
  activateProLicense,
  base64UrlToBytes,
  deactivateProLicense,
  decodeProTokenPayloadUnsafe,
  extractProToken,
  formatPvKeyFileContent,
  inspectProLicenseToken,
  loadActiveProLicense,
  saveStoredProLicenseToken,
  verifyEd25519PureJs,
  verifyProLicenseToken,
} from "../../app/static/js/pro-license.js";
import { runZeroRetentionSelfTest } from "../../app/static/js/privacy-proof.js";
import { extractRawPublicKeyB64U, signProToken } from "../../scripts/issue-pro-key.mjs";

function hexToBytes(hex) {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

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
    getItem() {
      throw new Error("SecurityError");
    },
    setItem() {
      throw new Error("QuotaExceededError");
    },
    removeItem() {
      throw new Error("SecurityError");
    },
  };
}

describe("PromptVeil M1 R2 Ed25519 Pro License Verifier", () => {
  let prevWindow;
  let prevDocument;
  let prevCryptoDescriptor;
  let keyPairA;
  let keyPairB;
  let pubA;
  let pubB;

  beforeEach(() => {
    prevWindow = globalThis.window;
    prevDocument = globalThis.document;
    prevCryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
    keyPairA = generateKeyPairSync("ed25519");
    keyPairB = generateKeyPairSync("ed25519");
    pubA = extractRawPublicKeyB64U(keyPairA.publicKey);
    pubB = extractRawPublicKeyB64U(keyPairB.publicKey);
  });

  afterEach(() => {
    globalThis.window = { localStorage: createMemoryLocalStorage(), location: { pathname: "/" } };
    deactivateProLicense();
    globalThis.window = prevWindow;
    globalThis.document = prevDocument;
    if (prevCryptoDescriptor) {
      Object.defineProperty(globalThis, "crypto", prevCryptoDescriptor);
    }
  });

  test("PRO_PUBLIC_KEY_B64U is valid 43-char / 32-byte literal with zero runtime test backdoors", () => {
    assert.match(PRO_PUBLIC_KEY_B64U, /^[A-Za-z0-9_-]{43}$/);
    const rawBytes = base64UrlToBytes(PRO_PUBLIC_KEY_B64U);
    assert.ok(rawBytes instanceof Uint8Array);
    assert.equal(rawBytes.length, 32);

    const src = readFileSync(
      new URL("../../app/static/js/pro-license.js", import.meta.url),
      "utf8"
    );
    assert.equal(src.includes("__PV_TEST_"), false);
  });

  test("verifyEd25519PureJs passes official RFC 8032 section 7.1 test vectors and rejects bit flips", () => {
    // RFC 8032 TEST 1 (empty message)
    const pk1 = hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const msg1 = new Uint8Array(0);
    const sig1 = hexToBytes(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    assert.equal(verifyEd25519PureJs(msg1, sig1, pk1), true);

    const badSig1 = sig1.slice();
    badSig1[0] ^= 0x01;
    assert.equal(verifyEd25519PureJs(msg1, badSig1, pk1), false);

    // RFC 8032 TEST 3 (2-byte message 0xaf82)
    const pk3 = hexToBytes("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    const msg3 = hexToBytes("af82");
    const sig3 = hexToBytes(
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    );
    assert.equal(verifyEd25519PureJs(msg3, sig3, pk3), true);
    assert.equal(verifyEd25519PureJs(hexToBytes("af83"), sig3, pk3), false);
  });

  test("verifies valid pro and owner tokens via WebCrypto", async () => {
    const proToken = signProToken(
      {
        v: 1,
        tier: "pro",
        keyId: "TEST-CLIENT-01",
        label: "Ephemeral Client",
        issuedAt: "2026-11-21T10:00:00.000Z",
      },
      keyPairA.privateKey
    );
    const ownerToken = signProToken(
      {
        v: 1,
        tier: "owner",
        keyId: "TEST-OWNER-01",
        label: "Ephemeral Owner",
        issuedAt: "2026-11-21T10:00:00.000Z",
      },
      keyPairA.privateKey
    );

    const resPro = await verifyProLicenseToken(proToken, { publicKeyB64U: pubA });
    assert.equal(resPro.valid, true);
    assert.equal(resPro.tier, "pro");
    assert.equal(resPro.isPro, true);
    assert.equal(resPro.isOwner, false);
    assert.equal(resPro.keyId, "TEST-CLIENT-01");
    assert.equal(resPro.method, "webcrypto");

    const resOwner = await verifyProLicenseToken(`  ${ownerToken}\n`, { publicKeyB64U: pubA });
    assert.equal(resOwner.valid, true);
    assert.equal(resOwner.tier, "owner");
    assert.equal(resOwner.isPro, true);
    assert.equal(resOwner.isOwner, true);
    assert.equal(resOwner.method, "webcrypto");
  });

  test("falls back to pure-JS Ed25519 when crypto.subtle throws NotSupportedError or crypto is absent", async () => {
    const token = signProToken(
      {
        v: 1,
        tier: "pro",
        keyId: "TEST-FALLBACK-01",
        label: "Fallback Test",
        issuedAt: "2026-11-21T10:00:00.000Z",
      },
      keyPairA.privateKey
    );

    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: {
        subtle: {
          async importKey() {
            const err = new Error("Ed25519 unsupported");
            err.name = "NotSupportedError";
            throw err;
          },
          async verify() {
            throw new Error("Should not reach");
          },
        },
      },
    });

    const resStubbed = await verifyProLicenseToken(token, { publicKeyB64U: pubA });
    assert.equal(resStubbed.valid, true);
    assert.equal(resStubbed.method, "pure-js");
    assert.equal(resStubbed.keyId, "TEST-FALLBACK-01");

    const wrongKeyStubbed = await verifyProLicenseToken(token, { publicKeyB64U: pubB });
    assert.equal(wrongKeyStubbed.valid, false);
    assert.equal(wrongKeyStubbed.reason, "signature");

    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: undefined,
    });

    const resNoCrypto = await verifyProLicenseToken(token, { publicKeyB64U: pubA });
    assert.equal(resNoCrypto.valid, true);
    assert.equal(resNoCrypto.method, "pure-js");

    // If WebCrypto verify returns false explicitly, do NOT fall back.
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: {
        subtle: {
          async importKey() {
            return {};
          },
          async verify() {
            return false;
          },
        },
      },
    });
    const resFalse = await verifyProLicenseToken(token, { publicKeyB64U: pubA });
    assert.equal(resFalse.valid, false);
    assert.equal(resFalse.reason, "signature");
  });

  test("rejects tampered, wrong-key, malformed, and expired tokens", async () => {
    const now = Date.parse("2026-11-21T12:00:00.000Z");
    const validToken = signProToken(
      {
        v: 1,
        tier: "pro",
        keyId: "TEST-01",
        label: "Valid",
        issuedAt: "2026-11-21T10:00:00.000Z",
        exp: "2026-12-21T12:00:00.000Z",
      },
      keyPairA.privateKey
    );
    const expiredToken = signProToken(
      {
        v: 1,
        tier: "pro",
        keyId: "TEST-EXP",
        label: "Expired",
        issuedAt: "2026-11-20T10:00:00.000Z",
        exp: "2026-11-21T11:59:59.000Z",
      },
      keyPairA.privateKey
    );

    const validFuture = await verifyProLicenseToken(validToken, { publicKeyB64U: pubA, nowMs: now });
    assert.equal(validFuture.valid, true);

    const expiredRes = await verifyProLicenseToken(expiredToken, { publicKeyB64U: pubA, nowMs: now });
    assert.equal(expiredRes.valid, false);
    assert.equal(expiredRes.isPro, false);
    assert.equal(expiredRes.reason, "expired");

    const parts = validToken.split(".");
    const tamperedPayload = Buffer.from(
      JSON.stringify({ v: 1, tier: "owner", keyId: "HACK", label: "Hack", issuedAt: "2026-11-21T10:00:00.000Z" })
    ).toString("base64url");
    const tamperedToken = `PV1.${tamperedPayload}.${parts[2]}`;
    assert.equal((await verifyProLicenseToken(tamperedToken, { publicKeyB64U: pubA })).valid, false);

    const flippedSig = `${parts[0]}.${parts[1]}.${parts[2].startsWith("A") ? "B" : "A"}${parts[2].slice(1)}`;
    assert.equal((await verifyProLicenseToken(flippedSig, { publicKeyB64U: pubA })).valid, false);
    const nonCanonicalTailSig = `${parts[0]}.${parts[1]}.${parts[2].slice(0, -1)}${parts[2].endsWith("A") ? "B" : "A"}`;
    assert.equal((await verifyProLicenseToken(nonCanonicalTailSig, { publicKeyB64U: pubA })).valid, false);

    assert.equal((await verifyProLicenseToken(validToken, { publicKeyB64U: pubB })).valid, false);
    assert.equal((await verifyProLicenseToken("", { publicKeyB64U: pubA })).reason, "empty");
    assert.equal((await verifyProLicenseToken("PV2.abc.def", { publicKeyB64U: pubA })).reason, "format");
    assert.equal((await verifyProLicenseToken("PV1.abc", { publicKeyB64U: pubA })).reason, "format");
    assert.equal((await verifyProLicenseToken("PV1.abc+def.ghi", { publicKeyB64U: pubA })).reason, "encoding");
  });

  test("storage lifecycle persists only valid tokens, clears invalid stored tokens, and handles throwing storage", async () => {
    const ls = createMemoryLocalStorage();
    globalThis.window = { localStorage: ls, location: { pathname: "/" } };

    const token = signProToken(
      {
        v: 1,
        tier: "pro",
        keyId: "TEST-STORE-01",
        label: "Storage Test",
        issuedAt: "2026-11-21T10:00:00.000Z",
      },
      keyPairA.privateKey
    );

    const badAct = await activateProLicense("PV1.bad.sig", { publicKeyB64U: pubA });
    assert.equal(badAct.valid, false);
    assert.equal(ls.getItem(PRO_LICENSE_STORAGE_KEY), null);

    const okAct = await activateProLicense(token, { publicKeyB64U: pubA });
    assert.equal(okAct.valid, true);
    assert.equal(ls.getItem(PRO_LICENSE_STORAGE_KEY), token);

    const loaded = await loadActiveProLicense({ publicKeyB64U: pubA });
    assert.equal(loaded.valid, true);
    assert.equal(loaded.keyId, "TEST-STORE-01");

    // Tampered token in localStorage gets cleared on load.
    ls.setItem(PRO_LICENSE_STORAGE_KEY, "PV1.tampered.token");
    const cleared = await loadActiveProLicense({ publicKeyB64U: pubA });
    assert.equal(cleared.valid, false);
    assert.equal(ls.getItem(PRO_LICENSE_STORAGE_KEY), null);

    // Deactivate clears storage.
    await activateProLicense(token, { publicKeyB64U: pubA });
    const removed = deactivateProLicense();
    assert.equal(removed.isPro, false);
    assert.equal(ls.getItem(PRO_LICENSE_STORAGE_KEY), null);

    // Throwing localStorage falls back safely to memory.
    globalThis.window = { localStorage: createThrowingStorage(), location: { pathname: "/" } };
    const memAct = await activateProLicense(token, { publicKeyB64U: pubA });
    assert.equal(memAct.valid, true);
    const memLoad = await loadActiveProLicense({ publicKeyB64U: pubA });
    assert.equal(memLoad.valid, true);
    assert.equal(memLoad.keyId, "TEST-STORE-01");
  });

  test("privacy-proof.js allowlists promptveil_pro_license_v1 with 0 unknown keys and 0 user text bytes", async () => {
    const ls = createMemoryLocalStorage();
    globalThis.window = {
      localStorage: ls,
      location: { protocol: "https:", hostname: "promptveil.netlify.app", origin: "https://promptveil.netlify.app" },
      isSecureContext: true,
    };
    globalThis.document = {
      cookie: "",
      querySelectorAll() {
        return [];
      },
    };

    const token = signProToken(
      {
        v: 1,
        tier: "pro",
        keyId: "TEST-PROOF-01",
        label: "Proof Check",
        issuedAt: "2026-11-21T10:00:00.000Z",
      },
      keyPairA.privateKey
    );
    await activateProLicense(token, { publicKeyB64U: pubA });

    const proof = runZeroRetentionSelfTest({
      rawText: "Иван Петров, карта 4276 3800 1234 5678",
      llmReply: "Здравствуйте, [FIO_1]!",
    });
    assert.equal(proof.storage.unknownStorageKeys, 0);
    assert.equal(proof.storage.storedTextBytes, 0);
    assert.equal(proof.storage.allowedPrefKeysPresent, 1);
    assert.equal(proof.allPassed, true);
  });

  test("verifyEd25519PureJs and verifyProLicenseToken reject identity & small-subgroup keys and invalid-schema/padded PV1 tokens", async () => {
    // 1. Identity public key (y=1, sign=0) & order-2 public key (y=p-1, sign=0) & order-4 public key (y=0, sign=0)
    const idPub = new Uint8Array(32);
    idPub[0] = 0x01;
    const order2Pub = new Uint8Array(32).fill(0xff);
    order2Pub[0] = 0xec;
    order2Pub[31] = 0x7f;
    const order4Pub = new Uint8Array(32); // y = 0, sign = 0 (order 4)
    const forgedSig = new Uint8Array(64);
    forgedSig[0] = 0x01; // R = identity, S = 0

    for (const msgText of ["m4-0", "m4-1", "m4-2", "m4-3"]) {
      const msgBytes = new TextEncoder().encode(msgText);
      assert.equal(verifyEd25519PureJs(msgBytes, forgedSig, idPub), false);
      assert.equal(verifyEd25519PureJs(msgBytes, forgedSig, order2Pub), false);
      assert.equal(verifyEd25519PureJs(msgBytes, forgedSig, order4Pub), false);
    }

    // Pure-JS fallback (crypto absent) parity for identity & small-subgroup PV1 tokens
    Object.defineProperty(globalThis, "crypto", {
      value: undefined,
      configurable: true,
      writable: true,
    });
    const forgedPayload = Buffer.from(
      JSON.stringify({
        v: 1,
        tier: "owner",
        keyId: "FORGED-ID",
        label: "Forged",
        issuedAt: "2026-11-21T10:00:00.000Z",
      })
    ).toString("base64url");
    const forgedSigB64U = Buffer.from(forgedSig).toString("base64url");
    const forgedTok = `PV1.${forgedPayload}.${forgedSigB64U}`;
    for (const badPub of [idPub, order2Pub, order4Pub]) {
      const pubB64U = Buffer.from(badPub).toString("base64url");
      const res = await verifyProLicenseToken(forgedTok, { publicKeyB64U: pubB64U });
      assert.equal(res.valid, false);
      assert.equal(res.isPro, false);
    }

    // 2. Signed-but-invalid-schema PV1 tokens & padded base64url
    const signRawPayload = (payload) => {
      const payloadB64U = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
      const sig = cryptoSign(null, Buffer.from(`PV1.${payloadB64U}`, "utf8"), keyPairA.privateKey);
      return `PV1.${payloadB64U}.${Buffer.from(sig).toString("base64url")}`;
    };
    const invalidPayloads = [
      { v: 1, tier: "admin", keyId: "PV-ADM", label: "Admin", issuedAt: "2026-11-21T00:00:00Z" },
      { v: 2, tier: "pro", keyId: "PV-V2", label: "V2", issuedAt: "2026-11-21T00:00:00Z" },
      { v: 1, tier: "pro", keyId: "PV-EXP0", label: "Exp0", issuedAt: "2026-11-21T00:00:00Z", exp: 0 },
      { v: 1, tier: "pro", keyId: "PV-BADEXP", label: "BadExp", issuedAt: "2026-11-21T00:00:00Z", exp: "not-a-date" },
      { v: 1, tier: "pro", keyId: "   ", label: "BlankId", issuedAt: "2026-11-21T00:00:00Z" },
    ];
    for (const payload of invalidPayloads) {
      const tok = signRawPayload(payload);
      const res = await verifyProLicenseToken(tok, { publicKeyB64U: pubA });
      assert.equal(res.valid, false);
      assert.equal(res.isPro, false);
    }
    const validTok = signProToken(
      { v: 1, tier: "pro", keyId: "PV-PAD", label: "Pad", issuedAt: "2026-11-21T00:00:00Z" },
      keyPairA.privateKey
    );
    const paddedRes = await verifyProLicenseToken(`${validTok}=`, { publicKeyB64U: pubA });
    assert.equal(paddedRes.valid, false);
    assert.equal(paddedRes.reason, "encoding");
  });

  test("extractProToken extracts PV1 tokens from raw text, markdown, receipts, .pvkey, and URL fragments while rejecting malformed forms", () => {
    const token = signProToken(
      {
        v: 1,
        tier: "pro",
        keyId: "TEST-EXTRACT-01",
        label: "Extract Test",
        issuedAt: "2026-11-21T10:00:00.000Z",
      },
      keyPairA.privateKey
    );

    assert.equal(extractProToken(token), token);
    assert.equal(extractProToken(`  \n\t${token}\r\n  `), token);
    assert.equal(extractProToken(`Use key \`${token}\` to activate.`), token);
    assert.equal(extractProToken(`\`\`\`\n${token}\n\`\`\``), token);
    assert.equal(
      extractProToken(
        `Order: PV-ORD-2026-11\n# Comment line PV1\nActivation Key: ${token}\nThank you!`
      ),
      token
    );
    assert.equal(extractProToken(`#code=${token}&lang=en`), token);

    const pctToken = token.replace(/\./g, "%2E");
    assert.equal(extractProToken(`https://example.invalid/pro/#code=${pctToken}&lang=ru`), token);
    assert.equal(extractProToken(`#code%3D${pctToken}`), token);
    assert.equal(extractProToken(`Save 100% off today! #code%3D${pctToken}&ok=1`), token);

    assert.equal(extractProToken(""), "");
    assert.equal(extractProToken(null), "");
    assert.equal(extractProToken(12345), "");
    assert.equal(extractProToken("PV2.abc.def"), "");
    assert.equal(extractProToken("pv1.abc.def"), "");
    assert.equal(extractProToken("PV1.abc"), "");
    assert.equal(extractProToken("PV1.abc+def.ghi"), "");
    assert.equal(extractProToken(`${token}=`), "");
    assert.equal(extractProToken(`${token}.extra`), "");
    assert.equal(extractProToken(`prefix${token}`), "");
    assert.equal(extractProToken(`#code=${pctToken}%3D`), "");
  });

  test("decodeProTokenPayloadUnsafe decodes claims with reason unverified and detects invalid structure", () => {
    const payloadObj = {
      v: 1,
      tier: "pro",
      keyId: "TEST-DECODE-01",
      label: "Decode Test",
      issuedAt: "2026-11-21T10:00:00.000Z",
      exp: "2027-11-21T10:00:00.000Z",
      plan: "pro-annual",
      orderId: "PV-ORD-42",
    };
    const payloadB64U = Buffer.from(JSON.stringify(payloadObj), "utf8").toString("base64url");
    const sig = cryptoSign(null, Buffer.from(`PV1.${payloadB64U}`, "utf8"), keyPairA.privateKey);
    const customTok = `PV1.${payloadB64U}.${Buffer.from(sig).toString("base64url")}`;

    const decoded = decodeProTokenPayloadUnsafe(`#code=${customTok}`);
    assert.equal(decoded.ok, true);
    assert.equal(decoded.reason, "unverified");
    assert.equal(decoded.token, customTok);
    assert.equal(decoded.claims.schemaValid, true);
    assert.equal(decoded.claims.keyId, "TEST-DECODE-01");
    assert.equal(decoded.claims.plan, "pro-annual");
    assert.equal(decoded.claims.orderId, "PV-ORD-42");

    assert.equal(decodeProTokenPayloadUnsafe("").reason, "empty");
    assert.equal(decodeProTokenPayloadUnsafe("PV2.abc.def").reason, "format");
    assert.equal(decodeProTokenPayloadUnsafe("PV1.abc+def.ghi").reason, "encoding");
    assert.equal(decodeProTokenPayloadUnsafe("PV1.YWJj.ZGVm").reason, "length");

    const badJsonB64U = Buffer.from("{bad-json", "utf8").toString("base64url");
    const badJsonSig = Buffer.from(
      cryptoSign(null, Buffer.from(`PV1.${badJsonB64U}`, "utf8"), keyPairA.privateKey)
    ).toString("base64url");
    assert.equal(decodeProTokenPayloadUnsafe(`PV1.${badJsonB64U}.${badJsonSig}`).reason, "payload");

    const badSchemaB64U = Buffer.from(
      JSON.stringify({ v: 2, tier: "admin", keyId: "X", label: "Y", issuedAt: "2026-01-01T00:00:00Z" }),
      "utf8"
    ).toString("base64url");
    const badSchemaSig = Buffer.from(
      cryptoSign(null, Buffer.from(`PV1.${badSchemaB64U}`, "utf8"), keyPairA.privateKey)
    ).toString("base64url");
    const badSchemaRes = decodeProTokenPayloadUnsafe(`PV1.${badSchemaB64U}.${badSchemaSig}`);
    assert.equal(badSchemaRes.ok, true);
    assert.equal(badSchemaRes.reason, "unverified");
    assert.equal(badSchemaRes.claims.schemaValid, false);
  });

  test("formatPvKeyFileContent formats sanitized .pvkey files round-tripping cleanly with extractProToken", async () => {
    const token = signProToken(
      {
        v: 1,
        tier: "pro",
        keyId: "TEST-PVKEY-01",
        label: "PVKey Test",
        issuedAt: "2026-11-21T10:00:00.000Z",
      },
      keyPairA.privateKey
    );

    const content = formatPvKeyFileContent(token, {
      plan: "pro-annual",
      orderId: "PV-ORD-77",
      label: "Line1\r\n# FakeHeader: injected",
      note: "Do not leak PV1.abc.def inside comments",
    });
    assert.ok(content.endsWith(`${token}\n`));
    const commentLines = content.split("\n").filter((l) => l.startsWith("#"));
    assert.ok(commentLines.some((l) => l.includes("# Key ID: TEST-PVKEY-01")));
    assert.ok(commentLines.some((l) => l.includes("# Order: PV-ORD-77")));
    assert.equal(commentLines.some((l) => l.startsWith("# FakeHeader:")), false);
    assert.equal(commentLines.some((l) => /PV1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(l)), false);

    const extracted = extractProToken(content);
    assert.equal(extracted, token);
    const verified = await verifyProLicenseToken(extracted, { publicKeyB64U: pubA });
    assert.equal(verified.valid, true);
    assert.equal(verified.keyId, "TEST-PVKEY-01");

    assert.equal(formatPvKeyFileContent(""), "");
    assert.equal(formatPvKeyFileContent("not-a-token"), "");
  });

  test("inspectProLicenseToken combines extraction, strict verification, and unverified claim inspection", async () => {
    const token = signProToken(
      {
        v: 1,
        tier: "owner",
        keyId: "TEST-INSPECT-01",
        label: "Inspect Test",
        issuedAt: "2026-11-21T10:00:00.000Z",
      },
      keyPairA.privateKey
    );
    const pvkey = formatPvKeyFileContent(token, { orderId: "PV-ORD-900" });
    assert.ok(pvkey.includes("# Order: PV-ORD-900"));

    const okRes = await inspectProLicenseToken(pvkey, { publicKeyB64U: pubA });
    assert.equal(okRes.valid, true);
    assert.equal(okRes.isOwner, true);
    assert.equal(okRes.extractedToken, token);
    assert.equal(okRes.unverifiedClaims?.keyId, "TEST-INSPECT-01");
    assert.equal(okRes.unverifiedClaims?.label, "Inspect Test");

    const wrongKeyRes = await inspectProLicenseToken(`#code=${token}`, { publicKeyB64U: pubB });
    assert.equal(wrongKeyRes.valid, false);
    assert.equal(wrongKeyRes.isPro, false);
    assert.equal(wrongKeyRes.keyId, "");
    assert.equal(wrongKeyRes.reason, "signature");
    assert.equal(wrongKeyRes.extractedToken, token);
    assert.equal(wrongKeyRes.unverifiedClaims?.keyId, "TEST-INSPECT-01");

    assert.equal((await inspectProLicenseToken("", { publicKeyB64U: pubA })).reason, "empty");
    assert.equal((await inspectProLicenseToken("bad", { publicKeyB64U: pubA })).reason, "format");
    assert.equal(
      (await inspectProLicenseToken("PV1.abc+def.ghi", { publicKeyB64U: pubA })).reason,
      "encoding"
    );
    assert.equal(
      (await inspectProLicenseToken(`${token}=`, { publicKeyB64U: pubA })).reason,
      "encoding"
    );
  });

  test("verifyProLicenseToken fails closed on non-finite, null, string, or out-of-range nowMs options", async () => {
    const expiredToken = signProToken(
      {
        v: 1,
        tier: "pro",
        keyId: "TEST-NOWMS-EXP",
        label: "Expired NowMs Regression",
        issuedAt: "2020-01-01T00:00:00.000Z",
        exp: "2020-02-01T00:00:00.000Z",
      },
      keyPairA.privateKey
    );
    const lifetimeToken = signProToken(
      {
        v: 1,
        tier: "owner",
        keyId: "TEST-NOWMS-LIFE",
        label: "Lifetime NowMs Regression",
        issuedAt: "2026-11-21T10:00:00.000Z",
      },
      keyPairA.privateKey
    );

    const invalidNowValues = [
      Number.NaN,
      null,
      Number.NEGATIVE_INFINITY,
      Number.POSITIVE_INFINITY,
      "2099-01-01",
      8.64e15 + 1,
      -8.64e15 - 1,
      true,
      {},
    ];

    for (const badNow of invalidNowValues) {
      const expRes = await verifyProLicenseToken(expiredToken, {
        publicKeyB64U: pubA,
        nowMs: badNow,
      });
      assert.equal(expRes.valid, false, `Expected expired token to fail closed for nowMs=${String(badNow)}`);
      assert.equal(expRes.isPro, false);
      assert.equal(expRes.isOwner, false);
      assert.equal(expRes.reason, "invalid_now");

      const lifeRes = await verifyProLicenseToken(lifetimeToken, {
        publicKeyB64U: pubA,
        nowMs: badNow,
      });
      assert.equal(lifeRes.valid, false, `Expected lifetime token to fail closed for nowMs=${String(badNow)}`);
      assert.equal(lifeRes.isPro, false);
      assert.equal(lifeRes.reason, "invalid_now");
    }

    // Explicit undefined defaults cleanly to Date.now()
    const expiredDefaultNow = await verifyProLicenseToken(expiredToken, {
      publicKeyB64U: pubA,
      nowMs: undefined,
    });
    assert.equal(expiredDefaultNow.valid, false);
    assert.equal(expiredDefaultNow.reason, "expired");

    const lifetimeDefaultNow = await verifyProLicenseToken(lifetimeToken, {
      publicKeyB64U: pubA,
      nowMs: undefined,
    });
    assert.equal(lifetimeDefaultNow.valid, true);
  });

  test("saveStoredProLicenseToken & activateProLicense return persisted boolean reflecting storage availability", async () => {
    const token = signProToken(
      {
        v: 1,
        tier: "pro",
        keyId: "TEST-PERSIST-01",
        label: "Persist Check",
        issuedAt: "2026-11-21T10:00:00.000Z",
      },
      keyPairA.privateKey
    );

    const ls = createMemoryLocalStorage();
    globalThis.window = { localStorage: ls, location: { pathname: "/" } };
    assert.equal(saveStoredProLicenseToken(token), true);
    assert.equal(ls.getItem(PRO_LICENSE_STORAGE_KEY), token);

    const okAct = await activateProLicense(token, { publicKeyB64U: pubA });
    assert.equal(okAct.valid, true);
    assert.equal(okAct.persisted, true);

    globalThis.window = { localStorage: createThrowingStorage(), location: { pathname: "/" } };
    assert.equal(saveStoredProLicenseToken(token), false);
    const quotaAct = await activateProLicense(token, { publicKeyB64U: pubA });
    assert.equal(quotaAct.valid, true);
    assert.equal(quotaAct.persisted, false);
  });
});
