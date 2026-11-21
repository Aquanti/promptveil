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
  loadActiveProLicense,
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
});
