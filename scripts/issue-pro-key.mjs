#!/usr/bin/env node
/**
 * Offline Ed25519 keypair & Pro activation key issuer for PromptVeil.
 * Never commit generated private keys or activation tokens to Git.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const DEFAULT_BUNDLE_PATH = path.join(ROOT_DIR, ".secrets", "pro_keys_bundle.json");
const PRO_LICENSE_PATH = path.join(ROOT_DIR, "app", "static", "js", "pro-license.js");

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

export function verifyTokenWithRawPublicKey(token, publicKeyB64U) {
  const parts = String(token || "").trim().split(".");
  if (parts.length !== 3 || parts[0] !== "PV1") {
    return { valid: false, reason: "format" };
  }
  const [, payloadB64U, sigB64U] = parts;
  if (!/^[A-Za-z0-9_-]+$/.test(payloadB64U) || !/^[A-Za-z0-9_-]+$/.test(sigB64U)) {
    return { valid: false, reason: "base64url" };
  }
  const rawPub = Buffer.from(publicKeyB64U, "base64url");
  const sigBytes = Buffer.from(sigB64U, "base64url");
  if (rawPub.length !== 32 || sigBytes.length !== 64) {
    return { valid: false, reason: "length" };
  }
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const pubKeyObj = crypto.createPublicKey({
    key: Buffer.concat([spkiPrefix, rawPub]),
    format: "der",
    type: "spki",
  });
  const ok = crypto.verify(null, Buffer.from(`PV1.${payloadB64U}`, "utf8"), pubKeyObj, sigBytes);
  if (!ok) {
    return { valid: false, reason: "signature" };
  }
  const payload = JSON.parse(Buffer.from(payloadB64U, "base64url").toString("utf8"));
  return { valid: true, payload };
}

function generateBundle({ outPath, handoffDir }) {
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

  console.log(`Generated Ed25519 bundle at ${outPath}`);
  console.log(`PRO_PUBLIC_KEY_B64U=${publicKeyB64U}`);
  console.log(`Owner keys: 1, Client keys: ${clientKeys.length}`);
}

function issueSingle({ bundlePath, tier, keyId, label, exp }) {
  const bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
  const privateKey = crypto.createPrivateKey(bundle.privateKeyPkcs8Pem);
  const token = signProToken(
    {
      v: 1,
      tier: tier || "pro",
      keyId: keyId || `PV-CUSTOM-${Date.now()}`,
      label: label || "PromptVeil Pro Custom",
      issuedAt: new Date().toISOString(),
      exp,
    },
    privateKey
  );
  const check = verifyTokenWithRawPublicKey(token, bundle.publicKeyB64U);
  if (!check.valid) {
    throw new Error(`Issued token failed self-check: ${check.reason}`);
  }
  console.log(token);
}

function readPublicKeyFromLicenseJs() {
  const src = fs.readFileSync(PRO_LICENSE_PATH, "utf8");
  const match = src.match(/export const PRO_PUBLIC_KEY_B64U\s*=\s*"([A-Za-z0-9_-]{43})"/);
  if (!match) {
    throw new Error(`Could not find 43-char PRO_PUBLIC_KEY_B64U in ${PRO_LICENSE_PATH}`);
  }
  return match[1];
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith("--")) {
      const key = token.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith("--")) {
        args[key] = true;
      } else {
        args[key] = next;
        i += 1;
      }
    } else {
      args._.push(token);
    }
  }
  return args;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = parseArgs(process.argv.slice(2));
  if (args["generate-bundle"]) {
    generateBundle({
      outPath: path.resolve(String(args.out || DEFAULT_BUNDLE_PATH)),
      handoffDir: args["handoff-dir"] ? path.resolve(String(args["handoff-dir"])) : null,
    });
  } else if (args.issue) {
    issueSingle({
      bundlePath: path.resolve(String(args.bundle || DEFAULT_BUNDLE_PATH)),
      tier: args.tier ? String(args.tier) : "pro",
      keyId: args["key-id"] ? String(args["key-id"]) : undefined,
      label: args.label ? String(args.label) : undefined,
      exp: args.exp ? String(args.exp) : undefined,
    });
  } else if (args.verify) {
    const token = typeof args.verify === "string" ? args.verify : args._[0];
    const pub = args.pub ? String(args.pub) : readPublicKeyFromLicenseJs();
    const res = verifyTokenWithRawPublicKey(token, pub);
    console.log(JSON.stringify(res));
    if (!res.valid) process.exit(1);
  } else {
    console.error(
      "Usage: node scripts/issue-pro-key.mjs --generate-bundle [--out <path>] [--handoff-dir <dir>] | --issue [--bundle <path>] --tier pro|owner --key-id <id> --label <label> [--exp <iso>] | --verify <token> [--pub <b64u>]"
    );
    process.exit(1);
  }
}
