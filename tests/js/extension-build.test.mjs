import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { crc32, readZipEntries } from "../../app/static/js/pro-documents.js";
import { openProDownloadsModal } from "../../app/static/js/modals.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..", "..");
const STATIC_DIR = path.join(ROOT_DIR, "app", "static");
const DIST_DIR = path.join(STATIC_DIR, "dist");
const EXT_DIST_DIR = path.join(ROOT_DIR, "extension", "dist");
const ZIP_PATH = path.join(STATIC_DIR, "downloads", "promptveil-pro-extension.zip");
const SW_PATH = path.join(STATIC_DIR, "sw.js");
const BUILD_SCRIPT = path.join(ROOT_DIR, "scripts", "build.mjs");

const EXPECTED_ZIP_ENTRIES = [
  "content.css",
  "dist/content.bundle.js",
  "dist/popup.bundle.js",
  "icons/icon-128.png",
  "icons/icon-16.png",
  "icons/icon-48.png",
  "manifest.json",
  "popup.css",
  "popup.html",
];

const EXPECTED_MATCHES = [
  "https://chatgpt.com/*",
  "https://claude.ai/*",
  "https://gemini.google.com/*",
  "https://chat.deepseek.com/*",
  "https://giga.chat/*",
  "https://alice.yandex.ru/*",
];

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function snapshotBuildHashes() {
  const hashes = new Map();
  hashes.set("zip", sha256File(ZIP_PATH));
  hashes.set("sw.js", sha256File(SW_PATH));
  for (const name of fs.readdirSync(EXT_DIST_DIR).sort()) {
    hashes.set(`extension/dist/${name}`, sha256File(path.join(EXT_DIST_DIR, name)));
  }
  for (const name of fs.readdirSync(DIST_DIR).sort()) {
    hashes.set(`app/static/dist/${name}`, sha256File(path.join(DIST_DIR, name)));
  }
  return hashes;
}

describe("PromptVeil M4B Deterministic Extension Build & PKZIP Archive", () => {
  test("double-run scripts/build.mjs produces byte-for-byte identical dist, extension/dist, .zip, and sw.js", () => {
    execFileSync(process.execPath, [BUILD_SCRIPT], { cwd: ROOT_DIR, stdio: "pipe" });
    const firstHashes = snapshotBuildHashes();

    execFileSync(process.execPath, [BUILD_SCRIPT], { cwd: ROOT_DIR, stdio: "pipe" });
    const secondHashes = snapshotBuildHashes();

    assert.deepEqual(
      Array.from(secondHashes.entries()),
      Array.from(firstHashes.entries()),
      "Two consecutive npm run build executions must produce identical SHA-256 digests"
    );
  });

  test("promptveil-pro-extension.zip is a valid PKZIP with exact 9 runtime files, sorted order, valid CRC32, and zero src/tests", async () => {
    assert.equal(fs.existsSync(ZIP_PATH), true, "Missing promptveil-pro-extension.zip");
    const zipBytes = fs.readFileSync(ZIP_PATH);
    assert.equal(zipBytes.subarray(0, 4).toString("latin1"), "PK\x03\x04");

    // Verify PKZIP local header entries have fixed DOS time/date, UTF-8 flag, and sorted order.
    const seenHeaderNames = [];
    let pos = 0;
    while (pos + 4 <= zipBytes.length && zipBytes.readUInt32LE(pos) === 0x04034b50) {
      const gpFlag = zipBytes.readUInt16LE(pos + 6);
      const method = zipBytes.readUInt16LE(pos + 8);
      const dosTime = zipBytes.readUInt16LE(pos + 10);
      const dosDate = zipBytes.readUInt16LE(pos + 12);
      const compSize = zipBytes.readUInt32LE(pos + 18);
      const nameLen = zipBytes.readUInt16LE(pos + 26);
      const extraLen = zipBytes.readUInt16LE(pos + 28);
      const name = zipBytes.subarray(pos + 30, pos + 30 + nameLen).toString("utf8");

      assert.equal(gpFlag & 0x0800, 0x0800, `Missing UTF-8 flag on ${name}`);
      assert.ok(method === 0 || method === 8, `Unexpected ZIP method ${method} on ${name}`);
      assert.equal(dosTime, 0x0000, `Non-deterministic DOS time on ${name}`);
      assert.equal(dosDate, 0x5c21, `Non-deterministic DOS date on ${name}`);

      seenHeaderNames.push(name);
      pos += 30 + nameLen + extraLen + compSize;
    }

    assert.deepEqual(seenHeaderNames, EXPECTED_ZIP_ENTRIES);

    const parsed = await readZipEntries(new Uint8Array(zipBytes));
    assert.deepEqual(Array.from(parsed.keys()).sort(), EXPECTED_ZIP_ENTRIES);

    for (const entryName of parsed.keys()) {
      assert.equal(entryName.startsWith("src/"), false, `Unexpected src file in ZIP: ${entryName}`);
      assert.equal(entryName.startsWith("tests/"), false, `Unexpected tests file in ZIP: ${entryName}`);
      assert.equal(entryName.includes(".."), false, `Path traversal in ZIP: ${entryName}`);
      assert.equal(typeof crc32(parsed.get(entryName)), "number");
    }
  });

  test("packaged manifest.json & text entries satisfy MV3, CSP, zero-egress, and zero-secrets contracts", async () => {
    const zipBytes = fs.readFileSync(ZIP_PATH);
    const parsed = await readZipEntries(new Uint8Array(zipBytes));

    const manifest = JSON.parse(new TextDecoder().decode(parsed.get("manifest.json")));
    assert.equal(manifest.manifest_version, 3);
    assert.deepEqual(manifest.permissions, ["storage", "activeTab"]);
    assert.equal(manifest.host_permissions, undefined);
    assert.equal(
      manifest.content_security_policy?.extension_pages,
      "script-src 'self'; object-src 'none'"
    );
    assert.deepEqual(manifest.content_scripts?.[0]?.matches, EXPECTED_MATCHES);
    assert.deepEqual(manifest.content_scripts?.[0]?.js, ["dist/content.bundle.js"]);
    assert.deepEqual(manifest.content_scripts?.[0]?.css, ["content.css"]);

    for (const refPath of [
      manifest.action.default_popup,
      ...manifest.content_scripts[0].js,
      ...manifest.content_scripts[0].css,
      ...Object.values(manifest.icons),
      ...Object.values(manifest.action.default_icon),
    ]) {
      assert.equal(parsed.has(refPath), true, `Referenced file missing from ZIP: ${refPath}`);
    }

    const forbiddenUrlLiteral = /(['"`])(?:https?|wss?):\/\//i;
    const forbiddenPatterns = [
      /\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b/,
      /\beval\s*\(/,
      /\bnew\s+Function\s*\(/,
      /\bfetch\s*\(/,
      /\bXMLHttpRequest\b/,
      /\bsendBeacon\b/,
      /\bnew\s+WebSocket\s*\(/,
      /\bEventSource\b/,
      /\blocalStorage\b/,
      /100vw\b/i,
      /BEGIN PRIVATE KEY/,
      /PV-CLIENT-/,
      /PV1\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}/,
      /__PV_TEST_/,
    ];

    for (const [name, data] of parsed.entries()) {
      if (name.endsWith(".png")) continue;
      const text = new TextDecoder().decode(data);
      if (name !== "manifest.json") {
        assert.equal(
          forbiddenUrlLiteral.test(text),
          false,
          `Forbidden external URL literal found in ZIP entry ${name}`
        );
      }
      for (const pat of forbiddenPatterns) {
        assert.equal(pat.test(text), false, `Forbidden pattern ${pat} found in ZIP entry ${name}`);
      }
    }
  });

  test("sw.js PRECACHE_URLS includes split pro-documents chunk, excludes heavy optional assets, and openProDownloadsModal blocks Free mode", () => {
    const swSrc = fs.readFileSync(SW_PATH, "utf8");
    assert.doesNotMatch(swSrc, /"\/downloads\/promptveil-pro-extension\.zip"/);
    assert.doesNotMatch(swSrc, /"\/og-image\.png"/);
    assert.match(swSrc, /"\/dist\/pro-documents-[A-Za-z0-9_-]+\.js"/);

    const freeBlocked = openProDownloadsModal(null, { proLicense: { isPro: false } });
    assert.equal(freeBlocked, null);
  });
});
