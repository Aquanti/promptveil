import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { EXTENSION_STRINGS } from "../src/i18n-ext.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EXT_DIR = path.resolve(__dirname, "..");

const EXPECTED_MATCHES = [
  "https://chatgpt.com/*",
  "https://claude.ai/*",
  "https://gemini.google.com/*",
  "https://chat.deepseek.com/*",
  "https://giga.chat/*",
  "https://alice.yandex.ru/*",
];

function readPngMetadata(filePath) {
  const buf = fs.readFileSync(filePath);
  const sig = buf.subarray(0, 8);
  const expectedSig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.equal(sig.equals(expectedSig), true, `${path.basename(filePath)} invalid PNG signature`);
  assert.equal(buf.subarray(12, 16).toString("ascii"), "IHDR");
  const width = buf.readUInt32BE(16);
  const height = buf.readUInt32BE(20);
  const bitDepth = buf.readUInt8(24);
  const colorType = buf.readUInt8(25);
  return { width, height, bitDepth, colorType };
}

test("manifest.json complies with MV3 minimal permissions, 6 AI hosts, and strict CSP", () => {
  const manifestPath = path.join(EXT_DIR, "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.name, "PromptVeil");
  assert.equal(manifest.version, "2.1.0");
  assert.deepEqual(manifest.permissions, ["storage", "activeTab"]);
  assert.equal(manifest.host_permissions, undefined);

  assert.ok(Array.isArray(manifest.content_scripts) && manifest.content_scripts.length === 1);
  const cs = manifest.content_scripts[0];
  assert.deepEqual(cs.matches, EXPECTED_MATCHES);
  assert.deepEqual(cs.js, ["dist/content.bundle.js"]);
  assert.deepEqual(cs.css, ["content.css"]);
  assert.equal(cs.run_at, "document_idle");

  assert.equal(manifest.action?.default_popup, "popup.html");
  assert.equal(
    manifest.content_security_policy?.extension_pages,
    "script-src 'self'; object-src 'none'"
  );

  for (const rel of [
    manifest.action.default_popup,
    ...cs.js,
    ...cs.css,
    ...Object.values(manifest.icons),
    ...Object.values(manifest.action.default_icon),
  ]) {
    assert.equal(fs.existsSync(path.join(EXT_DIR, rel)), true, `Missing referenced file: ${rel}`);
  }
});

test("PNG icons are valid RGBA PNGs at 16x16, 48x48, and 128x128", () => {
  for (const size of [16, 48, 128]) {
    const iconPath = path.join(EXT_DIR, "icons", `icon-${size}.png`);
    const meta = readPngMetadata(iconPath);
    assert.equal(meta.width, size);
    assert.equal(meta.height, size);
    assert.equal(meta.bitDepth, 8);
    assert.equal(meta.colorType, 6, `icon-${size}.png must be RGBA (colorType 6)`);
  }
});

test("Static CSP, zero-egress, zero-localStorage, and zero-URL-literal hygiene across extension/", () => {
  const htmlFiles = ["popup.html"].map((f) => path.join(EXT_DIR, f));
  const cssFiles = ["popup.css", "content.css"].map((f) => path.join(EXT_DIR, f));
  const jsFiles = [
    ...fs.readdirSync(path.join(EXT_DIR, "src")).map((f) => path.join(EXT_DIR, "src", f)),
    ...fs.readdirSync(path.join(EXT_DIR, "dist")).map((f) => path.join(EXT_DIR, "dist", f)),
  ];

  const forbiddenDomAndNetwork = [
    /innerHTML\b/,
    /outerHTML\b/,
    /insertAdjacentHTML\b/,
    /document\.write\b/,
    /\beval\s*\(/,
    /new\s+Function\s*\(/,
    /\bfetch\s*\(/,
    /\bXMLHttpRequest\b/,
    /\bsendBeacon\b/,
    /\bWebSocket\b/,
    /\bEventSource\b/,
    /__PV_TEST_/,
  ];

  for (const file of htmlFiles) {
    const html = fs.readFileSync(file, "utf8");
    assert.equal(/<style\b/i.test(html), false, `${file} must not contain <style>`);
    assert.equal(/\sstyle\s*=/i.test(html), false, `${file} must not contain style=`);
    assert.equal(/\son[a-z]+\s*=/i.test(html), false, `${file} must not contain inline on*= handlers`);
    assert.equal(
      /<script(?![^>]*\bsrc=)[^>]*>/i.test(html),
      false,
      `${file} must not contain inline <script>`
    );
    assert.equal(/https?:\/\/|wss?:\/\//i.test(html), false, `${file} must not contain external URLs`);
    assert.equal(/100vw\b/i.test(html), false, `${file} must not use 100vw`);
    assert.equal(/\bRAM\b/.test(html), false, `${file} RU default copy must not contain "RAM"`);
    for (const pat of forbiddenDomAndNetwork) {
      assert.equal(pat.test(html), false, `${file} matched forbidden pattern ${pat}`);
    }
  }

  for (const file of cssFiles) {
    const css = fs.readFileSync(file, "utf8");
    assert.equal(/@import\b/i.test(css), false, `${file} must not use @import`);
    assert.equal(/100vw\b/i.test(css), false, `${file} must not use 100vw`);
    assert.equal(/https?:\/\/|wss?:\/\//i.test(css), false, `${file} must not contain external URLs`);
  }

  for (const file of jsFiles) {
    const js = fs.readFileSync(file, "utf8");
    for (const pat of forbiddenDomAndNetwork) {
      assert.equal(pat.test(js), false, `${path.basename(file)} matched forbidden pattern ${pat}`);
    }
    assert.equal(
      /100vw\b/i.test(js),
      false,
      `${path.basename(file)} must not use 100vw`
    );
    assert.equal(
      /(['"`])(?:https?|wss?):\/\//i.test(js),
      false,
      `${path.basename(file)} must not contain http(s)/ws(s) string literals`
    );
    assert.equal(
      /\blocalStorage\b/.test(js),
      false,
      `${path.basename(file)} must not reference localStorage`
    );
  }
});

test("i18n-ext.js provides 100% RU/EN key parity and exact action labels", () => {
  const ruKeys = Object.keys(EXTENSION_STRINGS.ru).sort();
  const enKeys = Object.keys(EXTENSION_STRINGS.en).sort();
  assert.deepEqual(ruKeys, enKeys);

  assert.equal(EXTENSION_STRINGS.ru["pill.sanitizeBtn"], "Скрыть перед отправкой");
  assert.equal(EXTENSION_STRINGS.en["pill.sanitizeBtn"], "Sanitize before send");
  assert.equal(EXTENSION_STRINGS.ru["pill.rehydrateBtn"], "Вернуть ответ");
  assert.equal(EXTENSION_STRINGS.en["pill.rehydrateBtn"], "Rehydrate reply");

  for (const key of ruKeys) {
    assert.equal(EXTENSION_STRINGS.ru[key].trim().length > 0, true, `Empty RU string: ${key}`);
    assert.equal(EXTENSION_STRINGS.en[key].trim().length > 0, true, `Empty EN string: ${key}`);
    assert.equal(/\bRAM\b/.test(EXTENSION_STRINGS.ru[key]), false, `RU string must not use "RAM": ${key}`);
  }
});
