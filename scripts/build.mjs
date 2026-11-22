import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";
import * as esbuild from "esbuild";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const STATIC_DIR = path.join(ROOT_DIR, "app", "static");
const DIST_DIR = path.join(STATIC_DIR, "dist");
const DOWNLOADS_DIR = path.join(STATIC_DIR, "downloads");
const EXT_DIR = path.join(ROOT_DIR, "extension");
const EXT_DIST_DIR = path.join(EXT_DIR, "dist");
const EXT_ZIP_PATH = path.join(DOWNLOADS_DIR, "promptveil-pro-extension.zip");

const EXT_RUNTIME_FILES = [
  "manifest.json",
  "popup.html",
  "popup.css",
  "content.css",
  "dist/content.bundle.js",
  "dist/popup.bundle.js",
  "icons/icon-16.png",
  "icons/icon-48.png",
  "icons/icon-128.png",
];

// Deterministic DOS timestamp: 2026-01-01 00:00:00
const ZIP_DOS_TIME = 0x0000;
const ZIP_DOS_DATE = 0x5c21;
const ZIP_UTF8_FLAG = 0x0800;

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function buildDeterministicZip(entries) {
  const normalized = entries.map((entry) => {
    const cleanName = String(entry.name || "").replace(/\\/g, "/");
    if (!cleanName || cleanName.startsWith("/") || cleanName.includes("..")) {
      throw new Error(`Invalid ZIP entry path: ${entry.name}`);
    }
    const raw = Buffer.isBuffer(entry.data)
      ? entry.data
      : Buffer.from(entry.data);
    return { name: cleanName, raw };
  });

  normalized.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  const seenNames = new Set();
  const localParts = [];
  const cdParts = [];
  let offset = 0;

  for (const item of normalized) {
    if (seenNames.has(item.name)) {
      throw new Error(`Duplicate ZIP entry path: ${item.name}`);
    }
    seenNames.add(item.name);

    const nameBytes = Buffer.from(item.name, "utf8");
    const checksum = crc32(item.raw);
    const deflated = zlib.deflateRawSync(item.raw, { level: 9 });
    const useDeflate = deflated.length < item.raw.length;
    const method = useDeflate ? 8 : 0;
    const payload = useDeflate ? deflated : item.raw;

    const lfh = Buffer.allocUnsafe(30 + nameBytes.length);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(ZIP_UTF8_FLAG, 6);
    lfh.writeUInt16LE(method, 8);
    lfh.writeUInt16LE(ZIP_DOS_TIME, 10);
    lfh.writeUInt16LE(ZIP_DOS_DATE, 12);
    lfh.writeUInt32LE(checksum, 14);
    lfh.writeUInt32LE(payload.length, 18);
    lfh.writeUInt32LE(item.raw.length, 22);
    lfh.writeUInt16LE(nameBytes.length, 26);
    lfh.writeUInt16LE(0, 28);
    nameBytes.copy(lfh, 30);
    localParts.push(lfh, payload);

    const cdh = Buffer.allocUnsafe(46 + nameBytes.length);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE(20, 4);
    cdh.writeUInt16LE(20, 6);
    cdh.writeUInt16LE(ZIP_UTF8_FLAG, 8);
    cdh.writeUInt16LE(method, 10);
    cdh.writeUInt16LE(ZIP_DOS_TIME, 12);
    cdh.writeUInt16LE(ZIP_DOS_DATE, 14);
    cdh.writeUInt32LE(checksum, 16);
    cdh.writeUInt32LE(payload.length, 20);
    cdh.writeUInt32LE(item.raw.length, 24);
    cdh.writeUInt16LE(nameBytes.length, 28);
    cdh.writeUInt16LE(0, 30);
    cdh.writeUInt16LE(0, 32);
    cdh.writeUInt16LE(0, 34);
    cdh.writeUInt16LE(0, 36);
    cdh.writeUInt32LE(0, 38);
    cdh.writeUInt32LE(offset, 42);
    nameBytes.copy(cdh, 46);
    cdParts.push(cdh);

    offset += lfh.length + payload.length;
  }

  const cdSize = cdParts.reduce((sum, buf) => sum + buf.length, 0);
  const eocd = Buffer.allocUnsafe(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(normalized.length, 8);
  eocd.writeUInt16LE(normalized.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, ...cdParts, eocd]);
}

function replaceOnce(source, pattern, replacement, label) {
  const matches = source.match(pattern);
  if (!matches || matches.length !== 1) {
    throw new Error(
      `Expected exactly 1 match for ${label}, found ${matches ? matches.length : 0}`
    );
  }
  return source.replace(pattern, replacement);
}

function validateContentSecurity(baseDir, relFiles, labelPrefix, { checkLocalStorage = false } = {}) {
  const forbiddenJsPatterns = [
    [/\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b/, "unsafe HTML sink"],
    [/\beval\s*\(/, "eval()"],
    [/\bnew\s+Function\s*\(/, "new Function()"],
    [/\bfetch\s*\(/, "fetch()"],
    [/\bXMLHttpRequest\b/, "XMLHttpRequest"],
    [/\bsendBeacon\b/, "sendBeacon"],
    [/\bnew\s+WebSocket\s*\(/, "WebSocket"],
    [/\bEventSource\b/, "EventSource"],
    [/(['"`])(?:https?|wss?):\/\//i, "external URL literal"],
    [/100vw\b/i, "100vw"],
  ];

  if (checkLocalStorage) {
    forbiddenJsPatterns.push([/\blocalStorage\b/, "localStorage"]);
  }

  const forbiddenCssPatterns = [
    [/@import\b/i, "@import statement"],
    [/(?:https?|wss?):\/\//i, "external URL"],
    [/(?:url\(\s*['"]?|@import\s+['"])\/\//i, "protocol-relative URL"],
    [/100vw\b/i, "100vw"],
  ];

  for (const relFile of relFiles) {
    const fullPath = path.join(baseDir, relFile);
    const content = fs.readFileSync(fullPath, "utf8");
    if (relFile.endsWith(".js")) {
      for (const [pattern, label] of forbiddenJsPatterns) {
        if (pattern.test(content)) {
          throw new Error(`Forbidden ${label} detected in ${labelPrefix}/${relFile}`);
        }
      }
    } else if (relFile.endsWith(".css")) {
      for (const [pattern, label] of forbiddenCssPatterns) {
        if (pattern.test(content)) {
          throw new Error(`Forbidden ${label} detected in ${labelPrefix}/${relFile}`);
        }
      }
    }
  }
}

function validateDistOutputs(distFiles) {
  validateContentSecurity(DIST_DIR, distFiles, "dist");
}

async function build() {
  fs.rmSync(DIST_DIR, { recursive: true, force: true });
  fs.mkdirSync(DIST_DIR, { recursive: true });

  const cssResult = await esbuild.build({
    entryPoints: [path.join(STATIC_DIR, "styles.css")],
    bundle: true,
    minify: true,
    charset: "utf8",
    entryNames: "[name].[hash]",
    outdir: DIST_DIR,
    metafile: true,
    legalComments: "none",
    logLevel: "silent",
  });

  const cssOutputs = Object.keys(cssResult.metafile.outputs)
    .map((outPath) => path.basename(outPath))
    .filter((name) => name.endsWith(".css"));
  if (cssOutputs.length !== 1) {
    throw new Error(`Expected 1 CSS bundle in dist/, got ${cssOutputs.length}`);
  }
  const cssFile = cssOutputs[0];

  const jsResult = await esbuild.build({
    entryPoints: [path.join(STATIC_DIR, "js", "app.js")],
    bundle: true,
    splitting: true,
    format: "esm",
    minify: true,
    charset: "utf8",
    target: ["es2022"],
    entryNames: "[name].[hash]",
    chunkNames: "[name]-[hash]",
    outdir: DIST_DIR,
    metafile: true,
    legalComments: "none",
    logLevel: "silent",
  });

  let jsEntryFile = null;
  const jsFiles = [];
  for (const [outPath, meta] of Object.entries(jsResult.metafile.outputs)) {
    const fileName = path.basename(outPath);
    if (!fileName.endsWith(".js")) continue;
    jsFiles.push(fileName);
    if (meta.entryPoint && path.resolve(ROOT_DIR, meta.entryPoint) === path.join(STATIC_DIR, "js", "app.js")) {
      jsEntryFile = fileName;
    }
  }
  jsFiles.sort();
  if (!jsEntryFile) {
    throw new Error("Could not determine entry JS bundle filename from esbuild metafile");
  }
  const enChunkFile = jsFiles.find((f) => f.startsWith("i18n-en-"));
  const ruChunkFile = jsFiles.find((f) => f.startsWith("i18n-ru-"));
  const proDocsChunkFile = jsFiles.find((f) => f.startsWith("pro-documents-"));
  if (!enChunkFile || !ruChunkFile || !proDocsChunkFile) {
    throw new Error(
      `Expected split i18n-ru, i18n-en, and pro-documents chunks in dist/, found: ${jsFiles.join(", ")}`
    );
  }

  const distFiles = [cssFile, ...jsFiles].sort();
  validateDistOutputs(distFiles);

  // Build Manifest V3 browser extension bundles deterministically.
  fs.rmSync(EXT_DIST_DIR, { recursive: true, force: true });
  fs.mkdirSync(EXT_DIST_DIR, { recursive: true });

  await esbuild.build({
    entryPoints: [path.join(EXT_DIR, "src", "content.js")],
    outfile: path.join(EXT_DIST_DIR, "content.bundle.js"),
    bundle: true,
    format: "iife",
    target: ["es2022"],
    minify: true,
    charset: "utf8",
    legalComments: "none",
    logLevel: "silent",
  });

  await esbuild.build({
    entryPoints: [path.join(EXT_DIR, "src", "popup.js")],
    outfile: path.join(EXT_DIST_DIR, "popup.bundle.js"),
    bundle: true,
    format: "iife",
    target: ["es2022"],
    minify: true,
    charset: "utf8",
    legalComments: "none",
    logLevel: "silent",
  });

  validateContentSecurity(
    EXT_DIR,
    ["dist/content.bundle.js", "dist/popup.bundle.js", "content.css", "popup.css"],
    "extension",
    { checkLocalStorage: true }
  );

  // Package strictly allowlisted extension runtime files into deterministic PKZIP.
  const extEntries = EXT_RUNTIME_FILES.map((relPath) => {
    const absPath = path.join(EXT_DIR, relPath);
    if (!fs.existsSync(absPath) || !fs.statSync(absPath).isFile()) {
      throw new Error(`Missing required extension runtime file: ${relPath}`);
    }
    return {
      name: relPath,
      data: fs.readFileSync(absPath),
    };
  });
  const extZipBuffer = buildDeterministicZip(extEntries);
  fs.mkdirSync(DOWNLOADS_DIR, { recursive: true });
  fs.writeFileSync(EXT_ZIP_PATH, extZipBuffer);

  const hash = crypto.createHash("sha256");
  for (const relFile of distFiles) {
    hash.update(relFile);
    hash.update("\0");
    hash.update(fs.readFileSync(path.join(DIST_DIR, relFile)));
  }
  hash.update("downloads/promptveil-pro-extension.zip");
  hash.update("\0");
  hash.update(extZipBuffer);
  const buildHash = hash.digest("hex").slice(0, 10);

  const cssLinkPattern =
    /<link\s+rel="stylesheet"\s+href="(?:\.?\/styles\.css|\/dist\/styles\.[A-Za-z0-9_-]+\.css)"\s*\/>/;
  const jsScriptPattern =
    /<script\s+type="module"\s+src="(?:\.?\/js\/app\.js|\/dist\/app\.[A-Za-z0-9_-]+\.js)"\s*><\/script>(?:\r?\n\s*<link\s+rel="modulepreload"\s+href="\/dist\/i18n-(?:en|ru)-[A-Za-z0-9_-]+\.js"\s*\/>)?/;

  for (const [htmlRel, preloadChunk] of [
    ["index.html", ruChunkFile],
    [path.join("en", "index.html"), enChunkFile],
  ]) {
    const htmlPath = path.join(STATIC_DIR, htmlRel);
    let htmlSrc = fs.readFileSync(htmlPath, "utf8");
    htmlSrc = replaceOnce(
      htmlSrc,
      cssLinkPattern,
      `<link rel="stylesheet" href="/dist/${cssFile}" />`,
      `${htmlRel} stylesheet`
    );
    htmlSrc = replaceOnce(
      htmlSrc,
      jsScriptPattern,
      `<script type="module" src="/dist/${jsEntryFile}"></script>\n  <link rel="modulepreload" href="/dist/${preloadChunk}" />`,
      `${htmlRel} module script`
    );
    fs.writeFileSync(htmlPath, htmlSrc, "utf8");
  }

  const notFoundPath = path.join(STATIC_DIR, "404.html");
  let notFoundSrc = fs.readFileSync(notFoundPath, "utf8");
  notFoundSrc = replaceOnce(
    notFoundSrc,
    cssLinkPattern,
    `<link rel="stylesheet" href="/dist/${cssFile}" />`,
    "404.html stylesheet"
  );
  fs.writeFileSync(notFoundPath, notFoundSrc, "utf8");

  const swPath = path.join(STATIC_DIR, "sw.js");
  let swSrc = fs.readFileSync(swPath, "utf8");
  swSrc = replaceOnce(
    swSrc,
    /const CACHE_NAME = "[^"]+";/,
    `const CACHE_NAME = "promptveil-build-${buildHash}";`,
    "sw.js CACHE_NAME"
  );

  const precacheUrls = [
    "/",
    "/en/",
    "/404.html",
    "/manifest.webmanifest",
    "/favicon.svg",
    "/apple-touch-icon.png",
    "/icon-192.png",
    "/icon-512.png",
    `/dist/${cssFile}`,
    ...jsFiles.map((fileName) => `/dist/${fileName}`),
  ];
  swSrc = replaceOnce(
    swSrc,
    /const PRECACHE_URLS = \[[\s\S]*?\];/,
    `const PRECACHE_URLS = ${JSON.stringify(precacheUrls, null, 2)};`,
    "sw.js PRECACHE_URLS"
  );
  fs.writeFileSync(swPath, swSrc, "utf8");

  console.log(
    `Built PromptVeil dist (${buildHash}): ${cssFile}, ${jsEntryFile} (+${jsFiles.length - 1} chunk(s))`
  );
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
