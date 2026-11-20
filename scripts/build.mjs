import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const STATIC_DIR = path.join(ROOT_DIR, "app", "static");
const DIST_DIR = path.join(STATIC_DIR, "dist");

function replaceOnce(source, pattern, replacement, label) {
  const matches = source.match(pattern);
  if (!matches || matches.length !== 1) {
    throw new Error(
      `Expected exactly 1 match for ${label}, found ${matches ? matches.length : 0}`
    );
  }
  return source.replace(pattern, replacement);
}

function validateDistOutputs(distFiles) {
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
  ];

  const forbiddenCssPatterns = [
    [/@import\b/i, "@import statement"],
    [/(?:https?|wss?):\/\//i, "external URL"],
    [/(?:url\(\s*['"]?|@import\s+['"])\/\//i, "protocol-relative URL"],
  ];

  for (const relFile of distFiles) {
    const fullPath = path.join(DIST_DIR, relFile);
    const content = fs.readFileSync(fullPath, "utf8");
    if (relFile.endsWith(".js")) {
      for (const [pattern, label] of forbiddenJsPatterns) {
        if (pattern.test(content)) {
          throw new Error(`Forbidden ${label} detected in dist/${relFile}`);
        }
      }
    } else if (relFile.endsWith(".css")) {
      for (const [pattern, label] of forbiddenCssPatterns) {
        if (pattern.test(content)) {
          throw new Error(`Forbidden ${label} detected in dist/${relFile}`);
        }
      }
    }
  }
}

async function build() {
  fs.rmSync(DIST_DIR, { recursive: true, force: true });
  fs.mkdirSync(DIST_DIR, { recursive: true });

  const cssResult = await esbuild.build({
    entryPoints: [path.join(STATIC_DIR, "styles.css")],
    bundle: true,
    minify: true,
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
  if (!enChunkFile || !ruChunkFile) {
    throw new Error(`Expected split i18n-ru and i18n-en chunks in dist/, found: ${jsFiles.join(", ")}`);
  }

  const distFiles = [cssFile, ...jsFiles].sort();
  validateDistOutputs(distFiles);

  const hash = crypto.createHash("sha256");
  for (const relFile of distFiles) {
    hash.update(relFile);
    hash.update("\0");
    hash.update(fs.readFileSync(path.join(DIST_DIR, relFile)));
  }
  const buildHash = hash.digest("hex").slice(0, 10);

  const cssLinkPattern =
    /<link\s+rel="stylesheet"\s+href="(?:\.?\/styles\.css|\/dist\/styles\.[A-Za-z0-9_-]+\.css)"\s*\/>/;
  const jsScriptPattern =
    /<script\s+type="module"\s+src="(?:\.?\/js\/app\.js|\/dist\/app\.[A-Za-z0-9_-]+\.js)"\s*><\/script>(?:\r?\n\s*<link\s+rel="modulepreload"\s+href="\/dist\/i18n-(?:en|ru)-[A-Za-z0-9_-]+\.js"\s*\/>)?/;

  for (const [htmlRel, preloadChunk] of [
    ["index.html", enChunkFile],
    [path.join("en", "index.html"), ruChunkFile],
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
    "/og-image.png",
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
