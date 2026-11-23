import test, { afterEach, beforeEach, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

import {
  PRO_PUBLIC_KEY_B64U,
  extractProToken,
  verifyProLicenseToken,
} from "../../app/static/js/pro-license.js";
import {
  PLAN_PRESETS,
  extractRawPublicKeyB64U,
  formatPvKeyContent,
  issueTokens,
  readPublicKeyFromLicenseJs,
  redactToken,
  runCli,
  signProToken,
  verifyBundleObject,
  verifyTokenWithRawPublicKey,
} from "../../scripts/issue-pro-key.mjs";
import {
  OWNER_CONSOLE_CSP,
  assertLoopbackHost,
  createOwnerConsoleHandler,
  createOwnerConsoleServer,
  loadOwnerBundleStatus,
  startOwnerConsole,
} from "../../scripts/owner-console.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..", "..");
const ISSUE_SCRIPT = path.join(ROOT_DIR, "scripts", "issue-pro-key.mjs");

function runIssueCli(args) {
  return spawnSync(process.execPath, [ISSUE_SCRIPT, ...args], {
    cwd: ROOT_DIR,
    encoding: "utf8",
  });
}

describe("PromptVeil M1 F2/F3 Owner Pro-Code CLI & Local Console", () => {
  let tmpDirs = [];
  let activeServers = [];

  function makeTmpDir(prefix = "pv-m1-test-") {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    tmpDirs.push(dir);
    return dir;
  }

  beforeEach(() => {
    tmpDirs = [];
    activeServers = [];
  });

  afterEach(async () => {
    for (const srv of activeServers) {
      await srv.stop();
    }
    for (const dir of tmpDirs) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("issue-pro-key.mjs exposes required exports and readPublicKeyFromLicenseJs matches PRO_PUBLIC_KEY_B64U", () => {
    assert.equal(typeof extractRawPublicKeyB64U, "function");
    assert.equal(typeof signProToken, "function");
    assert.equal(typeof verifyTokenWithRawPublicKey, "function");
    assert.equal(typeof formatPvKeyContent, "function");
    assert.equal(typeof redactToken, "function");
    assert.equal(typeof runCli, "function");
    assert.deepEqual(Object.keys(PLAN_PRESETS).sort(), [
      "pro-annual",
      "pro-lifetime",
      "pro-monthly",
      "team-pack",
    ]);
    assert.equal(readPublicKeyFromLicenseJs(), PRO_PUBLIC_KEY_B64U);
  });

  test("verifyTokenWithRawPublicKey matches verifyProLicenseToken across valid, expired, boundary, small-subgroup, and invalid-schema cases", async () => {
    const keyPairA = generateKeyPairSync("ed25519");
    const keyPairB = generateKeyPairSync("ed25519");
    const pubA = extractRawPublicKeyB64U(keyPairA.publicKey);
    const pubB = extractRawPublicKeyB64U(keyPairB.publicKey);
    const nowMs = Date.parse("2026-11-21T12:00:00.000Z");

    const lifetimeTok = signProToken(
      { v: 1, tier: "owner", keyId: "EPH-OWN-1", label: "Owner", issuedAt: "2026-11-21T10:00:00.000Z" },
      keyPairA.privateKey
    );
    const futureIsoTok = signProToken(
      {
        v: 1,
        tier: "pro",
        keyId: "EPH-FUT-1",
        label: "Future ISO",
        issuedAt: "2026-11-21T10:00:00.000Z",
        exp: "2026-11-21T12:00:01.000Z",
      },
      keyPairA.privateKey
    );
    const boundaryTok = signProToken(
      {
        v: 1,
        tier: "pro",
        keyId: "EPH-BND-1",
        label: "Boundary",
        issuedAt: "2026-11-21T10:00:00.000Z",
        exp: nowMs,
      },
      keyPairA.privateKey
    );

    assert.equal(verifyTokenWithRawPublicKey(lifetimeTok, pubA, { nowMs }).valid, true);
    assert.equal((await verifyProLicenseToken(lifetimeTok, { publicKeyB64U: pubA, nowMs })).valid, true);

    assert.equal(verifyTokenWithRawPublicKey(futureIsoTok, pubA, { nowMs }).valid, true);
    const expBoundary = verifyTokenWithRawPublicKey(boundaryTok, pubA, { nowMs });
    assert.equal(expBoundary.valid, false);
    assert.equal(expBoundary.reason, "expired");
    assert.equal(expBoundary.payload?.keyId, "EPH-BND-1");

    const expAfter = verifyTokenWithRawPublicKey(futureIsoTok, pubA, {
      nowMs: Date.parse("2026-11-21T12:00:02.000Z"),
    });
    assert.equal(expAfter.valid, false);
    assert.equal(expAfter.reason, "expired");

    assert.equal(verifyTokenWithRawPublicKey("", pubA).reason, "empty");
    assert.equal(verifyTokenWithRawPublicKey("PV2.abc.def", pubA).reason, "format");
    assert.equal(verifyTokenWithRawPublicKey("PV1.abc", pubA).reason, "format");
    assert.equal(verifyTokenWithRawPublicKey(`${lifetimeTok}=`, pubA).reason, "encoding");
    assert.equal(verifyTokenWithRawPublicKey(lifetimeTok, `${pubA}=`).reason, "encoding");
    assert.equal(verifyTokenWithRawPublicKey("PV1.YWJj.ZGVm", pubA).reason, "length");
    assert.equal(verifyTokenWithRawPublicKey(lifetimeTok, pubB).reason, "signature");

    // Small-subgroup & identity public key rejection parity
    const idPub = Buffer.alloc(32);
    idPub[0] = 0x01;
    const order4Pub = Buffer.alloc(32);
    const forgedSig = Buffer.alloc(64);
    forgedSig[0] = 0x01;
    const forgedPayload = Buffer.from(
      JSON.stringify({ v: 1, tier: "owner", keyId: "BAD", label: "Bad", issuedAt: "2026-11-21T00:00:00Z" }),
      "utf8"
    ).toString("base64url");
    const forgedTok = `PV1.${forgedPayload}.${forgedSig.toString("base64url")}`;
    assert.equal(verifyTokenWithRawPublicKey(forgedTok, idPub.toString("base64url")).reason, "signature");
    assert.equal(verifyTokenWithRawPublicKey(forgedTok, order4Pub.toString("base64url")).reason, "signature");

    const signRaw = (obj) => {
      const p = Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
      const s = cryptoSign(null, Buffer.from(`PV1.${p}`, "utf8"), keyPairA.privateKey);
      return `PV1.${p}.${Buffer.from(s).toString("base64url")}`;
    };
    for (const badPayload of [
      { v: 2, tier: "pro", keyId: "A", label: "B", issuedAt: "2026-11-21T00:00:00Z" },
      { v: 1, tier: "admin", keyId: "A", label: "B", issuedAt: "2026-11-21T00:00:00Z" },
      { v: 1, tier: "pro", keyId: " ", label: "B", issuedAt: "2026-11-21T00:00:00Z" },
      { v: 1, tier: "pro", keyId: "A", label: "B", issuedAt: "not-a-date" },
      { v: 1, tier: "pro", keyId: "A", label: "B", issuedAt: "2026-11-21T00:00:00Z", exp: "bad-exp" },
    ]) {
      const badTok = signRaw(badPayload);
      const cliRes = verifyTokenWithRawPublicKey(badTok, pubA);
      const webRes = await verifyProLicenseToken(badTok, { publicKeyB64U: pubA });
      assert.equal(cliRes.valid, false);
      assert.equal(cliRes.reason, "payload");
      assert.equal(webRes.reason, "payload");
    }
  });

  test("CLI subprocess supports --generate-bundle, mismatch guard, --verify-bundle, --inspect-bundle --redact, presets, batch, pvkey, tables, ledger, and --verify --now", async () => {
    const tmp = makeTmpDir();
    const bundlePath = path.join(tmp, "bundle.json");
    const handoffDir = path.join(tmp, "handoff");

    const genRes = runIssueCli(["--generate-bundle", "--out", bundlePath, "--handoff-dir", handoffDir, "--json"]);
    assert.equal(genRes.status, 0, genRes.stderr);
    const genJson = JSON.parse(genRes.stdout);
    assert.equal(genJson.ok, true);
    assert.equal(genJson.ownerKeysCount, 1);
    assert.equal(genJson.clientKeysCount, 20);
    assert.equal(genJson.publicKeyMatchesCode, false);
    assert.ok(fs.existsSync(path.join(handoffDir, "PRO_KEYS_TABLE.md")));

    const ephemPub = genJson.publicKeyB64U;

    // Mismatch guard: omitting --pub or passing wrong --pub must fail
    const mismatchRes = runIssueCli(["--issue", "--bundle", bundlePath, "--json"]);
    assert.notEqual(mismatchRes.status, 0);
    assert.match(mismatchRes.stdout, /mismatch/i);

    const wrongPub = extractRawPublicKeyB64U(generateKeyPairSync("ed25519").publicKey);
    const wrongPubRes = runIssueCli(["--issue", "--bundle", bundlePath, "--pub", wrongPub, "--json"]);
    assert.notEqual(wrongPubRes.status, 0);

    // --verify-bundle fails without --pub, succeeds with --pub ephemPub
    assert.notEqual(runIssueCli(["--verify-bundle", "--bundle", bundlePath, "--json"]).status, 0);
    const verifyBundleOk = runIssueCli(["--verify-bundle", "--bundle", bundlePath, "--pub", ephemPub, "--json"]);
    assert.equal(verifyBundleOk.status, 0, verifyBundleOk.stderr);
    const vbJson = JSON.parse(verifyBundleOk.stdout);
    assert.equal(vbJson.ok, true);
    assert.equal(vbJson.validEntries, 21);

    // --inspect-bundle --redact never exposes privateKeyPkcs8Pem and masks tokens
    const inspectRes = runIssueCli(["--inspect-bundle", "--bundle", bundlePath, "--redact", "--json"]);
    assert.equal(inspectRes.status, 0);
    assert.equal(inspectRes.stdout.includes("BEGIN PRIVATE KEY"), false);
    const inspectJson = JSON.parse(inspectRes.stdout);
    assert.equal(inspectJson.publicKeyMatchesCode, false);
    assert.equal(inspectJson.privateKeyMatchesPublic, true);
    assert.ok(inspectJson.entries[0].token.includes("..."));

    // Plan presets & explicit overrides
    const nowIso = "2026-11-23T00:00:00.000Z";
    for (const [plan, expectedDays] of [
      ["pro-monthly", 30],
      ["pro-annual", 365],
      ["pro-lifetime", null],
      ["team-pack", 365],
    ]) {
      const planRes = runIssueCli([
        "--issue",
        "--bundle",
        bundlePath,
        "--pub",
        ephemPub,
        "--plan",
        plan,
        "--now",
        nowIso,
        "--json",
      ]);
      assert.equal(planRes.status, 0, planRes.stderr);
      const data = JSON.parse(planRes.stdout);
      const item = data.items[0];
      if (expectedDays === null) {
        assert.equal(item.exp, null);
      } else {
        const diffDays = Math.round((Date.parse(item.exp) - Date.parse(nowIso)) / 86400000);
        assert.equal(diffDays, expectedDays);
      }
      const webCheck = await verifyProLicenseToken(item.token, {
        publicKeyB64U: ephemPub,
        nowMs: Date.parse(nowIso),
      });
      assert.equal(webCheck.valid, true);
    }

    // Invalid plan / conflicting --days and --exp / zero days
    assert.notEqual(runIssueCli(["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--plan", "bogus"]).status, 0);
    assert.notEqual(
      runIssueCli(["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--days", "0"]).status,
      0
    );
    assert.notEqual(
      runIssueCli([
        "--issue",
        "--bundle",
        bundlePath,
        "--pub",
        ephemPub,
        "--days",
        "10",
        "--exp",
        "2027-01-01T00:00:00Z",
      ]).status,
      0
    );

    // Batch issuance + --order + --out-pvkey + --out-table + --append-ledger + --redact
    const pvDir = path.join(tmp, "pvkeys");
    const csvPath = path.join(tmp, "issued.csv");
    const mdPath = path.join(tmp, "issued.md");
    const ledgerPath = path.join(tmp, "issued_ledger.json");

    const batchRes = runIssueCli([
      "--issue",
      "--bundle",
      bundlePath,
      "--pub",
      ephemPub,
      "--plan",
      "pro-annual",
      "--count",
      "3",
      "--prefix",
      "PV-BATCH",
      "--order",
      "PV-ORD-2026-99",
      "--days",
      "10",
      "--now",
      nowIso,
      "--out-pvkey",
      pvDir,
      "--out-table",
      csvPath,
      "--append-ledger",
      "--ledger",
      ledgerPath,
      "--redact",
      "--json",
    ]);
    assert.equal(batchRes.status, 0, batchRes.stderr);
    const batchJson = JSON.parse(batchRes.stdout);
    assert.equal(batchJson.count, 3);
    assert.equal(batchJson.items[0].keyId, "PV-BATCH-01");
    assert.equal(batchJson.items[2].keyId, "PV-BATCH-03");
    assert.ok(batchJson.items[0].label.includes("PV-ORD-2026-99"));
    assert.ok(batchJson.items[0].token.includes("..."));

    const pv1Content = fs.readFileSync(path.join(pvDir, "PV-BATCH-01.pvkey"), "utf8");
    assert.match(pv1Content, /# Order: PV-ORD-2026-99/);
    const fullTok1 = extractProToken(pv1Content);
    assert.ok(fullTok1.startsWith("PV1."));
    assert.equal(batchRes.stdout.includes(fullTok1), false);

    assert.ok(fs.readFileSync(csvPath, "utf8").includes("PV-BATCH-01"));

    // Second ledger append + markdown table
    const singleRes = runIssueCli([
      "--issue",
      "--bundle",
      bundlePath,
      "--pub",
      ephemPub,
      "--key-id",
      "PV-SINGLE-01",
      "--out-table",
      mdPath,
      "--append-ledger",
      "--ledger",
      ledgerPath,
      "--json",
    ]);
    assert.equal(singleRes.status, 0, singleRes.stderr);
    assert.ok(fs.readFileSync(mdPath, "utf8").includes("PV-SINGLE-01"));

    const ledger = JSON.parse(fs.readFileSync(ledgerPath, "utf8"));
    assert.equal(ledger.entries.length, 4);

    // --verify with --file and --now before/after expiry
    const verifyOk = runIssueCli([
      "--verify",
      "--file",
      path.join(pvDir, "PV-BATCH-01.pvkey"),
      "--pub",
      ephemPub,
      "--now",
      "2026-11-25T00:00:00Z",
      "--json",
    ]);
    assert.equal(verifyOk.status, 0, verifyOk.stderr);
    assert.equal(JSON.parse(verifyOk.stdout).valid, true);

    const verifyExpired = runIssueCli([
      "--verify",
      fullTok1,
      "--pub",
      ephemPub,
      "--now",
      "2026-12-20T00:00:00Z",
      "--json",
    ]);
    assert.equal(verifyExpired.status, 1);
    assert.equal(JSON.parse(verifyExpired.stdout).reason, "expired");
  });

  test("owner-console.mjs enforces loopback host, does not auto-listen on import, serves strict CSP UI, and supports status/issue/verify APIs", async () => {
    assert.throws(() => assertLoopbackHost("0.0.0.0"), /non-loopback/i);
    assert.throws(() => createOwnerConsoleServer({ host: "0.0.0.0" }), /non-loopback/i);
    assert.throws(() => createOwnerConsoleServer({ host: "192.168.1.50" }), /non-loopback/i);
    assert.equal(assertLoopbackHost("localhost"), "localhost");
    assert.equal(assertLoopbackHost("127.0.0.1"), "127.0.0.1");
    assert.equal(assertLoopbackHost("::1"), "::1");

    const tmp = makeTmpDir();
    const bundlePath = path.join(tmp, "bundle.json");
    const ledgerPath = path.join(tmp, "ledger.json");
    const genRes = runIssueCli(["--generate-bundle", "--out", bundlePath, "--json"]);
    assert.equal(genRes.status, 0);
    const ephemPub = JSON.parse(genRes.stdout).publicKeyB64U;

    // Missing bundle status is graceful
    const missingStatus = loadOwnerBundleStatus(path.join(tmp, "missing.json"));
    assert.equal(missingStatus.loaded, false);

    // Start server on ephemeral loopback port (default expectedPublicKeyB64U = PRO_PUBLIC_KEY_B64U -> mismatch=true)
    const srv1 = await startOwnerConsole({ bundlePath, ledgerPath, host: "127.0.0.1", port: 0 });
    activeServers.push(srv1);

    const htmlRes = await fetch(srv1.url);
    assert.equal(htmlRes.status, 200);
    assert.equal(htmlRes.headers.get("content-security-policy"), OWNER_CONSOLE_CSP);
    assert.equal(htmlRes.headers.get("cache-control"), "no-store");
    assert.equal(htmlRes.headers.get("x-frame-options"), "DENY");
    assert.equal(htmlRes.headers.get("x-content-type-options"), "nosniff");
    const htmlBody = await htmlRes.text();
    assert.equal(/<script(?![^>]*src=)/i.test(htmlBody), false);
    assert.equal(/<style/i.test(htmlBody), false);
    assert.equal(/\son\w+=/i.test(htmlBody), false);

    const cssRes = await fetch(`${srv1.url}styles.css`);
    assert.equal(cssRes.status, 200);
    const cssBody = await cssRes.text();
    assert.equal(/@import|100vw|https?:\/\//i.test(cssBody), false);

    const jsRes = await fetch(`${srv1.url}app.js`);
    assert.equal(jsRes.status, 200);
    const jsBody = await jsRes.text();
    assert.equal(/\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval)\b/.test(jsBody), false);

    const healthRes = await fetch(`${srv1.url}api/health`);
    assert.equal(healthRes.status, 200);
    assert.equal((await healthRes.json()).status, "ok");

    // /api/status redacts by default and never exposes privateKeyPkcs8Pem
    const statusRedactedRes = await fetch(`${srv1.url}api/status`);
    assert.equal(statusRedactedRes.status, 200);
    const statusRedactedText = await statusRedactedRes.text();
    assert.equal(statusRedactedText.includes("privateKeyPkcs8Pem"), false);
    assert.equal(statusRedactedText.includes("BEGIN PRIVATE KEY"), false);
    const statusRedacted = JSON.parse(statusRedactedText);
    assert.equal(statusRedacted.loaded, true);
    assert.equal(statusRedacted.publicKeyMatchesApp, false);
    assert.equal(statusRedacted.privateKeyMatchesPublic, true);
    assert.ok(statusRedacted.ownerKey.token.includes("..."));

    // Cross-origin CSRF guard on POST
    const csrfRes = await fetch(`${srv1.url}api/issue`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://evil.example",
      },
      body: JSON.stringify({ plan: "pro-monthly" }),
    });
    assert.equal(csrfRes.status, 403);

    // POST /api/issue single + batch + ledger
    const issueRes = await fetch(`${srv1.url}api/issue`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        plan: "pro-annual",
        count: 2,
        prefix: "PV-UI",
        orderId: "PV-ORD-555",
        appendLedger: true,
      }),
    });
    assert.equal(issueRes.status, 200);
    const issueData = await issueRes.json();
    assert.equal(issueData.ok, true);
    assert.equal(issueData.count, 2);
    assert.equal(issueData.publicKeyMatchesApp, false);
    assert.ok(issueData.items[0].activationUrlRu.includes(`#code=${issueData.items[0].token}`));
    const extractedFromPvkey = extractProToken(issueData.items[0].pvkeyContent);
    assert.equal(extractedFromPvkey, issueData.items[0].token);
    const verifiedIssued = await verifyProLicenseToken(extractedFromPvkey, { publicKeyB64U: ephemPub });
    assert.equal(verifiedIssued.valid, true);
    assert.equal(JSON.parse(fs.readFileSync(ledgerPath, "utf8")).entries.length, 2);

    // POST /api/verify valid, signature failure, expired, format failure
    const verifyValidRes = await fetch(`${srv1.url}api/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rawText: issueData.items[0].activationUrlRu,
        publicKeyB64U: ephemPub,
      }),
    });
    assert.equal(verifyValidRes.status, 200);
    const verifyValidData = await verifyValidRes.json();
    assert.equal(verifyValidData.result.valid, true);
    assert.equal(verifyValidData.cliResult.valid, true);
    assert.equal(verifyValidData.decodedPayload.ok, true);

    const verifyExpiredRes = await fetch(`${srv1.url}api/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rawText: issueData.items[0].pvkeyContent,
        publicKeyB64U: ephemPub,
        nowIso: "2030-01-01T00:00:00.000Z",
      }),
    });
    assert.equal((await verifyExpiredRes.json()).result.reason, "expired");

    const verifyWrongKeyRes = await fetch(`${srv1.url}api/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rawText: issueData.items[0].token,
      }),
    });
    assert.equal((await verifyWrongKeyRes.json()).result.reason, "signature");

    const verifyFormatRes = await fetch(`${srv1.url}api/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rawText: "PV2.invalid.token" }),
    });
    assert.equal((await verifyFormatRes.json()).result.reason, "format");

    // Second server instance with expectedPublicKeyB64U matching ephemPub reports publicKeyMatchesApp: true
    const srv2 = await startOwnerConsole({
      bundlePath,
      ledgerPath,
      expectedPublicKeyB64U: ephemPub,
      host: "127.0.0.1",
      port: 0,
    });
    activeServers.push(srv2);
    const statusMatchRes = await fetch(`${srv2.url}api/status?reveal=1`);
    const statusMatch = await statusMatchRes.json();
    assert.equal(statusMatch.publicKeyMatchesApp, true);
    assert.equal(statusMatch.redacted, false);
    assert.equal(statusMatch.ownerKey.token.includes("..."), false);

    await srv1.stop();
    await srv2.stop();
    activeServers = [];
  });

  test("owner-console.mjs handles non-object JSON bundles gracefully and classifies invalid /api/issue payloads as HTTP 400", async () => {
    const tmp = makeTmpDir("pv-m1-reg-");
    const nonObjectBundlePath = path.join(tmp, "bad-bundle.json");
    const validBundlePath = path.join(tmp, "valid-bundle.json");
    const ledgerPath = path.join(tmp, "ledger.json");

    for (const rawJson of ["null", "[]", "123", '"str"', "true"]) {
      fs.writeFileSync(nonObjectBundlePath, rawJson, "utf8");
      const status = loadOwnerBundleStatus(nonObjectBundlePath);
      assert.equal(status.loaded, false, `Expected loaded=false for ${rawJson}`);
      assert.equal(status.clientCount, 0);
      assert.match(status.error, /expected JSON object/i);

      const srvBad = await startOwnerConsole({
        bundlePath: nonObjectBundlePath,
        ledgerPath,
        host: "127.0.0.1",
        port: 0,
      });
      activeServers.push(srvBad);
      const statusRes = await fetch(`${srvBad.url}api/status`);
      assert.equal(statusRes.status, 200, `Expected HTTP 200 on /api/status for ${rawJson}`);
      const statusData = await statusRes.json();
      assert.equal(statusData.ok, true);
      assert.equal(statusData.loaded, false);
      assert.match(statusData.error, /expected JSON object/i);
      await srvBad.stop();
      activeServers = [];
    }

    const genRes = runIssueCli(["--generate-bundle", "--out", validBundlePath, "--json"]);
    assert.equal(genRes.status, 0);
    const ephemPub = JSON.parse(genRes.stdout).publicKeyB64U;

    const srv = await startOwnerConsole({
      bundlePath: validBundlePath,
      ledgerPath,
      expectedPublicKeyB64U: ephemPub,
      host: "127.0.0.1",
      port: 0,
    });
    activeServers.push(srv);

    // Same-port CSRF check: mismatched loopback port must return 403; matching origin port succeeds
    const wrongPort = srv.port === 65432 ? 65431 : 65432;
    const crossPortRes = await fetch(`${srv.url}api/issue`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: `http://127.0.0.1:${wrongPort}`,
      },
      body: JSON.stringify({ plan: "pro-monthly" }),
    });
    assert.equal(crossPortRes.status, 403);

    const samePortOrigin = `http://127.0.0.1:${srv.port}`;
    const samePortRes = await fetch(`${srv.url}api/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: samePortOrigin,
      },
      body: JSON.stringify({ rawText: "PV2.invalid.token" }),
    });
    assert.equal(samePortRes.status, 200);

    // Invalid client /api/issue payloads must return HTTP 400 (never 500)
    const invalidPayloads = [
      { count: 2, keyId: "FIXED" },
      { label: "   " },
      { prefix: "   " },
      { exp: "2020-01-01T00:00:00Z" },
      { keyId: "   " },
      { label: 123 },
    ];
    for (const payload of invalidPayloads) {
      const res = await fetch(`${srv.url}api/issue`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      assert.equal(
        res.status,
        400,
        `Expected HTTP 400 for payload ${JSON.stringify(payload)}, got ${res.status}`
      );
      const data = await res.json();
      assert.equal(data.ok, false);
      assert.ok(typeof data.error === "string" && data.error.length > 0);
    }

    await srv.stop();
    activeServers = [];
  });

  test("owner-console.mjs normalizes default port 80 / protocol in Origin CSRF guard and rejects non-primitive/overflow inputs", async () => {
    const tmp = makeTmpDir("pv-m1-csrf-");
    const bundlePath = path.join(tmp, "bundle.json");
    const ledgerPath = path.join(tmp, "ledger.json");

    const genRes = runIssueCli(["--generate-bundle", "--out", bundlePath, "--json"]);
    assert.equal(genRes.status, 0);
    const ephemPub = JSON.parse(genRes.stdout).publicKeyB64U;

    const srv = await startOwnerConsole({
      bundlePath,
      ledgerPath,
      expectedPublicKeyB64U: ephemPub,
      host: "127.0.0.1",
      port: 0,
    });
    activeServers.push(srv);

    // Omitted-port / port-80 / https: Origins against running 127.0.0.1:<port> must return 403
    for (const forbiddenOrigin of [
      "http://127.0.0.1",
      "http://127.0.0.1:80",
      "http://[::1]",
      `https://127.0.0.1:${srv.port}`,
    ]) {
      const res = await fetch(`${srv.url}api/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: forbiddenOrigin,
        },
        body: JSON.stringify({ rawText: "PV2.invalid.token" }),
      });
      assert.equal(
        res.status,
        403,
        `Expected HTTP 403 for Origin=${forbiddenOrigin} against ${srv.url}, got ${res.status}`
      );
    }

    // Omitted Origin still returns 200
    const noOriginRes = await fetch(`${srv.url}api/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rawText: "PV2.invalid.token" }),
    });
    assert.equal(noOriginRes.status, 200);

    // Direct handler probes for omitted-port Host (port 80) and IPv6 [::1]
    const handler = createOwnerConsoleHandler({
      bundlePath,
      ledgerPath,
      expectedPublicKeyB64U: ephemPub,
    });

    async function invokeHandler({ host, origin, urlPath = "/api/verify", payload = { rawText: "PV2.invalid.token" } }) {
      const headers = { host, "content-type": "application/json" };
      if (origin !== undefined) {
        headers.origin = origin;
      }
      const req = Readable.from([Buffer.from(JSON.stringify(payload), "utf8")]);
      req.method = "POST";
      req.url = urlPath;
      req.headers = headers;

      let statusCode = 0;
      const resChunks = [];
      const res = {
        writeHead(code) {
          statusCode = code;
        },
        end(buf) {
          if (buf) resChunks.push(Buffer.isBuffer(buf) ? buf : Buffer.from(buf));
        },
      };
      await handler(req, res);
      return {
        status: statusCode,
        body: JSON.parse(Buffer.concat(resChunks).toString("utf8")),
      };
    }

    assert.equal((await invokeHandler({ host: "127.0.0.1", origin: "http://127.0.0.1:9999" })).status, 403);
    assert.equal((await invokeHandler({ host: "127.0.0.1", origin: "http://127.0.0.1" })).status, 200);
    assert.equal((await invokeHandler({ host: "127.0.0.1:80", origin: "http://127.0.0.1" })).status, 200);
    assert.equal((await invokeHandler({ host: "[::1]:5000", origin: "http://[::1]" })).status, 403);
    assert.equal((await invokeHandler({ host: "[::1]:5000", origin: "http://[::1]:5000" })).status, 200);

    // Non-primitive count/days/exp and Date overflow on POST /api/issue must return HTTP 400
    for (const badPayload of [
      { days: true },
      { days: [10] },
      { count: true },
      { count: [1] },
      { exp: true },
      { exp: {} },
      { days: 1e12 },
    ]) {
      const res = await fetch(`${srv.url}api/issue`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(badPayload),
      });
      assert.equal(
        res.status,
        400,
        `Expected HTTP 400 for payload ${JSON.stringify(badPayload)}, got ${res.status}`
      );
      const data = await res.json();
      assert.equal(data.ok, false);
    }

    // Direct issueTokens nowMs & overflow validation + CLI missing value-flag rejection
    assert.throws(
      () => issueTokens({ bundlePath, expectedPublicKeyB64U: ephemPub, nowMs: Number.NaN }),
      (err) => err.statusCode === 400
    );
    assert.throws(
      () => issueTokens({ bundlePath, expectedPublicKeyB64U: ephemPub, days: 1e12 }),
      (err) => err.statusCode === 400 && /out of range/i.test(err.message)
    );

    for (const missingValArgs of [
      ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--days", "--json"],
      ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--count", "--json"],
      ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--now", "--json"],
      ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--exp", "--json"],
    ]) {
      const cliFail = runIssueCli(missingValArgs);
      assert.notEqual(cliFail.status, 0, `Expected non-zero exit for ${missingValArgs.join(" ")}`);
      const parsed = JSON.parse(cliFail.stdout);
      assert.equal(parsed.ok, false);
      assert.match(parsed.error, /Missing value/i);
    }

    await srv.stop();
    activeServers = [];
  });

  test("runCli rejects --flag='' for VALUE_FLAGS and issueTokens rejects non-string string-fields with statusCode 400", () => {
    const tmp = makeTmpDir("pv-m1-flags-");
    const bundlePath = path.join(tmp, "bundle.json");

    const genRes = runIssueCli(["--generate-bundle", "--out", bundlePath, "--json"]);
    assert.equal(genRes.status, 0, genRes.stderr);
    const ephemPub = JSON.parse(genRes.stdout).publicKeyB64U;

    const emptyEqCases = [
      { flag: "days", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--days=", "--json"] },
      { flag: "exp", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--exp=", "--json"] },
      { flag: "bundle", args: ["--issue", "--bundle=", "--pub", ephemPub, "--json"] },
      { flag: "pub", args: ["--issue", "--bundle", bundlePath, "--pub=", "--json"] },
      { flag: "file", args: ["--verify", "--file=", "--pub", ephemPub, "--json"] },
      { flag: "plan", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--plan=", "--json"] },
      { flag: "tier", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--tier=", "--json"] },
      { flag: "key-id", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--key-id=", "--json"] },
      { flag: "prefix", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--prefix=", "--json"] },
      { flag: "count", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--count=", "--json"] },
      { flag: "label", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--label=", "--json"] },
      { flag: "order", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--order=", "--json"] },
      { flag: "now", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--now=", "--json"] },
      { flag: "out", args: ["--generate-bundle", "--out=", "--json"] },
      { flag: "handoff-dir", args: ["--generate-bundle", "--out", bundlePath, "--handoff-dir=", "--json"] },
      { flag: "out-pvkey", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--out-pvkey=", "--json"] },
      { flag: "out-table", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--out-table=", "--json"] },
      { flag: "ledger", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--ledger=", "--json"] },
    ];

    for (const { flag, args } of emptyEqCases) {
      const cliFail = runIssueCli(args);
      assert.notEqual(cliFail.status, 0, `Expected non-zero exit for --${flag}=`);
      const parsed = JSON.parse(cliFail.stdout);
      assert.equal(parsed.ok, false);
      assert.equal(parsed.error, `Missing value for --${flag}`);
      assert.equal(cliFail.stdout.includes("EISDIR"), false);
      assert.equal(cliFail.stdout.includes(".secrets"), false);
    }

    const nonStringOverrides = [
      { keyId: true },
      { keyId: false },
      { label: 123 },
      { prefix: [] },
      { orderId: {} },
      { tier: true },
      { plan: 42 },
    ];
    for (const override of nonStringOverrides) {
      assert.throws(
        () =>
          issueTokens({
            bundlePath,
            expectedPublicKeyB64U: ephemPub,
            ...override,
          }),
        (err) => err.statusCode === 400 && /must be a string/i.test(err.message),
        `Expected statusCode=400 for ${JSON.stringify(override)}`
      );
    }
  });

  test("runCli and issueTokens reject whitespace-only inputs and sub-millisecond days with statusCode 400", async () => {
    const tmp = makeTmpDir("pv-m1-ws-");
    const bundlePath = path.join(tmp, "bundle.json");
    const ledgerPath = path.join(tmp, "ledger.json");
    const cliWorkDir = path.join(tmp, "cli-work");
    fs.mkdirSync(cliWorkDir, { recursive: true });

    const genRes = runIssueCli(["--generate-bundle", "--out", bundlePath, "--json"]);
    assert.equal(genRes.status, 0, genRes.stderr);
    const ephemPub = JSON.parse(genRes.stdout).publicKeyB64U;

    const whitespaceCliCases = [
      { flag: "out-table", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--out-table=   ", "--json"] },
      { flag: "out", args: ["--generate-bundle", "--out=   ", "--json"] },
      { flag: "out-pvkey", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--out-pvkey=   ", "--json"] },
      { flag: "plan", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--plan=   ", "--json"] },
      { flag: "plan", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--plan", "   ", "--json"] },
      { flag: "order", args: ["--issue", "--bundle", bundlePath, "--pub", ephemPub, "--order=   ", "--json"] },
      { flag: "bundle", args: ["--issue", "--bundle=   ", "--pub", ephemPub, "--json"] },
      { flag: "pub", args: ["--issue", "--bundle", bundlePath, "--pub=   ", "--json"] },
      { flag: "file", args: ["--verify", "--file=   ", "--pub", ephemPub, "--json"] },
    ];

    for (const { flag, args } of whitespaceCliCases) {
      const cliFail = spawnSync(process.execPath, [ISSUE_SCRIPT, ...args], {
        cwd: cliWorkDir,
        encoding: "utf8",
      });
      assert.notEqual(cliFail.status, 0, `Expected non-zero exit for --${flag} whitespace`);
      const parsed = JSON.parse(cliFail.stdout);
      assert.equal(parsed.ok, false);
      assert.equal(parsed.error, `Missing value for --${flag}`);
      assert.equal(cliFail.stdout.includes("EISDIR"), false);
      assert.equal(cliFail.stderr.includes("EISDIR"), false);
      assert.deepEqual(fs.readdirSync(cliWorkDir), [], `Stray file created in cwd for --${flag}`);
    }

    for (const field of ["plan", "tier", "keyId", "prefix", "label", "orderId"]) {
      assert.throws(
        () =>
          issueTokens({
            bundlePath,
            expectedPublicKeyB64U: ephemPub,
            [field]: "   ",
          }),
        (err) => err.statusCode === 400,
        `Expected statusCode=400 for whitespace ${field}`
      );
    }

    assert.throws(
      () =>
        issueTokens({
          bundlePath,
          expectedPublicKeyB64U: ephemPub,
          days: 1e-10,
        }),
      (err) => err.statusCode === 400,
      "Expected statusCode=400 for sub-millisecond days"
    );

    const srv = await startOwnerConsole({
      bundlePath,
      ledgerPath,
      expectedPublicKeyB64U: ephemPub,
      host: "127.0.0.1",
      port: 0,
    });
    activeServers.push(srv);

    for (const badBody of [{ days: 1e-10 }, { plan: "   " }, { orderId: "   " }]) {
      const res = await fetch(`${srv.url}api/issue`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(badBody),
      });
      assert.equal(res.status, 400, `Expected HTTP 400 for ${JSON.stringify(badBody)}, got ${res.status}`);
      const body = await res.json();
      assert.equal(body.ok, false);
    }

    await srv.stop();
    activeServers = [];
  });

  test("verifyBundleObject rejects non-array clientKeys and empty bundles, and owner-console hardens CSRF/Referer/protocol-relative/ledger/favicon", async () => {
    const tmp = makeTmpDir("pv-m4-hardening-");
    const bundlePath = path.join(tmp, "bundle.json");
    const ledgerPath = path.join(tmp, "ledger.json");

    const genRes = runIssueCli(["--generate-bundle", "--out", bundlePath, "--json"]);
    assert.equal(genRes.status, 0, genRes.stderr);
    const ephemPub = JSON.parse(genRes.stdout).publicKeyB64U;
    const validBundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));

    // 1. verifyBundleObject rejects non-array clientKeys and empty bundles
    const nonArrayClientBundle = { ...validBundle, clientKeys: "not-an-array" };
    const nonArrayRes = verifyBundleObject(nonArrayClientBundle, {
      expectedPublicKeyB64U: ephemPub,
      strictCodeMatch: true,
    });
    assert.equal(nonArrayRes.ok, false);
    assert.ok(nonArrayRes.failures.some((f) => f.kind === "clientKeys"));

    const emptyBundle = {
      publicKeyB64U: validBundle.publicKeyB64U,
      privateKeyPkcs8Pem: validBundle.privateKeyPkcs8Pem,
    };
    const emptyRes = verifyBundleObject(emptyBundle, {
      expectedPublicKeyB64U: ephemPub,
      strictCodeMatch: true,
    });
    assert.equal(emptyRes.ok, false);
    assert.ok(emptyRes.failures.some((f) => f.reason === "empty_bundle"));

    // 2. owner-console HTTP handler hardening: cross-host Origin, evil Referer without Origin, //evil.com URL, corrupt ledger, /favicon.ico 204
    const handler = createOwnerConsoleHandler({
      bundlePath,
      ledgerPath,
      expectedPublicKeyB64U: ephemPub,
    });

    async function callHandler({ method = "POST", url = "/api/issue", headers = {}, body = "" }) {
      const req = Readable.from(body ? [Buffer.from(body, "utf8")] : []);
      req.method = method;
      req.url = url;
      req.headers = headers;

      let statusCode = 0;
      const chunks = [];
      const res = {
        writeHead(code) {
          statusCode = code;
        },
        end(buf) {
          if (buf) chunks.push(Buffer.isBuffer(buf) ? buf : Buffer.from(buf));
        },
      };
      await handler(req, res);
      return {
        status: statusCode,
        text: Buffer.concat(chunks).toString("utf8"),
      };
    }

    // Cross-host loopback Origin: http://localhost:5000 vs Host: 127.0.0.1:5000 -> 403
    const crossHostRes = await callHandler({
      method: "POST",
      url: "/api/issue",
      headers: {
        host: "127.0.0.1:5000",
        origin: "http://localhost:5000",
        "content-type": "application/json",
      },
      body: JSON.stringify({ plan: "pro-monthly" }),
    });
    assert.equal(crossHostRes.status, 403);

    // Omitted Origin + evil Referer -> 403; matching Referer -> 200
    const evilRefRes = await callHandler({
      method: "POST",
      url: "/api/issue",
      headers: {
        host: "127.0.0.1:5000",
        referer: "https://evil.com/attack.html",
        "content-type": "application/json",
      },
      body: JSON.stringify({ plan: "pro-monthly" }),
    });
    assert.equal(evilRefRes.status, 403);

    const sameRefRes = await callHandler({
      method: "POST",
      url: "/api/verify",
      headers: {
        host: "127.0.0.1:5000",
        referer: "http://127.0.0.1:5000/",
        "content-type": "application/json",
      },
      body: JSON.stringify({ rawText: "PV2.bad.sig" }),
    });
    assert.equal(sameRefRes.status, 200);

    // Protocol-relative //evil.com/api/health -> 400
    const protoRelRes = await callHandler({
      method: "GET",
      url: "//evil.com/api/health",
      headers: { host: "127.0.0.1:5000" },
    });
    assert.equal(protoRelRes.status, 400);

    // GET /favicon.ico -> 204
    const favRes = await callHandler({
      method: "GET",
      url: "/favicon.ico",
      headers: { host: "127.0.0.1:5000" },
    });
    assert.equal(favRes.status, 204);
    assert.equal(favRes.text, "");

    // Corrupt JSON and invalid schema in ledger.json -> 409 (no 500, no OS path leak)
    for (const badLedger of ["{corrupt json", JSON.stringify({ format: "PV1-LEDGER", entries: "bad" })]) {
      fs.writeFileSync(ledgerPath, badLedger, "utf8");
      const ledgerErrRes = await callHandler({
        method: "POST",
        url: "/api/issue",
        headers: {
          host: "127.0.0.1:5000",
          origin: "http://127.0.0.1:5000",
          "content-type": "application/json",
        },
        body: JSON.stringify({ plan: "pro-monthly", appendLedger: true }),
      });
      assert.ok(ledgerErrRes.status === 400 || ledgerErrRes.status === 409);
      assert.equal(ledgerErrRes.text.includes(ledgerPath), false);
      assert.equal(ledgerErrRes.text.includes(tmp), false);
    }
  });
});
