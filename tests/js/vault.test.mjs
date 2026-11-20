import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { SessionVault } from "../../app/static/js/vault.js";

describe("PromptVeil SessionVault Transient Evolution & Toggles (Item 26)", () => {
  test("evolveTransient=true keeps stable token when typing grows a detected secret", () => {
    const vault = new SessionVault();
    const prefix = 'DB_PASSWORD="AlphaBeta12"';
    const first = vault.sanitize(prefix, [], { evolveTransient: true });
    assert.equal(first.sanitizedText, 'DB_PASSWORD="[ENV_SECRET_1]"');

    const extended = 'DB_PASSWORD="AlphaBeta123456"';
    const second = vault.sanitize(extended, [], { evolveTransient: true });
    assert.equal(second.sanitizedText, 'DB_PASSWORD="[ENV_SECRET_1]"');
    assert.equal(vault.tokenToEntry.size, 1);
    assert.equal(vault.rehydrate("Reply: [ENV_SECRET_1]").rehydratedText, "Reply: AlphaBeta123456");
  });

  test("evolveTransient=true evicts inactive prefix entries when category upgrades (HIGH_ENTROPY -> JWT)", () => {
    const vault = new SessionVault();
    const partialJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    const first = vault.sanitize(partialJwt, [], { evolveTransient: true });
    assert.equal(first.maskedCount, 1);

    const fullJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const second = vault.sanitize(fullJwt, [], { evolveTransient: true });
    assert.equal(second.sanitizedText, "[JWT_1]");
    assert.equal(vault.tokenToEntry.size, 1);
    assert.equal(vault.rehydrate("[JWT_1]").rehydratedText, fullJwt);
  });

  test("evolveTransient=false preserves independent tokens across turns", () => {
    const vault = new SessionVault();
    const r1 = vault.sanitize("alice@example.com", [], { evolveTransient: false });
    const r2 = vault.sanitize("alice@example.com.org", [], { evolveTransient: false });
    assert.equal(r1.sanitizedText, "[EMAIL_1]");
    assert.equal(r2.sanitizedText, "[EMAIL_2]");
    assert.equal(vault.tokenToEntry.size, 2);
  });

  test("toggleToken and toggleValue control active masking and round-trip rehydration", () => {
    const vault = new SessionVault();
    const text = "Email a@b.co and b@c.co";
    const res1 = vault.sanitize(text);
    assert.equal(res1.sanitizedText, "Email [EMAIL_1] and [EMAIL_2]");
    assert.equal(res1.maskedCount, 2);

    vault.toggleToken("[EMAIL_1]", false);
    const res2 = vault.sanitize(text);
    assert.equal(res2.sanitizedText, "Email a@b.co and [EMAIL_2]");
    assert.equal(res2.maskedCount, 1);
    assert.equal(res2.skippedCount, 1);

    vault.toggleToken("[EMAIL_1]", true);
    const res3 = vault.sanitize(text);
    assert.equal(res3.sanitizedText, "Email [EMAIL_1] and [EMAIL_2]");
    assert.equal(res3.maskedCount, 2);

    const reh = vault.rehydrate("Hi [EMAIL_2] and [UNKNOWN_9]");
    assert.equal(reh.rehydratedText, "Hi b@c.co and [UNKNOWN_9]");
    assert.deepEqual(reh.restoredTokens, ["[EMAIL_2]"]);
    assert.deepEqual(reh.unresolvedTokens, ["[UNKNOWN_9]"]);
  });
});
