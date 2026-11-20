import test, { describe } from "node:test";
import assert from "node:assert/strict";

import {
  detectEntities,
  isValidIban,
  isValidRuAccountWithBik,
  isValidRuBik,
  isValidRuInn,
  isValidRuOgrn,
  isValidRuSnils,
  luhnCheck,
} from "../../app/static/js/detector.js";

describe("PromptVeil Core 25 Detectors & Checksums (Item 26)", () => {
  test("API_KEY, URL_TOKEN, and JWT detect credentials while skipping benign URLs", () => {
    const awsKey = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    const stripeKey = ["sk_live_", "51H8abcdef1234567890ABCD"].join("");
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const urlSecret = "https://example.com/cb?token=super_secret_token_987654&ok=1";
    const safeUrl = "https://example.com/docs?page=2&lang=en";

    const spans = detectEntities(`${awsKey} ${stripeKey} ${jwt} ${urlSecret} ${safeUrl}`);
    const cats = spans.map((s) => s.category);
    assert.equal(cats.filter((c) => c === "API_KEY").length, 2);
    assert.equal(cats.includes("JWT"), true);
    assert.equal(cats.includes("URL_TOKEN"), true);
    assert.equal(spans.some((s) => s.value.includes("page=2")), false);
  });

  test("IBAN validator accepts valid mod-97 IBANs, rejects bad mod-97, and handles unlisted prefix", () => {
    assert.equal(isValidIban("DE89 3704 0044 0532 0130 00"), true);
    assert.equal(isValidIban("DE89 3704 0044 0532 0130 01"), false);
    assert.equal(isValidIban("DE89 3704"), false);

    const spans = detectEntities("IBAN: DE89 3704 0044 0532 0130 00 and bad DE89 3704 0044 0532 0130 01");
    assert.deepEqual(
      spans.filter((s) => s.category === "IBAN").map((s) => s.value),
      ["DE89 3704 0044 0532 0130 00"]
    );
  });

  test("RU_INN, RU_SNILS, RU_OGRN, RU_BIK, RU_ACCOUNT, RU_OMS, and RU_PASSPORT validate checksums and context", () => {
    assert.equal(isValidRuInn("7707083893"), true);
    assert.equal(isValidRuInn("500100732259"), true);
    assert.equal(isValidRuInn("7707083890"), false);

    assert.equal(isValidRuSnils("112-233-445 95"), true);
    assert.equal(isValidRuSnils("112-233-445 00"), false);

    assert.equal(isValidRuOgrn("1027700132195"), true);
    assert.equal(isValidRuOgrn("304500116000157"), true);
    assert.equal(isValidRuOgrn("1027700132190"), false);

    assert.equal(isValidRuBik("044525225"), true);
    assert.equal(isValidRuBik("040000000"), false);
    assert.equal(isValidRuAccountWithBik("40702810938000012345", "044525225"), true);

    const text = [
      "ИНН 7707083893",
      "СНИЛС 112-233-445 95",
      "ОГРН 1027700132195",
      "БИК 044525225",
      "р/с 40702810938000012345",
      "ОМС 7746 1234 5678 9019",
      "паспорт 4512 123456",
    ].join(", ");
    const spans = detectEntities(text);
    for (const expectedCat of [
      "RU_INN",
      "RU_SNILS",
      "RU_OGRN",
      "RU_BIK",
      "RU_ACCOUNT",
      "RU_OMS",
      "RU_PASSPORT",
    ]) {
      assert.equal(
        spans.some((s) => s.category === expectedCat),
        true,
        `Expected ${expectedCat} in ${JSON.stringify(spans.map((s) => s.category))}`
      );
    }
  });

  test("CREDIT_CARD validates Luhn and strips trailing -NN suffix while rejecting 20-digit spans", () => {
    assert.equal(luhnCheck("4111 1111 1111 1111"), true);
    assert.equal(luhnCheck("0000 0000 0000 0000"), false);

    const text = "Card 4111-1111-1111-1111-01 and 40702810938000012345";
    const cardSpans = detectEntities(text).filter((s) => s.category === "CREDIT_CARD");
    assert.deepEqual(cardSpans.map((s) => s.value), ["4111-1111-1111-1111"]);
  });

  test("SSN, ENV_SECRET, EMAIL, PHONE, RU_AUTO_PLATE, IPV4, and HIGH_ENTROPY handle positive & negative guards", () => {
    const sample = [
      "SSN 123-45-6789",
      'DB_PASSWORD="Tr0ub4dor&3!RealSecret"',
      "API_DUMMY=your_key_here",
      "user.name+tag@company.example",
      "+7 (999) 123-45-67",
      "А123ВС777",
      "192.168.10.42",
      "v2.4.1.0",
      "2026-11-20",
      "C:\\Windows\\System32\\drivers\\etc\\hosts",
      "K7xM9pQ2vR8nL4wZ6tB1yF5hJ3cN0sD",
    ].join("\n");

    const spans = detectEntities(sample);
    const byCat = (cat) => spans.filter((s) => s.category === cat).map((s) => s.value);

    assert.deepEqual(byCat("SSN"), ["123-45-6789"]);
    assert.deepEqual(byCat("ENV_SECRET"), ["Tr0ub4dor&3!RealSecret"]);
    assert.deepEqual(byCat("EMAIL"), ["user.name+tag@company.example"]);
    assert.deepEqual(byCat("PHONE"), ["+7 (999) 123-45-67"]);
    assert.deepEqual(byCat("RU_AUTO_PLATE"), ["А123ВС777"]);
    assert.deepEqual(byCat("IPV4"), ["192.168.10.42"]);
    assert.equal(spans.some((s) => s.value === "v2.4.1.0"), false);
    assert.equal(spans.some((s) => s.value === "2026-11-20"), false);
    assert.equal(spans.some((s) => s.value.includes("System32")), false);
    assert.equal(byCat("HIGH_ENTROPY").includes("K7xM9pQ2vR8nL4wZ6tB1yF5hJ3cN0sD"), true);
  });
});
