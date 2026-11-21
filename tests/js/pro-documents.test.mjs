import test, { afterEach, beforeEach, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import zlib from "node:zlib";

import {
  DocumentParseError,
  FREE_MAX_FILE_BYTES,
  PRO_MAX_FILE_BYTES,
  buildZipArchive,
  crc32,
  decompressBytes,
  extractDocxText,
  extractPdfText,
  extractXlsxText,
  inflateRawPureJs,
  inflateZlibPureJs,
  parseDocumentFile,
  readZipEntries,
  validateBatchFiles,
} from "../../app/static/js/pro-documents.js";
import { SessionVault } from "../../app/static/js/vault.js";
import { createFileController } from "../../app/static/js/clipboard.js";
import { createPipelineController } from "../../app/static/js/pipeline.js";
import { renderBatchQueuePanel } from "../../app/static/js/render-workbench.js";
import { ensureDictionary, setLang } from "../../app/static/js/i18n.js";
import {
  hideInlineAlert,
  resetNotifications,
  showInlineAlert,
  showStatusBanner,
} from "../../app/static/js/notifications.js";

function buildSyntheticZip(entries, { compress = true, utf8Flag = true } = {}) {
  const encoder = new TextEncoder();
  const localChunks = [];
  const cdChunks = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBytes = encoder.encode(entry.name);
    const rawData =
      typeof entry.data === "string" ? encoder.encode(entry.data) : new Uint8Array(entry.data);
    const crc = crc32(rawData);
    const compData = compress ? new Uint8Array(zlib.deflateRawSync(rawData)) : rawData;
    const method = compress ? 8 : 0;
    const flag = utf8Flag ? 0x0800 : 0;

    const lfh = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(lfh.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, flag, true);
    lv.setUint16(8, method, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, compData.length, true);
    lv.setUint32(22, rawData.length, true);
    lv.setUint16(26, nameBytes.length, true);
    lfh.set(nameBytes, 30);
    localChunks.push(lfh, compData);

    const cdh = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(cdh.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, flag, true);
    cv.setUint16(10, method, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, compData.length, true);
    cv.setUint32(24, rawData.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint32(42, offset, true);
    cdh.set(nameBytes, 46);
    cdChunks.push(cdh);

    offset += lfh.length + compData.length;
  }

  const cdSize = cdChunks.reduce((acc, c) => acc + c.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, entries.length, true);
  ev.setUint16(10, entries.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, offset, true);

  const out = new Uint8Array(offset + cdSize + 22);
  let pos = 0;
  for (const chunk of localChunks) {
    out.set(chunk, pos);
    pos += chunk.length;
  }
  for (const chunk of cdChunks) {
    out.set(chunk, pos);
    pos += chunk.length;
  }
  out.set(eocd, pos);
  return out;
}

function escapeXml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function buildSyntheticDocx({
  paragraphs = [],
  tableRows = [],
  headerText = "",
  footerText = "",
  compress = true,
} = {}) {
  const pXml = paragraphs
    .map(
      (p) =>
        `<w:p><w:r><w:t xml:space="preserve">${escapeXml(p)}</w:t></w:r></w:p>`
    )
    .join("");
  const tblXml =
    tableRows.length > 0
      ? `<w:tbl>${tableRows
          .map(
            (row) =>
              `<w:tr>${row
                .map((cell) => `<w:tc><w:p><w:r><w:t>${escapeXml(cell)}</w:t></w:r></w:p></w:tc>`)
                .join("")}</w:tr>`
          )
          .join("")}</w:tbl>`
      : "";

  const docXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<w:document><w:body>${pXml}${tblXml}<w:p><w:r><w:t>Tab</w:t><w:tab/><w:t>Col</w:t><w:br/><w:t>Line2</w:t></w:r></w:p></w:body></w:document>`;

  const entries = [
    { name: "word/document.xml", data: docXml },
    { name: "[Content_Types].xml", data: "<Types></Types>" },
  ];
  if (headerText) {
    entries.push({
      name: "word/header1.xml",
      data: `<?xml version="1.0"?><w:hdr><w:p><w:r><w:t>${escapeXml(headerText)}</w:t></w:r></w:p></w:hdr>`,
    });
  }
  if (footerText) {
    entries.push({
      name: "word/footer1.xml",
      data: `<?xml version="1.0"?><w:ftr><w:p><w:r><w:t>${escapeXml(footerText)}</w:t></w:r></w:p></w:ftr>`,
    });
  }
  return buildSyntheticZip(entries, { compress });
}

function buildSyntheticXlsx({ compress = true } = {}) {
  const sstXml =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<sst count="3" uniqueCount="3">` +
    `<si><t>Алексей Смирнов</t></si>` +
    `<si><r><t>ceo</t></r><r><t>@acme.ru</t></r><rPh sb="0" eb="1"><t>IGNORE_PHONETIC</t></rPh></si>` +
    `<si><t>7707083893</t></si>` +
    `</sst>`;

  const sheet1Xml =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<worksheet><sheetData>` +
    `<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>` +
    `<row r="2"><c r="A2" t="inlineStr"><is><t>+7 916 123-45-67</t></is></c><c r="B2" t="b"><v>1</v></c><c r="C2"><v>42500</v></c></row>` +
    `</sheetData></worksheet>`;

  const sheet2Xml =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<worksheet><sheetData>` +
    `<row r="1"><c r="A1" t="s"><v>2</v></c></row>` +
    `</sheetData></worksheet>`;

  const wbXml =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<workbook><sheets>` +
    `<sheet name="Clients" sheetId="1" r:id="rId1"/>` +
    `<sheet name="TaxIDs" sheetId="2" r:id="rId2"/>` +
    `</sheets></workbook>`;

  const relsXml =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<Relationships>` +
    `<Relationship Id="rId1" Target="worksheets/sheet1.xml"/>` +
    `<Relationship Id="rId2" Target="worksheets/sheet2.xml"/>` +
    `</Relationships>`;

  return buildSyntheticZip(
    [
      { name: "xl/workbook.xml", data: wbXml },
      { name: "xl/_rels/workbook.xml.rels", data: relsXml },
      { name: "xl/sharedStrings.xml", data: sstXml },
      { name: "xl/worksheets/sheet1.xml", data: sheet1Xml },
      { name: "xl/worksheets/sheet2.xml", data: sheet2Xml },
    ],
    { compress }
  );
}

function buildPdfFromObjects(objects) {
  const chunks = ["%PDF-1.4\n"];
  const offsets = [0];
  let cursor = chunks[0].length;
  for (const [objNum, bodyBytes] of objects) {
    offsets.push(cursor);
    const header = Buffer.from(`${objNum} 0 obj\n`, "latin1");
    const footer = Buffer.from("\nendobj\n", "latin1");
    const raw = Buffer.isBuffer(bodyBytes) ? bodyBytes : Buffer.from(bodyBytes, "latin1");
    chunks.push(header, raw, footer);
    cursor += header.length + raw.length + footer.length;
  }
  const xrefOffset = cursor;
  let xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= objects.length; i += 1) {
    xref += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  }
  xref += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  chunks.push(xref);
  return new Uint8Array(Buffer.concat(chunks.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c, "latin1")))));
}

function makePdfStreamObj(rawStrOrBytes, { compress = true, filterArray = false } = {}) {
  const raw = Buffer.isBuffer(rawStrOrBytes) ? rawStrOrBytes : Buffer.from(rawStrOrBytes, "latin1");
  const payload = compress ? zlib.deflateSync(raw) : raw;
  const filterPart = compress
    ? filterArray
      ? "/Filter [/FlateDecode] "
      : "/Filter /FlateDecode "
    : "";
  return Buffer.concat([
    Buffer.from(`<< ${filterPart}/Length ${payload.length} >>\nstream\n`, "latin1"),
    payload,
    Buffer.from("\nendstream", "latin1"),
  ]);
}

function encodeUtf16BePdfLiteral(text) {
  const out = [0xfe, 0xff];
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    out.push((code >> 8) & 0xff, code & 0xff);
  }
  const escaped = [];
  for (const b of out) {
    if (b === 0x28 || b === 0x29 || b === 0x5c) {
      escaped.push(0x5c, b);
    } else if (b === 0x0a) {
      escaped.push(0x5c, 0x6e);
    } else if (b === 0x0d) {
      escaped.push(0x5c, 0x72);
    } else {
      escaped.push(b);
    }
  }
  return Buffer.from(escaped);
}

describe("PromptVeil M2 pro-documents.js: Validation, Inflate & ZIP", () => {
  test("validateBatchFiles enforces Free 2 MB / single text vs Pro 50 MB / multi-file", () => {
    assert.equal(FREE_MAX_FILE_BYTES, 2 * 1024 * 1024);
    assert.equal(PRO_MAX_FILE_BYTES, 50 * 1024 * 1024);

    const freeSmall = { name: "notes.txt", size: 1024 };
    assert.equal(validateBatchFiles([freeSmall], { isPro: false }).accepted.length, 1);

    const freeTooBig = { name: "big.txt", size: FREE_MAX_FILE_BYTES + 1 };
    assert.equal(
      validateBatchFiles([freeTooBig], { isPro: false }).rejection.code,
      "free_too_large"
    );

    const freeDocx = { name: "contract.docx", size: 4096 };
    assert.equal(
      validateBatchFiles([freeDocx], { isPro: false }).rejection.code,
      "pro_format"
    );

    const freeMulti = [freeSmall, { name: "second.txt", size: 100 }];
    assert.equal(
      validateBatchFiles(freeMulti, { isPro: false }).rejection.code,
      "pro_multi_file"
    );

    const freePng = { name: "photo.png", size: 512 };
    assert.equal(
      validateBatchFiles([freePng], { isPro: false }).rejection.code,
      "unsupported_ext"
    );

    const proBatch = [
      { name: "a.docx", size: 10 * 1024 * 1024 },
      { name: "b.xlsx", size: 20 * 1024 * 1024 },
      { name: "c.pdf", size: PRO_MAX_FILE_BYTES },
    ];
    assert.equal(validateBatchFiles(proBatch, { isPro: true }).accepted.length, 3);

    const proTooBig = { name: "huge.pdf", size: PRO_MAX_FILE_BYTES + 1 };
    assert.equal(
      validateBatchFiles([proTooBig], { isPro: true }).rejection.code,
      "pro_too_large"
    );
  });

  test("inflateRawPureJs & inflateZlibPureJs handle stored, fixed, dynamic, and RLE overlapping copies", async () => {
    const sampleText =
      "AAAAABBBBBCCCCCDDDDD " +
      "PromptVeil deterministic privacy check ivan@example.com ".repeat(40) +
      "Конец теста.";
    const rawBytes = new TextEncoder().encode(sampleText);

    // 1. Dynamic Huffman (Node zlib default)
    const deflatedDyn = new Uint8Array(zlib.deflateRawSync(rawBytes, { level: 9 }));
    assert.deepEqual(inflateRawPureJs(deflatedDyn), rawBytes);

    // 2. Fixed Huffman (Z_FIXED)
    const deflatedFixed = new Uint8Array(
      zlib.deflateRawSync(rawBytes, { strategy: zlib.constants.Z_FIXED })
    );
    assert.deepEqual(inflateRawPureJs(deflatedFixed), rawBytes);

    // 3. Stored block (BTYPE=00)
    const storedBlock = new Uint8Array(5 + 5);
    storedBlock[0] = 0x01; // BFINAL=1, BTYPE=00
    storedBlock[1] = 5;
    storedBlock[2] = 0;
    storedBlock[3] = 0xfa;
    storedBlock[4] = 0xff;
    storedBlock.set(new TextEncoder().encode("Hello"), 5);
    assert.equal(new TextDecoder().decode(inflateRawPureJs(storedBlock)), "Hello");

    // 4. Zlib stream
    const zlibData = new Uint8Array(zlib.deflateSync(rawBytes));
    assert.deepEqual(inflateZlibPureJs(zlibData), rawBytes);

    // 5. Native DecompressionStream & forcePureJs parity
    const nativeRes = await decompressBytes(zlibData, "deflate", { forcePureJs: false });
    const pureRes = await decompressBytes(zlibData, "deflate", { forcePureJs: true });
    assert.deepEqual(nativeRes, rawBytes);
    assert.deepEqual(pureRes, rawBytes);
  });

  test("readZipEntries & buildZipArchive round-trip Cyrillic UTF-8 names and reject corrupt/zip-bomb archives", async () => {
    const built = buildZipArchive([
      { name: "отчёт_клиента.txt", data: "Иван Петров +7 916 111-22-33" },
      { name: "empty.txt", data: "" },
    ]);
    const parsed = await readZipEntries(built);
    assert.equal(
      new TextDecoder().decode(parsed.get("отчёт_клиента.txt")),
      "Иван Петров +7 916 111-22-33"
    );
    assert.equal(parsed.get("empty.txt").length, 0);

    // Corrupted CRC
    const badZip = buildSyntheticZip([{ name: "a.txt", data: "hello" }], { compress: true });
    badZip[badZip.length - 30] ^= 0xff;
    await assert.rejects(
      () => readZipEntries(badZip),
      (err) => err instanceof DocumentParseError && err.code === "CORRUPT_ARCHIVE"
    );

    // Truncated archive
    const truncated = new TextEncoder().encode("PK\x03\x04\x14\x00corrupted");
    await assert.rejects(
      () => readZipEntries(truncated),
      (err) => err instanceof DocumentParseError && err.code === "INVALID_ZIP"
    );

    // Zip bomb bound enforcement (pure-JS & native)
    const largeZeros = new Uint8Array(64 * 1024);
    const bombZip = buildSyntheticZip([{ name: "zeros.bin", data: largeZeros }], {
      compress: true,
    });
    await assert.rejects(
      () => readZipEntries(bombZip, { maxOutputBytes: 1024, forcePureJs: true }),
      (err) => err instanceof DocumentParseError && err.code === "ZIP_BOMB"
    );
    await assert.rejects(
      () => readZipEntries(bombZip, { maxOutputBytes: 1024, forcePureJs: false }),
      (err) => err instanceof DocumentParseError && err.code === "ZIP_BOMB"
    );
  });
});

describe("PromptVeil M2 Office (.docx / .xlsx) & PDF Extractors", () => {
  test("extractDocxText extracts paragraphs, headers, footers, tables, tabs & breaks in pure-JS and DOMParser modes", async () => {
    const docxBytes = buildSyntheticDocx({
      headerText: "Конфиденциально — ООО «Вектор»",
      paragraphs: ["Договор № 42", "Контакт: test.client@example.com"],
      tableRows: [
        ["ФИО", "ИНН"],
        ["Алексей Смирнов", "7707083893"],
      ],
      footerText: "Подвал: support@vector.ru",
      compress: true,
    });

    const resPure = await extractDocxText(docxBytes, { forcePureJs: true });
    assert.match(resPure.text, /ООО «Вектор»/);
    assert.match(resPure.text, /test\.client@example\.com/);
    assert.match(resPure.text, /Алексей Смирнов\t7707083893/);
    assert.match(resPure.text, /Tab\tCol\nLine2/);
    assert.match(resPure.text, /support@vector\.ru/);
    assert.equal(resPure.partCount, 3);
  });

  test("extractXlsxText resolves sharedStrings (including rich text, excluding rPh), inlineStr, booleans & sheet order", async () => {
    const xlsxBytes = buildSyntheticXlsx({ compress: true });
    const res = await extractXlsxText(xlsxBytes, { forcePureJs: true });
    assert.equal(res.sheetCount, 2);
    assert.match(res.text, /\[Clients\]/);
    assert.match(res.text, /Алексей Смирнов\tceo@acme\.ru/);
    assert.equal(res.text.includes("IGNORE_PHONETIC"), false);
    assert.match(res.text, /\+7 916 123-45-67\tTRUE\t42500/);
    assert.match(res.text, /\[TaxIDs\]\n7707083893/);
  });

  test("extractPdfText decodes WinAnsi escapes/octal, FlateDecode TJ arrays, UTF-16BE Cyrillic, ToUnicode bfchar/bfrange, and detects scanned PDFs", async () => {
    // 1. Uncompressed WinAnsi with escapes & octal \101 ('A')
    const pdf1 = buildPdfFromObjects([
      [1, "<< /Type /Catalog /Pages 2 0 R >>"],
      [2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"],
      [3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"],
      [4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"],
      [
        5,
        makePdfStreamObj(
          "BT\n/F1 12 Tf\n72 720 Td\n(\\101gent \\(bob@example.com\\) \\\\ key) Tj\nET\n",
          { compress: false }
        ),
      ],
    ]);
    const r1 = await extractPdfText(pdf1);
    assert.equal(r1.isScannedPdf, false);
    assert.equal(r1.text, "Agent (bob@example.com) \\ key");

    // 2. FlateDecode + /Filter [/FlateDecode] + TJ kerning + UTF-16BE Cyrillic
    const cyrBytes = encodeUtf16BePdfLiteral("Иван Петров ivan@acme.ru");
    const content2 = Buffer.concat([
      Buffer.from("BT\n/F1 12 Tf\n[(user) -240 (@example.com)] TJ\n0 -16 Td\n(", "latin1"),
      cyrBytes,
      Buffer.from(") Tj\nET\n", "latin1"),
    ]);
    const pdf2 = buildPdfFromObjects([
      [1, "<< /Type /Catalog /Pages 2 0 R >>"],
      [2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"],
      [3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"],
      [4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"],
      [5, makePdfStreamObj(content2, { compress: true, filterArray: true })],
    ]);
    const r2 = await extractPdfText(pdf2, { forcePureJs: true });
    assert.match(r2.text, /user @example\.com/);
    assert.match(r2.text, /Иван Петров ivan@acme\.ru/);

    // 3. Type0 + ToUnicode CMap (beginbfchar + beginbfrange)
    const cmapText = [
      "/CIDInit /ProcSet findresource begin",
      "1 begincodespacerange",
      "<0001> <FFFF>",
      "endcodespacerange",
      "2 beginbfchar",
      "<0001> <0410>", // А
      "<0002> <0411>", // Б
      "endbfchar",
      "1 beginbfrange",
      "<0010> <0012> <0031>", // 1, 2, 3
      "endbfrange",
      "endcmap",
    ].join("\n");
    const pdf3 = buildPdfFromObjects([
      [1, "<< /Type /Catalog /Pages 2 0 R >>"],
      [2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"],
      [3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"],
      [4, "<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /ToUnicode 6 0 R >>"],
      [5, makePdfStreamObj("BT\n/F1 12 Tf\n<00010002001000110012> Tj\nET\n", { compress: true })],
      [6, makePdfStreamObj(cmapText, { compress: true })],
    ]);
    const r3 = await extractPdfText(pdf3);
    assert.equal(r3.text, "АБ123");

    // 4. Image-only scanned PDF
    const scannedPdf = buildPdfFromObjects([
      [1, "<< /Type /Catalog /Pages 2 0 R >>"],
      [2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"],
      [3, "<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im1 4 0 R >> >> /Contents 5 0 R >>"],
      [4, Buffer.from("<< /Type /XObject /Subtype /Image /Width 2 /Height 2 /Length 4 >>\nstream\n\xff\x00\x00\xff\nendstream", "latin1")],
      [5, makePdfStreamObj("q\n200 0 0 200 72 500 cm\n/Im1 Do\nQ\n", { compress: false })],
    ]);
    const r4 = await extractPdfText(scannedPdf);
    assert.equal(r4.isScannedPdf, true);
    assert.equal(r4.text, "");

    // 5. Corrupt & encrypted PDF rejections
    const corruptPdf = new TextEncoder().encode("%PDF-1.4\n1 0 obj\n<< /Type /Catalog\nCORRUPT");
    await assert.rejects(
      () => extractPdfText(corruptPdf),
      (err) => err instanceof DocumentParseError && err.code === "CORRUPT_PDF"
    );

    const encryptedPdf = buildPdfFromObjects([
      [1, "<< /Type /Catalog /Pages 2 0 R /Encrypt 3 0 R >>"],
      [2, "<< /Type /Pages /Kids [] /Count 0 >>"],
      [3, "<< /Filter /Standard /V 2 >>"],
    ]);
    await assert.rejects(
      () => extractPdfText(encryptedPdf),
      (err) => err instanceof DocumentParseError && err.code === "ENCRYPTED_PDF"
    );
  });

  test("DecompressionStream=undefined runtime fallback handles ZIP, DOCX, XLSX & FlateDecode PDF", async () => {
    const prevDs = globalThis.DecompressionStream;
    globalThis.DecompressionStream = undefined;
    try {
      const docx = buildSyntheticDocx({ paragraphs: ["Fallback test user@corp.ru"] });
      const xlsx = buildSyntheticXlsx();
      const pdf = buildPdfFromObjects([
        [1, "<< /Type /Catalog /Pages 2 0 R >>"],
        [2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"],
        [3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"],
        [4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"],
        [5, makePdfStreamObj("BT\n/F1 12 Tf\n(Fallback PDF ok@corp.ru) Tj\nET\n", { compress: true })],
      ]);
      const dRes = await extractDocxText(docx);
      const xRes = await extractXlsxText(xlsx);
      const pRes = await extractPdfText(pdf);
      assert.match(dRes.text, /user@corp\.ru/);
      assert.match(xRes.text, /ceo@acme\.ru/);
      assert.equal(pRes.text, "Fallback PDF ok@corp.ru");
    } finally {
      globalThis.DecompressionStream = prevDs;
    }
  });
});

describe("PromptVeil M2 Security Hygiene & Batch Vault/UI Integration", () => {
  let prevDocument;
  let prevWindow;
  let elements;

  function makeEl(id = "") {
    const attrs = new Map();
    const classes = new Set();
    return {
      id,
      value: "",
      textContent: "",
      className: "",
      hidden: false,
      disabled: false,
      children: [],
      setAttribute(name, val) {
        attrs.set(name, String(val));
      },
      getAttribute(name) {
        return attrs.has(name) ? attrs.get(name) : null;
      },
      hasAttribute(name) {
        return attrs.has(name);
      },
      removeAttribute(name) {
        attrs.delete(name);
      },
      appendChild(node) {
        this.children.push(node);
      },
      replaceChildren(...nodes) {
        this.children = nodes;
        this.textContent = nodes.map((n) => n.textContent || "").join("");
      },
      focus() {},
      classList: {
        toggle(cls, force) {
          if (force) classes.add(cls);
          else classes.delete(cls);
        },
        add(cls) {
          classes.add(cls);
        },
        remove(cls) {
          classes.delete(cls);
        },
        contains(cls) {
          return classes.has(cls);
        },
      },
    };
  }

  beforeEach(async () => {
    await ensureDictionary("ru");
    await ensureDictionary("en");
    prevDocument = globalThis.document;
    prevWindow = globalThis.window;
    elements = new Map([
      ["global-status-banner", makeEl("global-status-banner")],
      ["input-error-banner", makeEl("input-error-banner")],
      ["file-pro-upgrade-banner", makeEl("file-pro-upgrade-banner")],
      ["file-pro-upgrade-text", makeEl("file-pro-upgrade-text")],
      ["file-loading-indicator", makeEl("file-loading-indicator")],
      ["raw-prompt-input", makeEl("raw-prompt-input")],
      ["llm-reply-input", makeEl("llm-reply-input")],
      ["file-upload-input", makeEl("file-upload-input")],
      ["batch-queue-panel", makeEl("batch-queue-panel")],
      ["batch-queue-list", makeEl("batch-queue-list")],
      ["batch-queue-meta", makeEl("batch-queue-meta")],
      ["batch-download-txt-btn", makeEl("batch-download-txt-btn")],
      ["batch-download-zip-btn", makeEl("batch-download-zip-btn")],
      ["batch-rehydrate-btn", makeEl("batch-rehydrate-btn")],
      ["copy-sanitized-btn", makeEl("copy-sanitized-btn")],
      ["mobile-sticky-copy-btn", makeEl("mobile-sticky-copy-btn")],
      ["copy-restored-btn", makeEl("copy-restored-btn")],
    ]);
    globalThis.document = {
      getElementById(id) {
        return elements.get(id) || null;
      },
      createElement(tag) {
        return makeEl(tag);
      },
    };
    globalThis.window = {
      setTimeout() {
        return 1;
      },
      clearTimeout() {},
    };
    resetNotifications();
    setLang("ru");
  });

  afterEach(() => {
    resetNotifications();
    globalThis.document = prevDocument;
    globalThis.window = prevWindow;
    setLang("ru");
  });

  test("pro-documents.js contains zero unsafe sinks, network calls, or http(s) literals", () => {
    const src = readFileSync(
      new URL("../../app/static/js/pro-documents.js", import.meta.url),
      "utf8"
    );
    for (const forbidden of [
      "innerHTML",
      "outerHTML",
      "insertAdjacentHTML",
      "document.write",
      "eval(",
      "new Function(",
      "fetch(",
      "XMLHttpRequest",
      "sendBeacon",
      "WebSocket",
      "EventSource",
    ]) {
      assert.equal(src.includes(forbidden), false, `Forbidden pattern ${forbidden} in pro-documents.js`);
    }
    assert.equal(/(['"`])(?:https?|wss?):\/\//i.test(src), false);
    assert.equal(/https?:\/\//i.test(src), false);
  });

  test("multi-document batch parse -> SessionVault sanitize (resetOnEmpty: false) -> ZIP export -> Step 2 rehydrate", async () => {
    const docxBytes = buildSyntheticDocx({
      paragraphs: ["Клиент: Алексей Смирнов", "Почта: alex@vector.ru"],
    });
    const xlsxBytes = buildSyntheticXlsx();

    const doc1 = await parseDocumentFile(docxBytes, "contract.docx", { forcePureJs: true });
    const doc2 = await parseDocumentFile(xlsxBytes, "clients.xlsx", { forcePureJs: true });
    assert.match(doc1.text, /alex@vector\.ru/);
    assert.match(doc2.text, /ceo@acme\.ru/);

    let isPro = false;
    const state = {
      rawText: "",
      llmReply: "",
      activePresetId: "",
      lastSanitizeResult: null,
      lastSanitizedInput: "",
      lastRehydrateResult: null,
      mobileVaultExpanded: false,
      showAllCategories: false,
      highlightedToken: "",
      pinnedToken: "",
      rules: [],
      auditLog: [],
      detectUuid: false,
      sensitivity: "normal",
      vault: new SessionVault(),
      batchItems: [],
    };

    const pipeline = createPipelineController({
      state,
      getFileController: () => fileCtrl,
      refreshWorkbenchUi: () => {
        renderBatchQueuePanel({}, { batchItems: state.batchItems, isPro, lang: "ru" });
      },
      refreshDrawersUi: () => {},
      renderPrivacyProofModal: () => {},
    });

    const fileCtrl = createFileController({
      getRules: () => [],
      isProActive: () => isPro,
      showStatusBanner,
      showInlineAlert,
      hideInlineAlert,
      showProUpgradePrompt: pipeline.showProUpgradePrompt,
      hideProUpgradePrompt: pipeline.hideProUpgradePrompt,
      cancelPendingLiveSanitize: pipeline.cancelPendingLiveSanitize,
      cancelPendingLiveAudit: pipeline.cancelPendingLiveAudit,
      onPromptFileLoaded: () => {},
      onBatchFilesLoaded: pipeline.loadBatchFiles,
    });

    // Free rejection (> 2 MB) preserves "2 МБ" in role="alert" AND opens upgrade banner role="status"
    await fileCtrl.handleLocalFiles([{ name: "big.txt", size: FREE_MAX_FILE_BYTES + 10 }]);
    assert.equal(elements.get("input-error-banner").hidden, false);
    assert.equal(elements.get("input-error-banner").getAttribute("role"), "alert");
    assert.match(elements.get("input-error-banner").textContent, /2\s*МБ/i);
    assert.equal(elements.get("file-pro-upgrade-banner").hidden, false);

    // Free .png preserves exact unsupported format alert without upgrade banner
    await fileCtrl.handleLocalFiles([{ name: "pic.png", size: 100 }]);
    assert.match(elements.get("input-error-banner").textContent, /Формат «\.png» не поддерживается/);
    assert.equal(elements.get("file-pro-upgrade-banner").hidden, true);

    // Unlock Pro and load synthetic DOCX + XLSX + scanned PDF
    isPro = true;
    const scannedPdfBytes = buildPdfFromObjects([
      [1, "<< /Type /Catalog /Pages 2 0 R >>"],
      [2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"],
      [3, "<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im1 4 0 R >> >> /Contents 5 0 R >>"],
      [4, Buffer.from("<< /Type /XObject /Subtype /Image /Width 2 /Height 2 /Length 4 >>\nstream\n\xff\x00\x00\xff\nendstream", "latin1")],
      [5, makePdfStreamObj("q\n200 0 0 200 72 500 cm\n/Im1 Do\nQ\n", { compress: false })],
    ]);

    await fileCtrl.handleLocalFiles([
      { name: "contract.docx", size: docxBytes.length, arrayBuffer: async () => docxBytes.buffer },
      { name: "clients.xlsx", size: xlsxBytes.length, arrayBuffer: async () => xlsxBytes.buffer },
      { name: "scan.pdf", size: scannedPdfBytes.length, arrayBuffer: async () => scannedPdfBytes.buffer },
    ]);

    assert.equal(state.batchItems.length, 3);
    assert.equal(elements.get("batch-queue-panel").hidden, false);
    assert.equal(elements.get("batch-queue-list").children.length, 3);
    // Scanned PDF did not wipe earlier vault tokens
    assert.ok(state.vault.tokenToEntry.size >= 3);
    // Preview contains masked tokens, never raw email
    const listText = JSON.stringify(elements.get("batch-queue-list").children);
    assert.equal(listText.includes("alex@vector.ru"), false);
    assert.equal(listText.includes("ceo@acme.ru"), false);
    assert.match(listText, /\[EMAIL_\d+\]/);

    // Download ZIP verification
    let savedZip = null;
    pipeline.downloadBatchZip((name, data, mime) => {
      savedZip = { name, data, mime };
    });
    assert.equal(savedZip.mime, "application/zip");
    const unzipped = await readZipEntries(savedZip.data);
    assert.equal(unzipped.size, 2);
    const docxTxt = new TextDecoder().decode(unzipped.get("contract.sanitized.txt"));
    assert.equal(docxTxt.includes("alex@vector.ru"), false);
    assert.match(docxTxt, /\[EMAIL_1\]/);

    // Step 2 batch rehydrate restores both files' secrets
    let switchedMode = "";
    pipeline.rehydrateBatchAndOpenStep2((m) => {
      switchedMode = m;
    });
    assert.equal(switchedMode, "rehydrate");
    assert.match(state.lastRehydrateResult.rehydratedText, /alex@vector\.ru/);
    assert.match(state.lastRehydrateResult.rehydratedText, /ceo@acme\.ru/);
    assert.match(state.lastRehydrateResult.rehydratedText, /7707083893/);

    // Clear batch
    pipeline.clearBatchQueue();
    assert.equal(state.batchItems.length, 0);
    assert.equal(elements.get("batch-queue-panel").hidden, true);
  });
});
