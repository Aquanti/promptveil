/**
 * PromptVeil Pro Local Document Parser & Deterministic ZIP Archive Builder.
 * 100% browser-local ES2022: zero network requests, zero CDN scripts, zero unsafe HTML sinks,
 * zero external URL literals, and deterministic pure-JS fallbacks for ZIP/Deflate/XML.
 */

export const FREE_MAX_FILE_BYTES = 2 * 1024 * 1024;
export const PRO_MAX_FILE_BYTES = 50 * 1024 * 1024;
export const MAX_ZIP_UNCOMPRESSED_BYTES = 100 * 1024 * 1024;
export const MAX_ZIP_ENTRIES = 10000;

export const FREE_EXTENSIONS = new Set([".txt", ".md", ".csv", ".json", ".log", ".env"]);
export const PRO_DOCUMENT_EXTENSIONS = new Set([".docx", ".pdf", ".xlsx"]);
export const PRO_EXTENSIONS = new Set([...FREE_EXTENSIONS, ...PRO_DOCUMENT_EXTENSIONS]);

export const TEXT_FILE_EXTENSIONS = FREE_EXTENSIONS;
export const PRO_DOC_EXTENSIONS = PRO_DOCUMENT_EXTENSIONS;
export const ALL_ALLOWED_EXTENSIONS = PRO_EXTENSIONS;

export class DocumentParseError extends Error {
  constructor(code, details = {}) {
    super(String(code || "DOCUMENT_PARSE_ERROR"));
    this.name = "DocumentParseError";
    this.code = String(code || "DOCUMENT_PARSE_ERROR");
    this.details = details;
  }
}

export function getDocumentErrorI18nKey(code) {
  switch (String(code || "")) {
    case "EMPTY_FILE":
      return "doc.errorEmpty";
    case "INVALID_ZIP":
    case "CORRUPT_ARCHIVE":
    case "UNSUPPORTED_COMPRESSION":
    case "XML_PARSE_ERROR":
      return "doc.errorCorruptZip";
    case "INVALID_DOCX":
      return "doc.errorInvalidDocx";
    case "INVALID_XLSX":
      return "doc.errorInvalidXlsx";
    case "INVALID_PDF":
    case "CORRUPT_PDF":
      return "doc.errorInvalidPdf";
    case "ENCRYPTED_PDF":
      return "doc.errorEncryptedPdf";
    case "ZIP_BOMB":
      return "doc.errorZipBomb";
    default:
      return "doc.errorGeneric";
  }
}

export function getFileExtension(filename) {
  const name = String(filename || "").trim().toLowerCase();
  const dotIdx = name.lastIndexOf(".");
  return dotIdx >= 0 ? name.slice(dotIdx) : "";
}

export function validateBatchFiles(fileList, { isPro = false } = {}) {
  const files = Array.from(fileList || []).filter(Boolean);
  if (files.length === 0) {
    return { accepted: [], rejection: null };
  }

  if (!isPro) {
    if (files.length > 1) {
      return {
        accepted: [],
        rejection: {
          code: "pro_multi_file",
          fileName: files[0]?.name || "",
          ext: getFileExtension(files[0]?.name || ""),
          count: files.length,
        },
      };
    }
    const file = files[0];
    const ext = getFileExtension(file.name);
    if (PRO_DOCUMENT_EXTENSIONS.has(ext)) {
      return {
        accepted: [],
        rejection: { code: "pro_format", fileName: file.name, ext },
      };
    }
    if (!FREE_EXTENSIONS.has(ext)) {
      return {
        accepted: [],
        rejection: { code: "unsupported_ext", fileName: file.name, ext },
      };
    }
    if (Number(file.size || 0) > FREE_MAX_FILE_BYTES) {
      return {
        accepted: [],
        rejection: { code: "free_too_large", fileName: file.name, ext },
      };
    }
    return { accepted: [file], rejection: null };
  }

  for (const file of files) {
    const ext = getFileExtension(file.name);
    if (!PRO_EXTENSIONS.has(ext)) {
      return {
        accepted: [],
        rejection: { code: "unsupported_ext", fileName: file.name, ext },
      };
    }
    if (Number(file.size || 0) > PRO_MAX_FILE_BYTES) {
      return {
        accepted: [],
        rejection: { code: "pro_too_large", fileName: file.name, ext },
      };
    }
  }

  return { accepted: files, rejection: null };
}

// ---------------------------------------------------------------------------
// IEEE 802.3 CRC-32
// ---------------------------------------------------------------------------

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

export function crc32(bytes) {
  const data = toUint8Array(bytes);
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i += 1) {
    crc = CRC32_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function toUint8Array(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new DocumentParseError("INVALID_INPUT", { reason: "expected_bytes" });
}

// ---------------------------------------------------------------------------
// RFC 1951 (Deflate Raw) & RFC 1950 (Zlib) Pure-JS Inflate + DecompressionStream
// ---------------------------------------------------------------------------

const CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
const LENGTH_BASE = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83,
  99, 115, 131, 163, 195, 227, 258,
];
const LENGTH_EXTRA = [
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5,
  5, 0,
];
const DIST_BASE = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
  1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11,
  11, 12, 12, 13, 13,
];

function buildHuffmanTable(lengths, count) {
  const MAX_BITS = 15;
  const counts = new Uint16Array(MAX_BITS + 1);
  let maxBits = 0;
  for (let i = 0; i < count; i += 1) {
    const len = lengths[i];
    if (len > MAX_BITS) {
      throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "huffman_bits_overflow" });
    }
    if (len > 0) {
      counts[len] += 1;
      if (len > maxBits) maxBits = len;
    }
  }
  if (maxBits === 0) {
    return { counts, symbols: new Uint16Array(0), maxBits: 0 };
  }

  let left = 1;
  for (let len = 1; len <= MAX_BITS; len += 1) {
    left <<= 1;
    left -= counts[len];
    if (left < 0) {
      throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "huffman_oversubscribed" });
    }
  }

  const offs = new Uint16Array(MAX_BITS + 1);
  for (let len = 1; len < MAX_BITS; len += 1) {
    offs[len + 1] = offs[len] + counts[len];
  }

  const symbols = new Uint16Array(count);
  for (let sym = 0; sym < count; sym += 1) {
    const len = lengths[sym];
    if (len !== 0) {
      symbols[offs[len]++] = sym;
    }
  }
  return { counts, symbols, maxBits };
}

const FIXED_LIT_TABLE = (() => {
  const lengths = new Uint8Array(288);
  lengths.fill(8, 0, 144);
  lengths.fill(9, 144, 256);
  lengths.fill(7, 256, 280);
  lengths.fill(8, 280, 288);
  return buildHuffmanTable(lengths, 288);
})();

const FIXED_DIST_TABLE = (() => {
  const lengths = new Uint8Array(32);
  lengths.fill(5);
  return buildHuffmanTable(lengths, 32);
})();

class BitReader {
  constructor(src) {
    this.src = src;
    this.pos = 0;
    this.bitBuf = 0;
    this.bitCnt = 0;
  }

  ensureBits(n) {
    while (this.bitCnt < n) {
      if (this.pos >= this.src.length) {
        throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "truncated_deflate" });
      }
      this.bitBuf |= this.src[this.pos++] << this.bitCnt;
      this.bitCnt += 8;
    }
  }

  readBit() {
    if (this.bitCnt === 0) {
      if (this.pos >= this.src.length) {
        throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "truncated_deflate" });
      }
      this.bitBuf = this.src[this.pos++];
      this.bitCnt = 8;
    }
    const bit = this.bitBuf & 1;
    this.bitBuf >>>= 1;
    this.bitCnt -= 1;
    return bit;
  }

  readBits(n) {
    if (n === 0) return 0;
    this.ensureBits(n);
    const val = this.bitBuf & ((1 << n) - 1);
    this.bitBuf >>>= n;
    this.bitCnt -= n;
    return val;
  }

  alignToByte() {
    this.bitBuf = 0;
    this.bitCnt = 0;
  }

  readUint16LE() {
    if (this.pos + 2 > this.src.length) {
      throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "truncated_stored" });
    }
    const val = this.src[this.pos] | (this.src[this.pos + 1] << 8);
    this.pos += 2;
    return val;
  }
}

function decodeHuffman(reader, table) {
  let code = 0;
  let first = 0;
  let index = 0;
  for (let len = 1; len <= table.maxBits; len += 1) {
    code |= reader.readBit();
    const count = table.counts[len];
    if (code - count < first) {
      return table.symbols[index + (code - first)];
    }
    index += count;
    first += count;
    first <<= 1;
    code <<= 1;
  }
  throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "huffman_invalid_code" });
}

export function inflateRawPureJs(srcInput, { maxOutputBytes = MAX_ZIP_UNCOMPRESSED_BYTES } = {}) {
  const src = toUint8Array(srcInput);
  const reader = new BitReader(src);
  let out = new Uint8Array(Math.min(4096, Math.max(256, maxOutputBytes)));
  let outLen = 0;

  const ensureCapacity = (extra) => {
    const needed = outLen + extra;
    if (needed > maxOutputBytes) {
      throw new DocumentParseError("ZIP_BOMB", { maxOutputBytes });
    }
    if (needed <= out.length) return;
    let nextCap = out.length;
    while (nextCap < needed) {
      nextCap = Math.min(maxOutputBytes, nextCap * 2);
      if (nextCap === out.length) break;
    }
    if (nextCap < needed) nextCap = needed;
    const next = new Uint8Array(nextCap);
    next.set(out.subarray(0, outLen));
    out = next;
  };

  let bfinal = 0;
  do {
    bfinal = reader.readBits(1);
    const btype = reader.readBits(2);

    if (btype === 0) {
      reader.alignToByte();
      const len = reader.readUint16LE();
      const nlen = reader.readUint16LE();
      if ((len ^ 0xffff) !== nlen) {
        throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "stored_len_mismatch" });
      }
      if (reader.pos + len > src.length) {
        throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "truncated_stored_payload" });
      }
      ensureCapacity(len);
      out.set(src.subarray(reader.pos, reader.pos + len), outLen);
      reader.pos += len;
      outLen += len;
      continue;
    }

    if (btype === 3) {
      throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "invalid_btype" });
    }

    let litTable = FIXED_LIT_TABLE;
    let distTable = FIXED_DIST_TABLE;

    if (btype === 2) {
      const hlit = reader.readBits(5) + 257;
      const hdist = reader.readBits(5) + 1;
      const hclen = reader.readBits(4) + 4;
      if (hlit > 286 || hdist > 30) {
        throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "invalid_dynamic_counts" });
      }

      const clLengths = new Uint8Array(19);
      for (let i = 0; i < hclen; i += 1) {
        clLengths[CL_ORDER[i]] = reader.readBits(3);
      }
      const clTable = buildHuffmanTable(clLengths, 19);

      const totalCodes = hlit + hdist;
      const lengths = new Uint8Array(totalCodes);
      let idx = 0;
      while (idx < totalCodes) {
        const sym = decodeHuffman(reader, clTable);
        if (sym < 16) {
          lengths[idx++] = sym;
        } else {
          let repeat = 0;
          let value = 0;
          if (sym === 16) {
            if (idx === 0) {
              throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "bad_repeat_16" });
            }
            value = lengths[idx - 1];
            repeat = 3 + reader.readBits(2);
          } else if (sym === 17) {
            repeat = 3 + reader.readBits(3);
          } else {
            repeat = 11 + reader.readBits(7);
          }
          if (idx + repeat > totalCodes) {
            throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "repeat_overflow" });
          }
          lengths.fill(value, idx, idx + repeat);
          idx += repeat;
        }
      }

      if (lengths[256] === 0) {
        throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "missing_eob" });
      }
      litTable = buildHuffmanTable(lengths.subarray(0, hlit), hlit);
      distTable = buildHuffmanTable(lengths.subarray(hlit), hdist);
    }

    while (true) {
      const sym = decodeHuffman(reader, litTable);
      if (sym < 256) {
        ensureCapacity(1);
        out[outLen++] = sym;
      } else if (sym === 256) {
        break;
      } else {
        const lenIdx = sym - 257;
        if (lenIdx < 0 || lenIdx >= LENGTH_BASE.length) {
          throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "invalid_length_symbol" });
        }
        const matchLen = LENGTH_BASE[lenIdx] + reader.readBits(LENGTH_EXTRA[lenIdx]);
        const distSym = decodeHuffman(reader, distTable);
        if (distSym >= DIST_BASE.length) {
          throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "invalid_distance_symbol" });
        }
        const dist = DIST_BASE[distSym] + reader.readBits(DIST_EXTRA[distSym]);
        if (dist > outLen) {
          throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "distance_before_start" });
        }
        ensureCapacity(matchLen);
        let copyPos = outLen - dist;
        for (let k = 0; k < matchLen; k += 1) {
          out[outLen++] = out[copyPos++];
        }
      }
    }
  } while (bfinal === 0);

  return out.subarray(0, outLen).slice();
}

export function inflateZlibPureJs(srcInput, { maxOutputBytes = MAX_ZIP_UNCOMPRESSED_BYTES } = {}) {
  const src = toUint8Array(srcInput);
  if (src.length < 6) {
    throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "truncated_zlib" });
  }
  const cmf = src[0];
  const flg = src[1];
  if ((cmf & 0x0f) !== 8 || (cmf >> 4) > 7 || (((cmf << 8) | flg) % 31) !== 0) {
    throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "invalid_zlib_header" });
  }
  const headerLen = 2 + (flg & 0x20 ? 4 : 0);
  if (src.length < headerLen + 4) {
    throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "truncated_zlib_payload" });
  }
  return inflateRawPureJs(src.subarray(headerLen, src.length - 4), { maxOutputBytes });
}

export async function decompressBytes(
  bytesInput,
  format = "deflate-raw",
  { forcePureJs = false, maxOutputBytes = MAX_ZIP_UNCOMPRESSED_BYTES } = {}
) {
  const bytes = toUint8Array(bytesInput);
  if (bytes.length === 0) return new Uint8Array(0);

  if (!forcePureJs && typeof DecompressionStream === "function") {
    let ds;
    try {
      ds = new DecompressionStream(format);
    } catch (err) {
      if (err && err.name === "TypeError") {
        return format === "deflate"
          ? inflateZlibPureJs(bytes, { maxOutputBytes })
          : inflateRawPureJs(bytes, { maxOutputBytes });
      }
      throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "stream_init_failed" });
    }

    const writer = ds.writable.getWriter();
    const reader = ds.readable.getReader();
    const writePromise = writer
      .write(bytes)
      .then(() => writer.close())
      .catch(() => {});

    const chunks = [];
    let totalBytes = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value && value.byteLength > 0) {
          totalBytes += value.byteLength;
          if (totalBytes > maxOutputBytes) {
            await reader.cancel().catch(() => {});
            throw new DocumentParseError("ZIP_BOMB", { maxOutputBytes });
          }
          chunks.push(value);
        }
      }
      await writePromise;
      const out = new Uint8Array(totalBytes);
      let offset = 0;
      for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return out;
    } catch (err) {
      await reader.cancel().catch(() => {});
      await writePromise;
      if (err instanceof DocumentParseError) throw err;
      throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "stream_decompress_failed" });
    }
  }

  return format === "deflate"
    ? inflateZlibPureJs(bytes, { maxOutputBytes })
    : inflateRawPureJs(bytes, { maxOutputBytes });
}

// ---------------------------------------------------------------------------
// ZIP Archive Reader & Deterministic Store Builder
// ---------------------------------------------------------------------------

function readU16LE(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readU32LE(bytes, offset) {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>>
    0
  );
}

function decodeZipFilename(nameBytes, gpFlag) {
  if ((gpFlag & 0x0800) !== 0) {
    return new TextDecoder("utf-8", { fatal: false }).decode(nameBytes);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(nameBytes);
  } catch {
    let out = "";
    for (let i = 0; i < nameBytes.length; i += 1) {
      out += String.fromCharCode(nameBytes[i]);
    }
    return out;
  }
}

export async function readZipEntries(
  bytesInput,
  {
    forcePureJs = false,
    maxOutputBytes = MAX_ZIP_UNCOMPRESSED_BYTES,
    maxEntries = MAX_ZIP_ENTRIES,
  } = {}
) {
  const bytes = toUint8Array(bytesInput);
  if (bytes.length < 22) {
    throw new DocumentParseError("INVALID_ZIP", { reason: "too_short" });
  }
  if (bytes.length > PRO_MAX_FILE_BYTES) {
    throw new DocumentParseError("INVALID_ZIP", { reason: "exceeds_max_file_bytes" });
  }

  const minEocd = Math.max(0, bytes.length - 65557);
  let eocdOffset = -1;
  for (let i = bytes.length - 22; i >= minEocd; i -= 1) {
    if (
      bytes[i] === 0x50 &&
      bytes[i + 1] === 0x4b &&
      bytes[i + 2] === 0x05 &&
      bytes[i + 3] === 0x06
    ) {
      const commentLen = readU16LE(bytes, i + 20);
      if (i + 22 + commentLen === bytes.length) {
        eocdOffset = i;
        break;
      }
    }
  }
  if (eocdOffset < 0) {
    throw new DocumentParseError("INVALID_ZIP", { reason: "missing_eocd" });
  }

  const diskNum = readU16LE(bytes, eocdOffset + 4);
  const cdDisk = readU16LE(bytes, eocdOffset + 6);
  const totalEntries = readU16LE(bytes, eocdOffset + 10);
  const cdSize = readU32LE(bytes, eocdOffset + 12);
  const cdOffset = readU32LE(bytes, eocdOffset + 16);

  if (diskNum !== 0 || cdDisk !== 0) {
    throw new DocumentParseError("INVALID_ZIP", { reason: "multidisk_unsupported" });
  }
  if (totalEntries > maxEntries) {
    throw new DocumentParseError("ZIP_BOMB", { reason: "too_many_entries", totalEntries });
  }
  if (cdOffset + cdSize > eocdOffset) {
    throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "invalid_central_directory_bounds" });
  }

  const entries = new Map();
  let cursor = cdOffset;
  let totalUncompressed = 0;

  for (let idx = 0; idx < totalEntries; idx += 1) {
    if (cursor + 46 > eocdOffset || readU32LE(bytes, cursor) !== 0x02014b50) {
      throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "invalid_cd_header" });
    }
    const gpFlag = readU16LE(bytes, cursor + 8);
    const method = readU16LE(bytes, cursor + 10);
    const expectedCrc = readU32LE(bytes, cursor + 16);
    const compSize = readU32LE(bytes, cursor + 20);
    const uncompSize = readU32LE(bytes, cursor + 24);
    const nameLen = readU16LE(bytes, cursor + 28);
    const extraLen = readU16LE(bytes, cursor + 30);
    const commentLen = readU16LE(bytes, cursor + 32);
    const localOffset = readU32LE(bytes, cursor + 42);

    if (cursor + 46 + nameLen + extraLen + commentLen > eocdOffset) {
      throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "cd_entry_truncated" });
    }
    if ((gpFlag & 0x0001) !== 0) {
      throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "encrypted_zip_unsupported" });
    }

    const entryName = decodeZipFilename(
      bytes.subarray(cursor + 46, cursor + 46 + nameLen),
      gpFlag
    ).replace(/\\/g, "/");
    cursor += 46 + nameLen + extraLen + commentLen;

    if (uncompSize > maxOutputBytes || totalUncompressed + uncompSize > maxOutputBytes) {
      throw new DocumentParseError("ZIP_BOMB", { maxOutputBytes });
    }
    if (localOffset + 30 > cdOffset || readU32LE(bytes, localOffset) !== 0x04034b50) {
      throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "invalid_local_header" });
    }

    const lNameLen = readU16LE(bytes, localOffset + 26);
    const lExtraLen = readU16LE(bytes, localOffset + 28);
    const dataStart = localOffset + 30 + lNameLen + lExtraLen;
    if (dataStart + compSize > cdOffset) {
      throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "truncated_local_data" });
    }

    const compBytes = bytes.subarray(dataStart, dataStart + compSize);
    let data;
    if (method === 0) {
      if (compSize !== uncompSize) {
        throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "stored_size_mismatch" });
      }
      data = compBytes.slice();
    } else if (method === 8) {
      const remainingBudget = maxOutputBytes - totalUncompressed;
      data = await decompressBytes(compBytes, "deflate-raw", {
        forcePureJs,
        maxOutputBytes: remainingBudget,
      });
      if (data.length !== uncompSize) {
        throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "uncompressed_size_mismatch" });
      }
    } else {
      throw new DocumentParseError("UNSUPPORTED_COMPRESSION", { method });
    }

    totalUncompressed += data.length;
    if (totalUncompressed > maxOutputBytes) {
      throw new DocumentParseError("ZIP_BOMB", { maxOutputBytes });
    }
    if (crc32(data) !== expectedCrc) {
      throw new DocumentParseError("CORRUPT_ARCHIVE", { reason: "crc32_mismatch", entryName });
    }

    if (!entryName.endsWith("/")) {
      entries.set(entryName, data);
    }
  }

  return entries;
}

export const parseZipArchive = readZipEntries;

export function buildZipArchive(entries = []) {
  const encoder = new TextEncoder();
  const localChunks = [];
  const cdChunks = [];
  let offset = 0;

  for (const entry of entries) {
    const nameStr = String(entry?.name || "file.txt").replace(/\\/g, "/");
    const nameBytes = encoder.encode(nameStr);
    const dataBytes =
      typeof entry?.data === "string"
        ? encoder.encode(entry.data)
        : toUint8Array(entry?.data ?? new Uint8Array(0));
    const crc = crc32(dataBytes);
    const size = dataBytes.length;

    const lfh = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(lfh.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0x0800, true);
    lv.setUint16(8, 0, true);
    lv.setUint16(10, 0, true);
    lv.setUint16(12, 0, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, size, true);
    lv.setUint32(22, size, true);
    lv.setUint16(26, nameBytes.length, true);
    lv.setUint16(28, 0, true);
    lfh.set(nameBytes, 30);

    localChunks.push(lfh, dataBytes);

    const cdh = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(cdh.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0x0800, true);
    cv.setUint16(10, 0, true);
    cv.setUint16(12, 0, true);
    cv.setUint16(14, 0, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, size, true);
    cv.setUint32(24, size, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint16(30, 0, true);
    cv.setUint16(32, 0, true);
    cv.setUint16(34, 0, true);
    cv.setUint16(36, 0, true);
    cv.setUint32(38, 0, true);
    cv.setUint32(42, offset, true);
    cdh.set(nameBytes, 46);

    cdChunks.push(cdh);
    offset += lfh.length + size;
  }

  let cdSize = 0;
  for (const c of cdChunks) cdSize += c.length;

  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(4, 0, true);
  ev.setUint16(6, 0, true);
  ev.setUint16(8, entries.length, true);
  ev.setUint16(10, entries.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, offset, true);
  ev.setUint16(20, 0, true);

  const out = new Uint8Array(offset + cdSize + eocd.length);
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

// ---------------------------------------------------------------------------
// XML Parser (DOMParser + Pure-JS Fallback, Zero Namespace URL Literals)
// ---------------------------------------------------------------------------

function decodeXmlEntities(text) {
  return text.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);/g, (m, entity) => {
    if (entity === "amp") return "&";
    if (entity === "lt") return "<";
    if (entity === "gt") return ">";
    if (entity === "quot") return '"';
    if (entity === "apos") return "'";
    if (entity.startsWith("#x")) {
      const code = Number.parseInt(entity.slice(2), 16);
      return Number.isFinite(code) ? String.fromCodePoint(code) : m;
    }
    if (entity.startsWith("#")) {
      const code = Number.parseInt(entity.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : m;
    }
    return m;
  });
}

function createXmlTextNode(text) {
  return { nodeType: 3, textContent: text };
}

function createXmlElementNode(tagName, attrs) {
  const colonIdx = tagName.indexOf(":");
  return {
    nodeType: 1,
    tagName,
    localName: colonIdx >= 0 ? tagName.slice(colonIdx + 1) : tagName,
    attrs,
    children: [],
    childNodes: [],
    getAttribute(name) {
      if (Object.prototype.hasOwnProperty.call(this.attrs, name)) {
        return this.attrs[name];
      }
      const shortName = name.includes(":") ? name.slice(name.indexOf(":") + 1) : name;
      for (const [k, v] of Object.entries(this.attrs)) {
        const kShort = k.includes(":") ? k.slice(k.indexOf(":") + 1) : k;
        if (kShort === shortName) return v;
      }
      return null;
    },
    get textContent() {
      let buf = "";
      for (const child of this.childNodes) {
        buf += child.textContent;
      }
      return buf;
    },
  };
}

export function parseXmlPureJs(xmlText) {
  const src = String(xmlText || "").replace(/^\uFEFF/, "");
  const rootWrapper = createXmlElementNode("#root", {});
  const stack = [rootWrapper];
  let i = 0;
  const n = src.length;

  const appendText = (raw) => {
    if (!raw) return;
    const decoded = decodeXmlEntities(raw);
    if (!decoded) return;
    stack[stack.length - 1].childNodes.push(createXmlTextNode(decoded));
  };

  while (i < n) {
    const lt = src.indexOf("<", i);
    if (lt < 0) {
      appendText(src.slice(i));
      break;
    }
    if (lt > i) {
      appendText(src.slice(i, lt));
    }

    if (src.startsWith("<!--", lt)) {
      const endComment = src.indexOf("-->", lt + 4);
      if (endComment < 0) {
        throw new DocumentParseError("XML_PARSE_ERROR", { reason: "unclosed_comment" });
      }
      i = endComment + 3;
      continue;
    }
    if (src.startsWith("<![CDATA[", lt)) {
      const endCdata = src.indexOf("]]>", lt + 9);
      if (endCdata < 0) {
        throw new DocumentParseError("XML_PARSE_ERROR", { reason: "unclosed_cdata" });
      }
      stack[stack.length - 1].childNodes.push(
        createXmlTextNode(src.slice(lt + 9, endCdata))
      );
      i = endCdata + 3;
      continue;
    }
    if (src.startsWith("<?", lt)) {
      const endPi = src.indexOf("?>", lt + 2);
      if (endPi < 0) {
        throw new DocumentParseError("XML_PARSE_ERROR", { reason: "unclosed_pi" });
      }
      i = endPi + 2;
      continue;
    }
    if (src.startsWith("<!", lt)) {
      const endDecl = src.indexOf(">", lt + 2);
      if (endDecl < 0) {
        throw new DocumentParseError("XML_PARSE_ERROR", { reason: "unclosed_decl" });
      }
      i = endDecl + 1;
      continue;
    }

    let j = lt + 1;
    let quote = "";
    while (j < n) {
      const ch = src[j];
      if (quote) {
        if (ch === quote) quote = "";
      } else if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === ">") {
        break;
      }
      j += 1;
    }
    if (j >= n) {
      throw new DocumentParseError("XML_PARSE_ERROR", { reason: "unclosed_tag" });
    }

    const inner = src.slice(lt + 1, j).trim();
    i = j + 1;
    if (!inner) {
      throw new DocumentParseError("XML_PARSE_ERROR", { reason: "empty_tag" });
    }

    if (inner.startsWith("/")) {
      const closeName = inner.slice(1).trim();
      const top = stack.pop();
      if (!top || top === rootWrapper || top.tagName !== closeName) {
        throw new DocumentParseError("XML_PARSE_ERROR", {
          reason: "mismatched_closing_tag",
          tag: closeName,
        });
      }
      continue;
    }

    const selfClosing = inner.endsWith("/");
    const body = selfClosing ? inner.slice(0, -1).trim() : inner;
    const spaceMatch = /^([^\s/>]+)([\s\S]*)$/.exec(body);
    if (!spaceMatch) {
      throw new DocumentParseError("XML_PARSE_ERROR", { reason: "invalid_tag_name" });
    }
    const tagName = spaceMatch[1];
    const attrStr = spaceMatch[2];
    const attrs = Object.create(null);
    const attrRe = /([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
    let m;
    while ((m = attrRe.exec(attrStr)) !== null) {
      attrs[m[1]] = decodeXmlEntities(m[2] ?? m[3] ?? "");
    }

    const node = createXmlElementNode(tagName, attrs);
    const parent = stack[stack.length - 1];
    parent.children.push(node);
    parent.childNodes.push(node);
    if (!selfClosing) {
      stack.push(node);
    }
  }

  if (stack.length !== 1 || rootWrapper.children.length === 0) {
    throw new DocumentParseError("XML_PARSE_ERROR", { reason: "unbalanced_root" });
  }
  return rootWrapper.children[0];
}

export function parseXml(xmlText, { forcePureJs = false } = {}) {
  const clean = String(xmlText || "").replace(/^\uFEFF/, "");
  if (!forcePureJs && typeof DOMParser === "function") {
    const doc = new DOMParser().parseFromString(clean, "application/xml");
    if (
      !doc ||
      !doc.documentElement ||
      doc.getElementsByTagName("parsererror").length > 0
    ) {
      throw new DocumentParseError("XML_PARSE_ERROR", { reason: "dom_parser_error" });
    }
    return doc.documentElement;
  }
  return parseXmlPureJs(clean);
}

function getLocalName(node) {
  if (!node || node.nodeType !== 1) return "";
  if (node.localName) return node.localName;
  const tag = node.tagName || "";
  const idx = tag.indexOf(":");
  return idx >= 0 ? tag.slice(idx + 1) : tag;
}

function getElementChildren(node) {
  if (!node) return [];
  if (node.children) return Array.from(node.children);
  const out = [];
  for (const child of node.childNodes || []) {
    if (child.nodeType === 1) out.push(child);
  }
  return out;
}

function getElementAttr(node, attrLocalName) {
  if (!node) return null;
  if (typeof node.getAttribute === "function") {
    const direct = node.getAttribute(attrLocalName);
    if (direct !== null && direct !== undefined) return direct;
  }
  if (node.attributes) {
    for (let i = 0; i < node.attributes.length; i += 1) {
      const a = node.attributes[i];
      const aName = a.localName || (a.name.includes(":") ? a.name.split(":").pop() : a.name);
      if (aName === attrLocalName) return a.value;
    }
  }
  return null;
}

function naturalSortStrings(a, b) {
  return a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
}

// ---------------------------------------------------------------------------
// .docx Extractor
// ---------------------------------------------------------------------------

function extractDocxInline(node, outParts) {
  for (const child of node.childNodes || []) {
    if (child.nodeType !== 1) continue;
    const name = getLocalName(child);
    if (name === "t") {
      outParts.push(child.textContent || "");
    } else if (name === "tab") {
      outParts.push("\t");
    } else if (name === "br" || name === "cr") {
      outParts.push("\n");
    } else if (name === "delText" || name === "instrText") {
      continue;
    } else {
      extractDocxInline(child, outParts);
    }
  }
}

function extractDocxParagraphText(pNode) {
  const parts = [];
  extractDocxInline(pNode, parts);
  return parts.join("");
}

function collectDocxBlocks(node, blocks) {
  for (const child of getElementChildren(node)) {
    const name = getLocalName(child);
    if (name === "p") {
      const text = extractDocxParagraphText(child).trimEnd();
      if (text.length > 0) blocks.push(text);
    } else if (name === "tbl") {
      const rowLines = [];
      for (const tr of getElementChildren(child)) {
        if (getLocalName(tr) !== "tr") continue;
        const cellTexts = [];
        for (const tc of getElementChildren(tr)) {
          if (getLocalName(tc) !== "tc") continue;
          const cellBlocks = [];
          collectDocxBlocks(tc, cellBlocks);
          cellTexts.push(cellBlocks.join(" ").trim());
        }
        if (cellTexts.some((c) => c.length > 0)) {
          rowLines.push(cellTexts.join("\t").trimEnd());
        }
      }
      if (rowLines.length > 0) {
        blocks.push(rowLines.join("\n"));
      }
    } else {
      collectDocxBlocks(child, blocks);
    }
  }
}

export async function extractDocxText(bytesInput, options = {}) {
  const entries = await readZipEntries(bytesInput, options);
  const entryLookup = new Map();
  for (const [k, v] of entries.entries()) {
    entryLookup.set(k.toLowerCase(), { key: k, data: v });
  }

  if (!entryLookup.has("word/document.xml")) {
    throw new DocumentParseError("INVALID_DOCX", { reason: "missing_word_document" });
  }

  const headers = [];
  const footers = [];
  for (const [lowerKey, item] of entryLookup.entries()) {
    if (/^word\/header\d*\.xml$/.test(lowerKey)) headers.push(item);
    else if (/^word\/footer\d*\.xml$/.test(lowerKey)) footers.push(item);
  }
  headers.sort((a, b) => naturalSortStrings(a.key, b.key));
  footers.sort((a, b) => naturalSortStrings(a.key, b.key));

  const parts = [...headers, entryLookup.get("word/document.xml"), ...footers];
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const blocks = [];

  for (const part of parts) {
    const xmlStr = decoder.decode(part.data);
    const root = parseXml(xmlStr, options);
    collectDocxBlocks(root, blocks);
  }

  return {
    text: blocks.join("\n").trim(),
    partCount: parts.length,
  };
}

// ---------------------------------------------------------------------------
// .xlsx Extractor
// ---------------------------------------------------------------------------

function collectXlsxTextWithoutPhonetics(node, parts) {
  for (const child of node.childNodes || []) {
    if (child.nodeType !== 1) continue;
    const name = getLocalName(child);
    if (name === "rPh") continue;
    if (name === "t") {
      parts.push(child.textContent || "");
    } else {
      collectXlsxTextWithoutPhonetics(child, parts);
    }
  }
}

function parseSharedStrings(xmlStr, options) {
  const root = parseXml(xmlStr, options);
  const strings = [];
  for (const child of getElementChildren(root)) {
    if (getLocalName(child) !== "si") continue;
    const parts = [];
    collectXlsxTextWithoutPhonetics(child, parts);
    strings.push(parts.join(""));
  }
  return strings;
}

function resolveXlsxSheets(entryLookup, decoder, options) {
  const defaultSheets = [];
  for (const [lowerKey, item] of entryLookup.entries()) {
    if (/^xl\/worksheets\/sheet\d+\.xml$/.test(lowerKey)) {
      defaultSheets.push({ name: "", key: item.key, data: item.data });
    }
  }
  defaultSheets.sort((a, b) => naturalSortStrings(a.key, b.key));

  const wbEntry = entryLookup.get("xl/workbook.xml");
  const relsEntry = entryLookup.get("xl/_rels/workbook.xml.rels");
  if (!wbEntry || !relsEntry) {
    return defaultSheets;
  }

  try {
    const relsRoot = parseXml(decoder.decode(relsEntry.data), options);
    const idToTarget = new Map();
    for (const rel of getElementChildren(relsRoot)) {
      if (getLocalName(rel) !== "Relationship") continue;
      const id = getElementAttr(rel, "Id");
      const target = getElementAttr(rel, "Target");
      if (id && target) {
        const normalized = target.startsWith("/")
          ? target.slice(1).toLowerCase()
          : target.startsWith("xl/")
          ? target.toLowerCase()
          : `xl/${target.replace(/^\.\//, "").toLowerCase()}`;
        idToTarget.set(id, normalized);
      }
    }

    const wbRoot = parseXml(decoder.decode(wbEntry.data), options);
    const ordered = [];
    const stack = [...getElementChildren(wbRoot)];
    while (stack.length > 0) {
      const node = stack.shift();
      if (getLocalName(node) === "sheet") {
        const sheetName = getElementAttr(node, "name") || "";
        const rid = getElementAttr(node, "id") || "";
        const targetLower = idToTarget.get(rid);
        const found = targetLower ? entryLookup.get(targetLower) : null;
        if (found) {
          ordered.push({ name: sheetName, key: found.key, data: found.data });
        }
      } else {
        stack.unshift(...getElementChildren(node));
      }
    }
    return ordered.length > 0 ? ordered : defaultSheets;
  } catch {
    return defaultSheets;
  }
}

export async function extractXlsxText(bytesInput, options = {}) {
  const entries = await readZipEntries(bytesInput, options);
  const entryLookup = new Map();
  for (const [k, v] of entries.entries()) {
    entryLookup.set(k.toLowerCase(), { key: k, data: v });
  }

  const decoder = new TextDecoder("utf-8", { fatal: false });
  const sheets = resolveXlsxSheets(entryLookup, decoder, options);
  if (sheets.length === 0) {
    throw new DocumentParseError("INVALID_XLSX", { reason: "missing_worksheets" });
  }

  const sstEntry = entryLookup.get("xl/sharedstrings.xml");
  const sharedStrings = sstEntry ? parseSharedStrings(decoder.decode(sstEntry.data), options) : [];

  const sheetTexts = [];
  for (const sheet of sheets) {
    const root = parseXml(decoder.decode(sheet.data), options);
    const rowsOut = [];
    const sheetDataNodes = getElementChildren(root).filter((n) => getLocalName(n) === "sheetData");
    for (const sd of sheetDataNodes) {
      for (const rowNode of getElementChildren(sd)) {
        if (getLocalName(rowNode) !== "row") continue;
        const cells = [];
        for (const cell of getElementChildren(rowNode)) {
          if (getLocalName(cell) !== "c") continue;
          const cellType = getElementAttr(cell, "t") || "";
          let vText = "";
          let isNode = null;
          for (const ch of getElementChildren(cell)) {
            const chName = getLocalName(ch);
            if (chName === "v") vText = ch.textContent || "";
            else if (chName === "is") isNode = ch;
          }
          let cellText = "";
          if (cellType === "s") {
            const idx = Number.parseInt(vText, 10);
            cellText = Number.isFinite(idx) && idx >= 0 && idx < sharedStrings.length
              ? sharedStrings[idx]
              : "";
          } else if (cellType === "inlineStr" && isNode) {
            const parts = [];
            collectXlsxTextWithoutPhonetics(isNode, parts);
            cellText = parts.join("");
          } else if (cellType === "b") {
            cellText = vText.trim() === "1" ? "TRUE" : "FALSE";
          } else {
            cellText = vText;
          }
          cells.push(cellText.trim());
        }
        while (cells.length > 0 && cells[cells.length - 1] === "") {
          cells.pop();
        }
        if (cells.some((c) => c.length > 0)) {
          rowsOut.push(cells.join("\t"));
        }
      }
    }
    const body = rowsOut.join("\n").trim();
    if (body) {
      sheetTexts.push(sheets.length > 1 && sheet.name ? `[${sheet.name}]\n${body}` : body);
    }
  }

  return {
    text: sheetTexts.join("\n\n").trim(),
    sheetCount: sheets.length,
  };
}

// ---------------------------------------------------------------------------
// .pdf Extractor (Binary-Safe Latin-1, FlateDecode, ToUnicode CMap, Encodings)
// ---------------------------------------------------------------------------

const WIN_ANSI_HIGH = {
  0x80: 0x20ac, 0x82: 0x201a, 0x83: 0x0192, 0x84: 0x201e, 0x85: 0x2026,
  0x86: 0x2020, 0x87: 0x2021, 0x88: 0x02c6, 0x89: 0x2030, 0x8a: 0x0160,
  0x8b: 0x2039, 0x8c: 0x0152, 0x8e: 0x017d, 0x91: 0x2018, 0x92: 0x2019,
  0x93: 0x201c, 0x94: 0x201d, 0x95: 0x2022, 0x96: 0x2013, 0x97: 0x2014,
  0x98: 0x02dc, 0x99: 0x2122, 0x9a: 0x0161, 0x9b: 0x203a, 0x9c: 0x0153,
  0x9e: 0x017e, 0x9f: 0x0178,
};

const PDF_DOC_HIGH = {
  0x80: 0x2022, 0x81: 0x2020, 0x82: 0x2021, 0x83: 0x2026, 0x84: 0x2014,
  0x85: 0x2013, 0x86: 0x0192, 0x87: 0x2044, 0x88: 0x2039, 0x89: 0x203a,
  0x8a: 0x2212, 0x8b: 0x2030, 0x8c: 0x201e, 0x8d: 0x201c, 0x8e: 0x201d,
  0x8f: 0x2018, 0x90: 0x2019, 0x91: 0x201a, 0x92: 0x2122, 0x93: 0xfb01,
  0x94: 0xfb02, 0x95: 0x0141, 0x96: 0x0152, 0x97: 0x0160, 0x98: 0x0178,
  0x99: 0x017d, 0x9a: 0x0131, 0x9b: 0x0142, 0x9c: 0x0153, 0x9d: 0x0161,
  0x9e: 0x017e, 0xa0: 0x20ac,
};

function bytesToLatin1(bytes) {
  const CHUNK = 32768;
  const parts = [];
  for (let i = 0; i < bytes.length; i += CHUNK) {
    parts.push(String.fromCharCode(...bytes.subarray(i, i + CHUNK)));
  }
  return parts.join("");
}

function decodeSingleByteString(bytes, usePdfDoc = false) {
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    let out = "";
    for (let i = 2; i + 1 < bytes.length; i += 2) {
      out += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    }
    return out;
  }
  const highMap = usePdfDoc ? PDF_DOC_HIGH : WIN_ANSI_HIGH;
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i];
    if (b >= 0x80 && highMap[b] !== undefined) {
      out += String.fromCharCode(highMap[b]);
    } else {
      out += String.fromCharCode(b);
    }
  }
  return out;
}

function decodeUtf16BeHex(hexStr) {
  const clean = hexStr.replace(/\s+/g, "");
  const padded = clean.length % 2 === 1 ? `${clean}0` : clean;
  let out = "";
  for (let i = 0; i + 3 < padded.length; i += 4) {
    const code = Number.parseInt(padded.slice(i, i + 4), 16);
    if (Number.isFinite(code)) out += String.fromCharCode(code);
  }
  if (padded.length === 2) {
    const code = Number.parseInt(padded, 16);
    if (Number.isFinite(code)) out += String.fromCharCode(code);
  }
  return out;
}

function parseToUnicodeCmap(cmapBytes) {
  const text = bytesToLatin1(cmapBytes);
  let codeBytes = 2;
  const csMatch = /begincodespacerange\s*([\s\S]*?)endcodespacerange/.exec(text);
  if (csMatch) {
    const firstHex = /<([0-9a-fA-F]+)>/.exec(csMatch[1]);
    if (firstHex && firstHex[1].length <= 2) {
      codeBytes = 1;
    }
  }

  const map = new Map();

  const bfCharRe = /beginbfchar\s*([\s\S]*?)endbfchar/g;
  let m;
  while ((m = bfCharRe.exec(text)) !== null) {
    const pairRe = /<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>/g;
    let p;
    while ((p = pairRe.exec(m[1])) !== null) {
      const code = Number.parseInt(p[1], 16);
      map.set(code, decodeUtf16BeHex(p[2]));
      if (p[1].length > 2) codeBytes = 2;
    }
  }

  const bfRangeRe = /beginbfrange\s*([\s\S]*?)endbfrange/g;
  while ((m = bfRangeRe.exec(text)) !== null) {
    const block = m[1];
    const lineRe = /<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*(?:<([0-9a-fA-F]+)>|\[([^\]]*)\])/g;
    let r;
    while ((r = lineRe.exec(block)) !== null) {
      const start = Number.parseInt(r[1], 16);
      const end = Number.parseInt(r[2], 16);
      if (r[1].length > 2) codeBytes = 2;
      if (!Number.isFinite(start) || !Number.isFinite(end) || end < start || end - start > 65536) {
        continue;
      }
      if (r[3] !== undefined) {
        const baseHex = r[3];
        if (baseHex.length >= 4) {
          const prefix = baseHex.slice(0, -4);
          const startUnit = Number.parseInt(baseHex.slice(-4), 16);
          for (let code = start; code <= end; code += 1) {
            const unit = (startUnit + (code - start)) & 0xffff;
            map.set(code, decodeUtf16BeHex(`${prefix}${unit.toString(16).padStart(4, "0")}`));
          }
        } else {
          const startByte = Number.parseInt(baseHex, 16);
          for (let code = start; code <= end; code += 1) {
            map.set(code, String.fromCharCode((startByte + (code - start)) & 0xff));
          }
        }
      } else if (r[4] !== undefined) {
        const arrHex = Array.from(r[4].matchAll(/<([0-9a-fA-F]+)>/g), (hm) => hm[1]);
        for (let i = 0; i < arrHex.length && start + i <= end; i += 1) {
          map.set(start + i, decodeUtf16BeHex(arrHex[i]));
        }
      }
    }
  }

  return { codeBytes, map };
}

function decodePdfBytesWithFont(bytes, fontInfo, fallbackCmap) {
  const cmap = fontInfo?.cmap || (!fontInfo ? fallbackCmap : null);
  if (cmap && cmap.map.size > 0) {
    if (cmap.codeBytes === 2 && bytes.length >= 2) {
      let out = "";
      let matched = 0;
      for (let i = 0; i + 1 < bytes.length; i += 2) {
        const code = (bytes[i] << 8) | bytes[i + 1];
        if (cmap.map.has(code)) {
          out += cmap.map.get(code);
          matched += 1;
        } else {
          out += String.fromCharCode(code);
        }
      }
      if (matched > 0 || fontInfo?.cmap) return out;
    } else if (cmap.codeBytes === 1) {
      let out = "";
      let matched = 0;
      for (let i = 0; i < bytes.length; i += 1) {
        const code = bytes[i];
        if (cmap.map.has(code)) {
          out += cmap.map.get(code);
          matched += 1;
        } else {
          out += String.fromCharCode(code);
        }
      }
      if (matched > 0 || fontInfo?.cmap) return out;
    }
  }

  return decodeSingleByteString(bytes, fontInfo?.encoding === "PDFDocEncoding");
}

function skipPdfWhitespaceAndComments(str, pos) {
  let i = pos;
  const n = str.length;
  while (i < n) {
    const ch = str.charCodeAt(i);
    if (ch === 32 || ch === 9 || ch === 10 || ch === 13 || ch === 12 || ch === 0) {
      i += 1;
    } else if (ch === 37) {
      while (i < n && str.charCodeAt(i) !== 10 && str.charCodeAt(i) !== 13) i += 1;
    } else {
      break;
    }
  }
  return i;
}

function readPdfLiteralString(str, openParenPos) {
  const out = [];
  let i = openParenPos + 1;
  let depth = 1;
  const n = str.length;

  while (i < n && depth > 0) {
    const ch = str[i];
    if (ch === "(") {
      depth += 1;
      out.push(40);
      i += 1;
    } else if (ch === ")") {
      depth -= 1;
      if (depth > 0) out.push(41);
      i += 1;
    } else if (ch === "\\") {
      i += 1;
      if (i >= n) break;
      const esc = str[i];
      if (esc === "n") { out.push(10); i += 1; }
      else if (esc === "r") { out.push(13); i += 1; }
      else if (esc === "t") { out.push(9); i += 1; }
      else if (esc === "b") { out.push(8); i += 1; }
      else if (esc === "f") { out.push(12); i += 1; }
      else if (esc === "(" || esc === ")" || esc === "\\") {
        out.push(esc.charCodeAt(0));
        i += 1;
      } else if (esc === "\r") {
        i += str[i + 1] === "\n" ? 2 : 1;
      } else if (esc === "\n") {
        i += 1;
      } else if (esc >= "0" && esc <= "7") {
        let oct = esc;
        if (i + 1 < n && str[i + 1] >= "0" && str[i + 1] <= "7") {
          oct += str[i + 1];
          if (i + 2 < n && str[i + 2] >= "0" && str[i + 2] <= "7") {
            oct += str[i + 2];
          }
        }
        out.push(Number.parseInt(oct, 8) & 0xff);
        i += oct.length;
      } else {
        out.push(esc.charCodeAt(0) & 0xff);
        i += 1;
      }
    } else {
      out.push(str.charCodeAt(i) & 0xff);
      i += 1;
    }
  }

  return { bytes: new Uint8Array(out), nextPos: i };
}

function readPdfHexString(str, openAnglePos) {
  const closePos = str.indexOf(">", openAnglePos + 1);
  if (closePos < 0) return { bytes: new Uint8Array(0), nextPos: str.length };
  const hex = str.slice(openAnglePos + 1, closePos).replace(/\s+/g, "");
  const padded = hex.length % 2 === 1 ? `${hex}0` : hex;
  const out = new Uint8Array(padded.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const val = Number.parseInt(padded.slice(i * 2, i * 2 + 2), 16);
    out[i] = Number.isFinite(val) ? val : 0;
  }
  return { bytes: out, nextPos: closePos + 1 };
}

function findMatchingDictEnd(str, startPos) {
  let i = startPos;
  const n = str.length;
  let depth = 0;
  while (i < n) {
    if (str[i] === "<" && str[i + 1] === "<") {
      depth += 1;
      i += 2;
    } else if (str[i] === ">" && str[i + 1] === ">") {
      depth -= 1;
      i += 2;
      if (depth === 0) return i;
    } else if (str[i] === "(") {
      i = readPdfLiteralString(str, i).nextPos;
    } else if (str[i] === "%") {
      while (i < n && str[i] !== "\n" && str[i] !== "\r") i += 1;
    } else {
      i += 1;
    }
  }
  return -1;
}

function parsePdfIndirectObjects(bytes, latin1) {
  const objects = new Map();
  const objHeaderRe = /(\d+)\s+(\d+)\s+obj\b/g;
  let pos = 0;
  let sawBrokenObject = false;

  while (true) {
    objHeaderRe.lastIndex = pos;
    const match = objHeaderRe.exec(latin1);
    if (!match) break;

    const objNum = Number.parseInt(match[1], 10);
    let cursor = skipPdfWhitespaceAndComments(latin1, match.index + match[0].length);
    let dictStr = "";

    if (latin1[cursor] === "<" && latin1[cursor + 1] === "<") {
      const dictEnd = findMatchingDictEnd(latin1, cursor);
      if (dictEnd < 0) {
        sawBrokenObject = true;
        break;
      }
      dictStr = latin1.slice(cursor, dictEnd);
      cursor = skipPdfWhitespaceAndComments(latin1, dictEnd);
    }

    let rawStream = null;
    if (latin1.startsWith("stream", cursor)) {
      let streamStart = cursor + 6;
      if (latin1[streamStart] === "\r" && latin1[streamStart + 1] === "\n") {
        streamStart += 2;
      } else if (latin1[streamStart] === "\n" || latin1[streamStart] === "\r") {
        streamStart += 1;
      }

      const lenMatch = /\/Length\s+(\d+)\b(?!\s+\d+\s+R)/.exec(dictStr);
      let streamEnd = -1;
      if (lenMatch) {
        const declaredLen = Number.parseInt(lenMatch[1], 10);
        const candidateEnd = streamStart + declaredLen;
        if (candidateEnd <= latin1.length) {
          let check = candidateEnd;
          if (latin1[check] === "\r") check += 1;
          if (latin1[check] === "\n") check += 1;
          if (latin1.startsWith("endstream", check)) {
            streamEnd = candidateEnd;
          } else if (latin1.startsWith("endstream", candidateEnd)) {
            streamEnd = candidateEnd;
          }
        }
      }
      if (streamEnd < 0) {
        const esIdx = latin1.indexOf("endstream", streamStart);
        if (esIdx < 0) {
          sawBrokenObject = true;
          break;
        }
        streamEnd = esIdx;
        if (streamEnd > streamStart && latin1[streamEnd - 1] === "\n") streamEnd -= 1;
        if (streamEnd > streamStart && latin1[streamEnd - 1] === "\r") streamEnd -= 1;
      }
      rawStream = bytes.subarray(streamStart, streamEnd);
      const afterEndstream = latin1.indexOf("endstream", streamEnd);
      cursor = afterEndstream >= 0 ? afterEndstream + 9 : streamEnd;
    }

    const endobjIdx = latin1.indexOf("endobj", cursor);
    if (endobjIdx < 0) {
      sawBrokenObject = true;
      break;
    }
    const bodyText = dictStr || latin1.slice(cursor, endobjIdx);
    objects.set(objNum, { objNum, dictStr: dictStr || bodyText, bodyText, rawStream });
    pos = endobjIdx + 6;
  }

  return { objects, sawBrokenObject };
}

function tokenizePdfContentStream(streamBytes) {
  const str = bytesToLatin1(streamBytes);
  const tokens = [];
  let i = 0;
  const n = str.length;

  const readAtom = () => {
    if (str[i] === "(") {
      const res = readPdfLiteralString(str, i);
      i = res.nextPos;
      return { type: "str", bytes: res.bytes };
    }
    if (str[i] === "<" && str[i + 1] !== "<") {
      const res = readPdfHexString(str, i);
      i = res.nextPos;
      return { type: "str", bytes: res.bytes };
    }
    if (str[i] === "<" && str[i + 1] === "<") {
      const end = findMatchingDictEnd(str, i);
      i = end >= 0 ? end : n;
      return { type: "dict" };
    }
    if (str[i] === "[") {
      i += 1;
      const items = [];
      while (i < n) {
        i = skipPdfWhitespaceAndComments(str, i);
        if (i >= n || str[i] === "]") {
          i += 1;
          break;
        }
        items.push(readAtom());
      }
      return { type: "arr", items };
    }
    if (str[i] === "/") {
      const start = i + 1;
      i += 1;
      while (i < n && !/[\s()<>\[\]{}/%]/.test(str[i])) i += 1;
      return { type: "name", value: str.slice(start, i) };
    }
    const start = i;
    while (i < n && !/[\s()<>\[\]{}/%]/.test(str[i])) i += 1;
    if (i === start) {
      i += 1;
      return { type: "punct", value: str[start] };
    }
    const word = str.slice(start, i);
    if (/^[+-]?(?:\d+\.?\d*|\.\d+)$/.test(word)) {
      return { type: "num", value: Number.parseFloat(word) };
    }
    return { type: "op", value: word };
  };

  while (i < n) {
    i = skipPdfWhitespaceAndComments(str, i);
    if (i >= n) break;
    tokens.push(readAtom());
  }
  return tokens;
}

function extractTextFromContentStream(streamBytes, fontMap, fallbackCmap) {
  const tokens = tokenizePdfContentStream(streamBytes);
  const operands = [];
  const chunks = [];
  let inText = false;
  let activeFontName = "";
  let prevTmY = null;
  let sawImageDo = false;

  const currentLineEndsWithSpace = () => {
    if (chunks.length === 0) return true;
    const last = chunks[chunks.length - 1];
    return last.endsWith(" ") || last.endsWith("\n") || last.endsWith("\t");
  };

  const pushNewline = () => {
    if (chunks.length > 0 && !chunks[chunks.length - 1].endsWith("\n")) {
      chunks.push("\n");
    }
  };

  for (const tok of tokens) {
    if (tok.type !== "op") {
      operands.push(tok);
      continue;
    }

    const op = tok.value;
    const fontInfo = activeFontName ? fontMap.get(activeFontName) || null : null;

    if (op === "BT") {
      inText = true;
      prevTmY = null;
    } else if (op === "ET") {
      inText = false;
      pushNewline();
    } else if (op === "Tf") {
      const nameTok = operands.length >= 2 ? operands[operands.length - 2] : null;
      if (nameTok && nameTok.type === "name") {
        activeFontName = nameTok.value;
      }
    } else if (op === "T*") {
      if (inText) pushNewline();
    } else if (op === "Td" || op === "TD") {
      if (inText && operands.length >= 2) {
        const dx = operands[operands.length - 2]?.value ?? 0;
        const dy = operands[operands.length - 1]?.value ?? 0;
        if (Math.abs(dy) > 1) {
          pushNewline();
        } else if (dx > 20 && !currentLineEndsWithSpace()) {
          chunks.push(" ");
        }
      }
    } else if (op === "Tm") {
      if (inText && operands.length >= 6) {
        const ty = operands[operands.length - 1]?.value;
        if (typeof ty === "number") {
          if (prevTmY !== null && Math.abs(ty - prevTmY) > 1) {
            pushNewline();
          }
          prevTmY = ty;
        }
      }
    } else if (op === "Tj" && operands.length >= 1) {
      const strTok = operands[operands.length - 1];
      if (strTok?.type === "str") {
        chunks.push(decodePdfBytesWithFont(strTok.bytes, fontInfo, fallbackCmap));
      }
    } else if ((op === "'" || op === '"') && operands.length >= 1) {
      const strTok = operands[operands.length - 1];
      if (strTok?.type === "str") {
        pushNewline();
        chunks.push(decodePdfBytesWithFont(strTok.bytes, fontInfo, fallbackCmap));
      }
    } else if (op === "TJ" && operands.length >= 1) {
      const arrTok = operands[operands.length - 1];
      if (arrTok?.type === "arr") {
        for (const item of arrTok.items) {
          if (item.type === "str") {
            chunks.push(decodePdfBytesWithFont(item.bytes, fontInfo, fallbackCmap));
          } else if (item.type === "num" && item.value < -120 && !currentLineEndsWithSpace()) {
            chunks.push(" ");
          }
        }
      }
    } else if (op === "Do") {
      sawImageDo = true;
    }

    operands.length = 0;
  }

  return { text: chunks.join(""), sawImageDo };
}

async function decompressPdfStream(rawStream, dictStr, options) {
  const hasFlate = /\/Filter\s*(?:\/FlateDecode|\/Fl\b|\[[^\]]*\/FlateDecode)/.test(dictStr);
  if (!hasFlate) return rawStream;
  try {
    return await decompressBytes(rawStream, "deflate", options);
  } catch (err) {
    if (err instanceof DocumentParseError && err.code === "ZIP_BOMB") throw err;
    try {
      return await decompressBytes(rawStream, "deflate-raw", options);
    } catch {
      throw new DocumentParseError("CORRUPT_PDF", { reason: "flatedecode_failed" });
    }
  }
}

export async function extractPdfText(bytesInput, options = {}) {
  const bytes = toUint8Array(bytesInput);
  if (bytes.length < 8) {
    throw new DocumentParseError("INVALID_PDF", { reason: "too_short" });
  }
  const headStr = bytesToLatin1(bytes.subarray(0, Math.min(1024, bytes.length)));
  if (!headStr.includes("%PDF-")) {
    throw new DocumentParseError("INVALID_PDF", { reason: "missing_pdf_header" });
  }

  const latin1 = bytesToLatin1(bytes);
  if (/\/Encrypt\b/.test(latin1)) {
    const trailerIdx = latin1.lastIndexOf("trailer");
    const trailerSlice = trailerIdx >= 0 ? latin1.slice(trailerIdx) : "";
    if (/\/Encrypt\s+(?:\d+\s+\d+\s+R|<<)/.test(latin1) || /\/Encrypt\b/.test(trailerSlice)) {
      throw new DocumentParseError("ENCRYPTED_PDF", { reason: "encrypted_pdf_unsupported" });
    }
  }

  const { objects, sawBrokenObject } = parsePdfIndirectObjects(bytes, latin1);
  if (objects.size === 0 || (sawBrokenObject && !latin1.includes("%%EOF"))) {
    throw new DocumentParseError("CORRUPT_PDF", { reason: "corrupt_pdf_structure" });
  }

  let imageCount = 0;
  let pageCount = 0;
  let fontCount = 0;
  const decompressedStreams = new Map();
  const cmapObjNums = new Set();

  for (const obj of objects.values()) {
    if (/\/Subtype\s*\/Image\b/.test(obj.dictStr)) {
      imageCount += 1;
      continue;
    }
    if (obj.rawStream) {
      decompressedStreams.set(
        obj.objNum,
        await decompressPdfStream(obj.rawStream, obj.dictStr, options)
      );
    }
  }

  const fontObjs = new Map();
  let fallbackCmap = null;
  for (const obj of objects.values()) {
    if (!/\/Type\s*\/Font\b/.test(obj.dictStr)) continue;
    fontCount += 1;
    let encoding = "WinAnsiEncoding";
    if (/\/Encoding\s*\/PDFDocEncoding\b/.test(obj.dictStr)) {
      encoding = "PDFDocEncoding";
    }
    let cmap = null;
    const toUniMatch = /\/ToUnicode\s+(\d+)\s+\d+\s+R/.exec(obj.dictStr);
    if (toUniMatch) {
      const cmapNum = Number.parseInt(toUniMatch[1], 10);
      cmapObjNums.add(cmapNum);
      const cmapBytes = decompressedStreams.get(cmapNum);
      if (cmapBytes) {
        cmap = parseToUnicodeCmap(cmapBytes);
        if (!fallbackCmap) fallbackCmap = cmap;
      }
    }
    fontObjs.set(obj.objNum, { encoding, cmap });
  }

  const pageParts = [];
  let sawAnyImageDo = false;
  const visitedStreams = new Set();

  for (const obj of objects.values()) {
    if (!/\/Type\s*\/Page\b(?!s\b)/.test(obj.dictStr)) continue;
    pageCount += 1;

    const pageFontMap = new Map();
    const fontRefRe = /\/([A-Za-z0-9_.-]+)\s+(\d+)\s+\d+\s+R/g;
    let fm;
    while ((fm = fontRefRe.exec(obj.dictStr)) !== null) {
      const fObj = fontObjs.get(Number.parseInt(fm[2], 10));
      if (fObj) pageFontMap.set(fm[1], fObj);
    }

    const contentRefs = [];
    const singleRef = /\/Contents\s+(\d+)\s+\d+\s+R/.exec(obj.dictStr);
    const arrRef = /\/Contents\s*\[([^\]]*)\]/.exec(obj.dictStr);
    if (singleRef) {
      contentRefs.push(Number.parseInt(singleRef[1], 10));
    } else if (arrRef) {
      for (const rm of arrRef[1].matchAll(/(\d+)\s+\d+\s+R/g)) {
        contentRefs.push(Number.parseInt(rm[1], 10));
      }
    }

    for (const refNum of contentRefs) {
      visitedStreams.add(refNum);
      const streamBytes = decompressedStreams.get(refNum);
      if (!streamBytes) continue;
      const res = extractTextFromContentStream(streamBytes, pageFontMap, fallbackCmap);
      if (res.sawImageDo) sawAnyImageDo = true;
      if (res.text.trim()) pageParts.push(res.text.trim());
    }
  }

  if (pageParts.length === 0) {
    const defaultFontMap = new Map();
    let idx = 1;
    for (const fObj of fontObjs.values()) {
      defaultFontMap.set(`F${idx++}`, fObj);
    }
    for (const [objNum, streamBytes] of decompressedStreams.entries()) {
      if (visitedStreams.has(objNum) || cmapObjNums.has(objNum)) continue;
      const res = extractTextFromContentStream(streamBytes, defaultFontMap, fallbackCmap);
      if (res.sawImageDo) sawAnyImageDo = true;
      if (res.text.trim()) pageParts.push(res.text.trim());
    }
  }

  const normalized = pageParts
    .join("\n")
    .replace(/\r\n?/g, "\n")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  if (normalized.length === 0 && (imageCount > 0 || sawAnyImageDo)) {
    return {
      text: "",
      isScannedPdf: true,
      pageCount,
      imageCount,
      fontCount,
    };
  }

  return {
    text: normalized,
    isScannedPdf: false,
    pageCount,
    imageCount,
    fontCount,
  };
}

// ---------------------------------------------------------------------------
// Unified Document Parser Entrypoint
// ---------------------------------------------------------------------------

export async function extractDocumentFromBytes(bytesInput, filename = "", options = {}) {
  const bytes = toUint8Array(bytesInput);
  const ext = getFileExtension(filename);

  if (ext === ".docx") {
    if (bytes.length === 0) throw new DocumentParseError("EMPTY_FILE", { filename });
    const res = await extractDocxText(bytes, options);
    return {
      name: filename,
      ext,
      size: bytes.length,
      text: res.text,
      isScannedPdf: false,
      pageCount: 0,
      imageCount: 0,
    };
  }

  if (ext === ".xlsx") {
    if (bytes.length === 0) throw new DocumentParseError("EMPTY_FILE", { filename });
    const res = await extractXlsxText(bytes, options);
    return {
      name: filename,
      ext,
      size: bytes.length,
      text: res.text,
      isScannedPdf: false,
      pageCount: 0,
      imageCount: 0,
    };
  }

  if (ext === ".pdf") {
    if (bytes.length === 0) throw new DocumentParseError("EMPTY_FILE", { filename });
    const res = await extractPdfText(bytes, options);
    return {
      name: filename,
      ext,
      size: bytes.length,
      text: res.text,
      isScannedPdf: res.isScannedPdf,
      pageCount: res.pageCount,
      imageCount: res.imageCount,
    };
  }

  const decoded = new TextDecoder("utf-8", { fatal: false })
    .decode(bytes)
    .replace(/^\uFEFF/, "");
  return {
    name: filename,
    ext,
    size: bytes.length,
    text: decoded,
    isScannedPdf: false,
    pageCount: 0,
    imageCount: 0,
  };
}

export async function parseDocumentFile(fileOrBytes, fileName = "", options = {}) {
  if (fileOrBytes instanceof Uint8Array || fileOrBytes instanceof ArrayBuffer) {
    return extractDocumentFromBytes(fileOrBytes, fileName, options);
  }
  if (fileOrBytes && fileOrBytes.bytes !== undefined) {
    return extractDocumentFromBytes(
      fileOrBytes.bytes,
      fileOrBytes.name || fileName,
      options
    );
  }
  if (fileOrBytes && typeof fileOrBytes.arrayBuffer === "function") {
    const buf = await fileOrBytes.arrayBuffer();
    return extractDocumentFromBytes(new Uint8Array(buf), fileOrBytes.name || fileName, options);
  }
  throw new DocumentParseError("INVALID_INPUT", { reason: "unsupported_source" });
}

export const extractDocumentFromFile = parseDocumentFile;
