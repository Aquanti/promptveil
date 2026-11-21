"""Pure-stdlib synthetic office and PDF document builders for PromptVeil E2E tests.

Generates deterministic, PII-free synthetic `.docx`, `.xlsx`, `.pdf` (WinAnsi/UTF-16BE
and Type0/ToUnicode with optional FlateDecode), scanned image-only `.pdf`, corrupted
archives/PDFs, and oversized files using only Python's standard library.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import zipfile
import zlib
from collections.abc import Sequence
from pathlib import Path


_W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_XML_SPACE = "xml:space"

_PKG_RELS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_CONTENT_TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_REL_OFFICE_DOC = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
_REL_HEADER = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/header"
_REL_FOOTER = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer"
_REL_WORKSHEET = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
_REL_SHARED_STRINGS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings"

_SS_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def _xml_bytes(root: ET.Element) -> bytes:
    """Serialize an XML Element to UTF-8 bytes with XML declaration."""
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _col_letter(col_idx_1based: int) -> str:
    """Convert 1-based column index to Excel column letters (1 -> A, 27 -> AA)."""
    if col_idx_1based < 1:
        raise ValueError(f"Column index must be >= 1, got {col_idx_1based}")
    letters: list[str] = []
    n = col_idx_1based
    while n > 0:
        n, rem = divmod(n - 1, 26)
        letters.append(chr(65 + rem))
    return "".join(reversed(letters))


def _append_word_paragraph(parent: ET.Element, text: str) -> None:
    """Append a <w:p><w:r><w:t xml:space='preserve'>...</w:t></w:r></w:p> element."""
    p = ET.SubElement(parent, "w:p")
    r = ET.SubElement(p, "w:r")
    t = ET.SubElement(r, "w:t", {_XML_SPACE: "preserve"})
    t.text = text


def make_synthetic_docx(
    path: str | Path,
    paragraphs: Sequence[str],
    table_rows: Sequence[Sequence[str]] | None = None,
    header_text: str = "",
    footer_text: str = "",
) -> Path:
    """Build a valid minimal .docx archive with paragraphs, optional table, header, and footer."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    has_header = bool(header_text)
    has_footer = bool(footer_text)

    # [Content_Types].xml
    ct_root = ET.Element("Types", {"xmlns": _CONTENT_TYPES_NS})
    ET.SubElement(
        ct_root,
        "Default",
        {
            "Extension": "rels",
            "ContentType": "application/vnd.openxmlformats-package.relationships+xml",
        },
    )
    ET.SubElement(ct_root, "Default", {"Extension": "xml", "ContentType": "application/xml"})
    ET.SubElement(
        ct_root,
        "Override",
        {
            "PartName": "/word/document.xml",
            "ContentType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        },
    )
    if has_header:
        ET.SubElement(
            ct_root,
            "Override",
            {
                "PartName": "/word/header1.xml",
                "ContentType": "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml",
            },
        )
    if has_footer:
        ET.SubElement(
            ct_root,
            "Override",
            {
                "PartName": "/word/footer1.xml",
                "ContentType": "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml",
            },
        )

    # _rels/.rels
    pkg_rels = ET.Element("Relationships", {"xmlns": _PKG_RELS_NS})
    ET.SubElement(
        pkg_rels,
        "Relationship",
        {"Id": "rId1", "Type": _REL_OFFICE_DOC, "Target": "word/document.xml"},
    )

    # word/_rels/document.xml.rels
    doc_rels = ET.Element("Relationships", {"xmlns": _PKG_RELS_NS})
    if has_header:
        ET.SubElement(
            doc_rels,
            "Relationship",
            {"Id": "rId1", "Type": _REL_HEADER, "Target": "header1.xml"},
        )
    if has_footer:
        ET.SubElement(
            doc_rels,
            "Relationship",
            {"Id": "rId2", "Type": _REL_FOOTER, "Target": "footer1.xml"},
        )

    # word/document.xml
    doc_root = ET.Element("w:document", {"xmlns:w": _W_NS, "xmlns:r": _R_NS})
    body = ET.SubElement(doc_root, "w:body")
    for para in paragraphs:
        _append_word_paragraph(body, para)

    if table_rows:
        tbl = ET.SubElement(body, "w:tbl")
        for row in table_rows:
            tr = ET.SubElement(tbl, "w:tr")
            for cell_text in row:
                tc = ET.SubElement(tr, "w:tc")
                _append_word_paragraph(tc, cell_text)

    sect_pr = ET.SubElement(body, "w:sectPr")
    if has_header:
        ET.SubElement(sect_pr, "w:headerReference", {"w:type": "default", "r:id": "rId1"})
    if has_footer:
        ET.SubElement(sect_pr, "w:footerReference", {"w:type": "default", "r:id": "rId2"})

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _xml_bytes(ct_root))
        zf.writestr("_rels/.rels", _xml_bytes(pkg_rels))
        zf.writestr("word/_rels/document.xml.rels", _xml_bytes(doc_rels))
        zf.writestr("word/document.xml", _xml_bytes(doc_root))

        if has_header:
            hdr_root = ET.Element("w:hdr", {"xmlns:w": _W_NS})
            _append_word_paragraph(hdr_root, header_text)
            zf.writestr("word/header1.xml", _xml_bytes(hdr_root))

        if has_footer:
            ftr_root = ET.Element("w:ftr", {"xmlns:w": _W_NS})
            _append_word_paragraph(ftr_root, footer_text)
            zf.writestr("word/footer1.xml", _xml_bytes(ftr_root))

    return out


def make_synthetic_xlsx(
    path: str | Path,
    shared_strings: Sequence[str],
    rows: Sequence[Sequence[str | int | float | None]],
    sheet_name: str = "Sheet1",
) -> Path:
    """Build a valid minimal .xlsx workbook with sharedStrings.xml and sheet1.xml."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    sst_list: list[str] = list(shared_strings)
    sst_index: dict[str, int] = {}
    for idx, val in enumerate(sst_list):
        if val not in sst_index:
            sst_index[val] = idx

    def _intern_str(val: str) -> int:
        existing = sst_index.get(val)
        if existing is not None:
            return existing
        new_idx = len(sst_list)
        sst_list.append(val)
        sst_index[val] = new_idx
        return new_idx

    # xl/worksheets/sheet1.xml (populated before writing sharedStrings so any extra row strings are interned)
    ws_root = ET.Element("worksheet", {"xmlns": _SS_NS})
    sheet_data = ET.SubElement(ws_root, "sheetData")
    for r_idx, row in enumerate(rows, start=1):
        row_el = ET.SubElement(sheet_data, "row", {"r": str(r_idx)})
        for c_idx, cell_val in enumerate(row, start=1):
            if cell_val is None:
                continue
            ref = f"{_col_letter(c_idx)}{r_idx}"
            if isinstance(cell_val, bool):
                c_el = ET.SubElement(row_el, "c", {"r": ref, "t": "b"})
                v_el = ET.SubElement(c_el, "v")
                v_el.text = "1" if cell_val else "0"
            elif isinstance(cell_val, (int, float)):
                c_el = ET.SubElement(row_el, "c", {"r": ref})
                v_el = ET.SubElement(c_el, "v")
                v_el.text = str(cell_val)
            else:
                s_idx = _intern_str(str(cell_val))
                c_el = ET.SubElement(row_el, "c", {"r": ref, "t": "s"})
                v_el = ET.SubElement(c_el, "v")
                v_el.text = str(s_idx)

    # xl/sharedStrings.xml
    sst_root = ET.Element(
        "sst",
        {
            "xmlns": _SS_NS,
            "count": str(len(sst_list)),
            "uniqueCount": str(len(sst_list)),
        },
    )
    for text in sst_list:
        si = ET.SubElement(sst_root, "si")
        t_el = ET.SubElement(si, "t", {_XML_SPACE: "preserve"})
        t_el.text = text

    # [Content_Types].xml
    ct_root = ET.Element("Types", {"xmlns": _CONTENT_TYPES_NS})
    ET.SubElement(
        ct_root,
        "Default",
        {
            "Extension": "rels",
            "ContentType": "application/vnd.openxmlformats-package.relationships+xml",
        },
    )
    ET.SubElement(ct_root, "Default", {"Extension": "xml", "ContentType": "application/xml"})
    ET.SubElement(
        ct_root,
        "Override",
        {
            "PartName": "/xl/workbook.xml",
            "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        },
    )
    ET.SubElement(
        ct_root,
        "Override",
        {
            "PartName": "/xl/worksheets/sheet1.xml",
            "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
        },
    )
    ET.SubElement(
        ct_root,
        "Override",
        {
            "PartName": "/xl/sharedStrings.xml",
            "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml",
        },
    )

    # _rels/.rels
    pkg_rels = ET.Element("Relationships", {"xmlns": _PKG_RELS_NS})
    ET.SubElement(
        pkg_rels,
        "Relationship",
        {"Id": "rId1", "Type": _REL_OFFICE_DOC, "Target": "xl/workbook.xml"},
    )

    # xl/_rels/workbook.xml.rels
    wb_rels = ET.Element("Relationships", {"xmlns": _PKG_RELS_NS})
    ET.SubElement(
        wb_rels,
        "Relationship",
        {"Id": "rId1", "Type": _REL_WORKSHEET, "Target": "worksheets/sheet1.xml"},
    )
    ET.SubElement(
        wb_rels,
        "Relationship",
        {"Id": "rId2", "Type": _REL_SHARED_STRINGS, "Target": "sharedStrings.xml"},
    )

    # xl/workbook.xml
    wb_root = ET.Element("workbook", {"xmlns": _SS_NS, "xmlns:r": _R_NS})
    sheets_el = ET.SubElement(wb_root, "sheets")
    ET.SubElement(
        sheets_el,
        "sheet",
        {"name": sheet_name, "sheetId": "1", "r:id": "rId1"},
    )

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _xml_bytes(ct_root))
        zf.writestr("_rels/.rels", _xml_bytes(pkg_rels))
        zf.writestr("xl/_rels/workbook.xml.rels", _xml_bytes(wb_rels))
        zf.writestr("xl/workbook.xml", _xml_bytes(wb_root))
        zf.writestr("xl/sharedStrings.xml", _xml_bytes(sst_root))
        zf.writestr("xl/worksheets/sheet1.xml", _xml_bytes(ws_root))

    return out


def _escape_pdf_literal(raw: bytes) -> bytes:
    """Escape PDF literal string delimiters and line endings."""
    out = bytearray()
    for b in raw:
        if b == 0x5C:
            out.extend(b"\\\\")
        elif b == 0x28:
            out.extend(b"\\(")
        elif b == 0x29:
            out.extend(b"\\)")
        elif b == 0x0D:
            out.extend(b"\\r")
        elif b == 0x0A:
            out.extend(b"\\n")
        else:
            out.append(b)
    return bytes(out)


def _assemble_pdf(objects: Sequence[tuple[int, bytes]], root_obj_num: int = 1) -> bytes:
    """Assemble indirect PDF objects with exact 20-byte xref table and startxref offset."""
    buf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    max_obj_num = 0
    for obj_num, body in objects:
        if obj_num > max_obj_num:
            max_obj_num = obj_num
        offsets[obj_num] = len(buf)
        buf.extend(f"{obj_num} 0 obj\n".encode("ascii"))
        buf.extend(body)
        if not body.endswith(b"\n"):
            buf.extend(b"\n")
        buf.extend(b"endobj\n")

    total_entries = max_obj_num + 1
    xref_offset = len(buf)
    buf.extend(f"xref\n0 {total_entries}\n".encode("ascii"))
    buf.extend(b"0000000000 65535 f \n")
    for obj_num in range(1, total_entries):
        off = offsets.get(obj_num)
        if off is None:
            buf.extend(b"0000000000 65535 f \n")
        else:
            buf.extend(f"{off:010d} 00000 n \n".encode("ascii"))

    buf.extend(
        f"trailer\n<< /Size {total_entries} /Root {root_obj_num} 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(buf)


def _make_pdf_stream_obj(raw_stream: bytes, compressed: bool, extra_dict: str = "") -> bytes:
    """Wrap raw stream bytes in a PDF stream dictionary with optional FlateDecode."""
    payload = zlib.compress(raw_stream) if compressed else raw_stream
    filter_part = "/Filter /FlateDecode " if compressed else ""
    extra = f"{extra_dict.strip()} " if extra_dict.strip() else ""
    return (
        f"<< {extra}{filter_part}/Length {len(payload)} >>\nstream\n".encode("ascii")
        + payload
        + b"\nendstream"
    )


def _build_tounicode_cmap(char_to_gid: dict[str, int]) -> bytes:
    """Build a ToUnicode CMap stream with <=100-entry beginbfchar blocks."""
    lines: list[str] = [
        "/CIDInit /ProcSet findresource begin",
        "12 dict begin",
        "begincmap",
        "/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> def",
        "/CMapName /Adobe-Identity-UCS def",
        "/CMapType 2 def",
        "1 begincodespacerange",
        "<0000> <FFFF>",
        "endcodespacerange",
    ]
    items = list(char_to_gid.items())
    for start in range(0, len(items), 100):
        chunk = items[start : start + 100]
        lines.append(f"{len(chunk)} beginbfchar")
        for ch, gid in chunk:
            dst_hex = ch.encode("utf-16-be").hex().upper()
            lines.append(f"<{gid:04X}> <{dst_hex}>")
        lines.append("endbfchar")
    lines.extend(
        [
            "endcmap",
            "CMapName currentdict /CMap defineresource pop",
            "end",
            "end",
        ]
    )
    return ("\n".join(lines) + "\n").encode("ascii")


def make_synthetic_pdf(
    path: str | Path,
    text_lines: Sequence[str],
    compressed: bool = True,
    use_tounicode: bool = False,
) -> Path:
    """Build a valid PDF 1.4 with BT...ET text operators (WinAnsi/UTF-16BE or Type0+ToUnicode)."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    objects: list[tuple[int, bytes]] = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        ),
    ]

    if not use_tounicode:
        stream_parts: list[bytes] = [b"BT\n/F1 12 Tf\n72 720 Td\n"]
        for line in text_lines:
            try:
                encoded = line.encode("cp1252")
            except UnicodeEncodeError:
                encoded = b"\xfe\xff" + line.encode("utf-16-be")
            stream_parts.append(b"(" + _escape_pdf_literal(encoded) + b") Tj\n0 -16 Td\n")
        stream_parts.append(b"ET\n")
        content_raw = b"".join(stream_parts)

        objects.append(
            (4, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        )
        objects.append((5, _make_pdf_stream_obj(content_raw, compressed=compressed)))
    else:
        char_to_gid: dict[str, int] = {}
        for line in text_lines:
            for ch in line:
                if ch not in char_to_gid:
                    next_gid = len(char_to_gid) + 1
                    if next_gid > 0xFFFF:
                        raise ValueError("Too many unique characters for 16-bit ToUnicode glyph IDs")
                    char_to_gid[ch] = next_gid

        stream_lines: list[str] = ["BT", "/F1 12 Tf", "72 720 Td"]
        for line in text_lines:
            hex_glyphs = "".join(f"{char_to_gid[ch]:04X}" for ch in line)
            stream_lines.append(f"<{hex_glyphs}> Tj")
            stream_lines.append("0 -16 Td")
        stream_lines.append("ET")
        content_raw = ("\n".join(stream_lines) + "\n").encode("ascii")

        cmap_raw = _build_tounicode_cmap(char_to_gid)

        objects.append(
            (
                4,
                b"<< /Type /Font /Subtype /Type0 /BaseFont /SyntheticCID "
                b"/Encoding /Identity-H /DescendantFonts [6 0 R] /ToUnicode 7 0 R >>",
            )
        )
        objects.append((5, _make_pdf_stream_obj(content_raw, compressed=compressed)))
        objects.append(
            (
                6,
                b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /SyntheticCID "
                b"/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> "
                b"/FontDescriptor 8 0 R /DW 1000 >>",
            )
        )
        objects.append((7, _make_pdf_stream_obj(cmap_raw, compressed=compressed)))
        objects.append(
            (
                8,
                b"<< /Type /FontDescriptor /FontName /SyntheticCID /Flags 4 "
                b"/FontBBox [0 -200 1000 900] /ItalicAngle 0 /Ascent 800 "
                b"/Descent -200 /CapHeight 700 /StemV 80 >>",
            )
        )

    out.write_bytes(_assemble_pdf(objects, root_obj_num=1))
    return out


def make_scanned_image_pdf(path: str | Path) -> Path:
    """Build a valid PDF 1.4 containing only an Image XObject (/Im1 Do) and zero fonts/BT blocks."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    img_obj = (
        b"<< /Type /XObject /Subtype /Image /Width 2 /Height 2 "
        b"/ColorSpace /DeviceGray /BitsPerComponent 8 /Length 4 >>\n"
        b"stream\n\xff\x00\x00\xff\nendstream"
    )
    content_obj = _make_pdf_stream_obj(b"q\n200 0 0 200 72 500 cm\n/Im1 Do\nQ\n", compressed=False)

    objects: list[tuple[int, bytes]] = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /XObject << /Im1 4 0 R >> >> /Contents 5 0 R >>",
        ),
        (4, img_obj),
        (5, content_obj),
    ]
    out.write_bytes(_assemble_pdf(objects, root_obj_num=1))
    return out


def make_corrupted_docx(path: str | Path) -> Path:
    """Write a truncated/corrupted ZIP payload with a .docx path for error-handling tests."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"PK\x03\x04\x14\x00corrupted-docx-archive\x00\xff")
    return out


def make_corrupted_pdf(path: str | Path) -> Path:
    """Write a truncated/malformed PDF payload (missing xref and %%EOF) for error-handling tests."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog\nCORRUPT_UNTERMINATED_STREAM\n")
    return out


def make_oversized_file(path: str | Path, size_bytes: int, ext: str = ".txt") -> Path:
    """Stream deterministic PII-free ASCII filler in 1 MiB chunks to reach exact size_bytes."""
    if size_bytes < 0:
        raise ValueError(f"size_bytes must be >= 0, got {size_bytes}")
    target = Path(path)
    if not target.suffix and ext:
        norm_ext = ext if ext.startswith(".") else f".{ext}"
        target = target.with_suffix(norm_ext)
    target.parent.mkdir(parents=True, exist_ok=True)

    line = b"Filler line for oversized boundary test.\n"
    chunk_size = 1024 * 1024
    repeats = (chunk_size // len(line)) + 1
    chunk = (line * repeats)[:chunk_size]

    remaining = size_bytes
    with target.open("wb") as fh:
        while remaining >= chunk_size:
            fh.write(chunk)
            remaining -= chunk_size
        if remaining > 0:
            fh.write(chunk[:remaining])
    return target
