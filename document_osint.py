#!/usr/bin/env python3
"""
JEDI Document OSINT — archive-first document ingestion, triage, entity extraction & SQL/FTS search.

Design goals
------------
* The archive is authoritative; originals are never modified.
* SQLite is a disposable catalog/search/entity accelerator (rebuildable).
* Fast triage decides whether a PDF page needs native text extraction or OCR.
* Processing is page-granular so a mixed PDF does not force whole-document OCR.
* Work is transactional and resumable.
* Failed processing never removes an archived source.
* FTS5 provides SQL-queryable document content.
* Stdlib-first: docx/html/txt parsing use zipfile/xml/html.parser — no
  compiled dependency required for those formats. PDF and OCR remain
  optional-and-guarded so the tool degrades gracefully on Termux/Android
  when PyMuPDF/Tesseract aren't installed.

Dependencies
------------
Required:
    Python 3.10+
    SQLite with FTS5 support

Optional (guarded — missing deps just disable that format, not the tool):
    PyMuPDF:      pip install pymupdf        (PDF ingestion)
    pytesseract:  pip install pytesseract    (OCR for scanned PDFs + images)
                  + Tesseract executable installed on the host
    Pillow:       pip install Pillow         (image EXIF/GPS + OCR input)

Supported formats
------------------
.pdf                     native text + OCR fallback, page-granular
.docx                    native text via zipfile/XML, doc-properties metadata
.html / .htm             tag-stripped text, <title> metadata
.txt / .md               raw text
.jpg/.jpeg/.png/.tiff/   EXIF/GPS metadata + OCR (requires Pillow + pytesseract)
.tif/.bmp/.webp

Example
-------
    python3 document_osint.py ingest ./incoming --archive ./archive
    python3 document_osint.py search --archive ./archive '"contract" AND Louisiana'
    python3 document_osint.py entities --archive ./archive --type email
    python3 document_osint.py status --archive ./archive
    python3 document_osint.py rebuild --archive ./archive

The archive layout is:

archive/
  objects/aa/bb/<sha256>.<ext>       original immutable files
  derived/<sha256>/
      pages/000001.txt
      manifest.json
  osint.db                            catalog + FTS5 + entities accelerator

Entity extraction is regex-based (stdlib `re` only, no NLP dependency).
It is a triage aid, not ground truth — phone/SSN/IP patterns in particular
can false-positive on version numbers, IDs, and other numeric strings.
Treat `entities` output as leads to verify, not confirmed findings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable, Optional

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

try:
    import pytesseract
except ImportError:
    pytesseract = None

try:
    from PIL import ExifTags, Image
except ImportError:
    Image = None
    ExifTags = None


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL UNIQUE,
    archive_path TEXT NOT NULL,
    source_name TEXT NOT NULL,
    file_type TEXT NOT NULL,
    mime TEXT,
    size INTEGER NOT NULL,
    page_count INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'archived',
    text_quality REAL,
    metadata_json TEXT,
    indexed_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    page_no INTEGER NOT NULL,
    method TEXT NOT NULL,
    char_count INTEGER NOT NULL DEFAULT 0,
    quality REAL,
    text_path TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    UNIQUE(document_id, page_no)
);

CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    page_no INTEGER,
    entity_type TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS processing_errors (
    id INTEGER PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
    page_no INTEGER,
    stage TEXT NOT NULL,
    error TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS document_search USING fts5(
    document_id UNINDEXED,
    page_no UNINDEXED,
    content,
    tokenize='unicode61'
);

CREATE INDEX IF NOT EXISTS idx_pages_document ON pages(document_id);
CREATE INDEX IF NOT EXISTS idx_pages_status ON pages(status);
CREATE INDEX IF NOT EXISTS idx_docs_status ON documents(status);
CREATE INDEX IF NOT EXISTS idx_docs_filetype ON documents(file_type);
CREATE INDEX IF NOT EXISTS idx_entities_document ON entities(document_id);
CREATE INDEX IF NOT EXISTS idx_entities_type_value ON entities(entity_type, value);
"""


# --------------------------------------------------------------------------
# Shared primitives
# --------------------------------------------------------------------------

def utc_now() -> int:
    return int(time.time())


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def atomic_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".incoming-", dir=str(dst.parent))
    os.close(fd)
    tmp_path = Path(tmp)
    try:
        shutil.copy2(src, tmp_path)
        os.replace(tmp_path, dst)
    finally:
        tmp_path.unlink(missing_ok=True)


def archive_path_for(root: Path, digest: str, suffix: str) -> Path:
    return root / "objects" / digest[:2] / digest[2:4] / f"{digest}{suffix.lower()}"


def quality_score(text: str) -> float:
    """Cheap heuristic: usable text vs. empty/garbled extraction."""
    if not text or not text.strip():
        return 0.0

    chars = len(text)
    if chars < 20:
        return 0.05

    printable = sum(c.isprintable() or c in "\n\r\t" for c in text) / chars
    alpha = sum(c.isalpha() for c in text) / chars
    words = [w for w in text.split() if any(c.isalnum() for c in w)]
    word_ratio = min(len(words) / max(chars / 6, 1), 1.0)

    score = (
        0.35 * printable +
        0.35 * min(alpha * 2.0, 1.0) +
        0.30 * word_ratio
    )

    if chars < 100:
        score *= chars / 100.0

    return round(max(0.0, min(score, 1.0)), 4)


@dataclass
class PageResult:
    page_no: int
    text: str
    method: str
    quality: float


@dataclass
class ExtractedDocument:
    pages: list[PageResult]
    metadata: dict


# --------------------------------------------------------------------------
# Entity extraction (stdlib regex — triage aid, not ground truth)
# --------------------------------------------------------------------------

ENTITY_PATTERNS: dict[str, re.Pattern] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "url": re.compile(r"\bhttps?://[^\s<>\"'\]\)]+", re.IGNORECASE),
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
    ),
    "phone": re.compile(
        r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
    ),
    "btc_address": re.compile(r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "handle": re.compile(r"(?<![\w@])@[A-Za-z0-9_]{2,30}\b"),
    "hashtag": re.compile(r"(?<![\w#])#[A-Za-z0-9_]{2,50}\b"),
    "coordinates": re.compile(
        r"(?<![\w.-])-?(?:[1-8]?\d(?:\.\d+)|90(?:\.0+)?),\s*"
        r"-?(?:1[0-7]\d(?:\.\d+)|180(?:\.0+)?|[1-9]?\d(?:\.\d+))(?![\w.])"
    ),
    "date": re.compile(
        r"\b(?:\d{4}-\d{2}-\d{2}"
        r"|\d{1,2}/\d{1,2}/\d{2,4}"
        r"|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4})\b",
        re.IGNORECASE,
    ),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}


def extract_entities(text: str) -> dict[str, set[str]]:
    if not text:
        return {}
    found: dict[str, set[str]] = {}
    for etype, pattern in ENTITY_PATTERNS.items():
        matches = pattern.findall(text)
        if not matches:
            continue
        cleaned = {m.strip().rstrip(".,;:)") for m in matches if m and m.strip()}
        if cleaned:
            found[etype] = cleaned
    return found


def insert_entities(conn: sqlite3.Connection, doc_id: int, page_no: Optional[int], text: str) -> int:
    # Page retries must not multiply identical entity rows.
    conn.execute(
        "DELETE FROM entities WHERE document_id=? AND page_no=?",
        (doc_id, page_no),
    )
    found = extract_entities(text)
    now = utc_now()
    count = 0
    for etype, values in found.items():
        for value in values:
            conn.execute(
                "INSERT INTO entities (document_id, page_no, entity_type, value, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (doc_id, page_no, etype, value, now),
            )
            count += 1
    return count


# --------------------------------------------------------------------------
# Format extractors — each returns an ExtractedDocument or raises
# --------------------------------------------------------------------------

def extract_native(page) -> str:
    return page.get_text("text") or ""


def triage_page(page) -> tuple[str, float]:
    """
    Fast, non-OCR decision point.

    Returns:
        ("native", score) when extracted text looks usable.
        ("ocr", score) when text is absent/suspicious.

    This deliberately does not inspect pixels. The expensive OCR path only
    starts after native extraction fails the cheap quality test.
    """
    native = extract_native(page)
    score = quality_score(native)
    return ("native", score) if score >= 0.80 else ("ocr", score)


def ocr_page(page) -> str:
    if pytesseract is None:
        raise RuntimeError(
            "OCR requested but pytesseract is unavailable. "
            "Install pytesseract and Tesseract."
        )
    pix = page.get_pixmap(matrix=fitz.Matrix(1.75, 1.75), alpha=False)
    from PIL import Image as _Image  # avoid mandatory Pillow import unless OCR runs
    import io
    image = _Image.open(io.BytesIO(pix.tobytes("png")))
    return pytesseract.image_to_string(image)


def extract_pdf(obj: Path) -> ExtractedDocument:
    if fitz is None:
        raise RuntimeError("PyMuPDF is required for PDF ingestion: pip install pymupdf")

    pdf = fitz.open(str(obj))
    try:
        meta = {k: v for k, v in (pdf.metadata or {}).items() if v}
        pages: list[PageResult] = []

        for page_no in range(pdf.page_count):
            page = pdf.load_page(page_no)
            native = extract_native(page)
            native_q = quality_score(native)

            # Native text is authoritative when it passes the quality gate.
            if native_q >= 0.80:
                pages.append(PageResult(page_no + 1, native, "native", native_q))
                continue

            # Only questionable pages enter OCR. A mixed PDF therefore stays
            # mixed instead of forcing OCR over the whole document.
            try:
                text = ocr_page(page)
                ocr_q = quality_score(text)

                if ocr_q >= native_q:
                    pages.append(PageResult(page_no + 1, text, "ocr", ocr_q))
                else:
                    pages.append(
                        PageResult(page_no + 1, native, "native-low-quality", native_q)
                    )
            except Exception:
                # OCR availability/failure must never destroy native text.
                pages.append(
                    PageResult(page_no + 1, native, "native-fallback", native_q)
                )

        return ExtractedDocument(pages=pages, metadata=meta)
    finally:
        pdf.close()


_WORD_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_CORE_NS = "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}"
_DC_NS = "{http://purl.org/dc/elements/1.1/}"
_DCTERMS_NS = "{http://purl.org/dc/terms/}"


def extract_docx(obj: Path) -> ExtractedDocument:
    """Word docs are zip archives of XML — parsed via stdlib zipfile/ElementTree,
    no python-docx / compiled dependency required."""
    try:
        with zipfile.ZipFile(obj) as zf:
            names = set(zf.namelist())
            if "word/document.xml" not in names:
                raise RuntimeError("Not a valid .docx (missing word/document.xml)")

            root = ET.fromstring(zf.read("word/document.xml"))
            paragraphs = []
            for p in root.iter(f"{_WORD_NS}p"):
                runs = []
                for node in p.iter():
                    if node.tag == f"{_WORD_NS}t" and node.text:
                        runs.append(node.text)
                    elif node.tag == f"{_WORD_NS}tab":
                        runs.append("\t")
                    elif node.tag == f"{_WORD_NS}br":
                        runs.append("\n")
                paragraphs.append("".join(runs))
            text = "\n".join(paragraphs)

            meta: dict = {}
            if "docProps/core.xml" in names:
                try:
                    core = ET.fromstring(zf.read("docProps/core.xml"))
                    field_map = {
                        f"{_DC_NS}title": "title",
                        f"{_DC_NS}creator": "author",
                        f"{_DC_NS}subject": "subject",
                        f"{_CORE_NS}lastModifiedBy": "last_modified_by",
                        f"{_CORE_NS}revision": "revision",
                        f"{_DCTERMS_NS}created": "created",
                        f"{_DCTERMS_NS}modified": "modified",
                    }
                    for tag, key in field_map.items():
                        el = core.find(tag)
                        if el is not None and el.text:
                            meta[key] = el.text
                except ET.ParseError:
                    pass
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"Not a valid .docx: {exc}") from exc

    q = quality_score(text)
    return ExtractedDocument(pages=[PageResult(1, text, "native-docx", q)], metadata=meta)


class _HTMLTextExtractor(HTMLParser):
    _SKIP_TAGS = {"script", "style", "head", "noscript"}
    _BLOCK_TAGS = {"p", "br", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._in_title = False
        self.chunks: list[str] = []
        self.title = ""

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True
        if tag in self._BLOCK_TAGS:
            self.chunks.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._in_title:
            self.title += data
        else:
            self.chunks.append(data)


def extract_html(obj: Path) -> ExtractedDocument:
    raw = obj.read_bytes().decode("utf-8", errors="replace")

    parser = _HTMLTextExtractor()
    parser.feed(raw)
    parser.close()

    text = re.sub(r"[ \t]+", " ", "".join(parser.chunks))
    text = re.sub(r"\n{2,}", "\n\n", text).strip()

    meta = {"title": parser.title.strip()} if parser.title.strip() else {}
    q = quality_score(text)
    return ExtractedDocument(pages=[PageResult(1, text, "native-html", q)], metadata=meta)


def extract_text(obj: Path) -> ExtractedDocument:
    text = obj.read_text(encoding="utf-8", errors="replace")
    q = quality_score(text)
    return ExtractedDocument(pages=[PageResult(1, text, "native-text", q)], metadata={})


def _dms_to_decimal(dms, ref) -> Optional[float]:
    try:
        degrees, minutes, seconds = (float(x) for x in dms)
    except (TypeError, ValueError):
        return None
    value = degrees + minutes / 60.0 + seconds / 3600.0
    if ref in ("S", "W"):
        value = -value
    return round(value, 6)


def _image_metadata(img) -> dict:
    meta: dict = {"width": img.width, "height": img.height, "format": img.format}
    try:
        exif = img.getexif()
    except Exception:
        exif = None
    if not exif:
        return meta

    for tag_id, value in exif.items():
        name = ExifTags.TAGS.get(tag_id, str(tag_id))
        if name in ("DateTime", "DateTimeOriginal", "Make", "Model", "Software"):
            meta[name] = str(value)

    if hasattr(exif, "get_ifd"):
        gps_ifd = exif.get_ifd(0x8825)  # GPS IFD tag
        if gps_ifd:
            gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
            lat = _dms_to_decimal(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
            lon = _dms_to_decimal(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))
            if lat is not None and lon is not None:
                meta["gps_latitude"] = lat
                meta["gps_longitude"] = lon

    return meta


def extract_image(obj: Path) -> ExtractedDocument:
    if Image is None:
        raise RuntimeError("Pillow is required for image ingestion: pip install Pillow")

    with Image.open(obj) as img:
        meta = _image_metadata(img)
        text, method, q = "", "unsupported", 0.0
        if pytesseract is not None:
            try:
                text = pytesseract.image_to_string(img)
                q = quality_score(text)
                method = "ocr"
            except Exception as exc:
                raise RuntimeError(f"OCR failed: {exc}") from exc

    return ExtractedDocument(pages=[PageResult(1, text, method, q)], metadata=meta)


EXTRACTORS = {
    ".pdf": extract_pdf,
    ".docx": extract_docx,
    ".html": extract_html,
    ".htm": extract_html,
    ".txt": extract_text,
    ".md": extract_text,
    ".jpg": extract_image,
    ".jpeg": extract_image,
    ".png": extract_image,
    ".tiff": extract_image,
    ".tif": extract_image,
    ".bmp": extract_image,
    ".webp": extract_image,
}


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


# --------------------------------------------------------------------------
# Ingestion pipeline (format-agnostic)
# --------------------------------------------------------------------------

def ingest_document(path: Path, archive: Path, conn: sqlite3.Connection) -> None:
    suffix = path.suffix.lower()
    extractor = EXTRACTORS.get(suffix)
    if extractor is None:
        raise RuntimeError(f"Unsupported file type: {suffix or '(none)'}")

    digest = sha256_file(path)
    obj = archive_path_for(archive, digest, suffix)

    existing = conn.execute("SELECT id FROM documents WHERE sha256=?", (digest,)).fetchone()

    # Archive first. The source becomes durable before expensive processing.
    if not obj.exists():
        atomic_copy(path, obj)

    if existing:
        print(f"[duplicate] {path.name} -> {digest[:16]}")
        return

    now = utc_now()
    mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

    cur = conn.execute(
        """INSERT INTO documents
           (sha256, archive_path, source_name, file_type, mime, size, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'archived', ?)""",
        (digest, str(obj.relative_to(archive)), path.name, suffix.lstrip("."), mime,
         path.stat().st_size, now),
    )
    doc_id = cur.lastrowid
    conn.commit()

    try:
        conn.execute("UPDATE documents SET status='triaging' WHERE id=?", (doc_id,))
        conn.commit()

        extracted = extractor(obj)

        derived = archive / "derived" / digest
        pages_dir = derived / "pages"
        pages_dir.mkdir(parents=True, exist_ok=True)

        qualities = []
        entity_count = 0

        for pr in extracted.pages:
            text_path = pages_dir / f"{pr.page_no:06d}.txt"
            fd, tmp = tempfile.mkstemp(prefix=".text-", dir=str(pages_dir))
            os.close(fd)
            tmp_path = Path(tmp)
            try:
                tmp_path.write_text(pr.text, encoding="utf-8")
                os.replace(tmp_path, text_path)
            finally:
                tmp_path.unlink(missing_ok=True)

            conn.execute(
                "DELETE FROM document_search WHERE document_id=? AND page_no=?",
                (doc_id, pr.page_no),
            )
            conn.execute(
                "INSERT INTO document_search(document_id, page_no, content) VALUES (?, ?, ?)",
                (doc_id, pr.page_no, pr.text),
            )
            conn.execute(
                """INSERT INTO pages
                   (document_id, page_no, method, char_count, quality, text_path, status)
                   VALUES (?, ?, ?, ?, ?, ?, 'indexed')
                   ON CONFLICT(document_id, page_no) DO UPDATE SET
                     method=excluded.method,
                     char_count=excluded.char_count,
                     quality=excluded.quality,
                     text_path=excluded.text_path,
                     status=excluded.status""",
                (doc_id, pr.page_no, pr.method, len(pr.text), pr.quality,
                 str(text_path.relative_to(archive))),
            )

            entity_count += insert_entities(conn, doc_id, pr.page_no, pr.text)
            qualities.append(pr.quality)
            conn.commit()  # Page-granular recovery point.

        avg_quality = sum(qualities) / len(qualities) if qualities else 0.0

        manifest = {
            "sha256": digest,
            "source_name": path.name,
            "file_type": suffix.lstrip("."),
            "archive_object": str(obj.relative_to(archive)),
            "page_count": len(extracted.pages),
            "average_text_quality": round(avg_quality, 4),
            "metadata": extracted.metadata,
            "entity_count": entity_count,
            "generated_at": now,
        }
        (derived / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        conn.execute(
            """UPDATE documents
               SET page_count=?, status='indexed', text_quality=?, metadata_json=?, indexed_at=?
               WHERE id=?""",
            (len(extracted.pages), avg_quality, json.dumps(extracted.metadata), utc_now(), doc_id),
        )
        conn.commit()

        print(
            f"[indexed] {path.name} type={suffix.lstrip('.')} "
            f"pages={len(extracted.pages)} quality={avg_quality:.3f} entities={entity_count}"
        )

    except Exception as exc:
        conn.execute("UPDATE documents SET status='error' WHERE id=?", (doc_id,))
        conn.execute(
            """INSERT INTO processing_errors (document_id, stage, error, created_at)
               VALUES (?, 'document', ?, ?)""",
            (doc_id, repr(exc), utc_now()),
        )
        conn.commit()
        raise


def iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    yield from (
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in EXTRACTORS
    )


# --------------------------------------------------------------------------
# CLI commands
# --------------------------------------------------------------------------

def command_ingest(args) -> None:
    archive = Path(args.archive).resolve()
    archive.mkdir(parents=True, exist_ok=True)
    conn = connect(archive / "osint.db")

    try:
        for path in iter_files(Path(args.source).resolve()):
            try:
                ingest_document(path, archive, conn)
            except Exception as exc:
                print(f"[error] {path}: {exc}", file=sys.stderr)
    finally:
        conn.close()


def command_search(args) -> None:
    archive = Path(args.archive).resolve()
    conn = connect(archive / "osint.db")

    sql = """
        SELECT
            ds.document_id,
            ds.page_no,
            d.source_name,
            d.file_type,
            d.archive_path,
            snippet(document_search, 2, '[', ']', ' … ', 20) AS snippet,
            bm25(document_search) AS rank
        FROM document_search ds
        JOIN documents d ON d.id = ds.document_id
        WHERE document_search MATCH ?
    """
    params: list = [args.query]
    if args.type:
        sql += " AND d.file_type = ?"
        params.append(args.type)
    sql += " ORDER BY rank LIMIT ?"
    params.append(args.limit)

    for row in conn.execute(sql, params):
        print(
            f"{row['document_id']}  {row['file_type']:5}  "
            f"{row['source_name']}  p.{row['page_no']}  {row['snippet']}"
        )

    conn.close()


def command_entities(args) -> None:
    archive = Path(args.archive).resolve()
    conn = connect(archive / "osint.db")

    sql = (
        "SELECT entity_type, value, COUNT(*) AS occurrences, "
        "COUNT(DISTINCT document_id) AS documents FROM entities"
    )
    conditions, params = [], []
    if args.type:
        conditions.append("entity_type = ?")
        params.append(args.type)
    if args.value:
        conditions.append("value LIKE ?")
        params.append(f"%{args.value}%")
    if args.document_id:
        conditions.append("document_id = ?")
        params.append(args.document_id)
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " GROUP BY entity_type, value ORDER BY entity_type, occurrences DESC LIMIT ?"
    params.append(args.limit)

    rows = conn.execute(sql, params).fetchall()
    if not rows:
        print("No entities found.")
    for row in rows:
        print(
            f"{row['entity_type']:12} {row['value']:40} "
            f"occurrences={row['occurrences']} docs={row['documents']}"
        )

    conn.close()


def command_status(args) -> None:
    archive = Path(args.archive).resolve()
    conn = connect(archive / "osint.db")

    print("JEDI Document OSINT status")
    print("=" * 28)

    rows = conn.execute(
        "SELECT status, COUNT(*) AS n FROM documents GROUP BY status ORDER BY status"
    ).fetchall()
    for row in rows:
        print(f"{row['status']:16} {row['n']}")

    print()
    for row in conn.execute(
        "SELECT file_type, COUNT(*) AS n FROM documents GROUP BY file_type ORDER BY n DESC"
    ):
        print(f"{row['file_type']:16} {row['n']}")

    total = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
    size = conn.execute("SELECT COALESCE(SUM(size),0) FROM documents").fetchone()[0]
    entity_total = conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
    entity_types = conn.execute("SELECT COUNT(DISTINCT entity_type) FROM entities").fetchone()[0]

    print(f"\nDocuments: {total}")
    print(f"Original bytes: {size:,}")
    print(f"Entities extracted: {entity_total} ({entity_types} types)")

    conn.close()


def command_rebuild(args) -> None:
    """Rebuild only the disposable DB (search index + entities) from derived manifests/text."""
    archive = Path(args.archive).resolve()
    db = archive / "osint.db"

    if db.exists():
        backup = db.with_suffix(".db.bak")
        os.replace(db, backup)

    conn = connect(db)

    for manifest_path in (archive / "derived").glob("*/manifest.json"):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            digest = manifest["sha256"]
            obj = manifest["archive_object"]
            source_name = manifest["source_name"]
            file_type = manifest.get("file_type") or (Path(source_name).suffix.lstrip(".") or "unknown")
            metadata = manifest.get("metadata", {})

            object_path = archive / obj
            if not object_path.exists():
                continue

            conn.execute(
                """INSERT OR IGNORE INTO documents
                   (sha256, archive_path, source_name, file_type, mime, size,
                    page_count, status, text_quality, metadata_json, indexed_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'indexed', ?, ?, ?, ?)""",
                (
                    digest, obj, source_name, file_type,
                    mimetypes.guess_type(source_name)[0],
                    object_path.stat().st_size,
                    manifest.get("page_count", 0),
                    manifest.get("average_text_quality"),
                    json.dumps(metadata),
                    manifest.get("generated_at"),
                    manifest.get("generated_at", utc_now()),
                ),
            )

            doc_id = conn.execute("SELECT id FROM documents WHERE sha256=?", (digest,)).fetchone()[0]

            pages_dir = manifest_path.parent / "pages"
            for text_path in sorted(pages_dir.glob("*.txt")):
                page_no = int(text_path.stem)
                text = text_path.read_text(encoding="utf-8", errors="replace")
                q = quality_score(text)

                conn.execute(
                    "INSERT OR REPLACE INTO pages "
                    "(document_id, page_no, method, char_count, quality, text_path, status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (doc_id, page_no, "recovered", len(text), q,
                     str(text_path.relative_to(archive)), "indexed"),
                )
                conn.execute(
                    "INSERT INTO document_search(document_id,page_no,content) VALUES (?,?,?)",
                    (doc_id, page_no, text),
                )
                insert_entities(conn, doc_id, page_no, text)

            conn.commit()
        except Exception as exc:
            print(f"[rebuild warning] {manifest_path}: {exc}", file=sys.stderr)

    conn.close()
    print(f"[rebuilt] {db}")


def command_doctor(args) -> None:
    """Check archive/index consistency without modifying source documents."""
    archive = Path(args.archive).resolve()
    conn = connect(archive / "osint.db")

    missing_objects = 0
    missing_text = 0

    for row in conn.execute("SELECT id, sha256, archive_path FROM documents"):
        if not (archive / row["archive_path"]).exists():
            print(f"[missing-object] doc={row['id']} sha256={row['sha256']}")
            missing_objects += 1

    for row in conn.execute(
        "SELECT document_id, page_no, text_path FROM pages WHERE status='indexed'"
    ):
        if not (archive / row["text_path"]).exists():
            print(f"[missing-text] doc={row['document_id']} page={row['page_no']}")
            missing_text += 1

    print(f"Archive objects missing: {missing_objects}")
    print(f"Derived text files missing: {missing_text}")
    conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="JEDI Document OSINT — archive-first multi-format ingestion, entity extraction & search."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ingest", help="Archive and index documents (pdf, docx, html, txt, md, images).")
    p.add_argument("source")
    p.add_argument("--archive", default="./archive")
    p.set_defaults(func=command_ingest)

    p = sub.add_parser("search", help="SQL/FTS5 search over extracted document text.")
    p.add_argument("query")
    p.add_argument("--archive", default="./archive")
    p.add_argument("--type", help="Filter by file type (pdf, docx, html, txt, md, jpg, ...).")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=command_search)

    p = sub.add_parser("entities", help="List extracted OSINT entities (emails, IPs, URLs, coords, ...).")
    p.add_argument("--archive", default="./archive")
    p.add_argument("--type", help="Filter by entity type (email, url, ipv4, phone, ...).")
    p.add_argument("--value", help="Filter by substring match on entity value.")
    p.add_argument("--document-id", type=int, dest="document_id", help="Filter by document id.")
    p.add_argument("--limit", type=int, default=100)
    p.set_defaults(func=command_entities)

    p = sub.add_parser("status", help="Show corpus/index/entity status.")
    p.add_argument("--archive", default="./archive")
    p.set_defaults(func=command_status)

    p = sub.add_parser("rebuild", help="Rebuild disposable DB (search index + entities) from archive-derived data.")
    p.add_argument("--archive", default="./archive")
    p.set_defaults(func=command_rebuild)

    p = sub.add_parser("doctor", help="Check archive/index consistency without modifying originals.")
    p.add_argument("--archive", default="./archive")
    p.set_defaults(func=command_doctor)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
