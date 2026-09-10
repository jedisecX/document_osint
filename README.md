# JEDI Document OSINT

Archive-first document ingestion, page-granular text/OCR triage, regex entity extraction, and SQLite FTS5 search.

The archive is authoritative. Originals are never modified. `osint.db` is a disposable catalog and can be rebuilt from derived page text.

## Requirements

- Python 3.10+
- SQLite with FTS5

Optional (missing packages disable that format, not the tool):

```bash
pip install pymupdf pytesseract Pillow
```

Tesseract must also be installed on the host for OCR.

## Usage

```bash
python3 document_osint.py ingest ./incoming --archive ./archive
python3 document_osint.py search --archive ./archive '"contract" AND Louisiana'
python3 document_osint.py entities --archive ./archive --type email
python3 document_osint.py status --archive ./archive
python3 document_osint.py rebuild --archive ./archive
python3 document_osint.py doctor --archive ./archive
```

## Supported formats

| Type | Notes |
|------|--------|
| `.pdf` | Native text + page-granular OCR fallback |
| `.docx` | Stdlib zip/XML (no python-docx) |
| `.html` / `.htm` | Tag-stripped text + title |
| `.txt` / `.md` | Raw text |
| `.jpg` `.jpeg` `.png` `.tiff` `.tif` `.bmp` `.webp` | EXIF/GPS + OCR |

## Archive layout

```
archive/
  objects/aa/bb/<sha256>.<ext>   immutable originals
  derived/<sha256>/
      pages/000001.txt
      manifest.json
  osint.db                       catalog + FTS5 + entities
```

Entity extraction is regex-only and is a triage aid, not ground truth. Phone/SSN/IP hits in particular need verification.
