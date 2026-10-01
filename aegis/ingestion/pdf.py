"""Ingestion adapter for PDF documents (§5.1).

Multi-engine extraction pipeline: PyMuPDF (fitz) -> pdfplumber -> pypdf -> OCR.
Enforces text quality checks (printable ratio >= 0.85).
"""

import io
from typing import TYPE_CHECKING
import pymupdf

from aegis.ingestion.base import BaseAdapter, OversizeContentError, IngestionError
from aegis.models import InputSource, Segment
from aegis.policy.config import get_policy
from server.routes_health import is_ocr_available

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


LEGACY_INDIC_FONTS = (
    "ygsh", "kruti", "shree", "chanakya", "akruti", "walkman", "aps", "brh", "dv-"
)
MOJIBAKE_SYMBOLS = set("×÷§¶¤¬±µ°¥¢£")


def is_mojibake_or_unreadable(text: str, font: str = "") -> bool:
    """Detect if text is mojibake, unmapped glyphs, or legacy 8-bit font encoding (§5.1)."""
    if not text:
        return False
    font_lower = font.lower()
    if any(k in font_lower for k in LEGACY_INDIC_FONTS):
        return True
    if "\ufffd" in text:
        return True
    if any(0xE000 <= ord(c) <= 0xF8FF for c in text):
        return True
    if any(c in MOJIBAKE_SYMBOLS for c in text):
        return True
    return False


def is_text_mostly_printable(text: str, min_ratio: float = 0.85) -> bool:
    """Check if the extracted text contains at least min_ratio printable characters without mojibake."""
    if not text or not text.strip():
        return False
    clean = text.strip()
    printable_count = 0
    mojibake_count = 0
    for c in clean:
        code = ord(c)
        if c == "\ufffd" or (0xE000 <= code <= 0xF8FF) or c in MOJIBAKE_SYMBOLS:
            mojibake_count += 1
        elif c.isprintable() or c in "\r\n\t ":
            printable_count += 1

    if mojibake_count > 0 and (mojibake_count / len(clean)) > 0.05:
        return False
    return (printable_count / len(clean)) >= min_ratio


class PdfAdapter(BaseAdapter):
    """Multi-engine PDF adapter: PyMuPDF -> pdfplumber -> pypdf -> OCR."""

    source = InputSource.PDF

    def extract(
        self,
        data: bytes | str,
        *,
        filename: str | None = None,
        policy: "PolicyConfig | None" = None,
    ) -> list[Segment]:
        pol = policy or get_policy()

        if isinstance(data, str):
            raw_bytes = data.encode("utf-8")
        else:
            raw_bytes = data

        if len(raw_bytes) > pol.limits.max_upload_bytes:
            limit_mb = pol.limits.max_upload_bytes // (1024 * 1024)
            raise OversizeContentError(
                f"PDF size {len(raw_bytes)} bytes exceeds limit of {limit_mb} MB"
            )

        try:
            doc = pymupdf.open(stream=raw_bytes, filetype="pdf")
        except Exception as e:
            raise IngestionError(f"Failed to parse PDF document: {e}") from e

        if len(doc) > pol.limits.max_pdf_pages:
            doc.close()
            raise OversizeContentError(
                f"PDF page count {len(doc)} exceeds limit of {pol.limits.max_pdf_pages} pages"
            )

        segments: list[Segment] = []
        seg_idx = 0

        # 1. Document metadata
        meta = doc.metadata or {}
        for key in ("title", "author", "subject", "keywords"):
            val = meta.get(key)
            if val and val.strip() and is_text_mostly_printable(val.strip()):
                segments.append(
                    Segment(
                        id=f"seg-pdf-{seg_idx}",
                        text=val.strip(),
                        origin="metadata",
                        location=f"doc.metadata[{key}]",
                        hidden_reason=None,
                    )
                )
                seg_idx += 1

        # 2. Embedded files
        try:
            for emb_name in doc.embfile_names():
                segments.append(
                    Segment(
                        id=f"seg-pdf-{seg_idx}",
                        text=emb_name,
                        origin="metadata",
                        location="doc.embedded_files",
                        hidden_reason=None,
                    )
                )
                seg_idx += 1
        except Exception:
            pass

        # 3. Engine 1: PyMuPDF (fitz) detailed extraction
        fitz_segments: list[Segment] = []
        fitz_text_acc: list[str] = []

        for page_num in range(len(doc)):
            page = doc[page_num]
            page_rect = page.rect

            # Annotations
            for annot in page.annots() or []:
                info = annot.info or {}
                content = info.get("content", "").strip()
                if content and is_text_mostly_printable(content):
                    fitz_segments.append(
                        Segment(
                            id=f"seg-pdf-{seg_idx + len(fitz_segments)}",
                            text=content,
                            origin="comment",
                            location=f"page {page_num + 1} annot",
                            hidden_reason="pdf_annotation",
                        )
                    )

            # Text spans via page.get_text("dict")
            page_dict = page.get_text("dict")
            for block in page_dict.get("blocks", []):
                if block.get("type") != 0:  # 0 is text block
                    continue

                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        text = span.get("text", "").strip()
                        if not text:
                            continue

                        font_name = span.get("font", "")
                        if is_mojibake_or_unreadable(text, font_name):
                            continue

                        size = span.get("size", 12.0)
                        color = span.get("color", 0)  # integer sRGB
                        bbox = span.get("bbox", (0, 0, 0, 0))

                        # Determine if hidden
                        hidden_reason = None

                        # Check color: near-white on white background
                        r = (color >> 16) & 0xFF
                        g = (color >> 8) & 0xFF
                        b = color & 0xFF
                        if r >= 240 and g >= 240 and b >= 240:
                            hidden_reason = "white_text"
                        elif size < 2.0:
                            hidden_reason = "tiny_font"
                        elif (
                            bbox[2] < 0
                            or bbox[3] < 0
                            or bbox[0] > page_rect.width
                            or bbox[1] > page_rect.height
                        ):
                            hidden_reason = "offscreen"

                        origin = "hidden" if hidden_reason else "visible"
                        fitz_segments.append(
                            Segment(
                                id=f"seg-pdf-{seg_idx + len(fitz_segments)}",
                                text=text,
                                origin=origin,
                                location=f"page {page_num + 1}",
                                hidden_reason=hidden_reason,
                            )
                        )
                        fitz_text_acc.append(text)

        fitz_full_text = " ".join(fitz_text_acc)
        fitz_valid = bool(fitz_text_acc) and is_text_mostly_printable(fitz_full_text, min_ratio=0.85)

        if fitz_valid:
            segments.extend(fitz_segments)
            seg_idx += len(fitz_segments)
        else:
            # 4. Engine 2: pdfplumber fallback
            plumber_segments: list[Segment] = []
            try:
                import pdfplumber

                with pdfplumber.open(io.BytesIO(raw_bytes)) as pdf:
                    for p_num, p in enumerate(pdf.pages):
                        txt = p.extract_text() or ""
                        if txt.strip() and is_text_mostly_printable(txt.strip(), min_ratio=0.85):
                            plumber_segments.append(
                                Segment(
                                    id=f"seg-pdf-{seg_idx + len(plumber_segments)}",
                                    text=txt.strip(),
                                    origin="visible",
                                    location=f"page {p_num + 1}",
                                    hidden_reason=None,
                                )
                            )
            except Exception:
                pass

            if plumber_segments:
                segments.extend(plumber_segments)
                seg_idx += len(plumber_segments)
            else:
                # 5. Engine 3: pypdf fallback
                pypdf_segments: list[Segment] = []
                try:
                    import pypdf

                    reader = pypdf.PdfReader(io.BytesIO(raw_bytes))
                    for p_num, page in enumerate(reader.pages):
                        txt = page.extract_text() or ""
                        if txt.strip() and is_text_mostly_printable(txt.strip(), min_ratio=0.85):
                            pypdf_segments.append(
                                Segment(
                                    id=f"seg-pdf-{seg_idx + len(pypdf_segments)}",
                                    text=txt.strip(),
                                    origin="visible",
                                    location=f"page {p_num + 1}",
                                    hidden_reason=None,
                                )
                            )
                except Exception:
                    pass

                if pypdf_segments:
                    segments.extend(pypdf_segments)
                    seg_idx += len(pypdf_segments)
                else:
                    # 6. Engine 4: OCR on rendered page pixmaps
                    ocr_segments: list[Segment] = []
                    if is_ocr_available():
                        try:
                            import pytesseract
                            from PIL import Image

                            for p_num in range(len(doc)):
                                page = doc[p_num]
                                pix = page.get_pixmap(dpi=150)
                                img = Image.open(io.BytesIO(pix.tobytes("png")))
                                ocr_res = pytesseract.image_to_string(img, config="--psm 6").strip()
                                if ocr_res and is_text_mostly_printable(ocr_res, min_ratio=0.85):
                                    ocr_segments.append(
                                        Segment(
                                            id=f"seg-pdf-{seg_idx + len(ocr_segments)}",
                                            text=ocr_res,
                                            origin="ocr",
                                            location=f"page {p_num + 1} ocr",
                                            hidden_reason=None,
                                        )
                                    )
                        except Exception:
                            pass

                    if ocr_segments:
                        segments.extend(ocr_segments)
                        seg_idx += len(ocr_segments)

        doc.close()

        # If still no readable segments were extracted:
        # Flag as unreadable PDF so pipeline fails closed with a REVIEW verdict
        if not segments or all(not is_text_mostly_printable(s.text, min_ratio=0.85) for s in segments):
            segments = [
                Segment(
                    id=f"seg-pdf-unreadable-0",
                    text="Could not extract readable text from this PDF (OCR service offline)",
                    origin="ocr",
                    location="document",
                    hidden_reason="unreadable_pdf",
                )
            ]

        return segments
