#!/usr/bin/env python3
"""
AgenticGuard Learning Guide - PDF Build & Assembly Pipeline.

Assembles modular HTML source parts, inlines stylesheets, renders via
Chrome headless to PDF, applies running headers/footers with dynamic page
numbering via PyMuPDF, injects hierarchical PDF bookmarks (TOC outline),
and renders high-resolution inspection pixmaps for visual quality assurance.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
import pymupdf


BASE_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = BASE_DIR / "docs"
SOURCE_DIR = DOCS_DIR / "source"
PARTS_DIR = SOURCE_DIR / "parts"
ASSETS_DIR = DOCS_DIR / "assets"
RENDERED_PAGES_DIR = DOCS_DIR / "rendered_pages"
FINAL_PDF_PATH = DOCS_DIR / "AgenticGuard_Learning_Guide.pdf"
TEMP_RAW_PDF_PATH = DOCS_DIR / "temp_raw.pdf"

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]


def find_browser() -> str:
    """Locate Chrome or Edge executable on the system."""
    for path in CHROME_CANDIDATES:
        if os.path.exists(path):
            return path
    which_chrome = shutil.which("chrome") or shutil.which("msedge")
    if which_chrome:
        return which_chrome
    raise RuntimeError("Neither Google Chrome nor Microsoft Edge was found.")


def assemble_html() -> Path:
    """Concatenate HTML parts and inline CSS into a standalone document."""
    css_path = SOURCE_DIR / "book.css"
    css_content = css_path.read_text(encoding="utf-8") if css_path.exists() else ""

    part_files = sorted(PARTS_DIR.glob("*.html"))
    if not part_files:
        raise RuntimeError(f"No HTML part files found in {PARTS_DIR}")

    print(f"Assembling {len(part_files)} source parts into standalone HTML...")
    body_parts = []
    for pf in part_files:
        content = pf.read_text(encoding="utf-8")
        body_parts.append(f"<!-- BEGIN {pf.name} -->\n{content}\n<!-- END {pf.name} -->")

    joined_body = "\n".join(body_parts)
    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AgenticGuard: The Definitive Learning Guide & Technical Reference</title>
  <style>
{css_content}
  </style>
</head>
<body>
{joined_body}
</body>
</html>
"""
    output_html_path = SOURCE_DIR / "index.html"
    output_html_path.write_text(full_html, encoding="utf-8")
    print(f"Generated standalone HTML at: {output_html_path} ({len(full_html)} bytes)")
    return output_html_path


def render_html_to_pdf(html_path: Path, output_pdf: Path, browser_path: str):
    """Invoke Chrome/Edge headless to render HTML to PDF."""
    print(f"Rendering HTML to PDF via headless browser: {browser_path}")
    file_uri = html_path.as_uri()

    cmd = [
        browser_path,
        "--headless=new",
        "--disable-gpu",
        "--no-pdf-header-footer",
        "--run-all-compositor-stages-before-draw",
        f"--print-to-pdf={output_pdf}",
        file_uri,
    ]

    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0 or not output_pdf.exists():
        raise RuntimeError(f"Browser PDF generation failed:\nStdout: {res.stdout}\nStderr: {res.stderr}")
    print(f"Raw PDF successfully generated at: {output_pdf} ({output_pdf.stat().st_size} bytes)")


def post_process_pdf(raw_pdf_path: Path, final_pdf_path: Path):
    """Add running headers, footers with page numbers, and PDF bookmarks."""
    print("Post-processing PDF with PyMuPDF (headers, footers, outline bookmarks)...")
    doc = pymupdf.open(raw_pdf_path)
    total_pages = len(doc)
    print(f"Total raw pages generated: {total_pages}")

    # Outline definitions: [Level, Title, Search String for Page Detection]
    outline_targets = [
        [1, "Cover Page & Reading Paths", "HOW TO READ THIS GUIDE"],
        [1, "Part I: The Big Picture", "PART I"],
        [2, "1.1 What is Prompt Injection?", "1.1 What is Prompt Injection"],
        [2, "1.2 Three Real-World Analogies", "1.2 Three Real-World Analogies"],
        [2, "1.3 Why AI Agents Need a Specialized Firewall", "1.3 Why AI Agents Need"],
        [2, "1.4 The 9 Core Attack Types Explained", "1.4 The 9 Core Attack Types"],
        [1, "Part II: System Architecture & Data Flow", "PART II"],
        [2, "2.1 The Multi-Layer Cascade (L1-L5)", "2.1 The Multi-Layer Cascade"],
        [2, "2.2 Complete Technology Stack", "2.2 Complete Technology Stack"],
        [2, "2.3 Repository Map & Directory Layout", "2.3 Repository Map"],
        [2, "2.4 End-to-End Request Lifecycle", "2.4 End-to-End Request Lifecycle"],
        [1, "Part III: Feature-by-Feature Deep Dive", "PART III"],
        [2, "3.1 Inspector UI Dashboard & Controls", "3.1 Inspector UI Dashboard"],
        [2, "3.2 Attack Preset Dropdown", "3.2 Attack Preset Dropdown"],
        [2, "3.3 Carrier & Input Source Selector", "3.3 Carrier & Input Source Selector"],
        [2, "3.4 Multi-Format Ingestion Engine", "3.4 Multi-Format Ingestion Engine"],
        [2, "3.5 Text Normalization & De-obfuscation", "3.5 Text Normalization"],
        [2, "3.6 Deterministic Rule Engine", "3.6 Deterministic Rule Engine"],
        [2, "3.7 Provider-Agnostic LLM Judge", "3.7 Provider-Agnostic LLM Judge"],
        [2, "3.8 Risk Scoring & Noisy-OR Fusion", "3.8 Risk Scoring & Noisy-OR Fusion"],
        [2, "3.9 Policy Engine & Fail-Closed Verdicts", "3.9 Policy Engine & Fail-Closed Verdicts"],
        [2, "3.10 Neutralizer & Spotlighting Envelopes", "3.10 Neutralizer & Spotlighting Envelopes"],
        [2, "3.11 Runtime Guards & Session Tracker", "3.11 Runtime Guards & Session Tracker"],
        [2, "3.12 Attack Type Detection & Latency Panels", "3.12 Attack Type Detection & Latency Panels"],
        [2, "3.13 Agent Sandbox (ASR Live Demo)", "3.13 Agent Sandbox (ASR Live Demo)"],
        [2, "3.14 Evaluation & Claims Dashboard", "3.14 Evaluation & Claims Dashboard"],
        [2, "3.15 Audit, Review Queue & Feedback Loop", "3.15 Audit, Review Queue & Feedback Loop"],
        [2, "3.16 Policy Configuration Manager", "3.16 Policy Configuration Manager"],
        [2, "3.17 Public Demo Mode Guardrails", "3.17 Public Demo Mode Guardrails"],
        [2, "3.18 Theme Toggle & Visual Accessibility", "3.18 Theme Toggle & Visual Accessibility"],
        [2, "3.19 System Health & Degraded Mode", "3.19 System Health & Degraded Mode"],
        [2, "3.20 Complete REST API Reference (19 Endpoints)", "3.20 Complete REST API Reference"],
        [1, "Part IV: Setup, Installation & Verification", "PART IV"],
        [2, "4.1 Prerequisites", "4.1 Prerequisites"],
        [2, "4.2 Step-by-Step Installation", "4.2 Step-by-Step Installation"],
        [2, "4.3 Environment Configuration (.env)", "4.3 Environment Configuration"],
        [2, "4.4 Running the Application", "4.4 Running the Application"],
        [2, "4.5 Acquiring Free LLM API Keys", "4.5 Acquiring Free LLM API Keys"],
        [2, "4.6 Verification & Troubleshooting", "4.6 Diagnostics & Troubleshooting"],
        [1, "Part V: Worked Walkthroughs (5 Real Traces)", "PART V"],
        [2, "5.1 Trace 1: Benign Request", "5.1 Trace 1: Benign Business Inquiry"],
        [2, "5.2 Trace 2: Credential Exfiltration", "5.2 Trace 2: Credential Exfiltration"],
        [2, "5.3 Trace 3: Instruction Override", "5.3 Trace 3: Instruction Override"],
        [2, "5.4 Trace 4: Indirect Injection in HTML", "5.4 Trace 4: Indirect Prompt Injection"],
        [2, "5.5 Trace 5: Unreadable PDF & Fail-Closed Escalation", "5.5 Trace 5: Unreadable PDF"],
        [1, "Part VI: Testing, Validation & Quality Assurance", "PART VI"],
        [2, "6.1 Test Suite Architecture & Layout", "6.1 Test Suite Architecture & Layout"],
        [2, "6.2 Executing the Test Suite", "6.2 How to Execute the Test Suite"],
        [2, "6.3 Three-Class Testing Methodology", "6.3 Three-Class Testing Methodology"],
        [2, "6.4 What Is Covered vs. What Isn't", "6.4 What Is Covered vs. What Isn't"],
        [1, "Part VII: Honest Limitations & Production Roadmap", "PART VII"],
        [2, "7.1 False Negatives & Evasion Risks", "7.1 False Negatives & Adversarial Evasion Risks"],
        [2, "7.2 False Positives & Utility Degradation", "7.2 False Positives & Utility Degradation"],
        [2, "7.3 Privacy & Data Governance", "7.3 Privacy & Data Governance"],
        [2, "7.4 Free-Tier Rate Limits & Quotas", "7.4 Free-Tier Rate Limits & Operating Quotas"],
        [2, "7.5 Enterprise Production Targets", "7.5 What Would Be Needed for Enterprise Production"],
        [1, "Part VIII: Appendices, Glossary & Master Checklist", "PART VIII"],
        [2, "Appendix A: Comprehensive Glossary (32 Terms)", "Appendix A: Comprehensive Glossary"],
        [2, "Appendix B: Frequently Asked Questions (20 Q&As)", "Appendix B: Frequently Asked Questions"],
        [2, "Appendix C: One-Page Quick-Reference Cheat Sheet", "Appendix C: One-Page Quick-Reference Cheat Sheet"],
        [2, "Appendix D: Master Feature Inventory Verification Checklist", "Appendix D: Master Feature Inventory Verification Checklist"],
    ]

    # Pre-extract text from all pages to find bookmark page numbers
    page_texts = [p.get_text() for p in doc]
    toc = []

    last_page = 1
    for lvl, title, search_str in outline_targets:
        found_page = None
        for p_idx, text in enumerate(page_texts):
            if p_idx + 1 < last_page:
                continue
            if search_str.lower() in text.lower():
                found_page = p_idx + 1
                break
        if found_page is None:
            found_page = last_page
        else:
            last_page = found_page
        toc.append([lvl, title, found_page])

    # Apply running headers and footers to pages 2..N (skip cover page 1)
    purple_color = (161 / 255, 0 / 255, 255 / 255)
    gray_color = (0.5, 0.5, 0.5)
    rule_color = (0.85, 0.85, 0.85)

    header_text_left = "AgenticGuard: The Definitive Learning Guide & Technical Reference"
    header_text_right = "v2.1.0"
    footer_text_left = "Confidential & Security Architecture Reference — Open Source"

    for p_idx in range(1, total_pages):
        page = doc[p_idx]
        p_num = p_idx + 1
        rect = page.rect
        width, height = rect.width, rect.height

        # Running Top Header
        page.insert_text(
            pymupdf.Point(40, 24),
            header_text_left,
            fontsize=7.5,
            fontname="helv",
            color=purple_color,
        )
        page.insert_text(
            pymupdf.Point(width - 65, 24),
            header_text_right,
            fontsize=7.5,
            fontname="helv",
            color=gray_color,
        )
        # Header Rule
        page.draw_line(
            pymupdf.Point(40, 28),
            pymupdf.Point(width - 40, 28),
            color=purple_color,
            width=0.6,
        )

        # Running Bottom Footer Rule
        page.draw_line(
            pymupdf.Point(40, height - 28),
            pymupdf.Point(width - 40, height - 28),
            color=rule_color,
            width=0.5,
        )
        # Running Bottom Footer Text
        page.insert_text(
            pymupdf.Point(40, height - 18),
            footer_text_left,
            fontsize=7.5,
            fontname="helv",
            color=gray_color,
        )
        page_num_str = f"Page {p_num} of {total_pages}"
        page.insert_text(
            pymupdf.Point(width - 90, height - 18),
            page_num_str,
            fontsize=7.5,
            fontname="helv",
            color=gray_color,
        )

    # Set PDF TOC
    doc.set_toc(toc)
    doc.save(final_pdf_path)
    doc.close()
    print(f"Finalized PDF saved successfully to: {final_pdf_path} ({final_pdf_path.stat().st_size} bytes)")


def render_page_images(pdf_path: Path, output_dir: Path):
    """Render each page to a high-resolution PNG image for visual inspection."""
    output_dir.mkdir(parents=True, exist_ok=True)
    doc = pymupdf.open(pdf_path)
    total = len(doc)
    print(f"Rendering all {total} pages to PNG images in {output_dir}...")

    for i, page in enumerate(doc):
        pix = page.get_pixmap(dpi=130)
        img_name = f"page_{i + 1:02d}.png"
        pix.save(output_dir / img_name)
    doc.close()
    print(f"Successfully rendered {total} inspection images.")


def main():
    print("=" * 70)
    print(" AGENTICGUARD LEARNING GUIDE - PDF COMPILATION & VERIFICATION PIPELINE")
    print("=" * 70)

    browser_path = find_browser()
    html_path = assemble_html()
    render_html_to_pdf(html_path, TEMP_RAW_PDF_PATH, browser_path)
    post_process_pdf(TEMP_RAW_PDF_PATH, FINAL_PDF_PATH)

    if TEMP_RAW_PDF_PATH.exists():
        TEMP_RAW_PDF_PATH.unlink()

    render_page_images(FINAL_PDF_PATH, RENDERED_PAGES_DIR)

    doc = pymupdf.open(FINAL_PDF_PATH)
    page_count = len(doc)
    doc.close()

    print("=" * 70)
    print(f" BUILD COMPLETE!")
    print(f" Output PDF: {FINAL_PDF_PATH}")
    print(f" Final Page Count: {page_count} Pages")
    print(f" Rendered Inspection Images: {RENDERED_PAGES_DIR}")
    print("=" * 70)


if __name__ == "__main__":
    main()
