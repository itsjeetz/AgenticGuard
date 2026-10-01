import io
from pathlib import Path
from PIL import Image
import pymupdf

artifacts_dir = Path("test_artifacts")
artifacts_dir.mkdir(exist_ok=True)

# 1. Text PDF
doc = pymupdf.open()
page = doc.new_page(width=595, height=842)
page.insert_text((50, 100), "Quarterly Financial Analysis Report 2026.\nNet revenue increased by 14% across enterprise software lines.", fontsize=12)
text_pdf_path = artifacts_dir / "text_sample.pdf"
doc.save(str(text_pdf_path))
doc.close()

# 2. Scanned / Image-only PDF
doc = pymupdf.open()
page = doc.new_page(width=595, height=842)
img = Image.new("RGB", (300, 200), color=(100, 120, 140))
buf = io.BytesIO()
img.save(buf, format="PNG")
page.insert_image(pymupdf.Rect(50, 50, 350, 250), stream=buf.getvalue())
scanned_pdf_path = artifacts_dir / "scanned_sample.pdf"
doc.save(str(scanned_pdf_path))
doc.close()

# 3. HTML file
html_path = artifacts_dir / "sample.html"
html_path.write_text("<html><body><h1>System Notice</h1><p>Normal documentation content.</p></body></html>", encoding="utf-8")

# 4. EML file
eml_path = artifacts_dir / "sample.eml"
eml_path.write_text("From: alice@example.com\nTo: bob@example.com\nSubject: Meeting\n\nHi Bob, see you at 2pm.", encoding="utf-8")

# 5. PNG image
png_path = artifacts_dir / "sample.png"
img.save(str(png_path), format="PNG")

# 6. Large file (> 2 MB)
oversize_path = artifacts_dir / "oversize.txt"
oversize_path.write_bytes(b"A" * (2 * 1024 * 1024 + 1024))

print("Created test artifacts in", artifacts_dir.resolve())
