"""Tests for Evidence Pack, Position Declaration, /evidence route, and Tab 1 tooltip (§1, §2, §3, §4, §5)."""

import csv
import json
from pathlib import Path
from PIL import Image
import pytest
from fastapi.testclient import TestClient

from server.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_nav_tab_eval_removed_and_renumbered():
    """Verify Tab 3 Evaluation is removed from navigation and tabs are renumbered (§1)."""
    index_html = Path("static/index.html").read_text(encoding="utf-8")
    assert 'id="navEval"' not in index_html, "navEval button should be removed from nav"
    assert "3. Audit & Feedback" in index_html, "Tab 4 should be renumbered to 3"
    assert "4. Policy Configuration" in index_html, "Tab 5 should be renumbered to 4"
    assert 'id="tabEval"' in index_html, "tabEval container preserved for backward compatibility"


def test_hidden_evidence_route(client):
    """Verify GET /evidence returns 200 and renders offline evidence dashboard (§1)."""
    resp = client.get("/evidence")
    assert resp.status_code == 200
    html = resp.text
    assert "AgenticGuard — Offline Evidence & Declared Position" in html
    assert "Declared Position" in html
    assert "Attack Type Category Coverage" in html
    assert "Delivery Carrier & Format Reliability" in html


def test_tab1_category_pct_tooltip():
    """Verify per-category percentage displays the clarity tooltip (§5)."""
    app_js = Path("static/app.js").read_text(encoding="utf-8")
    assert 'title="Model confidence for this input, not an accuracy rate."' in app_js


def test_evidence_pack_csvs_and_metadata():
    """Verify evidence pack CSVs and metadata.json adhere to strict schema (§2)."""
    meta_path = Path("docs/evidence/metadata.json")
    assert meta_path.exists(), "metadata.json must exist"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert "benchmark_version" in meta
    assert "dataset_checksum_sha256" in meta
    assert "git_commit" in meta
    assert "llm_evaluated_share" in meta

    # per_category.csv
    cat_path = Path("docs/evidence/per_category.csv")
    assert cat_path.exists(), "per_category.csv must exist"
    with open(cat_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        cat_rows = list(reader)
    assert len(cat_rows) >= 8
    for row in cat_rows:
        assert "category" in row
        assert "n" in row
        assert "flagged_recall" in row
        assert "correct_recall" in row
        assert "ci_95_flagged_lower" in row
        assert "ci_95_flagged_upper" in row
        assert "low_confidence_flag" in row
        assert "status" in row

    # per_source.csv
    src_path = Path("docs/evidence/per_source.csv")
    assert src_path.exists(), "per_source.csv must exist"
    with open(src_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        src_rows = list(reader)
    assert len(src_rows) >= 11
    has_skipped = any("SKIPPED" in r["status"] for r in src_rows)
    assert has_skipped, "Must indicate SKIPPED sources with reason"


def test_evidence_pack_charts_generated():
    """Verify 1920x1080 slide charts are generated (§2)."""
    charts = [
        "docs/evidence/recall_by_category.png",
        "docs/evidence/recall_by_source.png",
        "docs/evidence/fpr_by_source.png",
    ]
    for ch in charts:
        p = Path(ch)
        assert p.exists(), f"Chart {ch} missing"
        with Image.open(p) as img:
            assert img.size == (1920, 1080), f"Chart {ch} must be 1920x1080 slide dimensions"


def test_evidence_markdown_guidelines():
    """Verify EVIDENCE.md contains quote / do not quote sections (§2)."""
    md = Path("docs/evidence/EVIDENCE.md").read_text(encoding="utf-8")
    assert "Numbers You CAN Quote" in md
    assert "Numbers You MUST NOT Quote" in md
    assert "Overall Flagged Recall" in md
    assert "Benign False Positive Rate" in md


def test_position_declaration_logic():
    """Verify POSITION.md contains declared cell, criteria table, and limitations (§3)."""
    pos = Path("docs/POSITION.md").read_text(encoding="utf-8")
    assert "Declared Position:" in pos
    assert "None / None" not in pos, "Must never display None / None"
    assert "Features Dimension" in pos
    assert "Depth Dimension" in pos
    assert "Cells Not Claimed and Why" in pos
    assert "D3" in pos
    assert "How to Reproduce" in pos


def test_demo_evidence_outputs_and_screenshots():
    """Verify demo scenarios and single attack outputs exist (§4)."""
    demo_dir = Path("docs/evidence/demo")
    assert (demo_dir / "summary.json").exists()
    assert (demo_dir / "scenario_1_ticket.json").exists()
    assert (demo_dir / "scenario_2_api.json").exists()
    assert (demo_dir / "scenario_3_email.json").exists()
    assert (demo_dir / "single_attack_instruction_override.json").exists()
    assert (demo_dir / "single_attack_role_change.json").exists()
    assert (demo_dir / "demo_gallery.png").exists()
    assert (demo_dir / "scenario_1_evidence.png").exists()
