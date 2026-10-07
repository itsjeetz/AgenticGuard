"""Tests for Tab 3 evaluation metrics, claim thresholds, and live demo checks (§9)."""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from eval.claims_config import CLAIM_THRESHOLDS
from eval.claims import evaluate_claims
from eval.metrics import ItemEvaluation, compute_all_metrics, evaluate_item
from aegis.models import AttackType, Finding, InputSource, Trust, Verdict
from server.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_claim_thresholds_config():
    """Verify claim thresholds config has clear written justifications and valid values."""
    assert "F3" in CLAIM_THRESHOLDS
    assert "D2" in CLAIM_THRESHOLDS
    assert "D3" in CLAIM_THRESHOLDS

    f3 = CLAIM_THRESHOLDS["F3"]
    d2 = CLAIM_THRESHOLDS["D2"]
    d3 = CLAIM_THRESHOLDS["D3"]

    # F3 configuration
    assert f3["min_detected_categories"] == 7
    assert f3["per_category_criteria"]["min_flagged_recall"] == 0.80
    assert f3["per_category_criteria"]["min_correct_recall"] == 0.70
    assert "reason" in f3

    # D2 configuration
    assert d2["min_overall_flagged_recall"] == 0.90
    assert d2["max_overall_fpr"] == 0.05
    assert d2["max_residual_attack_rate"] == 0.05
    assert "reason" in d2

    # D3 configuration
    assert d3["claimed"] is False
    assert d3["per_source_criteria"]["min_recall"] == 0.85
    assert d3["per_source_criteria"]["max_fpr"] == 0.05
    assert "reason" in d3


def test_metric_correct_recall_conditioned_on_flagged():
    """Ensure category_correct recall is bounded by flagged recall."""
    from eval.dataset import DatasetItem

    item_unflagged = DatasetItem(
        id="test-1",
        split="dev",
        source="email",
        carrier="email",
        technique="direct",
        is_attack=True,
        attack_types=["INDIRECT_PROMPT_INJECTION"],
    )
    # Verdict allows it, but internal category score was high
    v_allow = Verdict(
        request_id="req-1",
        source=InputSource.EMAIL,
        trust=Trust.UNTRUSTED,
        action="ALLOW",
        risk=0.1,
        content_sha256="abc",
        category_scores={AttackType.INDIRECT_PROMPT_INJECTION: 0.8},
        detected=[AttackType.INDIRECT_PROMPT_INJECTION],
    )
    eval_item = evaluate_item(item_unflagged, v_allow)
    assert eval_item.flagged is False
    assert eval_item.category_correct is False  # Cannot be correct if not flagged!

    metrics = compute_all_metrics([eval_item])
    cat_metrics = metrics["categories"]["INDIRECT_PROMPT_INJECTION"]
    assert cat_metrics["flagged_recall"] == 0.0
    assert cat_metrics["category_correct_recall"] == 0.0
    # Legacy unconditioned metric records the old unconditioned value
    assert cat_metrics["legacy_unconditioned_recall"] == 1.0


def test_claims_evaluation_logic():
    """Verify evaluate_claims correctly evaluates F3, D2, and marks D3 as NOT CLAIMED."""
    mock_report = {
        "metrics": {
            "binary": {
                "recall": 0.93,
                "fpr": 0.02,
            },
            "overall": {
                "flagged_recall": 0.93,
                "benign_fpr": 0.02,
                "residual_attack_rate": 0.04,
            },
            "latency": {
                "total_ms": {
                    "p95": 14.5,
                },
            },
            "sanitization": {
                "residual_attack_rate": 0.02,
            },
            "categories": {
                f"CAT_{i}": {
                    "count": 20,
                    "flagged_recall": 0.85,
                    "category_correct_recall": 0.75,
                }
                for i in range(8)
            },
            "sources": {
                f"SRC_{i}": {
                    "count": 10,
                    "flagged_recall": 0.90,
                    "benign_fpr": 0.02,
                }
                for i in range(11)
            },
        }
    }
    result = evaluate_claims(mock_report)
    claims = result["claims"]
    assert claims["F3"]["pass"] is True
    assert claims["F3"]["detected_categories"] == 8
    assert claims["D2"]["pass"] is True
    assert claims["D3"]["pass"] is False
    assert claims["D3"]["status"] == "NOT_CLAIMED"


def test_live_checks_endpoint(client):
    """Verify GET /api/eval/live-checks tests all 6 custom demo files with 100% pass rate."""
    res = client.get("/api/eval/live-checks")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 6
    assert data["passed"] == 6
    assert data["failed"] == 0
    assert len(data["checks"]) == 6
    for chk in data["checks"]:
        assert chk["passed"] is True
        assert chk["verdict"] in ("BLOCK", "SANITIZE", "ALLOW")
