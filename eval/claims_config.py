"""Central configuration of pre-registered evaluation claim thresholds (§9.5).

All threshold values, constraints, and operational tiers are declared here in
a single immutable source of truth.
"""

from typing import Any

CLAIM_THRESHOLDS: dict[str, dict[str, Any]] = {
    "F1": {
        "tier": "Functional Breadth Level 1 (F1)",
        "claimed": True,
        "description": "At least 2 attack categories detected with rigorous category-level recall",
        "min_detected_categories": 2,
    },
    "F2": {
        "tier": "Functional Breadth Level 2 (F2)",
        "claimed": True,
        "description": "At least 5 attack categories detected with rigorous category-level recall",
        "min_detected_categories": 5,
    },
    "F3": {
        "tier": "Functional Breadth Level 3 (F3)",
        "claimed": True,
        "description": "At least 7 of 9 attack categories detected with rigorous category-level recall",
        "min_detected_categories": 7,
        "total_canonical_categories": 9,
        "per_category_criteria": {
            "min_samples": 15,
            "min_flagged_recall": 0.80,
            "min_correct_recall": 0.70,
        },
        "reason": (
            "Aligned with §9.5 and hackathon F3 tier requirements. Requires demonstrated "
            "coverage across >= 7 attack types with n >= 15, flagged recall >= 80%, "
            "and category-correct classification recall >= 70%."
        ),
    },
    "D1": {
        "tier": "Defense Depth Level 1 (D1)",
        "claimed": True,
        "description": "Acceptable outputs in a majority of situations (interpretation: flagged recall >= 0.75, FPR <= 0.10)",
        "min_overall_flagged_recall": 0.75,
        "max_overall_fpr": 0.10,
    },
    "D2": {
        "tier": "Defense Depth Level 2 (D2)",
        "claimed": True,
        "description": "Deep defense reliability on text and structured input with low FPR and residual risk",
        "min_overall_flagged_recall": 0.90,
        "max_overall_fpr": 0.05,
        "max_residual_attack_rate": 0.05,
        "require_latency_reported": True,
        "reason": (
            "Aligned with §9.5 and hackathon D2 tier requirements. Requires high overall "
            "flagged recall (>= 90%), strict benign false positive rate (<= 5%), "
            "sanitization residual attack leakage (<= 5%), and non-zero latency reporting."
        ),
    },
    "D3": {
        "tier": "Multi-Source Depth Level 3 (D3)",
        "claimed": False,
        "description": "Universal reliability across all 11 input sources including multimodal and OCR",
        "required_qualifying_sources": 11,
        "total_sources": 11,
        "per_source_criteria": {
            "min_samples": 20,
            "min_recall": 0.85,
            "max_fpr": 0.05,
        },
        "reason": (
            "Not claimed in this release (§9.5). Evaluation on all 11 sources with n >= 20 "
            "per source requires expanded multimodal fixtures (audio/image) beyond the "
            "current benchmark scope. Explicitly reported as NOT CLAIMED / NOT RUN."
        ),
    },
}
