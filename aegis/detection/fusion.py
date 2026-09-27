"""L4 Fusion layer combining findings via dynamic layer weighting and Noisy-OR (§5.4)."""

from typing import Optional
from aegis.models import AttackType, Finding
from aegis.policy.config import PolicyConfig

# Baseline layer weights
DEFAULT_LAYER_WEIGHTS: dict[str, float] = {
    "rules": 0.40,
    "classifier": 0.30,
    "judge": 0.30,
}


def fuse_findings(
    findings: list[Finding],
    source_mult: float,
    hidden: bool,
    policy: PolicyConfig,
    layer_status: Optional[dict[str, dict]] = None,
) -> tuple[float, dict[AttackType, float]]:
    """Compute overall combined risk score and per-category maximum scores (§5.4).
    
    Combines:
    1. Per-category scores across all findings (including INDIRECT_PROMPT_INJECTION).
    2. Dynamic weighted aggregation across active/online layers (reweighting when judge/classifier offline).
    3. Max-of guarantee ensuring combined_risk >= max(category_scores) so any detected attack reflects in risk.
    4. Noisy-OR combination for independent multi-category coverage.
    5. Hidden content and encoding boosts.
    """
    by_cat: dict[AttackType, float] = {}
    for f in findings:
        by_cat[f.attack_type] = max(by_cat.get(f.attack_type, 0.0), f.score)

    if not findings and not by_cat:
        return 0.0, by_cat

    # 1. Category maximums and Noisy-OR probability combination
    # All attack categories contribute to the risk score
    p = 1.0
    for s in by_cat.values():
        p *= (1.0 - s)
    noisy_or_risk = 1.0 - p
    max_cat_score = max(by_cat.values(), default=0.0)

    # 2. Dynamic layer reweighting across online layers
    # Identify which layers are active
    active_layers: set[str] = set()
    if layer_status:
        for lname in ("rules", "classifier", "judge"):
            st = layer_status.get(lname, {}).get("status", "")
            # "ok" or "skipped_short_circuit" are considered active/functional
            if st in ("ok", "skipped_short_circuit"):
                active_layers.add(lname)
    
    # If no layer_status or none marked active, infer from findings or fallback to available
    if not active_layers:
        active_layers = {f.layer for f in findings if f.layer in DEFAULT_LAYER_WEIGHTS}
        if not active_layers:
            active_layers = {"rules"}

    # Extract maximum score per active layer
    layer_scores: dict[str, float] = {}
    for lname in active_layers:
        layer_findings = [f.score for f in findings if f.layer == lname]
        layer_scores[lname] = max(layer_findings, default=0.0)

    total_weight = sum(DEFAULT_LAYER_WEIGHTS[l] for l in active_layers)
    if total_weight > 0:
        weighted_layer_sum = sum(
            layer_scores[l] * (DEFAULT_LAYER_WEIGHTS[l] / total_weight)
            for l in active_layers
        )
    else:
        weighted_layer_sum = 0.0

    # 3. Combined risk aggregation:
    # Guarantee: combined_risk is at least the highest category score,
    # ensuring that if ANY category score > 0, combined_risk > 0.
    risk = max(weighted_layer_sum, max_cat_score, noisy_or_risk)

    # 4. Hidden content boost if any attack finding was detected
    if hidden and max_cat_score > 0:
        risk += policy.thresholds.hidden_boost

    # 5. Encoded instructions boost if encoded instructions detected
    if by_cat.get(AttackType.ENCODED_INSTRUCTIONS, 0.0) > 0.50:
        risk += policy.thresholds.encoded_boost

    final_risk = min(1.0, max(0.0, risk * source_mult))
    return final_risk, by_cat
