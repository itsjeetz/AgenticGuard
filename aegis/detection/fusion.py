"""L4 Fusion layer combining findings via dynamic layer weighting and Noisy-OR (§5.4)."""

from typing import Optional
from aegis.models import AttackType, Finding
from aegis.policy.config import PolicyConfig

# Baseline layer weights
DEFAULT_LAYER_WEIGHTS: dict[str, float] = {
    "rules": 0.50,
    "judge": 0.50,
    "classifier": 0.0,
}


ALL_ATTACK_TYPES: list[AttackType] = [
    AttackType.INSTRUCTION_OVERRIDE,
    AttackType.ROLE_CHANGE,
    AttackType.SECRET_EXTRACTION,
    AttackType.TOOL_ABUSE,
    AttackType.CREDENTIAL_THEFT,
    AttackType.CONTEXT_POISONING,
    AttackType.MULTI_STEP_JAILBREAK,
    AttackType.ENCODED_INSTRUCTIONS,
    AttackType.INDIRECT_PROMPT_INJECTION,
]


def fuse_findings(
    findings: list[Finding],
    source_mult: float,
    hidden: bool,
    policy: PolicyConfig,
    layer_status: Optional[dict[str, dict]] = None,
) -> tuple[float, dict[AttackType, float]]:
    """Compute overall combined risk score and per-category scores (§5.4).
    
    Per-category confidence strategy:
    Combines max(rules, llm_judge) per category with multi-layer consensus boost
    when multiple layers independently flag an attack type (score >= 0.50).
    Guarantees ALL 9 AttackType keys are present in category_scores every time.
    """
    by_cat: dict[AttackType, float] = {at: 0.0 for at in ALL_ATTACK_TYPES}

    for at in ALL_ATTACK_TYPES:
        cat_findings = [f for f in findings if f.attack_type == at]
        if not cat_findings:
            continue

        r_score = max([f.score for f in cat_findings if f.layer == "rules"], default=0.0)
        j_score = max([f.score for f in cat_findings if f.layer in ("judge", "llm_judge")], default=0.0)
        c_score = max([f.score for f in cat_findings if f.layer == "classifier"], default=0.0)
        other_score = max([f.score for f in cat_findings if f.layer not in ("rules", "judge", "llm_judge", "classifier")], default=0.0)

        max_score = max(r_score, j_score, c_score, other_score)

        # Multi-layer consensus boost: if 2+ layers independently flag the vector with confidence >= 0.50
        active_layers_flagged = sum(1 for s in (r_score, c_score, j_score, other_score) if s >= 0.50)
        if active_layers_flagged >= 2:
            max_score = min(1.0, max_score * 1.05)

        by_cat[at] = round(max_score, 4)

    if not findings:
        return 0.0, by_cat

    # 1. Category maximums and Noisy-OR probability combination
    p = 1.0
    for s in by_cat.values():
        if s > 0.0:
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

    total_weight = sum(DEFAULT_LAYER_WEIGHTS.get(l, 0.0) for l in active_layers)
    if total_weight > 0:
        weighted_layer_sum = sum(
            layer_scores[l] * (DEFAULT_LAYER_WEIGHTS.get(l, 0.0) / total_weight)
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
