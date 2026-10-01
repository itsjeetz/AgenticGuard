"""Detection cascade orchestrating Rules (L3a) -> Provider-Agnostic LLM Judge (§5.3, §8.3)."""

import time
from typing import Optional

from aegis.detection.base import DetectionContext
from aegis.detection.instruction_in_data import InstructionInDataDetector
from aegis.detection.rules import RuleDetector
from aegis.judge_llm import ProviderAgnosticJudge, get_llm_judge
from aegis.models import Finding, Segment, Trust
from aegis.policy.config import PolicyConfig, get_policy
from aegis.resilience import TIMEOUTS, run_with_timeout


class DetectionCascade:
    """Orchestrates L3 detection cascade across rules and provider-agnostic LLM judge."""

    def __init__(
        self,
        policy: Optional[PolicyConfig] = None,
        enable_rules: bool = True,
        enable_classifier: bool = False,
        enable_judge: bool = True,
    ):
        self.policy = policy or get_policy()
        self.enable_rules = enable_rules
        self.enable_classifier = enable_classifier
        self.enable_judge = enable_judge

        self.rule_detector = RuleDetector(self.policy)
        self.iid_detector = InstructionInDataDetector(self.policy)
        self.judge = get_llm_judge()

    def _run_rules(
        self, segment: Segment, variants: list, ctx: DetectionContext
    ) -> list[Finding]:
        r_findings = self.rule_detector.detect(segment, variants, ctx)
        iid_findings = self.iid_detector.detect(segment, variants, ctx)
        return r_findings + iid_findings

    def detect(
        self,
        segment: Segment,
        variants: list,
        ctx: DetectionContext,
    ) -> tuple[list[Finding], dict[str, dict]]:
        """Run cascade across enabled layers with timeouts and resilience. Returns (findings, layer_status)."""
        findings: list[Finding] = []
        layer_status: dict[str, dict] = {}

        # 1. Rules and Instruction-in-Data (L3a)
        if self.enable_rules:
            res, degraded, err = run_with_timeout(
                self._run_rules,
                args=(segment, variants, ctx),
                timeout_sec=TIMEOUTS.get("rules", 1.0),
                layer_name="rules",
            )
            if degraded or res is None:
                layer_status["rules"] = {
                    "status": "degraded_error",
                    "error": err or "Rules layer execution failed",
                    "findings_count": 0,
                }
            else:
                findings.extend(res)
                layer_status["rules"] = {
                    "status": "ok",
                    "findings_count": len(res),
                }
        else:
            layer_status["rules"] = {"status": "disabled", "findings_count": 0}

        prior_score = max([f.score for f in findings], default=0.0)

        # L3b ML Classifier is replaced by provider-agnostic LLM Judge
        layer_status["classifier"] = {
            "status": "replaced_by_judge",
            "findings_count": 0,
            "duration_ms": 0.0,
        }

        # High-confidence short-circuit check after L3a (§5.3):
        # If L3a rules already returned a score >= block_at (e.g. >= 0.85) or high-severity attack on untrusted:
        high_sev_untrusted = (
            ctx.trust == Trust.UNTRUSTED
            and any(
                f.attack_type in self.policy.high_severity_categories
                and f.score >= self.policy.high_severity_threshold
                for f in findings
            )
        )
        if prior_score >= self.policy.thresholds.block_at or high_sev_untrusted:
            if self.enable_judge:
                layer_status["judge"] = {
                    "status": "skipped_short_circuit",
                    "llm_judge_status": "skipped (short-circuit on high confidence rules)",
                    "findings_count": 0,
                    "duration_ms": 0.0,
                }
            return findings, layer_status

        # 2. Provider-Agnostic LLM Judge (L3c)
        if self.enable_judge:
            t_j_start = time.perf_counter()
            res, degraded, err = run_with_timeout(
                self.judge.detect,
                args=(segment, variants, ctx),
                kwargs={"prior_score": prior_score},
                timeout_sec=TIMEOUTS.get("judge", 10.0),
                layer_name="judge",
            )
            t_j_dur = round((time.perf_counter() - t_j_start) * 1000, 2)

            last_st = getattr(self.judge, "last_status", "standby")
            provider = getattr(self.judge, "last_provider", None)

            if degraded or res is None:
                layer_status["judge"] = {
                    "status": "degraded_error",
                    "llm_judge_status": f"degraded: {err or 'Judge execution failed'}",
                    "error": err or "Judge execution failed or timed out",
                    "provider": provider,
                    "findings_count": 0,
                    "duration_ms": t_j_dur,
                }
            elif last_st.startswith("fallback"):
                layer_status["judge"] = {
                    "status": "degraded_offline",
                    "llm_judge_status": last_st,
                    "provider": None,
                    "findings_count": 0,
                    "duration_ms": t_j_dur,
                }
            else:
                findings.extend(res)
                layer_status["judge"] = {
                    "status": "ok",
                    "llm_judge_status": last_st,
                    "provider": provider,
                    "findings_count": len(res),
                    "duration_ms": t_j_dur,
                }
        else:
            layer_status["judge"] = {
                "status": "disabled",
                "llm_judge_status": "disabled",
                "findings_count": 0,
                "duration_ms": 0.0,
            }

        return findings, layer_status
