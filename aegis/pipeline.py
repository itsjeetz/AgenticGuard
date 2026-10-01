from collections import OrderedDict
import hashlib
import logging
import secrets
import threading
import time
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

from aegis.detection.base import DetectionContext
from aegis.detection.cascade import DetectionCascade
from aegis.detection.fusion import fuse_findings
from aegis.detection.session import SessionTracker
from aegis.ingestion.registry import extract
from aegis.models import (
    AttackType,
    Finding,
    InputSource,
    Segment,
    Trust,
    Verdict,
)
from aegis.neutralize.envelope import wrap_in_nonce_envelope
from aegis.neutralize.redact import redact_all_segments
from aegis.normalize.deobfuscate import deobfuscate
from aegis.observability.audit import get_audit_logger
from aegis.observability.metrics import get_metrics_tracker
from aegis.policy.config import PolicyConfig, get_policy
from aegis.policy.engine import PolicyEngine
from aegis.resilience import (
    adjust_policy_for_degraded_mode,
    fail_closed_verdict,
    validate_input_limits,
)

if TYPE_CHECKING:
    pass


class VerdictCache:
    """Thread-safe LRU cache for identical payload verification (§8)."""

    def __init__(self, max_size: int = 1000):
        self._max_size = max_size
        self._cache: OrderedDict[tuple, Verdict] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: tuple) -> Verdict | None:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            return None

    def put(self, key: tuple, verdict: Verdict) -> None:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            else:
                if len(self._cache) >= self._max_size:
                    self._cache.popitem(last=False)
                self._cache[key] = verdict

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


class FirewallPipeline:
    """End-to-end prompt injection firewall pipeline (§2, §8)."""

    def __init__(
        self,
        policy: PolicyConfig | None = None,
        enable_rules: bool = True,
        enable_classifier: bool = True,
        enable_judge: bool = True,
    ):
        self.policy = policy or get_policy()
        self.cascade = DetectionCascade(
            policy=self.policy,
            enable_rules=enable_rules,
            enable_classifier=enable_classifier,
            enable_judge=enable_judge,
        )
        self.rule_detector = self.cascade.rule_detector
        self.session_tracker = SessionTracker(policy=self.policy)
        self.policy_engine = PolicyEngine(self.policy)
        self.cache = VerdictCache(max_size=1000)

    def process(
        self,
        content: bytes | str,
        *,
        source: InputSource | None = None,
        filename: str | None = None,
        session_id: str | None = None,
        trust: Trust | None = None,
        neutralize_content: bool = True,
    ) -> Verdict:
        """Process content through L1-L5 layers and return full Verdict."""
        t_start = time.perf_counter()
        timings: dict[str, float] = {}
        layer_status: dict[str, dict] = {}

        content_bytes = content.encode("utf-8") if isinstance(content, str) else content
        content_sha256 = hashlib.sha256(content_bytes).hexdigest()
        request_id = f"req-{secrets.token_hex(6)}"

        try:
            return self._process_internal(
                content=content,
                content_bytes=content_bytes,
                content_sha256=content_sha256,
                request_id=request_id,
                source=source,
                filename=filename,
                session_id=session_id,
                trust=trust,
                neutralize_content=neutralize_content,
                t_start=t_start,
                timings=timings,
                layer_status=layer_status,
            )
        except Exception as e:
            logger.exception("Pipeline unhandled exception, failing closed: %s", e)
            return fail_closed_verdict(
                request_id=request_id,
                source=source or InputSource.USER_MESSAGE,
                trust=trust or Trust.UNTRUSTED,
                content_sha256=content_sha256,
                layer_status=layer_status,
                error_msg=str(e),
            )

    def _process_internal(
        self,
        content: bytes | str,
        content_bytes: bytes,
        content_sha256: str,
        request_id: str,
        source: InputSource | None,
        filename: str | None,
        session_id: str | None,
        trust: Trust | None,
        neutralize_content: bool,
        t_start: float,
        timings: dict[str, float],
        layer_status: dict[str, dict],
    ) -> Verdict:
        # Content size validation (§8.3)
        validate_input_limits(content, filename=filename)

        # Check LRU cache for identical requests (§8)
        cache_key = (
            content_sha256,
            source.value if source else None,
            filename,
            neutralize_content,
        ) if session_id is None else None

        if cache_key:
            cached = self.cache.get(cache_key)
            if cached:
                cached_timings = dict(cached.timings_ms)
                cached_timings["total_pipeline_ms"] = round((time.perf_counter() - t_start) * 1000, 2)
                cached_timings["total_ms"] = cached_timings["total_pipeline_ms"]
                cached_timings["cache_hit"] = 1.0
                verdict = Verdict(
                    request_id=f"req-{secrets.token_hex(6)}",
                    source=cached.source,
                    trust=cached.trust,
                    action=cached.action,
                    risk=cached.risk,
                    category_scores=dict(cached.category_scores),
                    findings=list(cached.findings),
                    degraded=cached.degraded,
                    layer_status=dict(cached.layer_status),
                    sanitized_text=cached.sanitized_text,
                    envelope_text=cached.envelope_text,
                    extracted_text=cached.extracted_text,
                    timings_ms=cached_timings,
                    content_sha256=cached.content_sha256,
                )
                try:
                    get_audit_logger().log_verdict(verdict, content=content, session_id=session_id)
                    get_metrics_tracker().record(verdict)
                except Exception:
                    pass
                return verdict

        # ----------------------------------------------------
        # L1: Ingestion
        # ----------------------------------------------------
        t0 = time.perf_counter()
        detected_source, segments = extract(content, source=source, filename=filename, policy=self.policy)
        timings["l1_ingestion_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        layer_status["ingestion"] = {"status": "ok", "segments_count": len(segments)}
        extracted_text = "\n\n".join(s.text for s in segments if s.text.strip())

        # Trust determination: USER for direct user message, UNTRUSTED for all external channels
        resolved_trust = trust or (
            Trust.USER if detected_source == InputSource.USER_MESSAGE else Trust.UNTRUSTED
        )

        all_findings: list[Finding] = []
        hidden_count = sum(1 for s in segments if s.origin == "hidden")

        # ----------------------------------------------------
        # L2 & L3: Normalization and Detection Cascade
        # ----------------------------------------------------
        t_l2_l3 = time.perf_counter()
        for seg in segments:
            # L2: Variants generation
            t_norm = time.perf_counter()
            variants = deobfuscate(seg, policy=self.policy)
            timings.setdefault("l2_normalize_ms", 0.0)
            timings["l2_normalize_ms"] += (time.perf_counter() - t_norm) * 1000

            ctx = DetectionContext(
                request_id=request_id,
                source=detected_source,
                trust=resolved_trust,
                session_id=session_id,
                is_hidden=(seg.origin == "hidden"),
            )

            # L3: Run cascade (Rules -> Classifier -> Judge)
            cascade_findings, c_status = self.cascade.detect(seg, variants, ctx)
            all_findings.extend(cascade_findings)
            layer_status.update(c_status)

        # Check if rules layer failed -> Fail closed (§8.3)
        if layer_status.get("rules", {}).get("status") == "degraded_error":
            verdict = fail_closed_verdict(
                request_id=request_id,
                source=detected_source,
                trust=resolved_trust,
                content_sha256=content_sha256,
                layer_status=layer_status,
                error_msg=layer_status["rules"].get("error", "Rules execution failure"),
            )
            get_audit_logger().log_verdict(verdict, content=content, session_id=session_id)
            get_metrics_tracker().record(verdict)
            return verdict

        # L3d: Session Tracker (if session_id provided)
        if session_id:
            combined_user_text = " ".join(s.text for s in segments if s.text.strip())
            session_findings = self.session_tracker.process_turn(
                session_id,
                combined_user_text,
                all_findings,
                self.rule_detector,
            )
            all_findings.extend(session_findings)

        timings["l2_normalize_ms"] = round(timings.get("l2_normalize_ms", 0.0), 2)
        total_l3 = (time.perf_counter() - t_l2_l3) * 1000 - timings["l2_normalize_ms"]
        timings["l3_detection_ms"] = round(max(0.0, total_l3), 2)
        timings["l3a_rules_ms"] = round(layer_status.get("rules", {}).get("duration_ms", timings["l3_detection_ms"]), 2)
        timings["l3b_classifier_ms"] = round(layer_status.get("classifier", {}).get("duration_ms", 0.0), 2)
        timings["l3c_judge_ms"] = round(layer_status.get("judge", {}).get("duration_ms", 0.0), 2)

        # ----------------------------------------------------
        # L4: Fusion and Policy
        # ----------------------------------------------------
        t_l4 = time.perf_counter()
        source_mult = self.policy.source_multipliers.get(detected_source.value, 1.0)
        is_hidden = hidden_count > 0

        risk, category_scores = fuse_findings(
            all_findings,
            source_mult,
            is_hidden,
            self.policy,
            layer_status=layer_status,
        )

        # Check degraded status across layers (§8.3)
        is_degraded = any(
            st.get("status", "").startswith("degraded")
            for st in layer_status.values()
        )

        effective_policy = (
            adjust_policy_for_degraded_mode(self.policy) if is_degraded else self.policy
        )
        effective_engine = PolicyEngine(effective_policy)

        # Check localizable spans: can we redact spans or is whole-document redaction needed?
        has_localizable = all(f.span_original is not None for f in all_findings) if all_findings else True
        action = effective_engine.evaluate(
            risk=risk,
            category_scores=category_scores,
            findings=all_findings,
            trust=resolved_trust,
            has_localizable_spans=has_localizable,
        )

        # Enforce fail-closed REVIEW (ESCALATE) verdict if unreadable PDF content is detected (§5.1)
        has_unreadable_pdf = any(
            s.hidden_reason == "unreadable_pdf" or "Could not extract readable text from this PDF" in s.text
            for s in segments
        )
        if has_unreadable_pdf:
            action = "ESCALATE"
            risk = max(risk, 0.60)
            if not any(f.detector == "pdf_adapter" for f in all_findings):
                seg_id = next((s.id for s in segments if s.hidden_reason == "unreadable_pdf"), "seg-pdf-unreadable-0")
                all_findings.append(
                    Finding(
                        detector="pdf_adapter",
                        attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
                        score=0.60,
                        segment_id=seg_id,
                        evidence="Could not extract readable text from this PDF",
                        layer="rules",
                    )
                )

        timings["l4_fusion_policy_ms"] = round((time.perf_counter() - t_l4) * 1000, 2)
        layer_status["policy"] = {"status": "ok", "action": action, "risk": round(risk, 4)}

        # ----------------------------------------------------
        # L5: Neutralizer
        # ----------------------------------------------------
        t_l5 = time.perf_counter()
        sanitized_text: str | None = None
        envelope_text: str | None = None

        if action == "SANITIZE" or (neutralize_content and has_localizable and all_findings):
            sanitized_text = redact_all_segments(segments, all_findings)
            if resolved_trust == Trust.UNTRUSTED:
                envelope_text = wrap_in_nonce_envelope(
                    sanitized_text,
                    detected_source,
                    request_id=request_id,
                    hidden_segments_removed=hidden_count,
                )
        elif action == "ALLOW":
            raw_text = "\n\n".join(s.text for s in segments if s.text.strip())
            sanitized_text = raw_text
            if resolved_trust == Trust.UNTRUSTED:
                envelope_text = wrap_in_nonce_envelope(
                    raw_text,
                    detected_source,
                    request_id=request_id,
                    hidden_segments_removed=hidden_count,
                )
        else:  # BLOCK or ESCALATE
            sanitized_text = None
            envelope_text = None

        timings["l5_neutralize_ms"] = round((time.perf_counter() - t_l5) * 1000, 2)
        total_time = round((time.perf_counter() - t_start) * 1000, 2)
        timings["total_pipeline_ms"] = total_time
        timings["total_ms"] = total_time

        # Compute detected categories (score >= threshold, default 0.50)
        cat_thresh_map = getattr(getattr(self.policy, "thresholds", None), "category_thresholds", {}) or {}
        detected = [
            cat for cat, s in category_scores.items()
            if s >= cat_thresh_map.get(cat, 0.50)
        ]
        llm_judge_status = layer_status.get("judge", {}).get("llm_judge_status")

        verdict = Verdict(
            request_id=request_id,
            source=detected_source,
            trust=resolved_trust,
            action=action,
            risk=round(risk, 4),
            category_scores=category_scores,
            detected=detected,
            findings=all_findings,
            degraded=is_degraded,
            layer_status=layer_status,
            llm_judge_status=llm_judge_status,
            sanitized_text=sanitized_text,
            envelope_text=envelope_text,
            extracted_text=extracted_text,
            timings_ms=timings,
            content_sha256=content_sha256,
        )

        # Observability: log audit entry & record metrics (§8.1)
        try:
            get_audit_logger().log_verdict(verdict, content=content, session_id=session_id)
            get_metrics_tracker().record(verdict)
        except Exception:
            pass

        if cache_key:
            self.cache.put(cache_key, verdict)

        return verdict


_PIPELINE_INSTANCE = FirewallPipeline()


def get_pipeline() -> FirewallPipeline:
    return _PIPELINE_INSTANCE
