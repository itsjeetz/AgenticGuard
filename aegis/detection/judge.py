"""Hardened LLM Judge interface wrapping the provider-agnostic engine (§5.3c)."""

import json
import os
import secrets
import time
from typing import Any, Optional
from pydantic import BaseModel, Field, ValidationError

from aegis.detection.base import DetectionContext
from aegis.judge_llm import (
    JudgeScores,
    ProviderAgnosticJudge,
    get_llm_judge,
)
from aegis.models import AttackType, Finding, Segment
from aegis.policy.config import PolicyConfig, get_policy


class AttackCategoryScores(BaseModel):
    INSTRUCTION_OVERRIDE: float = Field(default=0.0, ge=0.0, le=1.0)
    ROLE_CHANGE: float = Field(default=0.0, ge=0.0, le=1.0)
    SECRET_EXTRACTION: float = Field(default=0.0, ge=0.0, le=1.0)
    TOOL_ABUSE: float = Field(default=0.0, ge=0.0, le=1.0)
    CREDENTIAL_THEFT: float = Field(default=0.0, ge=0.0, le=1.0)
    CONTEXT_POISONING: float = Field(default=0.0, ge=0.0, le=1.0)
    MULTI_STEP_JAILBREAK: float = Field(default=0.0, ge=0.0, le=1.0)
    ENCODED_INSTRUCTIONS: float = Field(default=0.0, ge=0.0, le=1.0)
    INDIRECT_PROMPT_INJECTION: float = Field(default=0.0, ge=0.0, le=1.0)


class JudgeOutputSchema(BaseModel):
    """Structured response schema required from LLM judge (§5.3c)."""

    is_injection: bool = Field(default=False)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    attack_types: list[AttackType] = Field(default_factory=list)
    category_scores: Optional[AttackCategoryScores] = None
    malicious_quotes: list[str] = Field(default_factory=list)
    rationale: str = Field(default="", max_length=500)


class JudgeCircuitBreaker:
    """Circuit breaker for LLM Judge: opens after 3 consecutive failures, retries after 60s (§8.3)."""

    def __init__(self, failure_threshold: int = 3, reset_timeout_sec: float = 60.0):
        self.failure_threshold = failure_threshold
        self.reset_timeout_sec = reset_timeout_sec
        self.failure_count = 0
        self.last_failure_time: float = 0.0
        self.state: str = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def record_success(self) -> None:
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"

    def can_execute(self) -> bool:
        if self.state == "CLOSED":
            return True
        elif self.state == "OPEN":
            if time.time() - self.last_failure_time > self.reset_timeout_sec:
                self.state = "HALF_OPEN"
                return True
            return False
        elif self.state == "HALF_OPEN":
            return True
        return False


class LLMJudge:
    """Provider-agnostic LLM Judge wrapper for backwards compatibility."""

    def __init__(self, policy: Optional[PolicyConfig] = None):
        self.policy = policy or get_policy()
        self.engine: ProviderAgnosticJudge = get_llm_judge()
        self.circuit_breaker = JudgeCircuitBreaker()

    @property
    def is_available(self) -> bool:
        # Check if provider keys are configured
        return self.engine.is_available and self.circuit_breaker.can_execute()

    @property
    def last_status(self) -> str:
        return self.engine.last_status

    @property
    def last_provider(self) -> Optional[str]:
        return self.engine.last_provider

    def format_prompt_envelope(self, content: str) -> tuple[str, str]:
        """Wrap untrusted content in nonce envelope and escape delimiters (§5.3c)."""
        nonce = secrets.token_hex(8)
        safe_content = content.replace("<<<", "«««").replace(">>>", "»»»")
        envelope = (
            f"Please evaluate the following untrusted content:\n\n"
            f"<<<UNTRUSTED_CONTENT id={nonce}>>>\n"
            f"{safe_content}\n"
            f"<<<END_UNTRUSTED_CONTENT id={nonce}>>>\n"
        )
        return envelope, nonce

    def parse_judge_response(self, raw_text: str) -> Optional[JudgeOutputSchema]:
        """Validate judge response strictly with Pydantic. Return None if invalid (§5.3c)."""
        if not raw_text or not raw_text.strip():
            return None

        cleaned = raw_text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        try:
            data = json.loads(cleaned)
            if not isinstance(data, dict):
                return None
            return JudgeOutputSchema.model_validate(data)
        except (json.JSONDecodeError, ValidationError, TypeError, ValueError):
            return None

    def evaluate_text(self, text: str) -> tuple[JudgeScores, str, str]:
        return self.engine.evaluate_text(text)

    def detect(
        self,
        segment: Segment,
        variants: list,
        ctx: DetectionContext,
        prior_score: float = 0.0,
    ) -> list[Finding]:
        if not self.is_available:
            return []
        return self.engine.detect(segment, variants, ctx, prior_score=prior_score)
