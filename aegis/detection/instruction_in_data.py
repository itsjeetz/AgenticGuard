"""Instruction-in-data detector: central detector for indirect prompt injections (§5.3)."""

import re
from typing import TYPE_CHECKING
from aegis.detection.base import DetectionContext
from aegis.models import AttackType, Finding, InputSource, Segment, Trust
from aegis.normalize.deobfuscate import Variant
from aegis.policy.config import get_policy

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig

IMPERATIVE_VERBS = re.compile(
    r"\b(?:send|forward|delete|execute|run|call|reveal|ignore|email|transfer|visit|download|reply|print|append|include|fetch|copy|post|leak|override|bypass)\b",
    re.IGNORECASE,
)

AI_ADDRESSEE_CUES = re.compile(
    r"\b(?:assistant|ai|agent|model|llm|claude|chatgpt|copilot|bot|if\s+you\s+are\s+an?\s+ai|when\s+summarizing|before\s+responding|when\s+reading\s+this|while\s+processing)\b",
    re.IGNORECASE,
)

EXFIL_TOOL_OBJECTS = re.compile(
    r"(?:https?://[^\s\"']+\?[^\s\"']+|[a-zA-Z0-9_.+-]+@(?!company\.local)[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|\b(?:api[_\s-]?keys?|passwords?|credentials?|tokens?|canary|confidential|secret|database|system\s+prompt|drop\s+table)\b)",
    re.IGNORECASE,
)

EXFIL_DESTINATION_CUES = re.compile(
    r"(?:https?://[^\s\"']+|[a-zA-Z0-9_.+-]+@(?!company\.local)[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|\b(?:webhook|exfil(?:trate)?|endpoint|pastebin|ngrok)\b)",
    re.IGNORECASE,
)


class InstructionInDataDetector:
    """Flags instructions embedded in untrusted or hidden content (§5.3)."""

    def __init__(self, policy: "PolicyConfig | None" = None):
        self.policy = policy or get_policy()

    def detect(
        self,
        segment: Segment,
        variants: list[Variant],
        ctx: DetectionContext,
    ) -> list[Finding]:
        """Detect instruction-in-data sentences across segment variants."""
        # Only untrusted content or hidden segments are subject to instruction-in-data checks
        is_hidden = ctx.is_hidden or segment.origin == "hidden"
        if ctx.trust != Trust.UNTRUSTED and not is_hidden:
            return []

        findings: list[Finding] = []
        base_visible = self.policy.thresholds.instruction_in_data_base_visible
        base_hidden = self.policy.thresholds.instruction_in_data_base_hidden

        # Evaluate variants (original first, then decoded)
        for var_idx, variant in enumerate(variants):
            mt = variant.mapped_text
            text = mt.text
            if not text.strip():
                continue

            # Split into sentence-like clauses
            sentence_matches = list(re.finditer(r"([^.!?\n\r]+[.!?\n\r]?)", text))
            for sent_m in sentence_matches:
                clause = sent_m.group(1).strip()
                if not clause or len(clause) < 10:
                    continue

                imp_match = IMPERATIVE_VERBS.search(clause)
                if not imp_match:
                    continue

                ai_match = AI_ADDRESSEE_CUES.search(clause)
                exfil_match = EXFIL_TOOL_OBJECTS.search(clause)

                # Core constraint: requires an AI cue, an exfiltration object, OR the segment being hidden
                if not (ai_match or exfil_match or is_hidden):
                    continue

                # In visible source code, developer comments frequently contain imperative verbs
                # with database/system keywords (e.g., "# Execute database query to fetch users").
                # To distinguish injection attacks from legitimate code instructions, visible
                # source code requires either a conversational AI cue or an external exfiltration destination.
                is_source_code = (
                    ctx.source == InputSource.SOURCE_CODE
                    or segment.origin == "source_code"
                    or (segment.location and "line" in str(segment.location))
                    or segment.id.startswith("seg-code")
                )
                if is_source_code and not is_hidden:
                    has_exfil_dest = bool(EXFIL_DESTINATION_CUES.search(clause))
                    if not (ai_match or has_exfil_dest):
                        continue

                # Calculate score
                score = base_hidden if is_hidden else base_visible
                if exfil_match:
                    score += 0.20
                if ai_match:
                    score += 0.15

                score = min(0.95, score)

                # Extract span mapped back to original document text
                sent_start = sent_m.start()
                sent_end = sent_m.end()
                orig_span = mt.to_original(sent_start, sent_end)

                # Target attack category based on content
                low_clause = clause.lower()
                attack_type = AttackType.INDIRECT_PROMPT_INJECTION
                if exfil_match and any(w in low_clause for w in ("drop table", "run", "execute", "email", "mailbox", "database", "curl", "bash", "transfer", "forward")):
                    attack_type = AttackType.TOOL_ABUSE
                elif exfil_match and ("password" in low_clause or "credential" in low_clause):
                    attack_type = AttackType.CREDENTIAL_THEFT
                elif exfil_match and ("prompt" in low_clause or "secret" in low_clause or "key" in low_clause):
                    attack_type = AttackType.SECRET_EXTRACTION

                findings.append(
                    Finding(
                        attack_type=attack_type,
                        score=score,
                        segment_id=segment.id,
                        span_original=orig_span,
                        evidence=clause[:120],
                        detector="instruction_in_data",
                        layer="rules",
                        variant_chain=variant.chain,
                        location=segment.location or segment.origin,
                    )
                )

                # Only need one strong finding per sentence/clause
                if len(findings) >= 5:
                    return findings

        return findings
