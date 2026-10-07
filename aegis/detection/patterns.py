"""ReDoS-safe regex pattern families for rule-based prompt injection detection (§5.3)."""

from dataclasses import dataclass
import re
from aegis.models import AttackType


@dataclass(frozen=True)
class RulePattern:
    """A weighted regex detection pattern."""

    id: str
    attack_type: AttackType
    regex: re.Pattern
    weight: float
    description: str


# 1. INSTRUCTION_OVERRIDE patterns
OVERRIDE_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="ovr_ignore_prev",
        attack_type=AttackType.INSTRUCTION_OVERRIDE,
        regex=re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass|discard|cancel)\s+"
            r"(?:all\s+)?(?:previous|prior|above|earlier|all|original|current)\s+"
            r"(?:instructions|rules|directions?|prompt|guidelines|context|constraints|system\s+message)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Ignore/override previous instructions directive",
    ),
    RulePattern(
        id="ovr_new_instructions",
        attack_type=AttackType.INSTRUCTION_OVERRIDE,
        regex=re.compile(
            r"\b(?:new\s+(?:instructions?|rules?|directives?)|here\s+are\s+your\s+real\s+instructions?)\s*:",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Declaration of new instructions/rules",
    ),
    RulePattern(
        id="ovr_delimiter_hijack",
        attack_type=AttackType.INSTRUCTION_OVERRIDE,
        regex=re.compile(
            r"(?:<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|###\s*System:?</system>|<system>|\[SYSTEM\s+PROMPT\]|\bHuman:\s*|\bAssistant:\s*|\bend\s+of\s+prompt\b)",
            re.IGNORECASE,
        ),
        weight=0.90,
        description="Prompt delimiter injection or hijack token",
    ),
    RulePattern(
        id="ovr_from_now_on",
        attack_type=AttackType.INSTRUCTION_OVERRIDE,
        regex=re.compile(
            r"\bfrom\s+now\s+on\s+you\s+(?:will|must|shall|should|are|have\s+to)\b",
            re.IGNORECASE,
        ),
        weight=0.80,
        description="'From now on you must/will' imperative override",
    ),
]

# 2. ROLE_CHANGE patterns
ROLE_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="role_act_as",
        attack_type=AttackType.ROLE_CHANGE,
        regex=re.compile(
            r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|simulate\s+being|play\s+the\s+role\s+of)\s+"
            r"(?:an?\s+)?(?:unfiltered|unrestricted|evil|jailbroken|DAN|anti-?ai|hacker|root|admin)",
            re.IGNORECASE,
        ),
        weight=0.90,
        description="Adoption of malicious, unrestricted, or evil persona",
    ),
    RulePattern(
        id="role_dan_devmode",
        attack_type=AttackType.ROLE_CHANGE,
        regex=re.compile(
            r"\b(?:DAN\s+mode|developer\s+mode\s+(?:enabled|activated)|jailbroken\s+mode|god\s+mode|unfiltered\s+mode)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Jailbreak persona toggle (DAN, developer mode)",
    ),
    RulePattern(
        id="role_no_restrictions",
        attack_type=AttackType.ROLE_CHANGE,
        regex=re.compile(
            r"\b(?:without\s+(?:any\s+)?restrictions?|no\s+(?:rules|filters|guidelines|safety)|disregard\s+content\s+policy)\b",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Explicit removal of safety filters or restrictions",
    ),
]

# 3. SECRET_EXTRACTION patterns
SECRET_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="sec_reveal_system",
        attack_type=AttackType.SECRET_EXTRACTION,
        regex=re.compile(
            r"\b(?:print|reveal|show|repeat|output|leak|display|echo|tell\s+me|give\s+me|dump|share|send|provide|read|copy|export)\s+"
            r"(?:your\s+|the\s+)?(?:(?:full|complete|entire)[,\s]+)*"
            r"(?:system\s+prompt|initial\s+instructions?|hidden\s+instructions?|developer\s+prompt|guardrails|canary)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Direct request to reveal system prompt or internal instructions",
    ),
    RulePattern(
        id="sec_what_told",
        attack_type=AttackType.SECRET_EXTRACTION,
        regex=re.compile(
            r"\b(?:what\s+were\s+you\s+told\s+(?:at\s+the\s+beginning|initially|in\s+your\s+prompt)|what\s+is\s+(?:your|the)\s+system\s+prompt)\b",
            re.IGNORECASE,
        ),
        weight=0.90,
        description="Querying initial prompt content",
    ),
    RulePattern(
        id="sec_api_keys",
        attack_type=AttackType.SECRET_EXTRACTION,
        regex=re.compile(
            r"\b(?:print|reveal|give\s+me|what\s+is|leak)\s+(?:your\s+)?(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|api_key|api\s+key|access\s+token|secret\s+key|env\s+vars?|environment\s+variables?)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Request for API keys, secret credentials, or environment variables",
    ),
    RulePattern(
        id="sec_verbatim_leak",
        attack_type=AttackType.SECRET_EXTRACTION,
        regex=re.compile(
            r"\b(?:output|repeat)\s+(?:everything\s+)?verbatim\s+(?:from\s+the\s+beginning|above)\b",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Request for verbatim output of prior instructions",
    ),
]

# 4. TOOL_ABUSE patterns
TOOL_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="tool_email_exfil",
        attack_type=AttackType.TOOL_ABUSE,
        regex=re.compile(
            r"\b(?:forward|send_email|send\s+(?:an?\s+)?(?:email|database|records?|mailbox|data)|email\s+(?:this|all|the|entire)?)\b[^;\n.]{0,80}?\bto\s+[a-zA-Z0-9_.+-]+@(?!company\.local)[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Direct instruction to send or forward data/email to an external recipient",
    ),
    RulePattern(
        id="tool_data_exfil",
        attack_type=AttackType.TOOL_ABUSE,
        regex=re.compile(
            r"\b(?:email|send|dump|export|forward|exfiltrate)\s+(?:the\s+|this\s+|all\s+|entire\s+)?(?:database|db|mailbox|emails?|customer\s+records?|user\s+records?|credentials?)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Instruction to email, dump, or exfiltrate database, mailbox, or records",
    ),
    RulePattern(
        id="tool_shell_pipe",
        attack_type=AttackType.TOOL_ABUSE,
        regex=re.compile(
            r"\b(?:curl|wget)\s+[^|\n;]+\|\s*(?:ba)?sh\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Shell execution pipe via curl/wget to shell",
    ),
    RulePattern(
        id="tool_destructive_cmd",
        attack_type=AttackType.TOOL_ABUSE,
        regex=re.compile(
            r"\b(?:rm\s+-rf\s+[/~]|DROP\s+TABLE\s+\w+|TRUNCATE\s+TABLE\s+\w+|DELETE\s+FROM\s+\w+\s*;|format\s+[a-z]:)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Destructive filesystem or database commands",
    ),
    RulePattern(
        id="tool_invoke_directive",
        attack_type=AttackType.TOOL_ABUSE,
        regex=re.compile(
            r"\b(?:run_bash|run_command|run_sql|execute_query|transfer_funds|make_payment)\s*\(",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Direct invocation syntax of restricted agent tools",
    ),
]


# 5. CREDENTIAL_THEFT patterns
CREDENTIAL_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="cred_reenter_password",
        attack_type=AttackType.CREDENTIAL_THEFT,
        regex=re.compile(
            r"\b(?:session\s+(?:has\s+)?expired|security\s+alert|identity\s+verification\s+required)[^;\n]{0,80}?"
            r"(?:re-?enter|submit|provide|verify)\s+(?:your\s+)?(?:password|credentials|login|token|OTP)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Fake session expiration or identity re-verification challenge",
    ),
    RulePattern(
        id="cred_ask_user_password",
        attack_type=AttackType.CREDENTIAL_THEFT,
        regex=re.compile(
            r"\b(?:ask|prompt|instruct)\s+(?:the\s+)?user\s+to\s+(?:re-?enter|provide|enter|submit|give)\s+(?:their\s+)?(?:password|credentials|pin|token|otp)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Direct instruction prompting or asking user to provide password/credentials",
    ),
    RulePattern(
        id="cred_send_password",
        attack_type=AttackType.CREDENTIAL_THEFT,
        regex=re.compile(
            r"\b(?:send|submit|message|email|enter)\s+(?:your\s+)?(?:password|API\s+key|private\s+key|recovery\s+phrase|seed\s+phrase|pin)\s+(?:to|at)\b",
            re.IGNORECASE,
        ),
        weight=0.90,
        description="Solicitation of user passwords, private keys, or PINs",
    ),
    RulePattern(
        id="cred_imperative_exfil",
        attack_type=AttackType.CREDENTIAL_THEFT,
        regex=re.compile(
            r"(?<!never\s)(?<!not\s)(?<!n't\s)\b(?:upload|dump|export|send|leak|exfil(?:trate)?|post|extract|fetch|transmit|output|display|show|share|read|steal)\s+"
            r"(?:the\s+|all\s+|your\s+|our\s+)?(?:production\s+|prod\s+|system\s+|master\s+|root\s+)?"
            r"(?:credentials?|passwords?|passwd|api[_\s-]?keys?|secret[_\s-]?keys?|tokens?|auth[_\s-]?tokens?|private[_\s-]?keys?|database\s+passwords?)\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Imperative verb soliciting production credentials or secret keys",
    ),
    RulePattern(
        id="cred_username_password_pair",
        attack_type=AttackType.CREDENTIAL_THEFT,
        regex=re.compile(
            r"\b(?:username|user|login)\s*[/\\:]\s*(?:password|pass|pwd)\b|"
            r"\b(?:username|user|login)\s*[:=]\s*\S+[\s,;]+(?:password|pass|pwd)\s*[:=]\s*\S+\b|"
            r"\b(?:credentials?|login)\s*[:=]\s*[\"']?\w+[\"']?\s*[/\\:]\s*[\"']?\S+[\"']?",
            re.IGNORECASE,
        ),
        weight=0.90,
        description="Structured username and password credential pair",
    ),
    RulePattern(
        id="cred_token_key_formats",
        attack_type=AttackType.CREDENTIAL_THEFT,
        regex=re.compile(
            r"\bAKIA[0-9A-Z]{16}\b|"
            r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----|"
            r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b|"
            r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b|"
            r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b",
            re.IGNORECASE,
        ),
        weight=0.95,
        description="Explicit secret access key, private key, or bearer token signature",
    ),
]

# 6. CONTEXT_POISONING patterns
POISONING_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="pois_persistence",
        attack_type=AttackType.CONTEXT_POISONING,
        regex=re.compile(
            r"\b(?:remember\s+that\s+for\s+all\s+future|from\s+now\s+on\s+always\s+remember|"
            r"(?:permanently\s+)?record\s+in(?:to)?\s+(?:permanent\s+)?memory|"
            r"store\s+this\s+in\s+(?:permanent\s+)?memory|"
            r"add\s+to\s+your\s+(?:long-?term\s+)?(?:memory|notes))\b",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Instructions attempting persistent memory or agent state poisoning",
    ),
    RulePattern(
        id="pois_authority_spoof",
        attack_type=AttackType.CONTEXT_POISONING,
        regex=re.compile(
            r"\b(?:official\s+(?:CFO|CEO|admin|IT|executive)\s+(?:memo|directive|order)|admin\s+has\s+authorized|treat\s+this\s+(?:file|document|text)\s+as\s+trusted\s+(?:source|authority))\b",
            re.IGNORECASE,
        ),
        weight=0.80,
        description="Spoofed administrative or executive authority directive",
    ),
    RulePattern(
        id="pois_rule_relaxation",
        attack_type=AttackType.CONTEXT_POISONING,
        regex=re.compile(
            r"\b(?:security\s+policy\s+(?:has\s+been\s+)?updated|restrictions\s+are\s+temporarily\s+suspended|"
            r"security\s+policies\s+are\s+(?:suspended|disabled)|"
            r"prompt\s+injection\s+firewall\s+is\s+disabled)\b",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Claims of security policy relaxation or firewall suspension",
    ),
]

# 7. INDIRECT_PROMPT_INJECTION patterns
INDIRECT_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="ind_ai_directive_in_data",
        attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
        regex=re.compile(
            r"\b(?:(?:note|instruction|directive|message|notice)\s+(?:for|to)\s+(?:the\s+)?(?:AI|assistant|LLM|agent|model)|"
            r"(?:AI|assistant|LLM|agent)\s*,\s*(?:please\s+)?(?:ignore|disregard|override|forward|send|execute|do\s+not))\b",
            re.IGNORECASE,
        ),
        weight=0.90,
        description="Embedded directive in passive content targeting the reading AI agent",
    ),
    RulePattern(
        id="ind_carrier_override",
        attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
        regex=re.compile(
            r"\b(?:when\s+(?:processing|reading|summarizing)\s+this\s+(?:email|document|page|file|ticket|data)|"
            r"if\s+you\s+are\s+an?\s+(?:AI|assistant|automated\s+system))\b",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Conditional injection directed at AI processing the carrier document",
    ),
]

# 8. MULTI_STEP_JAILBREAK patterns
MULTI_STEP_PATTERNS: list[RulePattern] = [
    RulePattern(
        id="multi_staged_steps",
        attack_type=AttackType.MULTI_STEP_JAILBREAK,
        regex=re.compile(
            r"\b(?:Step\s+1\s*:[\s\S]{1,140}?Step\s+2\s*:|"
            r"phase\s+1\s*:[\s\S]{1,140}?phase\s+2\s*:|"
            r"in\s+this\s+(?:two|multi|fictional)-?(?:part|step|turn|stage)\s+(?:game|scenario|exercise)\b)",
            re.IGNORECASE,
        ),
        weight=0.85,
        description="Explicit multi-step staged jailbreak framing",
    ),
]

ALL_RULE_PATTERNS: list[RulePattern] = (
    OVERRIDE_PATTERNS
    + ROLE_PATTERNS
    + SECRET_PATTERNS
    + TOOL_PATTERNS
    + CREDENTIAL_PATTERNS
    + POISONING_PATTERNS
    + INDIRECT_PATTERNS
    + MULTI_STEP_PATTERNS
)

