# CHANGELOG: AgenticGuard Upgrade

This changelog records the architectural and user-interface modifications transitioning from AegisAgent to **AgenticGuard**, integrating Google Gemini API, and implementing the 9-vector attack detection panel and light/purple theme.

---

## [2.1.0] - 2026-10-02

### 1. Product Renaming to AgenticGuard
- Renamed all user-facing instances of "AegisAgent" / "AEGISAGENT" to **"AgenticGuard"** across:
  - Header logo text (`AGENTICGUARD`)
  - HTML `<title>` (`AgenticGuard - Prompt Injection Firewall`)
  - Meta tags, footers, and dashboard labels
  - FastAPI application metadata (`server/main.py`)
  - Documentation files (`README.md`, `README_SPACE.md`, `docs/DEMO_SCRIPT.md`, `docs/ARCHITECTURE.md`)
  - Agent and Egress block messages (`[BLOCKED BY AGENTICGUARD: ...]`)
- Retained canonical subtitle: `"PROMPT INJECTION FIREWALL • DEFENSE-IN-DEPTH"`.

### 2. Header Status Strip Modernization
- Removed the top status strip pills (OCR, ML Classifier, LLM Judge, Victim Agent, and manual refresh button) from `static/index.html`.
- Removed corresponding status-polling JavaScript and legacy CSS rules (`.status-bar`, `.status-chip`, `.btn-refresh-health`).
- Retained backend `/api/health` endpoints intact.
- Retained the **PUBLIC DEMO MODE** notification banner (`#demoBanner`) with rate limits and quota tracking.

### 3. Per-Attack-Type Detection Panel (9 Vectors)
- Replaced the previous Category Scores block with a dedicated **Attack Type Detection** panel on the homepage/Inspector tab.
- Evaluates input against **ALL 9 supported attack types**:
  1. `INSTRUCTION_OVERRIDE` (Instruction Override)
  2. `ROLE_CHANGE` (Role Change)
  3. `SECRET_EXTRACTION` (Secret Extraction)
  4. `TOOL_ABUSE` (Tool Abuse)
  5. `CREDENTIAL_THEFT` (Credential Theft)
  6. `CONTEXT_POISONING` (Context Poisoning)
  7. `MULTI_STEP_JAILBREAK` (Multi-Step Jailbreak)
  8. `ENCODED_INSTRUCTIONS` (Encoded Instructions)
  9. `INDIRECT_PROMPT_INJECTION` (Indirect Prompt Injection)
- **Visual Display**:
  - Fixed canonical order in Standby state (all at 0%).
  - Detected attack types (confidence above threshold) are highlighted in purple accent (`#A100FF`), sorted to the top, and labelled `"Detected"`.
  - Undetected types display rounded percentage (0% below 5% noise floor) with muted styling and labelled `"Not detected"`.
  - Includes Standby, Loading, and Error states.
- **Backend Fusion**:
  - `aegis/detection/fusion.py` guarantees all 9 keys are returned in `category_scores`.
  - Fuses multi-layer confidence using maximum active layer score (`max(rules, classifier, judge)`) with a multi-layer consensus boost (+5%) when $\ge 2$ layers detect threat $\ge 0.50$.
  - Added `detected: list[AttackType]` and `llm_judge_status` fields to `Verdict`.

### 4. Google Gemini API Integration (`google-genai`)
- Integrated Google's official `google-genai` Python SDK with `python-dotenv` for environment management.
- Configured via environment variables:
  - `GEMINI_API_KEY`: Loaded from `.env` (gitignored, template provided in `.env.example`).
  - `GEMINI_MODEL`: Defaulting to `gemini-2.5-flash`.
- **L3c Judge (`aegis/detection/judge.py`)**:
  - Nonce-spotlighted prompt treating candidate text strictly as hostile data.
  - Pydantic schema validation (`AttackCategoryScores`, `JudgeOutputSchema`) utilizing structured JSON output mode.
  - Circuit breaker, timeout (8s), and exponential backoff retry logic.
  - Graceful degraded fallback: when `GEMINI_API_KEY` is missing or fails, falls back to Rules + ML Classifier and sets `llm_judge_status="offline_fallback"`.
- **Victim Agent (`agent/victim.py`)**:
  - Integrated Gemini model for agent intent simulation.
  - Retained deterministic sandboxed tools and mock fallback when offline.
- Created `scripts/check_gemini.py` for API connectivity verification.

### 5. Light Default Theme with Purple Accent & Dark Mode Toggle
- **Default Theme (Light)**:
  - Off-white background (`#F5F4F7`)
  - Crisp cards (`#FFFFFF`) with subtle borders (`#E2DEE9`)
  - Dark grey typography (`#2D283E`, `#171322`) for WCAG AA contrast
  - Primary accent purple `rgb(161, 0, 255)` (`#A100FF`) for buttons, active tab underlines, progress bars, and badges.
- **Dark Mode**:
  - Deep dark navy palette with the same `#A100FF` purple accent.
- **Persistent Toggle**:
  - Sun/Moon toggle button in top-right header (`#themeToggleBtn`).
  - Defaults to light mode on first visit (independent of OS preference).
  - Choice persisted in `localStorage` under `agenticguard_theme` and applied synchronously on page load to prevent theme flash.

---

## Modified Files Summary

| File | Changes |
|---|---|
| `requirements.txt` | Added `google-genai>=2.0.0` and `python-dotenv>=1.0.0` |
| `.env.example` | Added `GEMINI_API_KEY` and `GEMINI_MODEL=gemini-2.5-flash` |
| `.gitignore` | Added `.env` exclusion |
| `aegis/models.py` | Renamed to AgenticGuard; added `detected`, `llm_judge_status`, and Gemini health fields |
| `aegis/detection/fusion.py` | Guaranteed all 9 attack keys in `category_scores`; implemented consensus fusion |
| `aegis/detection/judge.py` | Gemini client, structured JSON output, retry backoff, circuit breaker |
| `aegis/detection/cascade.py` | Propagated `llm_judge_status` |
| `aegis/pipeline.py` | Attached `detected` categories and `llm_judge_status` to `Verdict` |
| `aegis/policy/config.py` | Added `category_thresholds` field to `ThresholdsConfig` |
| `aegis/resilience.py` | Initialized 9 attack keys in fail-closed verdict |
| `agent/victim.py` | Gemini victim agent integration; renamed block strings |
| `aegis/guard/egress.py` | Renamed block message to AgenticGuard |
| `server/main.py` | Added `load_dotenv()`; renamed FastAPI app to AgenticGuard |
| `server/routes_health.py` | Added Gemini capability reporting |
| `server/routes_inspect.py` | Updated inspection logs to AgenticGuard |
| `scripts/check_gemini.py` | Created Gemini connectivity check script |
| `static/index.html` | AgenticGuard branding; removed status pills; added theme toggle and 9-vector panel |
| `static/style.css` | Light default theme with `#A100FF` purple accent; dark mode; toggle button; attack panel |
| `static/app.js` | Theme switcher with localStorage; 9-vector panel rendering; removed status polling |
| `README.md` | Comprehensive setup, Gemini instructions, AgenticGuard branding |
| `README_SPACE.md` | Updated branding and clone URLs |
| `docs/DEMO_SCRIPT.md` | Updated presentation steps, theme, and 9-vector panel walkthrough |
| `docs/ARCHITECTURE.md` | Updated technical specification to AgenticGuard |
| `tests/test_agent_scenarios.py` | Updated assertions to support AgenticGuard block string |
| `CHANGELOG.md` | Documented all modifications and deliverables |
