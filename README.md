# AgenticGuard: Prompt Injection Firewall

> **ET AI Hackathon — Problem 2: Agentic Cybersecurity**  
> PROMPT INJECTION FIREWALL • DEFENSE-IN-DEPTH  
> An industrial-grade Prompt Injection Firewall for AI Agents featuring format-aware ingestion, character-mapped span sanitization, spotlighting nonce envelopes, AI cascade classification with Google Gemini L3c Judge & sandboxed victim agent, and runtime tool/egress guards.

[![Tests](https://img.shields.io/badge/pytest-passing-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)]()
[![Defense Depth](https://img.shields.io/badge/Grid%20Position-F3%20%2F%20D2-purple.svg)]()
[![ASR Reduction](https://img.shields.io/badge/Agent%20ASR-88.9%25%20%E2%86%92%200.0%25-success.svg)]()

---

## Key Features

1. **Format-Aware Ingestion Across 11 Sources (L1):** Ingests raw text, HTML, Markdown, PDF, DOCX, Email (.eml), API JSON, OCR text, Source Code, and Images. Extracts hidden text (white font, `<w:vanish/>`, off-screen CSS, metadata, comments).
2. **Character-Mapped Deobfuscation (L2):** `MappedText` tracks character-level coordinate transformations across decoders (Base64, Hex, ROT13, Leet, Spaced, Homoglyphs, Zero-Width, Unicode tags) back to exact raw file offsets.
3. **Multi-Layer Detection Cascade (L3):**
   - **L3a Rules + Instruction-in-Data:** 9 attack categories with ReDoS-safe patterns, distinguishing benign business language from imperative injections.
   - **L3b ML Classifier:** Sliding-window TF-IDF char n-grams + Logistic Regression providing measured recall lift.
   - **L3c Hardened LLM Judge:** Google Gemini (`gemini-2.5-flash`) structured JSON output validation evaluating all 9 vectors, with circuit breaker and offline fallback.
   - **L3d Session Tracker:** Stateful detection of multi-turn staged jailbreaks.
4. **9-Vector Attack Type Detection Panel:** Real-time homepage inspector evaluating inputs across all 9 canonical vectors (`INSTRUCTION_OVERRIDE`, `ROLE_CHANGE`, `SECRET_EXTRACTION`, `TOOL_ABUSE`, `CREDENTIAL_THEFT`, `CONTEXT_POISONING`, `MULTI_STEP_JAILBREAK`, `ENCODED_INSTRUCTIONS`, `INDIRECT_PROMPT_INJECTION`) with detection percentages, progress bars, and threat sorting.
5. **Spotlighting Neutralizer (L5):** Redacts identified hostile spans on the **original text** without breaking file structure, packaging safe content in cryptographically unique nonce envelopes (`<<<UNTRUSTED_CONTENT id=...>>>`).
6. **Runtime Blast Radius Guards (G1–G3):**
   - **G1 Tool Guard:** 5 risk tiers, taint enforcement, SQL validation, shell blocking.
   - **G2 Egress Guard:** Canary token exfiltration detection, credential masking, markdown image exfiltration blocking.
   - **G3 Memory Guard:** Prevents persistent context poisoning and authority spoofing.
7. **SOC Dashboard & Operations:** Light-default theme with `#A100FF` purple accent and persistent dark mode toggle, covering all 5 tabs: Inspector, Agent Sandbox, Benchmark Evaluation, Audit Trail, and Policy Config.
8. **Adversarial Red-Team Stress Corpus:** 1,050 curated test cases (`data/redteam_corpus.jsonl`) verifying 0 false positives on educational/interrogative framing and zero regressions across tool abuse vectors.

---

## Quick Start

### 1. Installation
```bash
# Clone repository
git clone https://github.com/itsjeetz/aegisagent.git
cd aegisagent

# Install dependencies (including google-genai and python-dotenv)
pip install -r requirements.txt
```

### 2. Configure Environment (.env)
```bash
# Copy example environment configuration
cp .env.example .env
```
Open `.env` in your text editor and add your Google Gemini API key:
```ini
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```
*(If no API key is provided, AgenticGuard degrades gracefully to offline rules + classifier mode and mock victim agent without crashing.)*

Verify Gemini API connectivity:
```bash
python scripts/check_gemini.py
```

### 3. Run the Firewall & Dashboard
```bash
uvicorn server.main:app --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser to access the AgenticGuard SOC Dashboard.
- Default theme is light mode with purple accent `#A100FF`.
- Toggle between light and dark themes using the sun/moon button in the top-right header (persisted in `localStorage`).

### 4. Run Automated Tests
```bash
python -m pytest
```
*Runs unit and integration tests across the ingestion adapters, normalization, rules, classifier, judge, guards, victim agent, ops, and dashboard endpoints.*

### 5. Run Benchmark Evaluation & Verify Claims
```bash
# Run evaluation on frozen test split
python -m eval.run_eval --split test

# Generate pre-registered claims verification document
python -m eval.claims
```

### 6. Run Adversarial Red-Team Generator & Benchmark
```bash
python -m eval.redteam --variants 3 --out data/redteam_bypasses.jsonl
python -m unittest tests/test_firewall.py
```

---

## Integrate with Your Agent

Protect any LLM agent pipeline in three lines of Python:

```python
from aegis.pipeline import get_pipeline
from aegis.models import InputSource

firewall = get_pipeline()

# Intercept and neutralize untrusted input (e.g. from an inbound email or web page)
verdict = firewall.process(untrusted_content, source=InputSource.EMAIL)

if verdict.action in ("ALLOW", "SANITIZE"):
    # Pass safe, spotlighted text to your LLM agent
    safe_prompt = verdict.envelope_text or verdict.sanitized_text
    response = agent.run(safe_prompt)
else:
    # Safely reject or escalate blocked attacks
    log_security_alert(verdict.request_id, verdict.category_scores, verdict.detected)
```

---

## Project Structure

```
Codebase/
├── aegis/
│   ├── ingestion/       # L1: 11 format adapters (pdf, docx, html, email, etc.)
│   ├── normalize/       # L2: MappedText coordinate tracker & decoders
│   ├── detection/       # L3: Rules cascade, ML classifier, Gemini LLM judge, session tracker
│   ├── policy/          # L4: Multi-layer fusion & policy engine
│   ├── neutralize/      # L5: Offset span redaction & nonce spotlighting envelope
│   ├── guard/           # G1-G3: Tool guard, egress guard, memory guard
│   ├── observability/   # Audit logger & continuous metrics tracker
│   ├── resilience.py    # Timeouts, circuit breakers, and degraded fail-closed mode
│   └── train.py         # Human-in-the-loop review queue and model retraining
├── aegis_firewall/      # Standalone zero-dependency firewall implementation
├── agent/
│   ├── scenarios/       # Scenarios S1-S9 (attacks) and B1-B3 (benign tasks)
│   └── victim.py        # ReAct victim agent (Gemini with sandboxed fallback tools)
├── eval/
│   ├── fixture_factory.py # Bit-exact reproducible attack carrier synthesis
│   ├── build_dataset.py   # Dataset compiler for dev and held-out test splits
│   ├── run_eval.py        # Benchmark evaluation CLI runner
│   ├── claims.py          # Pre-registered claims verification generator
│   └── redteam.py         # Automated adversarial evasion generator
├── scripts/
│   └── check_gemini.py  # Gemini API connectivity verification script
├── server/
│   ├── main.py          # FastAPI application entrypoint (AgenticGuard)
│   ├── routes_health.py # /api/health capabilities status & Gemini reporting
│   ├── routes_inspect.py# /api/inspect and /api/neutralize (9 attack scores)
│   └── routes_ops.py    # /api/audit, /api/metrics, /api/policy, /api/agent/run
├── static/              # SOC Single-Page Application (HTML/CSS/JS)
│   ├── index.html       # Light default + dark toggle + 9-vector attack panel
│   ├── style.css        # CSS custom properties (:root light & [data-theme="dark"])
│   └── app.js           # Theme persistence, 9-vector rendering, demo quota
├── docs/
│   ├── ARCHITECTURE.md  # Detailed technical architecture & layer specifications
│   ├── CLAIMS.md        # Empirically measured claims generated by eval/claims.py
│   ├── DECISIONS.md     # Architecture Decision Records (DEC-001 to DEC-012)
│   ├── DEMO_SCRIPT.md   # Step-by-step presentation demonstration guide
│   └── EVAL_REPORT.md   # Latest benchmark evaluation report
├── data/
│   ├── redteam_corpus.jsonl # 1,050 adversarial and benign test cases
│   ├── evaluation_results.json # Full benchmark results
│   ├── test.frozen.sha256 # Frozen test split integrity verification hash
│   ├── models/            # Trained ML classifier models
│   └── audit.sqlite       # Local SQLite audit log and review queue
└── tests/               # Unit and integration test suites
```

---

## Known Limitations (§15)

In compliance with Section 0 Rule 2 and Section 15 of the implementation plan:
- **No Silver Bullet:** Prompt injection is fundamentally non-lexical. Novel semantic paraphrases may bypass text pattern filters; this is why runtime ToolGuard and EgressGuard exist as defense-in-depth.
- **OCR Constraints:** Stylized typography, extreme noise, or steganographic instructions embedded in images may be missed by OCR preprocessing.
- **Judge Target Risk:** The LLM judge is itself an LLM; while protected by nonce spotlighting and strict JSON schema validation, it is kept exclusively in the grey zone to minimize attack surface and latency.
- **Environment Parity:** If host dependencies (Tesseract or Gemini API key) are absent, AgenticGuard degrades gracefully to offline modes without crashing or faking benchmarks.
