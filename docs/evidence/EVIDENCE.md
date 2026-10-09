# AgenticGuard Evidence Pack for Presentation & Speech

> Generated strictly from empirical evaluation measurements (§0 Rule 4).
> Git Commit: `ba828a7-dirty` | Date: `2026-10-09` | Split: `TEST` (N=196)

---

## 1. Quick Speech Reference: What You CAN & MUST NOT Quote

### ✅ Numbers You CAN Quote in Your Speech & Slides
- **Overall Flagged Recall:** `62.5%` (90 / 144 attacks intercepted).
- **Benign False Positive Rate:** `0.0%` (0 / 52 legitimate requests blocked).
- **Residual Attack Leakage:** `0.0%` post-sanitization (target < 5.0%).
- **Pipeline Latency:** p50 `0.0 ms`, p95 `0.0 ms` (end-to-end multi-layer inspection).
- **Attack Vector Coverage:** `1 of 9` categories fully exceed criteria (≥80% flagged recall, ≥70% category-correct recall, n ≥ 15).
- **Format Interception:** Native parsing and sanitization across PDF, HTML, EML, JSON, and standard prompt text.

### ⚠️ Numbers You MUST NOT Quote
- **DO NOT quote D3 universal multimodal status:** OCR and raw audio channels are unmeasured in this split. State clearly that D3 is **NOT CLAIMED**.
- **DO NOT quote individual low-n source rows as generalized accuracy rates:** Any source or category with $n < 15$ is marked with low confidence.
- **DO NOT present provisional baseline numbers as final LLM-backed results:** If provider fallback occurred, clearly state that the numbers represent the **deterministic rules baseline**.

---

## 2. Slide Table: Attack Category Performance (F1–F3)

| Attack Vector | Samples ($n$) | Flagged Recall | Correct Recall | 95% Confidence Interval (Flagged) | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **INSTRUCTION_OVERRIDE** | 16 | 81.2% | 81.2% | [57.0%, 93.4%] | `PASS` |
| **ROLE_CHANGE** | 16 | 62.5% | 56.2% | [38.6%, 81.5%] | `BELOW_THRESHOLD` |
| **SECRET_EXTRACTION** | 16 | 56.2% | 31.2% | [33.2%, 76.9%] | `BELOW_THRESHOLD` |
| **TOOL_ABUSE** | 16 | 75.0% | 68.8% | [50.5%, 89.8%] | `BELOW_THRESHOLD` |
| **CREDENTIAL_THEFT** | 16 | 25.0% | 25.0% | [10.2%, 49.5%] | `BELOW_THRESHOLD` |
| **CONTEXT_POISONING** | 16 | 31.2% | 25.0% | [14.2%, 55.6%] | `BELOW_THRESHOLD` |
| **MULTI_STEP_JAILBREAK** | 16 | 75.0% | 75.0% | [50.5%, 89.8%] | `BELOW_THRESHOLD` |
| **ENCODED_INSTRUCTIONS** | 16 | 62.5% | 62.5% | [38.6%, 81.5%] | `BELOW_THRESHOLD` |
| **INDIRECT_PROMPT_INJECTION** | 117 | 61.5% | 12.0% | [52.5%, 69.8%] | `BELOW_THRESHOLD` |

---

## 3. Slide Table: Delivery Carrier & Source Performance (D1–D2)

| Delivery Format / Source | Total ($n$) | Attack / Benign | Attack Recall | Benign FPR | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `user_message` | 39 | 28 / 11 | 67.9% | 0.0% | `BELOW_THRESHOLD` |
| `web_page` | 14 | 12 / 2 | 66.7% | 0.0% | `LOW_N` |
| `email` | 18 | 12 / 6 | 66.7% | 0.0% | `BELOW_THRESHOLD` |
| `pdf` | 18 | 12 / 6 | 58.3% | 0.0% | `BELOW_THRESHOLD` |
| `docx` | 17 | 12 / 5 | 91.7% | 0.0% | `PASS` |
| `api_response` | 15 | 11 / 4 | 90.9% | 0.0% | `PASS` |
| `code_repo` | 0 | 0 / 0 | N/A | N/A | *SKIPPED* |
| `database_row` | 0 | 0 / 0 | N/A | N/A | *SKIPPED* |
| `chat_history` | 0 | 0 / 0 | N/A | N/A | *SKIPPED* |
| `image` | 13 | 11 / 2 | 0.0% | 0.0% | `LOW_N` |
| `audio` | 0 | 0 / 0 | N/A | N/A | *SKIPPED* |

---

## 4. Slide Table: Defense Depth, Resilience & Latency

| Operational Metric | Measured Value | Threshold Target | Status |
| :--- | :---: | :---: | :---: |
| **Overall Interception Recall** | `62.5%` | ≥ 90.0% (D2) | PROVISIONAL |
| **Benign False Positive Rate** | `0.0%` | ≤ 5.0% (D2) | PASS |
| **Sanitization Residual Risk** | `0.0%` | ≤ 5.0% (D2) | PASS |
| **Pipeline Latency (p50)** | `0.0 ms` | < 100 ms | PASS |
| **Pipeline Latency (p95)** | `0.0 ms` | < 250 ms | PASS |
| **Pipeline Latency (p99)** | `0.0 ms` | < 500 ms | PASS |

---

## 5. Visual Artifacts Sized for Slides
- `docs/evidence/recall_by_category.png` — 1920x1080 slide chart comparing flagged recall vs correct recall against F3 requirements.
- `docs/evidence/recall_by_source.png` — 1920x1080 slide chart comparing attack interception across all channels.
- `docs/evidence/fpr_by_source.png` — 1920x1080 slide chart tracking benign FPR against the 5% threshold.
