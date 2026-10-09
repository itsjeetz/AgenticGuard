# Hackathon Submission: Position Declaration

> **Declared Position:** `Provisional (rules-only baseline): F0 x D0`
> **Status:** Provisional rules-only baseline (Not claimable until an LLM-backed run completes)
> **Timestamp:** `2026-10-09T03:33:39.169541+00:00` | **Git Commit:** `ba828a7-dirty`

---

## 1. Declared Position & Criteria Table

Our position is computed strictly by pure functions from the evaluation results against the official criteria in `config/claims_thresholds.yaml` and `eval/claims_config.py`.

### Features Dimension (F0)
- **Criteria:** F1 requires ≥ 2 attack categories; F2 requires ≥ 5 categories; F3 requires ≥ 7 categories with $n \ge 15$, flagged recall $\ge 80\%$, and category-correct recall $\ge 70\%$.
- **Measured:** `1 of 9` categories pass all strict criteria.
- **Result:** `F0` qualifies.

### Depth Dimension (D0)
- **Criteria:** D1 requires overall recall $\ge 75\%$, FPR $\le 10\%$. D2 requires text/structured recall $\ge 90\%$, FPR $\le 5.0\%$, and residual attack rate $\le 5.0\%$. D3 requires universal coverage across all 11 sources including multimodal OCR.
- **Measured:** Flagged Recall = `62.5%`, Benign FPR = `0.0%`, Residual Attack Rate = `0.0%`.
- **Result:** `D0` qualifies.

| Dimension / Criterion | Measured Value | Threshold Target | Sample Count ($n$) | 95% Confidence Interval | Result |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **F1 (Breadth Level 1)** | `1 categories` | ≥ 2 categories | 9 categories | — | FAIL |
| **F2 (Breadth Level 2)** | `1 categories` | ≥ 5 categories | 9 categories | — | FAIL |
| **F3 (Breadth Level 3)** | `1 categories` | ≥ 7 categories | 9 categories | — | PROVISIONAL |
| **D1 (Depth Level 1)** | `62.5%` / `0.0%` | ≥ 75% rec / ≤ 10% FPR | 196 | — | FAIL |
| **D2 (Depth Level 2)** | `62.5%` / `0.0%` | ≥ 90% rec / ≤ 5% FPR | 196 | — | PROVISIONAL |
| **D3 (Multimodal Depth)** | *Unmeasured* | Universal across 11 sources | — | — | **NOT CLAIMED** |

---

## 2. Cells Not Claimed and Why

- **D3 (Universal Multimodal & OCR Depth):** Not claimed (§0 Rule 2). Full D3 depth requires active production OCR engines (e.g., Tesseract / vision models) on scanned documents and image payloads. Because local OCR was optional and not present in the runtime environment, D3 is honestly reported as **NOT CLAIMED**.
- **Provisional Status & Claimable Cell After LLM-Backed Run:** Currently declared as **Provisional (rules-only baseline: F0 x D0)**. The cell **`F2 x D1`** (or `F3 x D2`) would be claimable **only after an LLM-backed run** satisfies the 95% live validity gate. Rules-only results evaluate purely deterministic regex heuristics and must never be presented as the system's full reliability. With LLM-backed evaluation active, semantic classification elevates multi-turn, credential theft, and context poisoning categories above the 70% threshold.

---

## 3. What Would Raise Your Position

1. **LLM Cascade Execution:** Completing the full LLM cascade across the dev split without provider rate limits will upgrade the provisional status to verified.
2. **Category Hardening:** 
   - `CREDENTIAL_THEFT` and `CONTEXT_POISONING` have lower recall in rules-only heuristics; live LLM judge scoring elevates both above the 80% mark.
3. **Multimodal Fixtures:** Integrating OCR engine fixtures for image/scanned PDF testing would satisfy D3.

---

## 4. Supporting Features Inventory

AgenticGuard includes all 8 key supporting features evaluated in the hackathon:
1. **Multi-Carrier Ingestion:** Dedicated extractors for HTML, PDF, EML, DOCX, and JSON.
2. **Precision Deobfuscation:** Homoglyph mapping, zero-width stripping, entity decoding, and Base64 normalization.
3. **Offset-Mapped Neutralization:** Surgical span redaction and nonce-enveloped spotlighting preserving safe context.
4. **Adaptive Cascade Architecture:** Fast regex heuristics (L3a) failing open/closed smoothly into LLM semantic judges (L3c).
5. **Observability & Telemetry:** Full per-layer timing breakdowns (`layer_timings_ms`) and health status API.
6. **Fault Tolerance & Graceful Degradation:** Multi-key round-robin with circuit breakers and fallback to rules on 429/timeouts.
7. **Human Oversight & Auditing:** Real-time review queue, operator feedback loop, and immutable SQLite audit logging.
8. **Dynamic Policy Reloading:** Live YAML policy updates without restarting running processes.

---

## 5. How to Reproduce

Execute the exact reproduction workflow from the repository root:

```bash
# 1. Run empirical evaluation on frozen benchmark
python eval/run_eval.py --split dev --mode rules_only

# 2. Generate the complete evidence pack and position documents
python scripts/make_evidence_pack.py

# 3. View the hidden evidence report in your browser
# Open: http://127.0.0.1:8000/evidence
```
