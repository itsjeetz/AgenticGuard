# AgenticGuard: Master Feature & Component Inventory

This master inventory catalogs every subsystem, module, class, function, and REST API endpoint in the AgenticGuard repository. It serves as the authoritative verification checklist for documentation and technical evaluation.

---

## 1. Pipeline Architecture & Orchestration

| Component / Feature | File Path & Symbol | Purpose / Description |
|---|---|---|
| **Pipeline Coordinator** | `aegis/pipeline.py: FirewallPipeline` | End-to-end coordinator managing L1 Ingestion through L5 Neutralization, timing instrumentation, and fail-closed error handling. |
| **Pipeline Factory** | `aegis/pipeline.py: get_pipeline()` | Singleton accessor returning the global initialized pipeline instance. |
| **LRU Verdict Cache** | `aegis/pipeline.py: VerdictCache` | Thread-safe in-memory LRU cache (1,000 entries) keyed by SHA-256 payload hash, source, and options to achieve sub-millisecond repeat latency. |
| **Timing Instrumentation** | `aegis/pipeline.py: process()` | High-precision microsecond timers recording latency for L1, L2, L3a, L3b, L3c, L4, and L5 layers. |
| **Fail-Closed Resilience** | `aegis/resilience.py: fail_closed_verdict()` | Constructs an immutable, fail-closed `BLOCK` or `ESCALATE` verdict whenever an unhandled exception or critical layer error occurs. |
| **Input Limit Validator** | `aegis/resilience.py: validate_input_limits()` | Enforces byte-size and dimension boundaries before expensive ingestion or decoding steps. |
| **Degraded Mode Policy Adapter** | `aegis/resilience.py: adjust_policy_for_degraded_mode()` | Automatically tightens decision thresholds when upstream dependencies (OCR, LLM Judge) are offline. |

---

## 2. Ingestion Layer (L1) — 11 Carrier Adapters

| Carrier / Adapter | File Path & Symbol | Extraction Features & Hidden Text Handling |
|---|---|---|
| **Adapter Registry & Dispatcher** | `aegis/ingestion/registry.py: extract()` | Format sniffer and dispatcher routing content by MIME type, magic bytes, or file extension across all 11 sources. |
| **Base Adapter Contract** | `aegis/ingestion/base.py: BaseAdapter` | Abstract base class establishing segment extraction interfaces, size validation, and `OversizeContentError`. |
| **1. Plain Text Adapter** | `aegis/ingestion/text.py: TextAdapter` | UTF-8 decoding, character normalization, line and paragraph chunking. |
| **2. HTML Adapter** | `aegis/ingestion/html.py: HtmlAdapter` | BeautifulSoup parser extracting visible DOM text, HTML comments, off-screen CSS (`position:absolute; left:-9999px`), `display:none`, `visibility:hidden`, zero opacity, and tiny fonts ($\le 2\text{pt}$). |
| **3. Markdown Adapter** | `aegis/ingestion/markdown.py: MarkdownAdapter` | CommonMark parsing, HTML comments, hidden text, and detection of markdown image exfiltration payloads (`![...](url)`). |
| **4. PDF Document Adapter** | `aegis/ingestion/pdf.py: PdfAdapter` | Extracts text coordinates using `pdfplumber` with `pypdf` fallback. Identifies white-on-white text, font sizes $\le 2\text{pt}$, document metadata annotations, and corrupt/unreadable PDF fail-closed handling (`unreadable_pdf` flag). |
| **5. Word Document Adapter** | `aegis/ingestion/docx.py: DocxAdapter` | Direct inspection of WordprocessingML (`word/document.xml`, `word/comments.xml`, `docProps/core.xml`) extracting `<w:vanish/>`, hidden runs, reviewer comments, and white fonts. |
| **6. Email Adapter** | `aegis/ingestion/email.py: EmailAdapter` | Multi-part MIME parser handling `text/plain`, `text/html`, suspicious routing headers, and extracting nested attachments (PDF, DOCX, Images). |
| **7. API JSON Adapter** | `aegis/ingestion/api_json.py: ApiJsonAdapter` | Recursive JSON traversal with depth bounding (max depth 20), scanning keys, string values, and metadata dictionaries for injection payloads. |
| **8. Source Code Adapter** | `aegis/ingestion/code.py: CodeAdapter` | AST and regex-based tokenization extracting single-line comments, block comments, docstrings, string literals, and detecting raw shell execution strings. |
| **9. OCR Extracted Text** | `aegis/ingestion/ocr_text.py: OcrTextAdapter` | Text adapter specialized for pre-extracted OCR strings with noise cleaning. |
| **10. Image OCR Adapter** | `aegis/ingestion/image_ocr.py: ImageOcrAdapter` | PIL/Pillow image loading, dimension validation ($\le 20\text{ MP}$), and Tesseract OCR invocation extracting faint or low-contrast text. Degrades gracefully if Tesseract binary is unavailable. |
| **11. User Message Adapter** | `aegis/ingestion/text.py: TextAdapter` | Direct conversational prompt channel assigned high baseline trust (`Trust.USER`). |

---

## 3. Normalization & Deobfuscation Layer (L2)

| Component / Feature | File Path & Symbol | Purpose / Description |
|---|---|---|
| **Coordinate Mapping (`MappedText`)** | `aegis/normalize/mapped_text.py: MappedText` | Bidirectional character-level coordinate mapper tracking transformed/decoded characters back to exact raw offsets in the original document. |
| **Deobfuscation Engine** | `aegis/normalize/deobfuscate.py: deobfuscate()` | Breadth-first search (BFS) variant generator exploring normalization and decoding permutations up to depth $\le 3$ and $\le 12$ variants per segment. |
| **Unicode NFKC Cleaner** | `aegis/normalize/unicode_clean.py: clean_nfkc()` | Standardizes full-width characters, ligature glyphs, and compatibility forms. |
| **Zero-Width Character Stripper** | `aegis/normalize/unicode_clean.py: strip_zero_width()` | Removes zero-width spaces (ZWSP, ZWNJ, ZWJ), byte order marks (BOM), and directional override tags. |
| **Homoglyph Normalizer** | `aegis/normalize/unicode_clean.py: fold_homoglyphs()` | Folds Cyrillic, Greek, and Unicode lookalike confusables to standard Latin ASCII. |
| **Unicode Tag Decoder** | `aegis/normalize/unicode_clean.py: decode_unicode_tags()` | Strips and decodes hidden ASCII characters concealed within Unicode Plane 14 tag characters (U+E0000–U+E007F). |
| **Base64 Decoder** | `aegis/normalize/decoders.py: decode_base64()` | Regex detection and decoding of standard and URL-safe Base64 blobs. |
| **Hexadecimal Decoder** | `aegis/normalize/decoders.py: decode_hex()` | Converts hex sequences (`0x...`, `\x...`, continuous hex) into plaintext. |
| **ROT13 Decoder** | `aegis/normalize/decoders.py: decode_rot13()` | Caesar cipher rotation for alphabetic strings. |
| **Leetspeak Decoder** | `aegis/normalize/decoders.py: decode_leet()` | Maps numeric and symbolic character substitutions (`1337` $\rightarrow$ `leet`) back to letters. |
| **Despacing Decoder** | `aegis/normalize/decoders.py: decode_despace()` | Reconstructs words fragmented by intervening whitespace or punctuation (`i g n o r e` $\rightarrow$ `ignore`). |
| **Binary String Decoder** | `aegis/normalize/decoders.py: decode_binary()` | Converts 8-bit binary strings (`01101001...`) into ASCII characters. |
| **HTML Entities Decoder** | `aegis/normalize/decoders.py: decode_html_entities()` | Unescapes named and numerical XML/HTML character references (`&amp;`, `&#x26;`). |
| **URL Percent Decoder** | `aegis/normalize/decoders.py: decode_url()` | Decodes `%20`, `%2e%2e`, and multi-byte URL-encoded tokens. |
| **Text Reversal Decoder** | `aegis/normalize/decoders.py: decode_reverse()` | Evaluates reversed text strings attempting to bypass left-to-right tokenizers. |
| **OCR Typo Fixer** | `aegis/normalize/decoders.py: decode_ocr_fix()` | Corrects common OCR scanner misreadings (e.g. `l`/`1`/`|`, `0`/`O`). |

---

## 4. Detection Cascade Layer (L3)

| Detector / Module | File Path & Symbol | Mechanism & Coverage |
|---|---|---|
| **Cascade Coordinator** | `aegis/detection/cascade.py: DetectionCascade` | Executes L3a Rules, L3b Classifier, and L3c Judge in sequence with short-circuit capabilities and timing tracking. |
| **L3a Deterministic Rules** | `aegis/detection/rules.py: RuleDetector` | Matches compiled ReDoS-safe regex patterns against all generated variants, projecting matched spans back to original document coordinates. |
| **Pattern Families Repository** | `aegis/detection/patterns.py: ALL_RULE_PATTERNS` | Curated regex libraries covering all 9 attack categories, credential theft, exfiltration payloads, and system prompt overrides. |
| **Meta-Label Generators** | `aegis/detection/rules.py: detect()` | Synthesizes meta-labels: generates `ENCODED_INSTRUCTIONS` if an attack pattern originates from a non-original variant, and `INDIRECT_PROMPT_INJECTION` if found in an untrusted carrier. |
| **Instruction-in-Data Detector** | `aegis/detection/instruction_in_data.py: InstructionInDataDetector` | Distinguishes benign business requests from indirect prompt injections by requiring co-occurrence of imperative verbs + AI cues / exfiltration objects / hidden origin. |
| **L3c Hardened LLM Judge** | `aegis/detection/judge.py: LLMJudgeDetector` | Arbitrates borderline grey-zone scores ($0.35 \le \text{risk} \le 0.75$) using an isolated LLM evaluator with nonce-spotlighted XML formatting. |
| **Multi-Provider LLM Adapter** | `aegis/judge_llm.py: ProviderAgnosticJudge` | Unified OpenAI-compatible client supporting Gemini (`gemini-2.5-flash`), Groq (`llama-3.3-70b-versatile`), Mistral (`mistral-small-latest`), OpenRouter, and local Ollama (`llama3`). |
| **LLM Output Schema Validation** | `aegis/judge_llm.py: JudgeScores` | Strict Pydantic schema enforcing structured JSON output containing all 9 attack category scores clamped between $0.0$ and $1.0$ plus a one-line rationale. |
| **LLM Hash-Based Cache** | `aegis/judge_llm.py: _get_from_cache()` | SHA-256 prompt hash caching with 10-minute TTL to prevent redundant model calls. |
| **LLM Rate Limiter** | `aegis/judge_llm.py: _check_rate_limit()` | Sliding-window per-minute rate limiter (default 30 RPM) preventing upstream API exhaustion. |
| **LLM Key Scrubbing** | `aegis/judge_llm.py: evaluate_text()` | Automatically strips API secret keys from exception strings before logging or display. |
| **L3d Session Tracker** | `aegis/detection/session.py: SessionTracker` | Rolling memory buffer ($t-3 \dots t$) detecting staged multi-turn jailbreak attempts with exponential time decay ($0.70$). |

---

## 5. Fusion & Policy Layer (L4)

| Component / Feature | File Path & Symbol | Mechanism / Formula |
|---|---|---|
| **Multi-Layer Consensus Fusion** | `aegis/detection/fusion.py: fuse_findings()` | Evaluates `max(rules, judge, classifier)` per category. Applies a $+5\%$ consensus boost when $\ge 2$ layers independently flag a threat ($\ge 0.50$). Guarantees all 9 attack keys are returned. |
| **Combined Risk Scoring** | `aegis/detection/fusion.py: fuse_findings()` | Calculates risk via $\max(\text{weighted\_layer\_sum}, \max(\text{cat\_scores}), \text{noisy\_or})$. Adds $+0.15$ for hidden content and $+0.05$ for encoded instructions, scaled by source multiplier. |
| **Policy Configuration Engine** | `aegis/policy/config.py: PolicyConfig` | Pydantic configuration model managing decision thresholds (`allow_below`, `block_at`, `judge_low`, `judge_high`), source multipliers, timeouts, and limits. |
| **Policy Persistence & Reload** | `aegis/policy/config.py: save_policy()` | Atomically writes and hot-reloads configuration in `config/policy.yaml`. |
| **Decision Table Engine** | `aegis/policy/engine.py: PolicyEngine` | Evaluates fused risk against thresholds: produces `ALLOW` ($\text{risk} < 0.25$), `SANITIZE` ($0.25 \le \text{risk} < 0.85$ with localizable spans), `BLOCK` ($\text{risk} \ge 0.85$ or high-severity threat on untrusted source), or `ESCALATE`. |

---

## 6. Neutralizer Layer (L5)

| Component / Feature | File Path & Symbol | Sanitization Mechanism |
|---|---|---|
| **Span Merger** | `aegis/neutralize/redact.py: merge_spans()` | Combines overlapping or adjacent detected intervals and resolves category label precedence. |
| **Original Offset Redactor** | `aegis/neutralize/redact.py: redact_segment()` | Slices original text from right-to-left, replacing malicious spans with `[REDACTED:<ATTACK_TYPE>]` markers without disturbing file layout. |
| **Delimiter Neutralizer** | `aegis/neutralize/envelope.py: escape_delimiters()` | Neutralizes envelope breakout attempts by escaping `<<<` to `&lt;&lt;&lt;` and `>>>` to `&gt;&gt;&gt;`. |
| **Spotlighting Nonce Envelope** | `aegis/neutralize/envelope.py: wrap_in_nonce_envelope()` | Packages untrusted content within `<<<UNTRUSTED_DATA id="..." source="..." request_id="...">>>` delimiters paired with a strict system security notice. |

---

## 7. Runtime Blast Radius Guards (G1–G3)

| Guard Component | File Path & Symbol | Security Controls & Enforcement |
|---|---|---|
| **G1 Tool Execution Firewall** | `aegis/guard/tool_guard.py: ToolGuard` | Categorizes tools into 5 risk tiers (`READ_PUBLIC`, `READ_SENSITIVE`, `WRITE_LOCAL`, `EGRESS`, `EXEC_DESTRUCTIVE`). Restricts tainted agents from calling egress or destructive tools; validates SQL statements against allowlisted tables; requires human confirmation for destructive operations. |
| **G2 Egress Guard** | `aegis/guard/egress.py: EgressGuard` | Scans outbound agent text for canary tokens, credentials (AWS keys, JWTs, passwords, private keys), markdown image exfiltration links, and system prompt leakage via 4-gram Jaccard overlap. |
| **G3 Memory Guard** | `aegis/guard/memory.py: MemoryGuard` | Intercepts prospective writes to long-term memory, blocking persistent context poisoning and unauthorized administrative authority claims. |

---

## 8. Victim Agent Sandbox (ASR Demo)

| Sandbox Component | File Path & Symbol | Purpose / Implementation |
|---|---|---|
| **Victim Agent Simulator** | `agent/victim.py: VictimAgent` | Lightweight ReAct agent interacting with sandboxed mock tools and an in-memory SQLite database (`demo_data/`). |
| **Side-by-Side Comparison** | `agent/victim.py: run_scenario()` | Runs identical attack scenarios through both an Unprotected Agent and an AgenticGuard Protected Agent, measuring Attack Success Rate (ASR) reduction. |
| **Benchmark Scenarios (S1–S9)** | `agent/scenarios/__init__.py: SCENARIOS` | 9 real-world attack scenarios covering all 9 attack vectors (email exfil, white-text SQL drop, bash RCE, canary leakage, encoded base64, etc.). |
| **Benign Utility Scenarios (B1–B3)** | `agent/scenarios/__init__.py: SCENARIOS` | 3 legitimate business workflows (sustainability report, travel policy, invoice reconciliation) verifying zero utility degradation on clean data. |

---

## 9. Observability, Audit & Feedback

| Component / Feature | File Path & Symbol | Mechanism / Purpose |
|---|---|---|
| **Structured Audit Logger** | `aegis/observability/audit.py: AuditLogger` | Thread-safe recorder appending structured JSON audit entries for every transaction (timestamp, SHA-256, source, action, risk, latency, redacted excerpt). |
| **System Metrics Tracker** | `aegis/observability/metrics.py: MetricsTracker` | Tracks moving-window latency percentiles (p50, p95, p99), action distributions, total volume, and error rates. |
| **Feedback Review Queue** | `aegis/review_queue.py: add_feedback()` | Human-in-the-loop review queue for reporting false positives and false negatives, with approval/rejection lifecycle endpoints. |

---

## 10. Public Demo Mode Engine

| Feature / Control | File Path & Symbol | Behavior in Demo Mode (`DEMO_MODE=1`) |
|---|---|---|
| **Demo Mode Activation** | `server/demo_mode.py: is_demo_mode()` | Environment flag toggling public hosting restrictions. |
| **Per-IP Rate Limiting** | `server/demo_mode.py: DemoRateLimitMiddleware` | Enforces 30 requests/minute on general API endpoints and 5 requests/minute on strict endpoints (`/api/agent/run`, `/api/eval/run`). |
| **Daily LLM Call Quota** | `server/demo_mode.py: DemoQuotaManager` | Thread-safe daily counter capped at 200 LLM calls per UTC day, resetting at midnight UTC. |
| **Upload Size Ceiling** | `server/demo_mode.py` | Restricts file uploads to 2 MB (compared to 10 MB in development). |
| **Administrative Endpoint Lockdown** | `server/routes_ops.py` | Returns HTTP 403 Forbidden on policy updates, review approvals, model retraining, and live eval runs. |

---

## 11. REST API Endpoints (FastAPI)

| Method | Endpoint Path | Source Handler File | Purpose / Description |
|---|---|---|---|
| `GET` | `/api/health` | `server/routes_health.py` | Health status, OCR availability, active LLM judge provider, degraded mode flag, demo mode quotas. |
| `POST` | `/api/inspect` | `server/routes_inspect.py` | Full multi-layer inspection of JSON or multipart file uploads, returning detailed `Verdict` without content rewriting. |
| `POST` | `/api/neutralize` | `server/routes_inspect.py` | Inspects content and returns `Verdict` populated with `sanitized_text` and `envelope_text`. |
| `GET` | `/api/audit` | `server/routes_ops.py` | Retrieves structured audit trail records with optional filtering by action and source. |
| `GET` | `/api/metrics` | `server/routes_ops.py` | Aggregate performance statistics and p50/p95/p99 latency percentiles. |
| `POST` | `/api/feedback` | `server/routes_ops.py` | Submits false positive or false negative reports to the review queue. |
| `GET` | `/api/review-queue` | `server/routes_ops.py` | Lists items currently pending human triage. |
| `POST` | `/api/review-queue/{id}/approve` | `server/routes_ops.py` | Marks feedback items as approved (disabled in demo mode). |
| `POST` | `/api/review-queue/{id}/reject` | `server/routes_ops.py` | Rejects feedback items (disabled in demo mode). |
| `POST` | `/api/train` | `server/routes_ops.py` | Returns deprecation notice (ML classifier replaced by Provider-Agnostic LLM Judge). |
| `GET` | `/api/policy` | `server/routes_ops.py` | Reads active policy thresholds, multipliers, limits, and tool tiers. |
| `PUT` | `/api/policy` | `server/routes_ops.py` | Validates, updates, and hot-reloads runtime policy configuration. |
| `POST` | `/api/guard/tool-call` | `server/routes_ops.py` | Evaluates a prospective agent tool execution against risk tiers and taint state. |
| `POST` | `/api/guard/output` | `server/routes_ops.py` | Scans agent responses for credential leakage, canary tokens, and markdown image exfiltration. |
| `POST` | `/api/guard/memory-write` | `server/routes_ops.py` | Validates prospective memory entries to prevent persistent context poisoning. |
| `POST` | `/api/agent/run` | `server/routes_ops.py` | Executes victim agent test scenarios (S1–S9, B1–B3) in protected or unprotected mode. |
| `GET` | `/api/eval/latest` | `server/routes_ops.py` | Serves pre-computed empirical benchmark evaluation results (`reports/report.json`). |
| `GET` | `/api/eval/report-markdown` | `server/routes_ops.py` | Serves the full formatted markdown evaluation report (`reports/EVAL_REPORT.md`). |
| `POST` | `/api/eval/run` | `server/routes_ops.py` | Initiates a live benchmark evaluation run across the test split. |
| `POST` | `/api/redteam/run` | `server/routes_ops.py` | Generates adversarial red-team mutations across attack templates. |
| `GET` | `/` | `server/main.py` | Serves the dynamic SOC Dashboard HTML with cache-busting headers. |
| `GET` | `/index.html` | `server/main.py` | Equivalent root dashboard endpoint with no-store cache headers. |
| `GET` | `/static/*` | `server/main.py` | Serves static CSS, JS, and image assets via `DevStaticFiles`. |

---

## 12. Frontend SOC Dashboard (HTML/CSS/JS)

| Tab / UI Element | DOM ID / Selector | Purpose / Interactive Capabilities |
|---|---|---|
| **Theme Toggle Button** | `#themeToggleBtn` | Toggles between default light theme and dark theme, persisting preference in `localStorage`. |
| **Demo Mode Banner** | `#demoBanner` | Displays real-time rate limit thresholds and remaining daily LLM quota. |
| **Tab 1: Inspector Navigation** | `#navInspector`, `#tabInspector` | Real-time content scanner and surgical sanitizer workspace. |
| **Attack Preset Dropdown** | `#selectPreset` | Pre-loads sample payloads for all 9 attack categories and benign hard negatives. |
| **Carrier Source Selector** | `#selectSource` | Sets or auto-detects delivery format across all 11 supported carriers. |
| **Content Input & Dropzone** | `#textInput`, `#fileDropzone` | Direct text entry area paired with a drag-and-drop file uploader for binary documents. |
| **Action & Risk Badge** | `#actionBadge`, `#riskValue`, `#riskBarFill` | Visual verdict badge (`ALLOW`, `SANITIZE`, `BLOCK`, `ESCALATE`) and risk progress bar. |
| **9-Vector Attack Panel** | `#attackDetectionList` | Dedicated panel displaying confidence percentages for all 9 attack vectors, highlighting detected threats in `#A100FF` purple. |
| **Cascade Latency Grid** | `#layerPillsGrid`, `#totalPipelineTime` | Per-layer execution latency pills (L1 Ingestion through L5 Neutralization) and total duration. |
| **Three-Pane Output Display** | `#rawContentPane`, `#variantsContentPane`, `#sanitizedContentPane` | Side-by-side inspection: Raw Ingested Text, Deobfuscated L2 Variants with character offsets, and Sanitized L5 Output wrapped in Nonce Delimiters. |
| **Tab 2: Agent Sandbox** | `#navSandbox`, `#tabSandbox` | Side-by-side ReAct execution view comparing Unprotected Agent vs Protected Agent on scenarios S1–S9 and B1–B3. |
| **Tab 3: Benchmark & Claims** | `#navEval`, `#tabEval` | Empirical evaluation dashboard verifying pre-registered claims F3, D2, and D3, displaying per-category recall, per-source FPR, and ablation lifts. |
| **Tab 4: Audit & Feedback** | `#navAudit`, `#tabAudit` | Searchable transaction audit log, false positive/negative feedback submission card, and review queue triage. |
| **Tab 5: Policy Configuration** | `#navPolicy`, `#tabPolicy` | Interactive sliders for decision thresholds, source risk multiplier grid, tool risk tier definitions, and hot-reload save button. |
| **Footer Build & Status** | `#footerBuildLabel`, `#footerLlmJudge` | Displays current build commit version and active LLM Judge provider status. |
