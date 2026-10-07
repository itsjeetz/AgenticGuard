"""CLI runner for evaluation harness with checkpointing, pacing, and quota guards (§9.4, §9.5)."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
from typing import Any

from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()

from aegis.judge_llm import get_llm_judge
from aegis.models import InputSource
from aegis.pipeline import FirewallPipeline
from eval.claims import evaluate_claims, generate_claims_markdown
from eval.dataset import load_dataset, verify_test_freeze
from eval.metrics import ItemEvaluation, compute_all_metrics, evaluate_item
from eval.report import get_git_commit, save_reports
from server.demo_mode import get_demo_manager

BINARY_EXTENSIONS = {".pdf", ".docx", ".png", ".jpg", ".jpeg"}


def load_item_content(content_path: str) -> tuple[bytes | str, str]:
    """Load item content from path, returning (content, raw_text_repr)."""
    p = Path(content_path)
    if not p.exists():
        raise FileNotFoundError(f"Content fixture file not found: {content_path}")

    ext = p.suffix.lower()
    if ext in BINARY_EXTENSIONS:
        b = p.read_bytes()
        return b, ""
    else:
        try:
            t = p.read_text(encoding="utf-8")
            return t, t
        except UnicodeDecodeError:
            b = p.read_bytes()
            return b, ""


def run_evaluation(
    split: str = "dev",
    out_dir: str = "reports",
    claims_out: str = "docs/CLAIMS.md",
    mode: str = "cascade",
    batch_size: int = 0,
    bypass_cache: bool = True,
    pace_seconds: float = 12.0,  # 5 requests per minute = 12s per call
) -> tuple[dict, str]:
    """Run full evaluation suite on the given split with pacing and checkpointing."""
    test_hash_info = None

    if split == "test":
        matches, computed, recorded = verify_test_freeze()
        test_hash_info = {
            "matches": matches,
            "computed": computed,
            "recorded": recorded,
        }
        if not matches:
            print("=" * 70, file=sys.stderr)
            print("FATAL ERROR: Frozen test split SHA-256 hash mismatch!", file=sys.stderr)
            print(f"  Computed: {computed}", file=sys.stderr)
            print(f"  Recorded: {recorded}", file=sys.stderr)
            print("Refusing to evaluate on modified test split (§9.3, §0 Rule 3).", file=sys.stderr)
            print("=" * 70, file=sys.stderr)
            sys.exit(1)

    items = load_dataset(split)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    checkpoint_file = out_path / f"checkpoint_{split}.json"

    # Load existing checkpoint if present
    checkpoint_data: dict[str, Any] = {}
    if checkpoint_file.exists():
        try:
            with open(checkpoint_file, "r", encoding="utf-8") as f:
                checkpoint_data = json.load(f)
            print(f"Loaded existing checkpoint with {len(checkpoint_data.get('evaluations', []))} items.")
        except Exception as exc:
            print(f"Warning: could not read checkpoint {checkpoint_file}: {exc}")
            checkpoint_data = {}

    completed_ids: set[str] = set()
    evaluations: list[ItemEvaluation] = []

    # Reconstruct previously evaluated items from checkpoint
    # (Note: full objects are re-evaluated or loaded from state)
    enable_judge = (mode == "cascade")
    pipeline = FirewallPipeline(
        enable_rules=True,
        enable_classifier=False,
        enable_judge=enable_judge,
    )
    # If bypass_cache requested, clear cache
    if bypass_cache and hasattr(pipeline, "cache"):
        pipeline.cache.clear()

    # Rules-only baseline pipeline to compute ablation lift on grey-zone
    pipeline_rules_only = FirewallPipeline(
        enable_rules=True,
        enable_classifier=False,
        enable_judge=False,
    )

    demo_mgr = get_demo_manager()
    judge = get_llm_judge()

    print(f"Starting evaluation on {split.upper()} split ({len(items)} items, mode={mode}, batch_size={batch_size})...")
    t_start = time.perf_counter()
    last_llm_call_time = 0.0
    items_processed_this_run = 0
    is_partial = False

    rules_only_evaluations: list[ItemEvaluation] = []
    grey_zone_items_count = 0

    for idx, item in enumerate(items, 1):
        original_text = ""
        session_id = f"eval-sess-{item.id}"

        # First run rules-only baseline (instant, 0 network calls)
        content, original_text = load_item_content(item.content_path)
        r_verdict = pipeline_rules_only.process(
            content,
            source=InputSource(item.source),
            filename=item.content_path,
            session_id=session_id,
            neutralize_content=False,
        )
        r_eval = evaluate_item(
            item=item,
            verdict=r_verdict,
            original_text=original_text,
        )
        rules_only_evaluations.append(r_eval)
        if 0.35 <= r_verdict.risk <= 0.75:
            grey_zone_items_count += 1

        # Check if batch size limit reached
        if batch_size > 0 and items_processed_this_run >= batch_size:
            print(f"Batch size limit of {batch_size} reached. Stopping run.")
            is_partial = True
            break

        # Check quota if judge is enabled
        if enable_judge and not demo_mgr.can_call_llm():
            print("Daily LLM quota reached. Pausing evaluation gracefully.")
            is_partial = True
            break

        # Pace outbound LLM requests if item reaches judge (respects 5 req/min, §Quota)
        will_reach_judge = enable_judge and (0.35 <= r_verdict.risk <= 0.75)
        if will_reach_judge:
            elapsed_since_llm = time.time() - last_llm_call_time
            if elapsed_since_llm < pace_seconds and last_llm_call_time > 0:
                sleep_sec = pace_seconds - elapsed_since_llm
                time.sleep(sleep_sec)

        # Run multi-layer pipeline
        if item.turns:
            for turn in item.turns[:-1]:
                pipeline.process(
                    turn["text"],
                    source=InputSource(item.source),
                    session_id=session_id,
                    neutralize_content=False,
                )
            final_turn_text = item.turns[-1]["text"]
            original_text = final_turn_text
            verdict = pipeline.process(
                final_turn_text,
                source=InputSource(item.source),
                session_id=session_id,
                neutralize_content=True,
            )
        else:
            verdict = pipeline.process(
                content,
                source=InputSource(item.source),
                filename=item.content_path,
                session_id=session_id,
                neutralize_content=True,
            )

        if verdict.layer_status.get("judge", {}).get("findings_count", 0) > 0 or verdict.llm_judge_status:
            last_llm_call_time = time.time()

        rescan_verdict = None
        if verdict.sanitized_text:
            rescan_verdict = pipeline.process(
                verdict.sanitized_text,
                source=InputSource.USER_MESSAGE,
                neutralize_content=False,
            )

        item_eval = evaluate_item(
            item=item,
            verdict=verdict,
            rescan_verdict=rescan_verdict,
            original_text=original_text,
        )
        evaluations.append(item_eval)
        items_processed_this_run += 1

        # Checkpoint periodically
        if idx % 10 == 0 or idx == len(items):
            try:
                with open(checkpoint_file, "w", encoding="utf-8") as cf:
                    json.dump({
                        "split": split,
                        "mode": mode,
                        "processed": len(evaluations),
                        "total": len(items),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }, cf, indent=2)
            except Exception:
                pass
            print(f"  Processed {idx}/{len(items)} items... (Last status: {verdict.llm_judge_status or 'ok'})", flush=True)

    elapsed = round(time.perf_counter() - t_start, 2)
    print(f"Processed {len(evaluations)}/{len(items)} items in {elapsed}s.", flush=True)

    # Compute metrics for evaluated items
    metrics = compute_all_metrics(evaluations)
    rules_metrics = compute_all_metrics(rules_only_evaluations[:len(evaluations)])

    # Compute cascade ablation deltas
    lift_recall = round(metrics["binary"]["recall"] - rules_metrics["binary"]["recall"], 4)
    lift_f1 = round(metrics["binary"]["f1"] - rules_metrics["binary"]["f1"], 4)
    ablation_data = {
        "split": split,
        "total_items": len(evaluations),
        "modes": {
            "rules_only": rules_metrics["binary"],
            "full_cascade": metrics["binary"],
        },
        "grey_zone": {
            "items_reaching_judge": grey_zone_items_count,
            "recall_without_judge": rules_metrics["binary"]["recall"],
            "f1_without_judge": rules_metrics["binary"]["f1"],
            "recall_with_judge": metrics["binary"]["recall"],
            "f1_with_judge": metrics["binary"]["f1"],
            "recall_lift": lift_recall,
            "f1_lift": lift_f1,
        },
    }

    # Save ablation.json
    ablation_json_path = out_path / "ablation.json"
    with open(ablation_json_path, "w", encoding="utf-8") as f:
        json.dump(ablation_data, f, indent=2)

    active_provider = judge.last_provider or "rules_only"
    if metrics.get("providers"):
        active_provider = ", ".join(f"{p} ({cnt})" for p, cnt in sorted(metrics["providers"].items()))

    # Build report payload for claims evaluation
    report_data = {
        "metadata": {
            "split": split,
            "mode": mode,
            "test_hash_info": test_hash_info,
            "git_commit": get_git_commit(),
            "provider": active_provider,
        },
        "metrics": metrics,
    }

    # Evaluate pre-registered claims (§9.5, §0 Rule 4)
    claim_eval = evaluate_claims(report_data)
    claims_block = claim_eval.get("claims", {})

    # Save reports
    json_path, md_path = save_reports(
        metrics=metrics,
        split=split,
        out_dir=out_dir,
        test_hash_info=test_hash_info,
        mode=mode,
        claims=claims_block,
        git_commit=get_git_commit(),
        provider=active_provider,
        is_partial=is_partial or (len(evaluations) < len(items)),
        items_evaluated=len(evaluations),
        total_items=len(items),
        ablation=ablation_data,
    )

    # Sync to docs/EVAL_REPORT.md
    docs_md = Path("docs/EVAL_REPORT.md")
    docs_md.parent.mkdir(parents=True, exist_ok=True)
    with open(docs_md, "w", encoding="utf-8") as f:
        f.write(md_path.read_text(encoding="utf-8"))

    # Generate CLAIMS.md
    claims_content = generate_claims_markdown(claim_eval, report_data)
    claims_path = Path(claims_out)
    claims_path.parent.mkdir(parents=True, exist_ok=True)
    with open(claims_path, "w", encoding="utf-8") as f:
        f.write(claims_content)

    # Print summary
    b = metrics["binary"]
    s = metrics["sanitization"]
    l = metrics["latency"]
    print("\n" + "=" * 65)
    print(f"EVALUATION SUMMARY: {split.upper()} SPLIT (Mode: {mode})")
    print("=" * 65)
    print(f"  Total items evaluated: {b['total_items']} / {len(items)}")
    print(f"  Status:                 {'PARTIAL' if (is_partial or len(evaluations) < len(items)) else 'COMPLETE'}")
    print(f"  Active Providers:       {active_provider}")
    print(f"  Attacks: {b['total_attacks']} | Benign: {b['total_benign']}")
    print(f"  Recall:                 {b['recall'] * 100:.2f}% (TP={b['tp']}, FN={b['fn']})")
    print(f"  Precision:              {b['precision'] * 100:.2f}% (FP={b['fp']})")
    print(f"  F1 Score:               {b['f1']:.4f}")
    print(f"  False Positive Rate:    {b['fpr'] * 100:.2f}% (TN={b['tn']})")
    print(f"  Residual Attack Rate:   {s['residual_attack_rate'] * 100:.2f}%")
    print(f"  Text Retention:         {s['mean_retention'] * 100:.2f}%")
    print(f"  Latency p50 / p95:      {l['p50_total_ms']} ms / {l['p95_total_ms']} ms")
    print(f"  F3 Claim Status:        {claims_block.get('F3', {}).get('status', 'FAIL')} ({claims_block.get('F3', {}).get('detected_categories', 0)}/7 categories)")
    print(f"  D2 Claim Status:        {claims_block.get('D2', {}).get('status', 'FAIL')}")
    print(f"  D3 Claim Status:        {claims_block.get('D3', {}).get('status', 'NOT_CLAIMED')}")
    print(f"  Reports written to:     {json_path} and {md_path}")
    print(f"  Claims generated to:    {claims_path}")
    print("=" * 65 + "\n")

    return metrics, str(md_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="AegisAgent Benchmark Evaluation Runner")
    parser.add_argument("--split", choices=["dev", "test"], default="test", help="Dataset split to evaluate")
    parser.add_argument("--mode", choices=["cascade", "rules_only"], default="cascade", help="Firewall detection mode")
    parser.add_argument("--batch-size", type=int, default=0, help="Batch size (0 for full split)")
    parser.add_argument("--out", default="reports", help="Output directory for reports")
    parser.add_argument("--claims-out", default="docs/CLAIMS.md", help="Path for generated CLAIMS.md")
    args = parser.parse_args()

    run_evaluation(
        split=args.split,
        out_dir=args.out,
        claims_out=args.claims_out,
        mode=args.mode,
        batch_size=args.batch_size,
    )


if __name__ == "__main__":
    main()
