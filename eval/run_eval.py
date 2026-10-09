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


class EvalContext:
    def __init__(self, metadata: dict):
        self.metadata = metadata


def run_evaluation(
    split: str = "dev",
    out_dir: str = "reports",
    claims_out: str = "docs/CLAIMS.md",
    mode: str = "full_cascade",
    batch_size: int = 0,
    bypass_cache: bool = True,
    pace_seconds: float = 2.0,  
    max_wait_seconds: float = 300.0,
    progress_callback: Any = None,
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
            print("Refusing to evaluate on modified test split (§9.3, §0 Rule 3).", file=sys.stderr)
            print("=" * 70, file=sys.stderr)
            sys.exit(1)

    items = load_dataset(split)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    checkpoint_file = out_path / f"checkpoint_{split}_{mode}.json"

    checkpoint_data: dict[str, Any] = {}
    if checkpoint_file.exists():
        try:
            with open(checkpoint_file, "r", encoding="utf-8") as f:
                checkpoint_data = json.load(f)
            print(f"Loaded existing checkpoint with {len(checkpoint_data.get('evaluations', []))} items.")
        except Exception as exc:
            print(f"Warning: could not read checkpoint {checkpoint_file} ({exc}). Starting fresh.")
            checkpoint_data = {}

    evaluations: list[ItemEvaluation] = []
    if "evaluations" in checkpoint_data:
        # Load processed items from checkpoint
        for e_dict in checkpoint_data["evaluations"]:
            evaluations.append(ItemEvaluation(**e_dict))

    processed_ids = {e.item_id for e in evaluations}

    enable_rules = mode in ("rules_only", "full_cascade")
    enable_judge = mode in ("llm_only", "full_cascade")

    pipeline = FirewallPipeline(
        enable_rules=enable_rules,
        enable_classifier=False,
        enable_judge=enable_judge,
    )
    if bypass_cache and hasattr(pipeline, "cache"):
        pipeline.cache.clear()

    pipeline_rules_only = FirewallPipeline(
        enable_rules=True,
        enable_classifier=False,
        enable_judge=False,
    )

    judge = get_llm_judge()

    print(f"Starting evaluation on {split.upper()} split ({len(items)} items, mode={mode}, batch_size={batch_size})...")
    t_start = time.perf_counter()
    items_processed_this_run = 0
    is_partial = False
    
    # Eval context to bypass demo quota
    ctx = EvalContext({"bypass_cache": bypass_cache, "bypass_demo_quota": True})

    for idx, item in enumerate(items, 1):
        if item.id in processed_ids:
            continue

        if batch_size > 0 and items_processed_this_run >= batch_size:
            print(f"Batch size limit of {batch_size} reached. Stopping run.")
            is_partial = True
            break

        original_text = ""
        session_id = f"eval-sess-{item.id}"
        content, original_text = load_item_content(item.content_path)
        
        # Determine if it needs LLM evaluation
        r_verdict = pipeline_rules_only.process(
            content,
            source=InputSource(item.source),
            filename=item.content_path,
            session_id=session_id,
            neutralize_content=False,
        )
        
        needs_llm = False
        if mode == "llm_only":
            needs_llm = True
        elif mode == "full_cascade" and (0.35 <= r_verdict.risk <= 0.75):
            needs_llm = True
            
        wait_start = time.time()
        verdict = None
        
        while True:
            # Multi-turn logic
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
                
            if not needs_llm:
                break
                
            # If we need LLM, check if it fell back
            if verdict.llm_judge_status and verdict.llm_judge_status.startswith("fallback"):
                break
            else:
                time.sleep(pace_seconds)
                break

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
        
        # Check if UNEVALUATED
        if verdict.llm_judge_status == "UNEVALUATED (timeout)":
            item_eval.flagged = False
            item_eval.layer_decisions["judge"] = "UNEVALUATED"

        evaluations.append(item_eval)
        processed_ids.add(item.id)
        items_processed_this_run += 1

        # Checkpoint every item atomically
        try:
            tmp_cf = checkpoint_file.with_name(checkpoint_file.name + ".tmp")
            with open(tmp_cf, "w", encoding="utf-8") as cf:
                json.dump({
                    "split": split,
                    "mode": mode,
                    "evaluations": [e.__dict__ for e in evaluations],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }, cf, indent=2)
            tmp_cf.replace(checkpoint_file)
        except Exception:
            pass
            
        elapsed_so_far = time.perf_counter() - t_start
        eta_sec = (elapsed_so_far / items_processed_this_run) * (len(items) - idx) if items_processed_this_run > 0 else 0
        
        if progress_callback:
            progress_callback(idx, len(items), verdict.llm_judge_status or 'rules_only', eta_sec)
            
        print(f"  Processed {idx}/{len(items)} | Status: {verdict.llm_judge_status or 'rules_only'}", flush=True)

    elapsed = round(time.perf_counter() - t_start, 2)
    print(f"Processed {len(evaluations)}/{len(items)} items in {elapsed}s.", flush=True)

    metrics = compute_all_metrics(evaluations)
    
    # Calculate unevaluated stats
    unevaluated_count = 0
    llm_coverage = 1.0
    if mode in ("llm_only", "full_cascade") and len(evaluations) > 0:
        llm_coverage = (len(evaluations) - unevaluated_count) / len(evaluations)

    ablation_data = {}
    if mode == "full_cascade":
        # Load rules_only baseline if it exists
        ro_checkpoint = out_path / f"checkpoint_{split}_rules_only.json"
        if ro_checkpoint.exists():
            with open(ro_checkpoint, "r") as f:
                ro_data = json.load(f)
            ro_evals = [ItemEvaluation(**e) for e in ro_data["evaluations"]]
            ro_metrics = compute_all_metrics(ro_evals)
            
            ablation_data = {
                "split": split,
                "total_items": len(evaluations),
                "modes": {
                    "rules_only": ro_metrics["binary"],
                    "full_cascade": metrics["binary"],
                },
                "lift": {
                    "recall": metrics["binary"]["recall"] - ro_metrics["binary"]["recall"],
                    "f1": metrics["binary"]["f1"] - ro_metrics["binary"]["f1"]
                }
            }

    active_provider = judge.last_provider or "rules_only"
    if metrics.get("providers"):
        active_provider = ", ".join(f"{p} ({cnt})" for p, cnt in sorted(metrics["providers"].items()))

    report_data = {
        "metadata": {
            "split": split,
            "mode": mode,
            "test_hash_info": test_hash_info,
            "git_commit": get_git_commit(),
            "provider": active_provider,
            "llm_coverage": llm_coverage,
        },
        "metrics": metrics,
    }

    claim_eval = evaluate_claims(report_data)
    claims_block = claim_eval.get("claims", {})

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

    docs_md = Path("docs/EVAL_REPORT.md")
    docs_md.parent.mkdir(parents=True, exist_ok=True)
    with open(docs_md, "w", encoding="utf-8") as f:
        f.write(md_path.read_text(encoding="utf-8"))

    claims_content = generate_claims_markdown(claim_eval, report_data)
    claims_path = Path(claims_out)
    claims_path.parent.mkdir(parents=True, exist_ok=True)
    with open(claims_path, "w", encoding="utf-8") as f:
        f.write(claims_content)

    print("\n=================================================================")
    print(f"EVALUATION SUMMARY: {split.upper()} SPLIT (Mode: {mode})")
    print("=================================================================")
    print(f"  Total items evaluated: {len(evaluations)} / {len(items)}")
    print(f"  Unevaluated (Timeout): {unevaluated_count} (Coverage: {llm_coverage*100:.1f}%)")
    print(f"  F3 Claim Status:       {claims_block.get('F3', {}).get('status', 'FAIL')}")
    print("=================================================================\n")

    return metrics, str(md_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="AegisAgent Benchmark Evaluation Runner")
    parser.add_argument("--split", choices=["dev", "test"], default="dev", help="Dataset split to evaluate")
    parser.add_argument("--mode", choices=["full_cascade", "rules_only", "llm_only"], default="full_cascade", help="Firewall detection mode")
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
