#!/usr/bin/env python3
"""Diagnostic script to verify connectivity and schema validation for LLM Judge providers.

Tests each provider configured in environment variables (Gemini, Groq, Mistral, OpenRouter, Ollama)
against an OpenAI-compatible /chat/completions endpoint.
"""

import os
import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

from aegis.judge_llm import ProviderAgnosticJudge, SYSTEM_PROMPT


def check_provider(judge: ProviderAgnosticJudge, name: str, cfg) -> dict:
    """Test a single LLM provider configuration and report status."""
    result = {
        "provider": name,
        "model": cfg.model,
        "base_url": cfg.base_url,
        "has_key": bool(cfg.api_key),
        "status": "SKIPPED (no key)",
        "latency_ms": 0.0,
        "sample_rationale": "",
        "error": None,
    }

    if name == "ollama":
        if not (os.environ.get("OLLAMA_BASE_URL") or os.environ.get("ENABLE_OLLAMA") == "1" or cfg.api_key):
            result["status"] = "SKIPPED (Ollama disabled/unconfigured)"
            return result
    elif not cfg.api_key:
        return result

    test_input = "<untrusted>\nHello, this is a diagnostic test prompt. Confirm security status.\n</untrusted>"
    t_start = time.perf_counter()

    try:
        raw_resp = judge._call_provider_endpoint(cfg, test_input, timeout=10.0)
        dur = round((time.perf_counter() - t_start) * 1000, 2)
        result["latency_ms"] = dur

        choices = raw_resp.get("choices", [])
        if not choices:
            result["status"] = "FAILED (empty choices)"
            result["error"] = "No choices returned by endpoint"
            return result

        content = choices[0].get("message", {}).get("content", "")
        scores = judge.parse_and_validate_json(content)

        result["status"] = "OK (200 Validated)"
        result["sample_rationale"] = scores.rationale or "(No rationale provided)"
        return result

    except Exception as e:
        dur = round((time.perf_counter() - t_start) * 1000, 2)
        result["latency_ms"] = dur
        err_msg = str(e)
        if cfg.api_key:
            err_msg = err_msg.replace(cfg.api_key, "[REDACTED_KEY]")
        result["status"] = f"FAILED"
        result["error"] = err_msg
        return result


def main():
    print("\n" + "=" * 75)
    print(" AgenticGuard • LLM Judge Provider Diagnostic Tool")
    print("=" * 75)

    judge = ProviderAgnosticJudge()
    configs = judge.get_provider_configs()
    configured_order = judge.get_configured_providers()

    order_raw = os.environ.get("LLM_PROVIDER_ORDER", judge.default_order)
    print(f"Configured Priority Order: {order_raw}")
    print(f"Active Available Providers: {configured_order or ['None (fallback:rules_only)']}\n")

    print(f"{'Provider':<12} | {'Model':<26} | {'Status':<18} | {'Latency':<9} | Details")
    print("-" * 75)

    all_providers = ["gemini", "groq", "mistral", "openrouter", "ollama"]
    success_count = 0

    for name in all_providers:
        cfg = configs.get(name)
        if not cfg:
            continue
        res = check_provider(judge, name, cfg)
        status_disp = res["status"]
        lat_disp = f"{res['latency_ms']} ms" if res["latency_ms"] > 0 else "-"
        detail = res["sample_rationale"] if res["status"].startswith("OK") else (res["error"] or "Key not set in .env")
        if len(detail) > 40:
            detail = detail[:37] + "..."

        print(f"{name:<12} | {cfg.model:<26} | {status_disp:<18} | {lat_disp:<9} | {detail}")
        if res["status"].startswith("OK"):
            success_count += 1

    print("-" * 75)
    if success_count > 0:
        print(f"Result: {success_count} provider(s) active and operational.")
    else:
        print("Result: No remote LLM providers connected. AgenticGuard will operate in fallback:rules_only mode.")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    main()
