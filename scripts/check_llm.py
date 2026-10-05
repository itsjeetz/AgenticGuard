#!/usr/bin/env python3
"""Diagnostic script to verify connectivity, authentication, and schema validation for LLM Judge providers.

Tests each provider separately:
  1. Gemini Key 1 (GEMINI_API_KEY)
  2. Gemini Key 2 (GEMINI_API_KEY_2)
  3. Groq (GROQ_API_KEY) at https://api.groq.com/openai/v1

Never exposes credentials (shows only last 4 characters).
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

from aegis.judge_llm import ProviderAgnosticJudge, get_llm_judge, mask_key


def main():
    print("\n" + "=" * 102)
    print(" AgenticGuard - LLM Judge Multi-Provider Diagnostic Tool")
    print(" Priority Ladder: 1. Gemini Key 1 -> 2. Gemini Key 2 -> 3. Groq -> 4. Rules-Only Fallback")
    print("=" * 102)

    judge = get_llm_judge()
    configs = judge.get_provider_configs()
    order_raw = os.environ.get("LLM_PROVIDER_ORDER", judge.default_order)

    print(f"Configured Priority Order : {order_raw}")
    print(f"Active Available Providers: {judge.get_configured_providers() or ['None (fallback:rules_only)']}\n")

    # Table Header
    print(f"{'Provider':<10} | {'Key Mask':<9} | {'Auth':<18} | {'Status':<7} | {'Model':<24} | {'Latency':<9} | {'Raw JSON':<8} | Details")
    print("-" * 102)

    test_targets = ["gemini_1", "gemini_2", "groq"]
    results = []

    for name in test_targets:
        res = judge.test_provider(name, timeout=12.0)
        results.append(res)

        provider_disp = res["provider"]
        key_disp = res["masked_key"]
        auth_disp = res["auth"]
        status_disp = str(res["status_code"])
        model_disp = res["model"]
        lat_disp = f"{res['latency_ms']} ms" if res["latency_ms"] > 0 else "-"
        json_disp = res["json_valid"]
        detail = res.get("details", "") or ""
        if len(detail) > 36:
            detail = detail[:33] + "..."

        print(f"{provider_disp:<10} | {key_disp:<9} | {auth_disp:<18} | {status_disp:<7} | {model_disp:<24} | {lat_disp:<9} | {json_disp:<8} | {detail}")

    print("-" * 102)

    operational = [r for r in results if r["status_code"] == 200 and r["json_valid"] == "VALID"]
    if operational:
        print(f"Result: {len(operational)} remote provider(s) active and validated.")
        for op in operational:
            print(f"  [+] {op['display_name']} ({op['model']}): reachable and valid JSON.")
    else:
        print("Result: No remote LLM providers connected. AgenticGuard will operate in fallback:rules_only mode.")

    # Show health state snapshot
    states = judge.get_provider_states()
    print("\n--- /api/health Provider States Snapshot ---")
    for p, st in states.items():
        print(f"  * {p:<8}: configured={st['configured']}, reachable={st['reachable']}, last_call_ok={st['last_call_ok']}, latency={st['last_latency_ms']}ms, error={st['last_error']}")
    print("=" * 102 + "\n")


if __name__ == "__main__":
    main()
