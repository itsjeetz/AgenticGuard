#!/usr/bin/env python3
"""Diagnostic script to verify connectivity, authentication, and schema validation for LLM Judge providers.

Tests each provider separately:
  1. Groq Key 1 (GROQ_API_KEY)
  2. Groq Key 2 (GROQ_API_KEY_2)
  3. Gemini Key 1 (GEMINI_API_KEY)
  4. Gemini Key 2 (GEMINI_API_KEY_2)

Never exposes credentials (shows only last 4 characters).
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.env import load_environment
load_environment(override=True)

from aegis.judge_llm import ProviderAgnosticJudge, get_llm_judge, mask_key


def main():
    print("\n" + "=" * 106)
    print(" AgenticGuard - LLM Judge Multi-Provider Diagnostic Tool")
    print(" Priority Ladder: 1. Groq Key 1 (PRIMARY) -> 2. Groq Key 2 -> 3. Gemini Key 1 (backup) -> 4. Gemini Key 2 (backup) -> 5. Rules Fallback")
    print("=" * 106)

    judge = get_llm_judge()
    configs = judge.get_provider_configs()
    order_raw = os.environ.get("LLM_PROVIDER_ORDER", judge.default_order)

    print(f"Configured Priority Order : {order_raw}")
    print(f"Effective Priority Order  : {', '.join(judge.resolve_provider_order(order_raw))}")
    print(f"Active Available Providers: {judge.get_configured_providers() or ['None (fallback:rules_only)']}\n")

    # Table Header
    print(f"{'Provider':<10} | {'Key Mask':<9} | {'Auth':<18} | {'Status':<7} | {'Model':<24} | {'Latency':<9} | {'Raw JSON':<8} | Details")
    print("-" * 106)

    test_targets = ["groq_1", "groq_2", "gemini_1", "gemini_2"]
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
        if len(detail) > 40:
            detail = detail[:37] + "..."

        print(f"{provider_disp:<10} | {key_disp:<9} | {auth_disp:<18} | {status_disp:<7} | {model_disp:<24} | {lat_disp:<9} | {json_disp:<8} | {detail}")

    print("-" * 106)

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
    for p in ("groq_1", "groq_2", "gemini_1", "gemini_2"):
        st = states.get(p, {})
        print(f"  * {p:<8}: configured={st.get('configured')}, reachable={st.get('reachable')}, last_call_ok={st.get('last_call_ok')}, latency={st.get('last_latency_ms')}ms, error={st.get('last_error')}")
    print("=" * 106 + "\n")


if __name__ == "__main__":
    main()

