#!/usr/bin/env python3
"""Simulation script for multi-key LLM failover scenarios:
  (i)   Key 1 returns 429 while Key 2 works -> groq_2 serves, footer shows "LLM: Groq (key 2)"
  (ii)  Both Groq keys return 429 within 60s -> shared limit detected, group cooldown, moves to Gemini
  (iii) All providers fail -> degrades to rules-only fallback (amber)
  (iv)  Recovery -> Groq key 1 cooldown ends / probe succeeds, recovers back to groq_1

Also uses Playwright to capture screenshots of each footer state in the dashboard.
"""

import asyncio
import json
import logging
import os
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from pathlib import Path

# Add project root
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis.judge_llm import ProviderAgnosticJudge, get_llm_judge
from playwright.async_api import async_playwright

DIAGNOSTICS_DIR = ROOT / "screenshots"
DIAGNOSTICS_DIR.mkdir(parents=True, exist_ok=True)

MOCK_STATE = {
    "groq_1_status": 200,
    "groq_2_status": 200,
    "gemini_1_status": 200,
    "gemini_2_status": 200,
    "retry_after": 30,
}

VALID_LLM_RESPONSE = {
    "choices": [
        {
            "message": {
                "content": json.dumps({
                    "INSTRUCTION_OVERRIDE": 0.0,
                    "ROLE_CHANGE": 0.0,
                    "SECRET_EXTRACTION": 0.0,
                    "TOOL_ABUSE": 0.0,
                    "CREDENTIAL_THEFT": 0.0,
                    "CONTEXT_POISONING": 0.0,
                    "MULTI_STEP_JAILBREAK": 0.0,
                    "ENCODED_INSTRUCTIONS": 0.0,
                    "INDIRECT_PROMPT_INJECTION": 0.0,
                    "confidence": 0.95,
                    "rationale": "Mock clean inspection response"
                })
            }
        }
    ]
}


class MockLLMHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress console logging

    def do_POST(self):
        auth_header = self.headers.get("Authorization", "")
        # Identify key from auth header
        if "mock-groq-key-1" in auth_header:
            status = MOCK_STATE["groq_1_status"]
            prov = "groq_1"
        elif "mock-groq-key-2" in auth_header:
            status = MOCK_STATE["groq_2_status"]
            prov = "groq_2"
        elif "mock-gemini-key-1" in auth_header:
            status = MOCK_STATE["gemini_1_status"]
            prov = "gemini_1"
        elif "mock-gemini-key-2" in auth_header:
            status = MOCK_STATE["gemini_2_status"]
            prov = "gemini_2"
        else:
            status = 200
            prov = "unknown"

        print(f"    [Mock Server] -> Received call for {prov} (status {status})")

        if status == 429:
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", str(MOCK_STATE["retry_after"]))
            self.end_headers()
            self.wfile.write(b'{"error":{"message":"Rate limit reached for model","type":"tokens_exceeded","code":429}}')
        elif status == 500:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":{"message":"Internal server error","code":500}}')
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(VALID_LLM_RESPONSE).encode("utf-8"))


def start_mock_server(port=8002):
    server = HTTPServer(("127.0.0.1", port), MockLLMHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


async def capture_footer_screenshot(footer_text, filename):
    """Render and capture the footer status badge in Playwright."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1280, "height": 800})
        page = await context.new_page()

        # Route /api/health to inject this specific footer label
        await page.route("**/api/health", lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({
                "status": "ok",
                "version": "0.1.0",
                "ocr_available": False,
                "classifier_backend": "provider_agnostic_llm_judge",
                "judge_available": True,
                "anthropic_key_set": False,
                "judge_model": "claude-haiku-4-5-20251001",
                "agent_model": "claude-sonnet-5",
                "gemini_key_set": True,
                "gemini_available": True,
                "gemini_model": "gemini-2.5-flash",
                "hf_classifier_id": None,
                "degraded_mode": "rules only" in footer_text.lower(),
                "demo_mode": False,
                "rate_limit_per_minute": 30,
                "daily_llm_calls_limit": 300,
                "daily_llm_calls_used": 12,
                "daily_llm_calls_remaining": 188,
                "llm_judge_provider": "groq_2" if "key 2" in footer_text else ("gemini_1" if "Gemini" in footer_text else "fallback:rules_only"),
                "llm_judge_status": "ok",
                "footer_label": footer_text,
                "llm_providers_configured": ["groq_1", "groq_2", "gemini_1", "gemini_2"],
                "providers": {
                    "groq_1": {"configured": True, "reachable": True, "last_call_ok": True, "last_error": None, "last_latency_ms": 120.0, "model": "openai/gpt-oss-20b", "masked_key": "...ey-1", "cooldown_seconds_remaining": 30.0 if "cooling down" in footer_text else 0.0},
                    "groq_2": {"configured": True, "reachable": True, "last_call_ok": True, "last_error": None, "last_latency_ms": 115.0, "model": "openai/gpt-oss-20b", "masked_key": "...ey-2", "cooldown_seconds_remaining": 0.0},
                    "gemini_1": {"configured": True, "reachable": True, "last_call_ok": True, "last_error": None, "last_latency_ms": 140.0, "model": "gemini-2.5-flash", "masked_key": "...ey-1", "cooldown_seconds_remaining": 0.0},
                    "gemini_2": {"configured": True, "reachable": True, "last_call_ok": True, "last_error": None, "last_latency_ms": 0.0, "model": "gemini-2.5-flash", "masked_key": "...ey-2", "cooldown_seconds_remaining": 0.0},
                }
            })
        ))

        await page.goto("http://127.0.0.1:8000")
        await page.wait_for_selector("#footerLlmJudge")
        await page.wait_for_timeout(500)

        footer_el = page.locator("#socFooter")
        out_path = DIAGNOSTICS_DIR / filename
        await footer_el.screenshot(path=str(out_path))
        print(f"  [Screenshot] Captured footer badge: {out_path.name}")
        await browser.close()


def run_simulations():
    print("\n" + "=" * 90)
    print(" AgenticGuard - Multi-Key Failover & Recovery Simulations")
    print("=" * 90)

    # Configure mock server environment overrides in-process
    os.environ["GROQ_BASE_URL_1"] = "http://127.0.0.1:8002/v1"
    os.environ["GROQ_BASE_URL_2"] = "http://127.0.0.1:8002/v1"
    os.environ["GEMINI_BASE_URL"] = "http://127.0.0.1:8002/v1"
    os.environ["GEMINI_BASE_URL_2"] = "http://127.0.0.1:8002/v1"

    os.environ["GROQ_API_KEY"] = "mock-groq-key-1"
    os.environ["GROQ_API_KEY_2"] = "mock-groq-key-2"
    os.environ["GEMINI_API_KEY"] = "mock-gemini-key-1"
    os.environ["GEMINI_API_KEY_2"] = "mock-gemini-key-2"
    os.environ["LLM_PROVIDER_ORDER"] = "groq_1,groq_2,gemini_1,gemini_2"

    judge = ProviderAgnosticJudge()

    # Capture log outputs to verify "groq keys appear to share a limit"
    log_capture = []
    class LogCaptureHandler(logging.Handler):
        def emit(self, record):
            log_capture.append(self.format(record))

    cap_handler = LogCaptureHandler()
    cap_handler.setLevel(logging.DEBUG)
    llm_logger = logging.getLogger("aegis.judge_llm")
    llm_logger.setLevel(logging.DEBUG)
    llm_logger.addHandler(cap_handler)

    print("\n[Baseline] Initial State (all mock endpoints 200 OK):")
    MOCK_STATE["groq_1_status"] = 200
    MOCK_STATE["groq_2_status"] = 200
    MOCK_STATE["gemini_1_status"] = 200
    MOCK_STATE["gemini_2_status"] = 200

    scores, prov, status = judge.evaluate_text("Initial baseline check", bypass_cache=True)
    footer = judge.get_footer_label()
    print(f"  Served by: {prov} | status: {status} | footer: '{footer}'")
    assert prov == "groq_1"
    assert footer == "LLM: Groq (key 1)"

    # -------------------------------------------------------------
    # Scenario (i): Key 1 returns 429 while Key 2 works
    # -------------------------------------------------------------
    print("\n" + "-" * 90)
    print("Scenario (i): Groq Key 1 returns 429, Groq Key 2 returns 200 OK")
    print("-" * 90)
    MOCK_STATE["groq_1_status"] = 429
    MOCK_STATE["groq_2_status"] = 200
    MOCK_STATE["retry_after"] = 38

    scores, prov, status = judge.evaluate_text("Payload during key 1 429 limit", bypass_cache=True)
    footer_i = judge.get_footer_label()
    states_i = judge.get_provider_states()

    print(f"  Served by     : {prov}")
    print(f"  Status        : {status}")
    print(f"  Footer label  : '{footer_i}'")
    print(f"  groq_1 state  : cooldown={states_i['groq_1']['cooldown_seconds_remaining']:.1f}s, last_error={states_i['groq_1']['last_error']}")
    print(f"  groq_2 state  : ok={states_i['groq_2']['last_call_ok']}, latency={states_i['groq_2']['last_latency_ms']:.1f}ms")

    assert prov == "groq_2", f"Expected groq_2, got {prov}"
    assert footer_i == "LLM: Groq (key 2)"
    assert states_i["groq_1"]["cooldown_seconds_remaining"] > 0.0

    # -------------------------------------------------------------
    # Scenario (ii): Both Groq keys return 429 (shared limit)
    # -------------------------------------------------------------
    print("\n" + "-" * 90)
    print("Scenario (ii): Both Groq keys return 429 (Shared Rate Limit Detection)")
    print("-" * 90)
    # Reset judge to clean cooldown state to simulate sequential 429s within 60s
    judge._provider_cooldown_until.clear()
    MOCK_STATE["groq_1_status"] = 429
    MOCK_STATE["groq_2_status"] = 429
    MOCK_STATE["gemini_1_status"] = 200
    MOCK_STATE["retry_after"] = 45

    scores, prov, status = judge.evaluate_text("Payload triggering shared rate limit", bypass_cache=True)
    footer_ii = judge.get_footer_label()
    states_ii = judge.get_provider_states()
    print(f"  DEBUG _provider_cooldown_until: {judge._provider_cooldown_until}")
    print(f"  DEBUG log_capture length: {len(log_capture)}, items: {log_capture}")
    shared_log_found = any("groq keys appear to share a limit" in msg.lower() for msg in log_capture)
    print(f"  Served by             : {prov}")
    print(f"  Status                : {status}")
    print(f"  Footer label          : '{footer_ii}'")
    print(f"  Shared limit log seen : {shared_log_found}")
    print(f"  groq_1 cooldown       : {states_ii['groq_1']['cooldown_seconds_remaining']:.1f}s")
    print(f"  groq_2 cooldown       : {states_ii['groq_2']['cooldown_seconds_remaining']:.1f}s")

    assert prov == "gemini_1", f"Expected fallback to gemini_1, got {prov}"
    assert shared_log_found, "Expected 'groq keys appear to share a limit' in logs"
    assert "Gemini (backup" in footer_ii
    assert "Groq cooling down" in footer_ii

    # -------------------------------------------------------------
    # Scenario (iii): All providers fail -> rules-only fallback
    # -------------------------------------------------------------
    print("\n" + "-" * 90)
    print("Scenario (iii): All Providers Fail (Network/500/429 Outage)")
    print("-" * 90)
    MOCK_STATE["groq_1_status"] = 500
    MOCK_STATE["groq_2_status"] = 500
    MOCK_STATE["gemini_1_status"] = 500
    MOCK_STATE["gemini_2_status"] = 500

    scores, prov, status = judge.evaluate_text("Payload during complete outage", bypass_cache=True)
    footer_iii = judge.get_footer_label()

    print(f"  Served by     : '{prov}' (empty string denotes rules-only)")
    print(f"  Status        : {status}")
    print(f"  Footer label  : '{footer_iii}'")

    assert prov == "", f"Expected empty provider for rules-only, got {prov}"
    assert status.startswith("fallback:rules_only")
    assert "Rules only" in footer_iii

    # -------------------------------------------------------------
    # Scenario Recovery: Groq key 1 recovers
    # -------------------------------------------------------------
    print("\n" + "-" * 90)
    print("Scenario Recovery: Groq Key 1 cooldown expires / restored 200 OK")
    print("-" * 90)
    MOCK_STATE["groq_1_status"] = 200
    MOCK_STATE["groq_2_status"] = 200
    MOCK_STATE["gemini_1_status"] = 200
    MOCK_STATE["gemini_2_status"] = 200

    # Clear cooldowns to simulate timer expiration
    judge._provider_cooldown_until.clear()
    judge._auth_failure_until.clear()

    scores, prov, status = judge.evaluate_text("Payload after recovery", bypass_cache=True)
    footer_rec = judge.get_footer_label()
    states_rec = judge.get_provider_states()

    print(f"  Served by     : {prov}")
    print(f"  Status        : {status}")
    print(f"  groq_1 state  : ok={states_rec['groq_1']['last_call_ok']}, latency={states_rec['groq_1']['last_latency_ms']:.1f}ms, error={states_rec['groq_1']['last_error']}")
    print(f"  groq_2 state  : ok={states_rec['groq_2']['last_call_ok']}, latency={states_rec['groq_2']['last_latency_ms']:.1f}ms, error={states_rec['groq_2']['last_error']}")

    assert prov == "groq_1", f"Expected recovery back to groq_1, got {prov}"
    assert footer_rec == "LLM: Groq (key 1)"

    print("=" * 90)
    print("All multi-key scenarios verified successfully!")

    return footer_i, footer_ii, footer_iii, footer_rec


async def main():
    server = start_mock_server(8002)
    time.sleep(0.5)

    try:
        footer_i, footer_ii, footer_iii, footer_rec = run_simulations()

        print("\n--- Generating Playwright Screenshots for Dashboard Footer States ---")
        await capture_footer_screenshot("LLM: Groq (key 2)", "sim_1_footer_groq_key2.png")
        await capture_footer_screenshot(footer_ii, "sim_2_footer_gemini_backup.png")
        await capture_footer_screenshot("LLM: Rules only (amber degraded)", "sim_3_footer_rules_only.png")
        await capture_footer_screenshot("LLM: Groq (key 1)", "sim_4_footer_groq_recovered.png")
        print("All screenshots generated in screenshots/\n")

    finally:
        server.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
