"""Tests for LLM rate limiting, key hashing recovery, 429 handling, and retest (§2, §3, §4, §6)."""

import json
import time
from unittest.mock import patch
from fastapi.testclient import TestClient

from aegis.judge_llm import (
    ProviderAgnosticJudge,
    ProviderHTTPError,
    get_key_hash,
    seconds_until_midnight_pacific,
)
from server.main import app

client = TestClient(app)


def test_changed_key_recovers_from_invalid_state(monkeypatch):
    """Prove that keying state by hash allows a changed key to start clean after invalid state (§2, §6)."""
    judge = ProviderAgnosticJudge()
    judge.reset_session_state()

    bad_key = "gsk_invalidKey11111111111111111111"
    good_key = "gsk_validKey222222222222222222222"

    monkeypatch.setenv("GROQ_API_KEY", bad_key)
    monkeypatch.setenv("GROQ_API_KEY_2", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY_2", "")
    monkeypatch.setenv("LLM_PROVIDER_ORDER", "groq_1")

    # 1. Simulate bad_key receiving 401 Unauthorized
    def mock_bad_call(config, prompt, **kwargs):
        raise ProviderHTTPError(status_code=401, body='{"error": {"message": "Invalid API Key"}}')

    with patch.object(judge, "_call_provider_endpoint", side_effect=mock_bad_call):
        scores, prov, status = judge.evaluate_text("test input", bypass_cache=True)
        assert status == "fallback:rules_only"

    # State for bad_key must now be 'invalid'
    states = judge.get_provider_states()
    assert states["groq_1"]["state"] == "invalid"
    assert "groq_1" in judge._auth_failure_until
    bad_hash = get_key_hash(bad_key)
    assert judge._get_key_state(bad_hash).state == "invalid"

    # 2. User replaces key in environment (simulating server restart with new key in .env)
    monkeypatch.setenv("GROQ_API_KEY", good_key)

    # Prove new key starts clean: state is NOT invalid
    states_new = judge.get_provider_states()
    assert states_new["groq_1"]["state"] == "configured"
    assert states_new["groq_1"]["cooldown_seconds_remaining"] == 0.0
    good_hash = get_key_hash(good_key)
    assert judge._get_key_state(good_hash).state != "invalid"

    # 3. Simulate new key succeeding
    def mock_good_call(config, prompt, **kwargs):
        return {
            "choices": [{"message": {"content": '{"INSTRUCTION_OVERRIDE": 0.0, "rationale": "clean"}'}}]
        }

    with patch.object(judge, "_call_provider_endpoint", side_effect=mock_good_call):
        scores, prov, status = judge.evaluate_text("test input", bypass_cache=True)
        assert status == "ok (groq_1)"
        assert prov == "groq_1"

    states_recovered = judge.get_provider_states()
    assert states_recovered["groq_1"]["state"] == "ok"
    assert states_recovered["groq_1"]["last_call_ok"] is True


def test_per_minute_429_recovers_after_cooldown(monkeypatch):
    """Prove per-minute 429 sets short cooldown and recovers when reset time expires (§3, §6)."""
    judge = ProviderAgnosticJudge()
    judge.reset_session_state()

    monkeypatch.setenv("GROQ_API_KEY", "gsk_perMinuteKey1234")
    monkeypatch.setenv("GROQ_API_KEY_2", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY_2", "")
    monkeypatch.setenv("LLM_PROVIDER_ORDER", "groq_1")

    # 1. Simulate 429 with Retry-After: 3 seconds
    headers_429 = {
        "retry-after": "3",
        "x-ratelimit-reset-requests": "3s",
        "x-ratelimit-remaining-requests": "0",
    }
    body_429 = '{"error": {"message": "Rate limit reached. Please try again in 3s."}}'

    def mock_rate_limit(config, prompt, **kwargs):
        raise ProviderHTTPError(status_code=429, body=body_429, headers=headers_429)

    with patch.object(judge, "_call_provider_endpoint", side_effect=mock_rate_limit):
        scores, prov, status = judge.evaluate_text("test input", bypass_cache=True)
        assert status == "fallback:rules_only"

    # State must be 'cooldown' with ~3s remaining, NOT exhausted
    states = judge.get_provider_states()
    assert states["groq_1"]["state"] == "cooldown"
    assert 0.0 < states["groq_1"]["cooldown_seconds_remaining"] <= 4.0
    footer = judge.get_footer_label()
    assert "rate limited" in footer or "rules only" in footer

    # 2. Advance time past the 3-second cooldown
    with patch("time.time", return_value=time.time() + 5.0):
        states_after = judge.get_provider_states()
        assert states_after["groq_1"]["cooldown_seconds_remaining"] == 0.0
        assert states_after["groq_1"]["state"] in ("configured", "ok")


def test_per_day_429_shows_exhausted_until_reset_time(monkeypatch):
    """Prove per-day limits set state to EXHAUSTED until midnight Pacific for Gemini or reported reset for Groq (§3, §6)."""
    judge = ProviderAgnosticJudge()
    judge.reset_session_state()

    # 1. Test Gemini daily quota parsing (QuotaFailure PerDay)
    monkeypatch.setenv("GEMINI_API_KEY", "gem_dailyExhaustedKey1234")
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("LLM_PROVIDER_ORDER", "gemini_1")

    gemini_body = json.dumps({
        "error": {
            "code": 429,
            "message": "Resource has been exhausted (e.g. check quota).",
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "RATE_LIMIT_EXCEEDED",
                    "domain": "googleapis.com",
                    "metadata": {
                        "consumer": "projects/123456789",
                        "quota_limit": "GenerateContentRequestsPerDayPerProject",
                        "quota_limit_value": "1500",
                    },
                },
                {
                    "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                    "violations": [
                        {
                            "subject": "project:123456789",
                            "description": "Quota exceeded for quota metric 'GenerateContentRequestsPerDay'",
                        }
                    ],
                },
            ],
        }
    })

    def mock_gemini_429(config, prompt, **kwargs):
        raise ProviderHTTPError(status_code=429, body=gemini_body)

    with patch.object(judge, "_call_provider_endpoint", side_effect=mock_gemini_429):
        scores, prov, status = judge.evaluate_text("test input", bypass_cache=True)
        assert status == "fallback:rules_only"

    # State must be 'exhausted' with cooldown matching midnight Pacific (~seconds_until_midnight_pacific())
    states = judge.get_provider_states()
    assert states["gemini_1"]["state"] == "exhausted"
    expected_secs = seconds_until_midnight_pacific()
    # Cooldown should be close to expected_secs (within 5 seconds)
    assert abs(states["gemini_1"]["cooldown_seconds_remaining"] - expected_secs) < 10.0
    assert states["gemini_1"]["learned_limits"]["rpd"]["limit"] == 1500

    footer = judge.get_footer_label()
    assert "Gemini daily request limit reached" in footer
    assert "resets in" in footer

    # 2. Test Groq daily token limit parsing
    judge.reset_session_state()
    monkeypatch.setenv("GROQ_API_KEY", "gsk_groqDailyExhausted5678")
    monkeypatch.setenv("LLM_PROVIDER_ORDER", "groq_1")

    groq_daily_headers = {
        "x-ratelimit-reset-tokens": "5h30m",
        "x-ratelimit-remaining-tokens": "0",
        "groq-organization": "org_agenticguard",
    }
    groq_daily_body = json.dumps({
        "error": {
            "message": "Rate limit reached for model `openai/gpt-oss-20b` in organization `org_agenticguard` on tokens per day. Please try again in 5h30m.",
            "type": "tokens",
            "code": "rate_limit_exceeded",
        }
    })

    def mock_groq_daily(config, prompt, **kwargs):
        raise ProviderHTTPError(status_code=429, body=groq_daily_body, headers=groq_daily_headers)

    with patch.object(judge, "_call_provider_endpoint", side_effect=mock_groq_daily):
        scores, prov, status = judge.evaluate_text("test input", bypass_cache=True)
        assert status == "fallback:rules_only"

    states_groq = judge.get_provider_states()
    assert states_groq["groq_1"]["state"] == "exhausted"
    # Cooldown should be 5*3600 + 30*60 = 19800 seconds
    assert 19700.0 < states_groq["groq_1"]["cooldown_seconds_remaining"] <= 19805.0
    footer_groq = judge.get_footer_label()
    assert "Groq daily token limit reached" in footer_groq
    assert "5 h" in footer_groq or "5h" in footer_groq


def test_post_llm_retest_endpoint(monkeypatch):
    """Prove POST /api/llm/retest endpoint makes 1 call per provider and returns classification and when_to_retry (§2)."""
    monkeypatch.setenv("GROQ_API_KEY", "gsk_retestKey1")
    monkeypatch.setenv("GROQ_API_KEY_2", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY_2", "")

    from aegis.judge_llm import get_llm_judge
    judge = get_llm_judge()
    judge.reset_session_state()

    def mock_retest_call(config, prompt, **kwargs):
        if config.name == "groq_1":
            raise ProviderHTTPError(
                status_code=429,
                body='{"error": {"message": "Rate limit reached. Please try again in 25s."}}',
                headers={"retry-after": "25"}
            )
        return {"choices": [{"message": {"content": "{}"}}]}

    with patch.object(judge, "_call_provider_endpoint", side_effect=mock_retest_call):
        response = client.post("/api/llm/retest")
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "ok"
        assert "results" in data
        assert "footer_label" in data

        groq_1 = data["results"]["groq_1"]
        assert groq_1["configured"] is True
        assert groq_1["status_code"] == 429
        assert groq_1["classification"] == "per-minute limit"
        assert "in 25 s" in groq_1["when_to_retry"] or "25" in groq_1["when_to_retry"]

        # groq_2, gemini_1, gemini_2 should be unconfigured
        assert data["results"]["groq_2"]["configured"] is False
