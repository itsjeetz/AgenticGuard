"""Unit tests for health endpoint and capability reporting (§10, §8.4)."""

import os
from fastapi.testclient import TestClient
from server.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "ok"
    assert "version" in data
    assert "ocr_available" in data
    assert isinstance(data["ocr_available"], bool)
    assert "anthropic_key_set" in data
    assert isinstance(data["anthropic_key_set"], bool)
    assert "judge_available" in data
    assert isinstance(data["judge_available"], bool)
    assert "classifier_backend" in data
    assert "degraded_mode" in data
    assert isinstance(data["degraded_mode"], bool)


def test_health_reflects_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-12345")
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["anthropic_key_set"] is True
    assert data["judge_available"] is True


def test_health_per_provider_state_and_judge_status(monkeypatch):
    """Verify /api/health lists per-provider state and llm_judge_status is ok only after real call."""
    from aegis.judge_llm import get_llm_judge
    judge = get_llm_judge()
    judge.reset_session_state()

    # Even with GEMINI_API_KEY set, llm_judge_status must NOT be "ok (gemini_1)" before a real successful call
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyTestKey1234")
    monkeypatch.setenv("GEMINI_API_KEY_2", "")
    monkeypatch.setenv("GROQ_API_KEY", "")
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()

    assert "providers" in data
    providers = data["providers"]
    assert "gemini_1" in providers
    assert "gemini_2" in providers
    assert "groq" in providers

    # Verify per-provider schema
    for p_name in ("gemini_1", "gemini_2", "groq"):
        st = providers[p_name]
        assert "configured" in st
        assert "reachable" in st
        assert "last_call_ok" in st
        assert "last_error" in st
        assert "last_latency_ms" in st

    assert providers["gemini_1"]["configured"] is True
    assert providers["gemini_1"]["masked_key"] == "...1234"
    assert providers["gemini_2"]["configured"] is False
    assert providers["groq"]["configured"] is False

    # Must be fallback before any real outbound call succeeds
    assert data["llm_judge_status"] == "fallback:rules_only"

    # Now simulate a real successful call
    judge.update_provider_state("gemini_1", reachable=True, last_call_ok=True, last_error=None, last_latency_ms=120.5)
    judge.last_status = "ok (gemini_1)"
    judge.last_provider = "gemini_1"

    response_after = client.get("/api/health")
    data_after = response_after.json()
    assert data_after["llm_judge_status"] == "ok (gemini_1)"
    assert data_after["llm_judge_provider"] == "gemini_1"
    assert data_after["providers"]["gemini_1"]["last_call_ok"] is True
    assert data_after["providers"]["gemini_1"]["last_latency_ms"] == 120.5

    # Clean up
    judge.reset_session_state()

