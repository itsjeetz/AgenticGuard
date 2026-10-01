"""Health and capabilities check endpoint (§10, §8.4)."""

import os
from pathlib import Path
from fastapi import APIRouter
from aegis.models import HealthResponse

from server.demo_mode import (
    DEFAULT_GENERAL_LIMIT_PER_MINUTE,
    get_demo_manager,
    is_demo_mode,
)

router = APIRouter(prefix="/api", tags=["health"])


def is_ocr_available() -> bool:
    """Check if Tesseract binary is accessible and functional."""
    try:
        import pytesseract

        version = pytesseract.get_tesseract_version()
        return bool(version)
    except Exception:
        return False


def get_classifier_backend() -> str:
    """Check configured and available classifier backend."""
    return "provider_agnostic_llm_judge"


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return health status and capabilities of the firewall."""
    from aegis.judge_llm import get_llm_judge

    ocr_avail = is_ocr_available()
    api_key_set = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    demo_active = is_demo_mode()
    demo_mgr = get_demo_manager()

    # In demo mode, judge is available only if provider is configured AND remaining quota > 0
    quota_exhausted = False
    rate_limit = None
    llm_limit = None
    llm_used = None
    llm_rem = None

    if demo_active:
        rate_limit = DEFAULT_GENERAL_LIMIT_PER_MINUTE
        stats = demo_mgr.get_llm_stats()
        llm_limit = stats["limit"]
        llm_used = stats["used"]
        llm_rem = stats["remaining"]
        if llm_rem <= 0:
            quota_exhausted = True

    gemini_key_set = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    gemini_model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    gemini_avail = gemini_key_set and (not quota_exhausted)

    llm_judge = get_llm_judge()
    configured_providers = llm_judge.get_configured_providers()
    judge_avail = (len(configured_providers) > 0 or api_key_set or gemini_key_set) and (not quota_exhausted)

    if judge_avail:
        active_provider = configured_providers[0] if configured_providers else ("gemini" if gemini_key_set else "anthropic")
        llm_status = f"ok ({active_provider})"
    elif quota_exhausted:
        active_provider = "fallback (quota_exhausted)"
        llm_status = "fallback:quota_exhausted"
    else:
        active_provider = "fallback (rules_only)"
        llm_status = "fallback:rules_only"

    clf_backend = get_classifier_backend()
    judge_model = gemini_model if gemini_key_set else os.environ.get("JUDGE_MODEL", "claude-haiku-4-5-20251001")
    agent_model = gemini_model if gemini_key_set else os.environ.get("AGENT_MODEL", "claude-sonnet-5")
    hf_id = os.environ.get("HF_CLASSIFIER_ID")

    degraded = not ocr_avail or not judge_avail

    return HealthResponse(
        status="ok",
        version="0.1.0",
        ocr_available=ocr_avail,
        classifier_backend=clf_backend,
        judge_available=judge_avail,
        anthropic_key_set=api_key_set,
        judge_model=judge_model,
        agent_model=agent_model,
        gemini_key_set=gemini_key_set,
        gemini_available=gemini_avail,
        gemini_model=gemini_model,
        hf_classifier_id=hf_id,
        degraded_mode=degraded,
        demo_mode=demo_active,
        rate_limit_per_minute=rate_limit,
        daily_llm_calls_limit=llm_limit,
        daily_llm_calls_used=llm_used,
        daily_llm_calls_remaining=llm_rem,
        llm_judge_provider=active_provider,
        llm_judge_status=llm_status,
        llm_providers_configured=configured_providers,
    )
