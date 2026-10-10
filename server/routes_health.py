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
    """Return health status and capabilities of the firewall (§10, §8.4)."""
    from aegis.judge_llm import get_llm_judge

    ocr_avail = is_ocr_available()
    demo_active = is_demo_mode()
    demo_mgr = get_demo_manager()

    stats = demo_mgr.get_llm_stats()
    llm_limit = stats["limit"]
    llm_used = stats["used"]
    llm_rem = stats["remaining"]
    quota_exhausted = llm_rem <= 0 and demo_active
    rate_limit = DEFAULT_GENERAL_LIMIT_PER_MINUTE

    llm_judge = get_llm_judge()
    configs = llm_judge.get_provider_configs()
    groq_model = configs.get("groq_1", configs.get("groq")).model
    gemini_model = configs.get("gemini_1", configs.get("gemini")).model

    gemini_key_set = bool(
        (configs.get("gemini_1") and configs["gemini_1"].api_key)
        or (configs.get("gemini_2") and configs["gemini_2"].api_key)
    )
    gemini_avail = gemini_key_set and (not quota_exhausted)

    configured_providers = llm_judge.get_configured_providers()
    provider_states = llm_judge.get_provider_states()
    judge_avail = (len(configured_providers) > 0) and (not quota_exhausted)

    # llm_judge_status is "ok (<provider>)" ONLY after a real successful call
    if llm_judge.last_provider and llm_judge.last_status and llm_judge.last_status.startswith("ok"):
        active_provider = llm_judge.last_provider
        llm_status = llm_judge.last_status
    elif quota_exhausted:
        active_provider = "fallback (quota_exhausted)"
        llm_status = "fallback:quota_exhausted"
    else:
        active_provider = "fallback (rules_only)"
        llm_status = "fallback:rules_only"

    clf_backend = get_classifier_backend()
    degraded = not ocr_avail or not judge_avail

    from eval.report import get_git_commit
    commit = get_git_commit()

    return HealthResponse(
        status="ok",
        version="0.1.0",
        git_commit=commit,
        ocr_available=ocr_avail,
        classifier_backend=clf_backend,
        judge_available=judge_avail,
        groq_model=groq_model,
        gemini_key_set=gemini_key_set,
        gemini_available=gemini_avail,
        gemini_model=gemini_model,
        degraded_mode=degraded,
        demo_mode=demo_active,
        rate_limit_per_minute=rate_limit,
        daily_llm_calls_limit=llm_limit,
        daily_llm_calls_used=llm_used,
        daily_llm_calls_remaining=llm_rem,
        llm_judge_provider=active_provider,
        llm_judge_status=llm_status,
        footer_label=llm_judge.get_footer_label(),
        llm_providers_configured=configured_providers,
        providers=provider_states,
    )


@router.post("/llm/retest")
def retest_llm_providers():
    """Retest all configured LLM providers making one tiny real call per provider."""
    from aegis.judge_llm import get_llm_judge

    llm_judge = get_llm_judge()
    results = llm_judge.retest_all_providers()
    return {
        "status": "ok",
        "results": results,
        "footer_label": llm_judge.get_footer_label(),
    }

