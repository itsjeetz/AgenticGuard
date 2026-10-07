"""Operational endpoints: audit, metrics, feedback, policy, guards, agent sandbox (§10)."""

import json
from pathlib import Path
from typing import Any, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from aegis.models import InputSource
from aegis.guard.egress import get_egress_guard
from aegis.guard.memory import get_memory_guard
from aegis.guard.tool_guard import GuardContext, get_tool_guard
from aegis.observability.audit import get_audit_logger
from aegis.observability.metrics import get_metrics_tracker
from aegis.policy.config import get_policy, save_policy
from aegis.review_queue import (
    add_feedback,
    approve_feedback,
    get_review_queue,
    reject_feedback,
)
from agent.victim import run_scenario, run_custom_comparison
from server.demo_mode import is_demo_mode

router = APIRouter(prefix="/api", tags=["ops"])


# -------------------------------------------------------------------------
# Audit and Metrics (§8.1, §10)
# -------------------------------------------------------------------------

@router.get("/audit")
def query_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    source: Optional[str] = None,
    action: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Query structured firewall audit records."""
    audit_logger = get_audit_logger()
    return audit_logger.query(limit=limit, offset=offset, source=source, action=action)


@router.get("/metrics")
def get_system_metrics() -> dict[str, Any]:
    """Retrieve aggregate firewall performance metrics and percentiles."""
    metrics_tracker = get_metrics_tracker()
    return metrics_tracker.get_metrics()


# -------------------------------------------------------------------------
# Feedback Loop and Retraining (§8.2, §10)
# -------------------------------------------------------------------------

class FeedbackSubmission(BaseModel):
    request_id: str
    label: str  # "false_positive" or "false_negative"
    note: str = ""
    content: Optional[str] = None


@router.post("/feedback")
def submit_feedback_item(payload: FeedbackSubmission) -> dict[str, Any]:
    """Submit a false positive / false negative finding to the review queue."""
    if payload.label not in ("false_positive", "false_negative"):
        raise HTTPException(status_code=400, detail="Label must be 'false_positive' or 'false_negative'")

    item_id = add_feedback(
        request_id=payload.request_id,
        label=payload.label,
        note=payload.note,
        content=payload.content,
    )
    return {"id": item_id, "status": "pending", "request_id": payload.request_id}


@router.get("/review-queue")
def list_review_queue(status: Optional[str] = None) -> list[dict[str, Any]]:
    """List pending or approved review queue items."""
    return get_review_queue(status=status)


@router.post("/review-queue/{item_id}/approve")
def approve_review_item(item_id: int) -> dict[str, Any]:
    """Approve a review queue item for future model retraining."""
    if is_demo_mode():
        raise HTTPException(status_code=403, detail="Modifying the review queue is disabled in public demo mode.")
    success = approve_feedback(item_id)
    if not success:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"id": item_id, "status": "approved"}


@router.post("/review-queue/{item_id}/reject")
def reject_review_item(item_id: int) -> dict[str, Any]:
    """Reject a review queue item."""
    if is_demo_mode():
        raise HTTPException(status_code=403, detail="Modifying the review queue is disabled in public demo mode.")
    success = reject_feedback(item_id)
    if not success:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"id": item_id, "status": "rejected"}


@router.post("/train")
def trigger_retraining() -> dict[str, Any]:
    """Deprecated: ML classifier replaced with Provider-Agnostic LLM Judge."""
    if is_demo_mode():
        raise HTTPException(status_code=403, detail="Model retraining is disabled in public demo mode.")
    return {
        "status": "deprecated",
        "message": "The self-trained classifier has been replaced with the Provider-Agnostic LLM Judge. Retraining is not required.",
    }


# -------------------------------------------------------------------------
# Policy Configuration (§4, §10)
# -------------------------------------------------------------------------

@router.get("/policy")
def get_current_policy() -> dict[str, Any]:
    """Read active policy thresholds, multipliers, and limits."""
    return get_policy().model_dump()


@router.put("/policy")
def update_firewall_policy(policy_data: dict[str, Any]) -> dict[str, Any]:
    """Hot-reload and persist updated firewall policy settings."""
    if is_demo_mode():
        raise HTTPException(status_code=403, detail="Modifying firewall policy is disabled in public demo mode.")
    try:
        updated = save_policy(policy_data)
        return {"status": "updated", "policy": updated.model_dump()}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid policy schema: {exc}")


# -------------------------------------------------------------------------
# Guard Check Endpoints (§6, §10)
# -------------------------------------------------------------------------

class ToolGuardCheckRequest(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    session_id: str


@router.post("/guard/tool-call")
def check_tool_call(payload: ToolGuardCheckRequest) -> dict[str, Any]:
    """Check tool execution against tool tiers and taint state."""
    tool_guard = get_tool_guard()
    ctx = GuardContext(session_id=payload.session_id)
    res = tool_guard.check(payload.tool, payload.args, ctx)
    return {
        "tool": payload.tool,
        "decision": res.action,
        "reason": res.reason,
        "tier": res.tier.value,
    }


class EgressCheckRequest(BaseModel):
    text: str
    session_id: Optional[str] = None


@router.post("/guard/output")
def check_agent_output(payload: EgressCheckRequest) -> dict[str, Any]:
    """Check agent output for credentials, canary exfiltration, or leaked prompts."""
    egress_guard = get_egress_guard()
    verdict = egress_guard.scan_output(payload.text, payload.session_id or "")
    return {
        "action": verdict.action,
        "text": verdict.text,
        "reasons": verdict.reasons,
        "blocked_canary": verdict.blocked_canary,
        "findings_count": len(verdict.findings),
    }


class MemoryCheckRequest(BaseModel):
    text: str
    source: str = "user_message"
    session_id: Optional[str] = None


@router.post("/guard/memory-write")
def check_memory_write(payload: MemoryCheckRequest) -> dict[str, Any]:
    """Inspect prospective memory writes for context poisoning or authority spoofing."""
    from aegis.models import InputSource
    try:
        src = InputSource(payload.source)
    except Exception:
        src = InputSource.USER_MESSAGE
    memory_guard = get_memory_guard()
    verdict = memory_guard.check_memory_write(payload.text, source=src, session_id=payload.session_id or "")
    return {
        "action": verdict.action,
        "sanitized_text": verdict.sanitized_text,
        "reasons": verdict.reasons,
        "findings_count": len(verdict.findings),
    }


# -------------------------------------------------------------------------
# Agent Sandbox & Eval Runs (§7, §9, §10)
# -------------------------------------------------------------------------

class AgentRunPayload(BaseModel):
    scenario_id: str
    protected: bool = True


@router.post("/agent/run")
def run_victim_agent_scenario(payload: AgentRunPayload) -> dict[str, Any]:
    """Execute a victim agent scenario (S1-S9, B1-B3) unprotected or protected."""
    try:
        report = run_scenario(payload.scenario_id, protected=payload.protected)
        return {
            "scenario_id": report.scenario_id,
            "attack_type": report.attack_type,
            "carrier": report.carrier,
            "technique": report.technique,
            "protected": report.protected,
            "attack_succeeded": report.attack_succeeded,
            "benign_task_succeeded": report.benign_task_succeeded,
            "tool_calls_attempted": report.tool_calls_attempted,
            "tool_calls_blocked": report.tool_calls_blocked,
            "canary_leaked": report.canary_leaked,
            "final_response": report.final_response,
            "execution_log": report.execution_log,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scenario execution failed: {exc}")


class CustomAgentComparePayload(BaseModel):
    content: Optional[str] = None
    source_type: Optional[str] = None
    user_task: str = "Summarize this content for me."
    runs: int = 1


@router.post("/agent/compare/custom")
async def compare_victim_agent_custom(request: Request) -> dict[str, Any]:
    """Execute side-by-side comparison on user-supplied custom content (§7).
    
    Supports both JSON and Multipart (with optional file upload).
    Enforces rate limits, quotas, content size, and runs caps.
    """
    content_type = request.headers.get("content-type", "").lower()
    content_data: bytes | str = ""
    source_str: Optional[str] = None
    user_task: str = "Summarize this content for me."
    runs: int = 1
    filename: Optional[str] = None

    try:
        if "application/json" in content_type:
            body = await request.json()
            payload = CustomAgentComparePayload.model_validate(body)
            content_data = payload.content or ""
            source_str = payload.source_type
            user_task = payload.user_task or "Summarize this content for me."
            runs = payload.runs
        elif "multipart/form-data" in content_type:
            form = await request.form()
            file = form.get("file")
            content_field = form.get("content")
            source_str = form.get("source_type") or form.get("source")
            user_task = str(form.get("user_task") or "Summarize this content for me.")
            runs_val = form.get("runs")
            try:
                runs = int(runs_val) if runs_val else 1
            except ValueError:
                runs = 1

            if file is not None and hasattr(file, "read"):
                content_data = await file.read()
                filename = getattr(file, "filename", None)
            elif content_field:
                content_data = str(content_field)
            else:
                raise HTTPException(status_code=400, detail="No content or file provided for comparison.")
        else:
            try:
                body = await request.json()
                payload = CustomAgentComparePayload.model_validate(body)
                content_data = payload.content or ""
                source_str = payload.source_type
                user_task = payload.user_task or "Summarize this content for me."
                runs = payload.runs
            except Exception:
                raise HTTPException(status_code=400, detail="Must provide either JSON content or multipart form data.")

        if not content_data:
            raise HTTPException(status_code=400, detail="Content cannot be empty.")

        if len(content_data) > 200_000:
            raise HTTPException(
                status_code=400,
                detail="Content exceeds maximum allowed size (200,000 characters / bytes).",
            )

        runs = min(max(int(runs), 1), 5)

        if is_demo_mode():
            from server.demo_mode import get_demo_manager
            mgr = get_demo_manager()
            if not mgr.can_call_llm():
                gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
                anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
                if gemini_key or anthropic_key:
                    stats = mgr.get_llm_stats()
                    raise HTTPException(
                        status_code=429,
                        detail=f"Daily LLM quota exceeded ({stats['used']}/{stats['limit']} calls used). Requests are limited in demo mode.",
                    )

        src = None
        if source_str:
            try:
                src = InputSource(source_str)
            except Exception:
                src = None

        result = await run_in_threadpool(
            run_custom_comparison,
            content=content_data,
            source_type=src,
            user_task=user_task,
            runs=runs,
            filename=filename,
        )
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Custom comparison failed: {exc}")


@router.get("/eval/latest")
def get_latest_eval_report() -> dict[str, Any]:
    """Retrieve the latest evaluation report from disk."""
    report_file = Path("reports/report.json")
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="No evaluation report found. Run evaluation first.")
    try:
        return json.loads(report_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error reading report: {exc}")


@router.get("/eval/report-markdown")
def get_eval_report_markdown() -> dict[str, str]:
    """Retrieve the latest markdown evaluation report (EVAL_REPORT.md)."""
    report_file = Path("reports/EVAL_REPORT.md")
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="No markdown evaluation report found.")
    try:
        content = report_file.read_text(encoding="utf-8")
        return {"markdown": content}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error reading report: {exc}")


@router.get("/eval/live-checks")
def get_live_demo_checks() -> dict[str, Any]:
    """Evaluate the 6 demo files (demo_data/custom_scenarios/ex1-ex3) live."""
    from aegis.pipeline import FirewallPipeline
    from aegis.models import InputSource
    from eval.run_eval import load_item_content

    pipeline = FirewallPipeline()
    files = [
        ("ex1_attack_ticket.txt", "Support Ticket", "Attack", InputSource.USER_MESSAGE),
        ("ex1_benign_ticket.txt", "Support Ticket", "Benign", InputSource.USER_MESSAGE),
        ("ex2_attack_api.json", "CRM API Payload", "Attack", InputSource.API_RESPONSE),
        ("ex2_benign_api.json", "CRM API Payload", "Benign", InputSource.API_RESPONSE),
        ("ex3_attack_email.eml", "Partner Email", "Attack", InputSource.EMAIL),
        ("ex3_benign_email.eml", "Partner Email", "Benign", InputSource.EMAIL),
    ]

    results = []
    for fname, ftype, expected, src in files:
        fpath = Path("demo_data/custom_scenarios") / fname
        if not fpath.exists():
            continue
        content, _ = load_item_content(str(fpath))
        verdict = pipeline.process(content, source=src, filename=fname, neutralize_content=True)
        detected_names = [c.value if hasattr(c, "value") else str(c) for c in verdict.detected]
        results.append({
            "file": fname,
            "format": ftype,
            "expected": expected,
            "verdict": verdict.action,
            "risk": round(verdict.risk, 2),
            "categories": detected_names,
            "passed": (verdict.action != "ALLOW") if expected == "Attack" else (verdict.action == "ALLOW"),
        })
    passed_cnt = sum(1 for r in results if r["passed"])
    return {
        "total": len(results),
        "passed": passed_cnt,
        "failed": len(results) - passed_cnt,
        "checks": results,
    }


@router.post("/eval/run")
def trigger_eval_run() -> dict[str, Any]:
    """Trigger a new live evaluation run."""
    if is_demo_mode():
        raise HTTPException(
            status_code=403,
            detail="Live evaluation runs are disabled in public demo mode. Pre-generated benchmark reports are served under /api/eval/latest."
        )
    try:
        from eval.benchmark import run_benchmark
        report = run_benchmark()
        return {"status": "success", "report": report}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Evaluation run failed: {exc}")


@router.post("/redteam/run")
def trigger_redteam_run() -> dict[str, Any]:
    """Trigger adversarial red-team mutation generation."""
    if is_demo_mode():
        raise HTTPException(
            status_code=403,
            detail="Adversarial red-team generation is disabled in public demo mode."
        )
    try:
        from eval.redteam import RedTeamRunner
        runner = RedTeamRunner()
        return {"status": "success", "results": "Red-team run complete"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Red-team run failed: {exc}")
