"""Inspection and neutralization API endpoints supporting JSON and multipart upload (§10)."""

import logging
import secrets
from fastapi import APIRouter, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from aegis.models import InputSource, Trust, Verdict
from aegis.pipeline import get_pipeline
from aegis.resilience import fail_closed_verdict

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["inspection"])


class InspectJsonRequest(BaseModel):
    content: str
    source: InputSource | None = None
    session_id: str | None = None


@router.post("/inspect", response_model=Verdict)
async def inspect_content(request: Request) -> Verdict:
    """Analyze input content through firewall cascade and return detailed verdict."""
    pipeline = get_pipeline()
    content_type = request.headers.get("content-type", "")

    bypass_cache = (
        request.headers.get("cache-control") == "no-cache"
        or request.headers.get("x-bypass-cache") == "1"
        or request.query_params.get("fresh") == "1"
    )

    try:
        if "application/json" in content_type:
            body = await request.json()
            payload = InspectJsonRequest.model_validate(body)
            return await run_in_threadpool(
                pipeline.process,
                content=payload.content,
                source=payload.source,
                session_id=payload.session_id,
                neutralize_content=False,
                bypass_cache=bypass_cache,
            )
        elif "multipart/form-data" in content_type:
            form = await request.form()
            file = form.get("file")
            source_str = form.get("source")
            session_id = form.get("session_id")
            src = InputSource(source_str) if source_str else None

            if file is not None and hasattr(file, "read"):
                data = await file.read()
                filename = getattr(file, "filename", None)
                return await run_in_threadpool(
                    pipeline.process,
                    content=data,
                    source=src,
                    filename=filename,
                    session_id=str(session_id) if session_id else None,
                    neutralize_content=False,
                    bypass_cache=bypass_cache,
                )

            content_field = form.get("content")
            if content_field:
                return await run_in_threadpool(
                    pipeline.process,
                    content=str(content_field),
                    source=src,
                    session_id=str(session_id) if session_id else None,
                    neutralize_content=False,
                    bypass_cache=bypass_cache,
                )
            raise ValueError("No file or content provided in multipart request")
        else:
            raise ValueError("Must provide either JSON content or a multipart file upload.")
    except Exception as e:
        logger.exception("Error during /api/inspect: %s", e)
        return fail_closed_verdict(
            request_id=f"req-err-{secrets.token_hex(4)}",
            source=InputSource.USER_MESSAGE,
            trust=Trust.UNTRUSTED,
            content_sha256="",
            layer_status={"error": {"status": "error", "error": str(e)}},
            error_msg=str(e),
        )


@router.post("/neutralize", response_model=Verdict)
async def neutralize_content(request: Request) -> Verdict:
    """Analyze and sanitize input content, returning Verdict with sanitized_text and envelope_text."""
    pipeline = get_pipeline()
    content_type = request.headers.get("content-type", "")

    bypass_cache = (
        request.headers.get("cache-control") == "no-cache"
        or request.headers.get("x-bypass-cache") == "1"
        or request.query_params.get("fresh") == "1"
    )

    try:
        if "application/json" in content_type:
            body = await request.json()
            payload = InspectJsonRequest.model_validate(body)
            return await run_in_threadpool(
                pipeline.process,
                content=payload.content,
                source=payload.source,
                session_id=payload.session_id,
                neutralize_content=True,
                bypass_cache=bypass_cache,
            )
        elif "multipart/form-data" in content_type:
            form = await request.form()
            file = form.get("file")
            source_str = form.get("source")
            session_id = form.get("session_id")
            src = InputSource(source_str) if source_str else None

            if file is not None and hasattr(file, "read"):
                data = await file.read()
                filename = getattr(file, "filename", None)
                return await run_in_threadpool(
                    pipeline.process,
                    content=data,
                    source=src,
                    filename=filename,
                    session_id=str(session_id) if session_id else None,
                    neutralize_content=True,
                    bypass_cache=bypass_cache,
                )

            content_field = form.get("content")
            if content_field:
                return await run_in_threadpool(
                    pipeline.process,
                    content=str(content_field),
                    source=src,
                    session_id=str(session_id) if session_id else None,
                    neutralize_content=True,
                    bypass_cache=bypass_cache,
                )
            raise ValueError("No file or content provided in multipart request")
        else:
            raise ValueError("Must provide either JSON content or a multipart file upload.")
    except Exception as e:
        logger.exception("Error during /api/neutralize: %s", e)
        return fail_closed_verdict(
            request_id=f"req-err-{secrets.token_hex(4)}",
            source=InputSource.USER_MESSAGE,
            trust=Trust.UNTRUSTED,
            content_sha256="",
            layer_status={"error": {"status": "error", "error": str(e)}},
            error_msg=str(e),
        )

