from contextlib import asynccontextmanager
import os
from pathlib import Path
import re
import socket
import sys

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

# Load environment variables early from .env
load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = PROJECT_ROOT / "static"
DEFAULT_PORT = int(os.environ.get("PORT", "8000"))
DEFAULT_HOST = os.environ.get("HOST", "127.0.0.1")


def validate_port_available(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Print project path and port on startup, and fail if port is already in use (§4)."""
    # Do not execute port bind checks inside pytest or test runners
    if "pytest" in sys.modules or os.environ.get("PYTEST_CURRENT_TEST"):
        return

    # Guard against multiple executions in the same process
    if getattr(validate_port_available, "_checked", False):
        return
    validate_port_available._checked = True

    banner = (
        f"\n{'='*70}\n"
        f"[AgenticGuard Startup] Project Path: {PROJECT_ROOT}\n"
        f"[AgenticGuard Startup] Host: {host} | Port: {port}\n"
        f"{'='*70}\n"
    )
    sys.stdout.write(banner)
    sys.stdout.flush()

    # Pre-flight check: attempt to connect to detect an existing listening process
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(0.3)
        port_in_use = (s.connect_ex((host, port)) == 0)
    except Exception:
        port_in_use = False
    finally:
        s.close()

    if port_in_use:
        err_msg = (
            f"\n[AgenticGuard FATAL] Port {port} is already in use by another process!\n"
            f"Cannot start AgenticGuard server on {host}:{port}.\n"
            f"Silently coexisting with another listening service is strictly prevented.\n"
            f"Please terminate the process currently occupying port {port} or configure a different port.\n\n"
        )
        sys.stderr.write(err_msg)
        sys.stderr.flush()
        sys.exit(1)


# Execute pre-flight port and banner check at startup
validate_port_available(DEFAULT_HOST, DEFAULT_PORT)


class DevStaticFiles(StaticFiles):
    """StaticFiles subclass enforcing Cache-Control: no-store in development mode (§1)."""

    def is_not_modified(self, response_headers, request_headers) -> bool:
        return False

    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response


def get_static_versions() -> tuple[str, str, str]:
    """Generate dynamic version strings based on asset mtimes (§2, §3)."""
    app_js = STATIC_DIR / "app.js"
    style_css = STATIC_DIR / "style.css"

    js_v = str(int(app_js.stat().st_mtime)) if app_js.exists() else "1.0.0"
    css_v = str(int(style_css.stat().st_mtime)) if style_css.exists() else "1.0.0"
    build_label = f"v0.1.0-dev.{js_v[-6:]}"
    return js_v, css_v, build_label


def render_versioned_index() -> str:
    """Read index.html and inject auto-generated cache-busting query strings and build label."""
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return "<h1>AgenticGuard Dashboard</h1>"

    content = index_file.read_text(encoding="utf-8")
    js_v, css_v, build_label = get_static_versions()

    # Automatically reference app.js and style.css with version query string
    content = re.sub(r'href="style\.css(?:\?v=[^"]*)?"', f'href="style.css?v={css_v}"', content)
    content = re.sub(r'href="/static/style\.css(?:\?v=[^"]*)?"', f'href="/static/style.css?v={css_v}"', content)
    content = re.sub(r'src="app\.js(?:\?v=[^"]*)?"', f'src="app.js?v={js_v}"', content)
    content = re.sub(r'src="/static/app\.js(?:\?v=[^"]*)?"', f'src="/static/app.js?v={js_v}"', content)

    # Inject visible build version label
    content = re.sub(
        r'(<span id="buildVersionValue">)[^<]*(</span>)',
        rf'\g<1>{build_label}\g<2>',
        content,
    )

    # Inject visible LLM Judge provider or fallback status (§5)
    try:
        from aegis.judge_llm import get_llm_judge
        judge = get_llm_judge()
        providers = judge.get_configured_providers()
        if providers:
            judge_tag_text = f"LLM judge: {providers[0]}"
        else:
            judge_tag_text = "LLM judge: fallback (rules_only)"
    except Exception:
        judge_tag_text = "LLM judge: fallback (rules_only)"

    content = re.sub(
        r'(<span class="llm-judge-tag" id="footerLlmJudge">)[^<]*(</span>)',
        rf'\g<1>{judge_tag_text}\g<2>',
        content,
    )
    return content


def sync_index_file_on_disk() -> None:
    """Keep static/index.html synced on disk with latest version strings."""
    try:
        index_file = STATIC_DIR / "index.html"
        if index_file.exists():
            updated = render_versioned_index()
            current = index_file.read_text(encoding="utf-8")
            if updated != current:
                index_file.write_text(updated, encoding="utf-8")
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-warm pipeline, sync static versions, and initialize in-memory guards (§10)."""
    sync_index_file_on_disk()
    try:
        from aegis.models import InputSource
        from aegis.pipeline import get_pipeline

        pipeline = get_pipeline()
        pipeline.process("Warmup prompt initialization", source=InputSource.USER_MESSAGE)
    except Exception:
        pass
    yield


from server.demo_mode import DemoRateLimitMiddleware
from server.routes_health import router as health_router
from server.routes_inspect import router as inspect_router
from server.routes_ops import router as ops_router

app = FastAPI(
    title="AgenticGuard Prompt Injection Firewall",
    description="Multi-layer prompt injection firewall with offset-mapped sanitization and runtime guards.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(DemoRateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def dev_cache_control_middleware(request: Request, call_next):
    """Enforce Cache-Control: no-store for static files and dashboard pages in dev mode (§1)."""
    response = await call_next(request)
    path = request.url.path
    if (
        path.startswith("/static")
        or path.endswith((".js", ".css", ".html"))
        or path in ("/", "/index.html")
    ):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


app.include_router(health_router)
app.include_router(inspect_router)
app.include_router(ops_router)


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve dynamically versioned dashboard with Cache-Control: no-store (§1, §2)."""
    return HTMLResponse(
        content=render_versioned_index(),
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get("/index.html", response_class=HTMLResponse)
async def serve_index_html():
    """Serve dynamically versioned index.html with Cache-Control: no-store (§1, §2)."""
    return HTMLResponse(
        content=render_versioned_index(),
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


# Mount /static directory with DevStaticFiles (no-store headers)
if STATIC_DIR.exists():
    app.mount("/static", DevStaticFiles(directory=str(STATIC_DIR)), name="static_dir")
    app.mount("/", DevStaticFiles(directory=str(STATIC_DIR), html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    validate_port_available(host, port)
    uvicorn.run("server.main:app", host=host, port=port, reload=True)
