from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from server.demo_mode import DemoRateLimitMiddleware
from server.routes_health import router as health_router
from server.routes_inspect import router as inspect_router
from server.routes_ops import router as ops_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-warm pipeline, classifier, and regex patterns in memory at startup (§10)."""
    try:
        from aegis.models import InputSource
        from aegis.pipeline import get_pipeline
        pipeline = get_pipeline()
        pipeline.process("Warmup prompt initialization", source=InputSource.USER_MESSAGE)
    except Exception:
        pass
    yield


app = FastAPI(
    title="AegisAgent Prompt Injection Firewall",
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

app.include_router(health_router)
app.include_router(inspect_router)
app.include_router(ops_router)


# Mount static files if directory exists
static_dir = Path(__file__).resolve().parent.parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
