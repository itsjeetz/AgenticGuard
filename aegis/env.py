"""Centralized environment loading and API key tracking (§Secrets)."""

import logging
import os
from pathlib import Path
from typing import Any
from dotenv import dotenv_values, load_dotenv

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_ENV_LOADED = False


def mask_key_suffix(val: Any) -> str:
    """Mask key displaying only last 4 characters, or <none>/***."""
    if not val:
        return "<none>"
    s = str(val).strip()
    if len(s) <= 4:
        return "***"
    return f"...{s[-4:]}"


def load_environment(override: bool = True) -> dict[str, dict[str, str]]:
    """Load .env and .env.local with override=True, logging key name, masked suffix, and source."""
    global _ENV_LOADED

    env_path = PROJECT_ROOT / ".env"
    local_path = PROJECT_ROOT / ".env.local"

    # Inspect pre-existing environment variables
    pre_env = dict(os.environ)

    # Check file contents without polluting os.environ yet
    file_sources: dict[str, str] = {}
    if env_path.exists():
        for k in dotenv_values(env_path).keys():
            file_sources[k] = ".env file"
    if local_path.exists():
        for k in dotenv_values(local_path).keys():
            file_sources[k] = ".env.local file"

    # Load with override=True
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=override)
    if local_path.exists():
        load_dotenv(dotenv_path=local_path, override=override)

    # Harmonize primary alias variables from files if present
    if "GROQ_API_KEY_1" in file_sources and "GROQ_API_KEY" not in file_sources:
        os.environ["GROQ_API_KEY"] = os.environ.get("GROQ_API_KEY_1", "")
        file_sources["GROQ_API_KEY"] = file_sources["GROQ_API_KEY_1"]
    elif "GROQ_API_KEY" in file_sources and "GROQ_API_KEY_1" not in file_sources:
        os.environ["GROQ_API_KEY_1"] = os.environ.get("GROQ_API_KEY", "")
        file_sources["GROQ_API_KEY_1"] = file_sources["GROQ_API_KEY"]

    if "GEMINI_API_KEY" in file_sources and "GEMINI_API_KEY_1" not in file_sources:
        os.environ["GEMINI_API_KEY_1"] = os.environ.get("GEMINI_API_KEY", "")
        file_sources["GEMINI_API_KEY_1"] = file_sources["GEMINI_API_KEY"]
    elif "GEMINI_API_KEY_1" in file_sources and "GEMINI_API_KEY" not in file_sources:
        os.environ["GEMINI_API_KEY"] = os.environ.get("GEMINI_API_KEY_1", "")
        file_sources["GEMINI_API_KEY"] = file_sources["GEMINI_API_KEY_1"]

    tracked_keys = [
        "GROQ_API_KEY",
        "GROQ_API_KEY_1",
        "GROQ_API_KEY_2",
        "GROQ_KEY",
        "GROQ_KEY_2",
        "GEMINI_API_KEY",
        "GEMINI_API_KEY_1",
        "GEMINI_API_KEY_2",
        "GOOGLE_API_KEY",
        "GOOGLE_API_KEY_2",
        "ANTHROPIC_API_KEY",
        "MISTRAL_API_KEY",
        "OPENROUTER_API_KEY",
    ]

    key_summary: dict[str, dict[str, str]] = {}
    for kn in tracked_keys:
        val = os.environ.get(kn)
        if val:
            masked = mask_key_suffix(val)
            # Source determination
            if kn in file_sources:
                source = file_sources[kn]
            elif kn in pre_env:
                source = "environment"
            else:
                source = "unknown"

            key_summary[kn] = {"masked": masked, "source": source}
            if not _ENV_LOADED:
                log_line = f"[Env Startup] {kn}: {masked} (source: {source})"
                print(log_line)
                logger.info(log_line)

    _ENV_LOADED = True
    return key_summary
