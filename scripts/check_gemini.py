"""Script to verify Google Gemini API connectivity for AgenticGuard."""

import os
import sys
from pathlib import Path

# Ensure root directory is on sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from aegis.env import load_environment
load_environment(override=True)


def check_gemini() -> bool:
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    model_name = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

    print("==================================================")
    print("AgenticGuard - Gemini Connectivity Verification")
    print("==================================================")
    print(f"Target Model : {model_name}")

    if not api_key or api_key == "your_key_here":
        print("[!] GEMINI_API_KEY is not configured in .env or environment.")
        print("[i] To enable Gemini L3c Judge and Agent Sandbox:")
        print("    1. Create a .env file from .env.example")
        print("    2. Set GEMINI_API_KEY=your_actual_gemini_api_key")
        print("[i] AgenticGuard will operate in graceful degraded fallback mode (Rules + ML Classifier).")
        return False

    # Mask key for secure display
    masked_key = api_key[:4] + "..." + api_key[-4:] if len(api_key) > 8 else "***"
    print(f"API Key      : {masked_key} (Format detected)")

    try:
        from google import genai
        from google.genai import types

        print("[*] Initializing official google-genai client...")
        client = genai.Client(api_key=api_key)

        print(f"[*] Sending ping test to {model_name}...")
        response = client.models.generate_content(
            model=model_name,
            contents="Respond strictly with the single word: OK",
            config=types.GenerateContentConfig(
                temperature=0.0,
                max_output_tokens=10,
            ),
        )

        reply = response.text.strip() if response and response.text else ""
        print(f"[+] Response received: {reply!r}")
        print("[+] SUCCESS: Gemini API connection verified and active for AgenticGuard!")
        return True

    except Exception as exc:
        print(f"[-] ERROR: Failed to connect to Gemini API: {exc}")
        print("[i] Check your network connection, API key permissions, and model availability.")
        return False


if __name__ == "__main__":
    success = check_gemini()
    sys.exit(0 if success else 1)
