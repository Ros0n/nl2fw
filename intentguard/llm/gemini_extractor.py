from __future__ import annotations

import json
from typing import Any, Dict

from google import genai
from google.genai import errors as genai_errors

from ..config import settings
from .extraction_models import ExtractedIntent


SYSTEM_PROMPT = """You are IntentGuard's extraction component.

Your behaviour should follow best practices from:
- NetConfEval (CoNEXT 2024) on reliable, benchmarkable network config extraction.
- "Natural Language Inference for Firewall Configuration" (ArXiv, 2024) on schema-bound IR.
- Capirca (Google) on separating high-level policy from backend syntax.

You must output ONLY JSON that conforms to the provided JSON Schema.

Hard constraints:
- Treat this as information extraction, not generation.
- Never generate firewall syntax (no iptables, no chains, no CLI).
- Never invent IPs, CIDRs, ports, or protocols that are not grounded in the text or context.
- Only reference zones/objects/services that appear in the provided context.
- If uncertain, leave fields null/empty and add a short ambiguity note.
"""


def extract_intent(
    *,
    nl_policy: str,
    context_index: Dict[str, Any],
    model: str = "gemini-2.5-flash",
) -> ExtractedIntent:
    """Use Gemini for schema-bound extraction only (JSON output).
    
    Args:
        nl_policy: Natural language firewall policy description
        context_index: Context dictionary with zones, objects, and services
        model: Gemini model to use (default: gemini-2.5-flash)
        
    Returns:
        ExtractedIntent: Validated schema-bound extraction result
        
    Raises:
        RuntimeError: If API quota exceeded, API key invalid, or network error occurs
    """
    # Validate that API key is available
    if not settings.GEMINI_API_KEY:
        raise RuntimeError(
            "Gemini API key not configured. "
            "Please set GEMINI_API_KEY in your environment or .env file."
        )

    try:
        client = genai.Client(api_key=settings.GEMINI_API_KEY)
    except Exception as e:
        raise RuntimeError(
            f"Failed to initialize Gemini client: {e}\n"
            "Check that GEMINI_API_KEY is valid and has proper permissions."
        ) from e

    prompt = {
        "nl_policy": nl_policy,
        "context_index": context_index,
        "instructions": {
            "allowed_actions": ["allow", "deny", "reject"],
            "note": "Use ONLY names from context_index; do not invent new names.",
        },
    }

    try:
        resp = client.models.generate_content(
            model=model,
            contents=[
                {"role": "user", "parts": [{"text": SYSTEM_PROMPT + "\n\n" + json.dumps(prompt)}]}
            ],
            config={
                "response_mime_type": "application/json",
                "response_json_schema": ExtractedIntent.model_json_schema(),
                "temperature": 0,
            },
        )
    except genai_errors.ClientError as e:
        # Common failure modes
        error_msg = str(e)
        if getattr(e, "status_code", None) == 429 or "RESOURCE_EXHAUSTED" in error_msg:
            raise RuntimeError(
                "Gemini API quota/rate-limit exceeded (429 RESOURCE_EXHAUSTED). "
                "Either wait/upgrade billing, or run the CLI with --extracted-json to "
                "skip the live LLM call for a deterministic demo."
            ) from e
        elif getattr(e, "status_code", None) == 401 or "UNAUTHENTICATED" in error_msg:
            raise RuntimeError(
                "Gemini API authentication failed (401 UNAUTHENTICATED). "
                "Check that GEMINI_API_KEY is valid and not expired."
            ) from e
        elif getattr(e, "status_code", None) == 403 or "PERMISSION_DENIED" in error_msg:
            raise RuntimeError(
                "Gemini API permission denied (403 PERMISSION_DENIED). "
                "Your API key may not have access to this model."
            ) from e
        else:
            raise RuntimeError(
                f"Gemini API error: {error_msg}"
            ) from e
    except Exception as e:
        raise RuntimeError(
            f"Unexpected error during Gemini extraction: {e}"
        ) from e

    # SDK returns text JSON; parse strictly
    try:
        data = json.loads(resp.text)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Failed to parse Gemini response as JSON: {e}\n"
            f"Response: {resp.text[:200]}"
        ) from e
    
    try:
        return ExtractedIntent.model_validate(data)
    except Exception as e:
        raise RuntimeError(
            f"Extracted intent failed schema validation: {e}"
        ) from e
