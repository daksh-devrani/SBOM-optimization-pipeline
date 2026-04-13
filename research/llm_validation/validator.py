"""
LLM validation module for uncertain vulnerability cases.

For vulnerabilities that pass all static rules (UNCERTAIN), this module
calls an OpenAI-compatible LLM with a structured prompt to determine:
  1. Is the vulnerability actually exploitable in this codebase context?
  2. How confident is the assessment?
  3. What is the reasoning?

Temperature is always 0 for determinism. Response must be strict JSON.
"""

import json
from typing import Optional

import openai

from research.config.settings import Settings, get_settings
from research.models import LLMResult, StaticSignals, Vulnerability
from research.utils.logger import get_logger

logger = get_logger(__name__)

# ── System prompt (constant) ──────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are a security expert analyzing software vulnerabilities. "
    "You must respond ONLY with valid JSON matching exactly this schema:\n"
    "{\n"
    '  "exploitable": <boolean>,\n'
    '  "confidence": <float between 0.0 and 1.0>,\n'
    '  "reasoning": <string>\n'
    "}\n"
    "Do not include any text outside of this JSON object. "
    "No markdown, no explanation, no code fences — raw JSON only."
)

# ── Safe default returned when LLM call fails ─────────────────────────────────

_SAFE_DEFAULT_KEEP = LLMResult(
    exploitable=True,
    confidence=0.0,
    reasoning="LLM validation failed or was unavailable — defaulting to KEEP (safe fallback).",
    raw_response="",
)


def build_prompt(
    vulnerability: Vulnerability,
    signals: StaticSignals,
    code_snippets: Optional[list[str]] = None,
) -> str:
    """
    Build the user-facing prompt for the LLM.

    Returns only the user message; the system message is defined as SYSTEM_PROMPT.

    Args:
        vulnerability:  The vulnerability to analyze.
        signals:        Static analysis signals for context.
        code_snippets:  Optional list of relevant code snippet strings.

    Returns:
        Formatted user prompt string.
    """
    affected = ", ".join(vulnerability.affected_functions) or "Unknown"

    lines = [
        "Analyze whether the following vulnerability is actually exploitable "
        "in the given codebase context.",
        "",
        "VULNERABILITY:",
        f"- CVE ID: {vulnerability.id}",
        f"- Package: {vulnerability.package} v{vulnerability.version}",
        f"- Severity: {vulnerability.severity}",
        f"- Description: {vulnerability.description}",
        f"- Affected Functions: {affected}",
        "",
        "STATIC ANALYSIS SIGNALS:",
        f"- Package is imported in codebase: {signals.package_used}",
        f"- Affected function is called: {signals.function_used}",
        f"- Call path to function exists: {signals.call_path_exists}",
        f"- User-controlled input reaches function: {signals.input_controlled}",
        f"- Sanitization detected before function call: {signals.sanitized}",
        f"- Import locations: {signals.import_locations}",
        f"- Function call locations: {signals.function_locations}",
    ]

    if code_snippets:
        lines.append("")
        lines.append("RELEVANT CODE SNIPPETS:")
        for i, snippet in enumerate(code_snippets, start=1):
            lines.append(f"--- Snippet {i} ---")
            lines.append(snippet)

    lines.extend([
        "",
        "Based on this context, determine:",
        "1. Is this vulnerability actually exploitable given the code context?",
        "2. How confident are you (0.0 = not confident, 1.0 = fully confident)?",
        "3. Provide brief reasoning.",
        "",
        "Respond ONLY with the JSON object.",
    ])

    return "\n".join(lines)


def call_llm(system_msg: str, user_msg: str, settings: Settings) -> str:
    """
    Call the LLM via the OpenAI client with JSON mode enabled.

    Args:
        system_msg: The system prompt string.
        user_msg:   The user prompt string.
        settings:   Settings instance with API key and model configuration.

    Returns:
        Raw string content from the LLM response.

    Raises:
        openai.OpenAIError: On API or network failure (caller handles this).
    """
    base_url = settings.llm_base_url if settings.llm_base_url else None
    client = openai.OpenAI(api_key=settings.llm_api_key, base_url=base_url)

    response = client.chat.completions.create(
        model=settings.llm_model,
        messages=[
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg},
        ],
        temperature=0,
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content


def parse_llm_response(raw: str) -> LLMResult:
    """
    Parse the raw LLM JSON string into an LLMResult.

    On any parse error, returns a safe default (exploitable=True, confidence=0.0)
    to prevent a failed parse from silently removing a real vulnerability.

    Args:
        raw: Raw string from the LLM response.

    Returns:
        Populated LLMResult.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error(
            "Failed to parse LLM JSON response",
            extra={"error": str(e), "raw_preview": raw[:200]},
        )
        return LLMResult(
            exploitable=True,
            confidence=0.0,
            reasoning="Failed to parse LLM response — defaulting to KEEP",
            raw_response=raw,
        )

    try:
        exploitable = bool(data.get("exploitable", True))
        raw_conf = data.get("confidence", 0.0)
        confidence = max(0.0, min(float(raw_conf), 1.0))
        reasoning = str(data.get("reasoning", ""))
    except (TypeError, ValueError) as e:
        logger.error(
            "LLM response had unexpected field types",
            extra={"error": str(e), "data": data},
        )
        return LLMResult(
            exploitable=True,
            confidence=0.0,
            reasoning="LLM response fields had unexpected types — defaulting to KEEP",
            raw_response=raw,
        )

    return LLMResult(
        exploitable=exploitable,
        confidence=confidence,
        reasoning=reasoning,
        raw_response=raw,
    )


def validate_with_llm(
    vulnerability: Vulnerability,
    signals: StaticSignals,
    code_snippets: Optional[list[str]] = None,
) -> LLMResult:
    """
    Top-level function: validate a vulnerability using the LLM.

    Handles missing API key, LLM errors, and JSON parse failures gracefully.
    Always returns an LLMResult — never raises.

    Args:
        vulnerability:  The vulnerability to validate.
        signals:        Static analysis signals for the vulnerability.
        code_snippets:  Optional list of relevant code snippets.

    Returns:
        LLMResult with exploitability assessment and confidence.
    """
    settings = get_settings()

    if not settings.llm_api_key:
        logger.warning(
            "LLM API key not configured — skipping LLM validation",
            extra={"vulnerability_id": vulnerability.id},
        )
        return LLMResult(
            exploitable=True,
            confidence=0.0,
            reasoning="LLM API key not configured — defaulting to KEEP",
            raw_response="",
        )

    user_prompt = build_prompt(vulnerability, signals, code_snippets)

    logger.info(
        "Calling LLM for validation",
        extra={
            "vulnerability_id": vulnerability.id,
            "model": settings.llm_model,
        },
    )

    try:
        raw = call_llm(SYSTEM_PROMPT, user_prompt, settings)
        result = parse_llm_response(raw)

        logger.info(
            "LLM validation complete",
            extra={
                "vulnerability_id": vulnerability.id,
                "exploitable": result.exploitable,
                "confidence": result.confidence,
            },
        )
        return result

    except Exception as e:
        logger.error(
            "LLM call failed",
            extra={"vulnerability_id": vulnerability.id, "error": str(e)},
        )
        return _SAFE_DEFAULT_KEEP
