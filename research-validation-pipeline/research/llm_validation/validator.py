from typing import List, Optional
import openai
from research.models import Vulnerability, StaticSignals, LLMResult
from research.config.settings import get_settings
from research.utils.logger import get_logger
import json

logger = get_logger(__name__)

def build_prompt(vulnerability: Vulnerability, signals: StaticSignals, code_snippets: Optional[List[str]] = None) -> str:
    system_msg = (
        "You are a security expert analyzing software vulnerabilities. "
        "You must respond ONLY with valid JSON matching exactly this schema:\n"
        "{\n"
        "  \"exploitable\": <boolean>,\n"
        "  \"confidence\": <float between 0.0 and 1.0>,\n"
        "  \"reasoning\": <string>\n"
        "}\n"
        "Do not include any text outside of this JSON object."
    )
    
    user_msg = (
        "Analyze whether the following vulnerability is actually exploitable in the given codebase context.\n"
        "VULNERABILITY:\n"
        f"- CVE ID: {vulnerability.id}\n"
        f"- Package: {vulnerability.package} v{vulnerability.version}\n"
        f"- Severity: {vulnerability.severity}\n"
        f"- Description: {vulnerability.description}\n"
        f"- Affected Functions: {', '.join(vulnerability.affected_functions) or 'Unknown'}\n"
        "STATIC ANALYSIS SIGNALS:\n"
        f"- Package is imported in codebase: {signals.package_used}\n"
        f"- Affected function is called: {signals.function_used}\n"
        f"- Call path to function exists: {signals.call_path_exists}\n"
        f"- User-controlled input reaches function: {signals.input_controlled}\n"
        f"- Sanitization detected before function call: {signals.sanitized}\n"
        f"- Import locations: {signals.import_locations}\n"
        f"- Function call locations: {signals.function_locations}\n"
    )
    
    if code_snippets:
        user_msg += f"{'CODE_SNIPPETS_SECTION': {code_snippets}}"

    return f"{system_msg}\n{user_msg}"

def call_llm(prompt: str, settings) -> str:
    client = openai.OpenAI(api_key=settings.llm_api_key, base_url=settings.llm_base_url or None)
    response = client.chat.completions.create(
        model=settings.llm_model,
        messages=[
            {"role": "system", "content": prompt.split('\n')[0]},
            {"role": "user", "content": prompt}
        ],
        temperature=0,
        response_format={"type": "json_object"}
    )
    return response.choices[0].message.content

def parse_llm_response(raw: str) -> LLMResult:
    try:
        data = json.loads(raw)
        exploitable = bool(data.get("exploitable", True))
        confidence = max(0.0, min(float(data.get("confidence", 0.0)), 1.0))
        reasoning = data.get("reasoning", "")
    except json.JSONDecodeError:
        logger.error("Failed to parse LLM response: %s", raw)
        return LLMResult(exploitable=True, confidence=0.0, reasoning="Failed to parse LLM response", raw_response=raw)

    return LLMResult(exploitable=exploitable, confidence=confidence, reasoning=reasoning, raw_response=raw)

def validate_with_llm(vulnerability: Vulnerability, signals: StaticSignals, code_snippets: Optional[List[str]] = None) -> LLMResult:
    settings = get_settings()
    if not settings.llm_api_key:
        logger.warning("LLM API key not configured — defaulting to KEEP")
        return LLMResult(exploitable=True, confidence=0.0, reasoning="LLM API key not configured — defaulting to KEEP", raw_response="")

    prompt = build_prompt(vulnerability, signals, code_snippets)
    try:
        raw_response = call_llm(prompt, settings)
        llm_result = parse_llm_response(raw_response)
        logger.info("LLM response: %s", llm_result)
        return llm_result
    except Exception as e:
        logger.error("Error during LLM validation: %s", str(e))
        return LLMResult(exploitable=True, confidence=0.0, reasoning="Error during LLM validation", raw_response="")