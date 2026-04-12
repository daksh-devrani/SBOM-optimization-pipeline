"""
Centralized configuration for the research validation pipeline.

All magic values live here. Settings are read from environment variables
with sensible defaults. Use get_settings() to obtain a Settings instance.
"""

import os
from dataclasses import dataclass, field

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv optional; env vars may be set externally


@dataclass
class Settings:
    llm_model: str
    llm_api_key: str
    llm_base_url: str
    confidence_threshold: float
    supported_languages: list
    output_dir: str
    log_level: str


def get_settings() -> Settings:
    """
    Build a Settings instance from environment variables.

    Environment variables:
        RESEARCH_LLM_MODEL          LLM model name (default: gpt-4o-mini)
        OPENAI_API_KEY              OpenAI API key (also checked: GROQ_API_KEY)
        RESEARCH_LLM_BASE_URL       Base URL for OpenAI-compatible APIs
        RESEARCH_CONFIDENCE_THRESHOLD  Float threshold for LLM decisions (default: 0.75)
        RESEARCH_OUTPUT_DIR         Output directory (default: research_outputs)
        RESEARCH_LOG_LEVEL          Logging level (default: INFO)
    """
    # Try OpenAI key first, fall back to Groq key for OpenAI-compatible usage
    api_key = (
        os.environ.get("OPENAI_API_KEY", "")
        or os.environ.get("GROQ_API_KEY", "")
    )

    try:
        threshold = float(os.environ.get("RESEARCH_CONFIDENCE_THRESHOLD", "0.75"))
    except ValueError:
        threshold = 0.75

    return Settings(
        llm_model=os.environ.get("RESEARCH_LLM_MODEL", "gpt-4o-mini"),
        llm_api_key=api_key,
        llm_base_url=os.environ.get("RESEARCH_LLM_BASE_URL", ""),
        confidence_threshold=threshold,
        supported_languages=["python"],
        output_dir=os.environ.get("RESEARCH_OUTPUT_DIR", "research_outputs"),
        log_level=os.environ.get("RESEARCH_LOG_LEVEL", "INFO"),
    )
