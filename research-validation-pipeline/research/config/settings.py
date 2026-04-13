from pydantic import BaseModel, Field
import os
from dataclasses import dataclass

def get_settings() -> 'Settings':
    return Settings(
        llm_model=os.environ.get("RESEARCH_LLM_MODEL", "gpt-4o-mini"),
        llm_api_key=os.environ.get("OPENAI_API_KEY", ""),
        llm_base_url=os.environ.get("RESEARCH_LLM_BASE_URL", ""),
        confidence_threshold=float(os.environ.get("RESEARCH_CONFIDENCE_THRESHOLD", "0.75")),
        supported_languages=["python"],
        output_dir=os.environ.get("RESEARCH_OUTPUT_DIR", "research_outputs"),
        log_level=os.environ.get("RESEARCH_LOG_LEVEL", "INFO"),
    )

@dataclass
class Settings:
    llm_model: str
    llm_api_key: str
    llm_base_url: str
    confidence_threshold: float
    supported_languages: list[str]
    output_dir: str
    log_level: str