import sys
from pathlib import Path
from ai_engine.schemas.pipeline_state import PipelineState
from research.pipeline.run_validation import run_pipeline
from research.utils.logger import get_logger

logger = get_logger(__name__)

def validation_node(state: dict) -> dict:
    trivy_report_path = state.get("trivy_report_path", "")
    sbom_report_path = state.get("sbom_report_path", "")
    target_repo = state.get("target_repo", "")
    
    if not trivy_report_path or not sbom_report_path or not target_repo:
        logger.warning("Missing required paths for validation")
        return {"validation_report": None, "validation_errors": ["Missing required paths for validation"]}
    
    try:
        report = run_pipeline(sbom_path=sbom_report_path, trivy_path=trivy_report_path, repo_path=target_repo, output_dir="research_outputs", threshold=0.75, disable_llm=False)
        return {"validation_report": report.model_dump(), "validation_errors": report.errors}
    except Exception as e:
        return {"validation_report": None, "validation_errors": [str(e)]}