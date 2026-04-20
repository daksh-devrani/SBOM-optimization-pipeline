"""
LangGraph node: SBOM Vulnerability Validation.

Bridges the existing LangGraph pipeline and the research validation system.
This node runs after sbom_node and before END.

Reads from state:
    trivy_report_path  — filesystem path to Trivy JSON report
    sbom_report_path   — filesystem path to Syft SBOM JSON
    repo_path          — filesystem path to the cloned target repository

Writes to state:
    validation_report  — ValidationReport dict (or None on failure)
    validation_errors  — list of error strings
"""

import sys
from pathlib import Path

# ── Ensure repo root is on sys.path so `research` package is importable ───────
# This file lives at: ai_engine/nodes/validation_node.py
# Repo root is:       ai_engine/nodes/../../  (two levels up)
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from schemas.pipeline_state import PipelineState  # noqa: E402
from research.pipeline.run_validation import run_pipeline  # noqa: E402
from research.utils.logger import get_logger  # noqa: E402

logger = get_logger(__name__)


def validation_node(state: PipelineState | dict) -> dict:
    """
    LangGraph node: SBOM Vulnerability Validation Agent.

    Invokes the research pipeline to filter false-positive vulnerabilities
    using static analysis + rule engine + optional LLM validation.

    Args:
        state: LangGraph state as PipelineState or dict (merged graph state).

    Returns:
        Dict with 'validation_report' and 'validation_errors' keys to
        merge back into PipelineState.
    """
    ps = state if isinstance(state, PipelineState) else PipelineState.model_validate(state)
    trivy_report_path: str = ps.trivy_report_path or ""
    sbom_report_path: str = ps.sbom_report_path or ""
    repo_path: str = ps.repo_path or ""

    # ── Guard: skip if required paths are missing ────────────────────────────
    if not trivy_report_path or not sbom_report_path or not repo_path:
        missing = [
            name
            for name, val in [
                ("trivy_report_path", trivy_report_path),
                ("sbom_report_path", sbom_report_path),
                ("repo_path", repo_path),
            ]
            if not val
        ]
        logger.warning(
            "Validation node skipped — missing required paths",
            extra={"missing_fields": missing},
        )
        return {
            "validation_report": None,
            "validation_errors": [
                f"Missing required state fields: {', '.join(missing)}"
            ],
        }

    logger.info(
        "Validation node started",
        extra={
            "trivy_report_path": trivy_report_path,
            "sbom_report_path": sbom_report_path,
            "repo_path": repo_path,
        },
    )

    try:
        report = run_pipeline(
            sbom_path=sbom_report_path,
            trivy_path=trivy_report_path,
            repo_path=repo_path,
            output_dir="research_outputs",
            threshold=0.75,
            disable_llm=False,
        )

        logger.info(
            "Validation node complete",
            extra={
                "total": report.total_input,
                "kept": report.kept_count,
                "removed": report.removed_count,
            },
        )
        return {
            "validation_report": report.model_dump(mode="json"),
            "validation_errors": report.errors,
        }

    except Exception as e:
        error_msg = f"Validation pipeline failed: {e}"
        logger.error("Validation node error", extra={"error": error_msg})
        return {
            "validation_report": None,
            "validation_errors": [error_msg],
        }
