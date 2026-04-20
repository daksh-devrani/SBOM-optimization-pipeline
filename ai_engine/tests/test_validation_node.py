"""validation_node must accept PipelineState (LangGraph) and plain dicts."""

from nodes.validation_node import validation_node
from schemas.pipeline_state import PipelineState


def test_validation_skips_with_pipeline_state_when_paths_missing():
    ps = PipelineState(
        trivy_report_path="",
        sbom_report_path="",
        repo_path="",
    )
    out = validation_node(ps)
    assert out["validation_report"] is None
    assert out["validation_errors"]
    joined = " ".join(out["validation_errors"]).lower()
    assert "missing" in joined


def test_validation_skips_with_dict_when_paths_missing():
    ps = PipelineState(
        trivy_report_path="",
        sbom_report_path="",
        repo_path="",
    )
    out = validation_node(ps.model_dump())
    assert out["validation_report"] is None
    assert out["validation_errors"]
